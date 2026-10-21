"""CLI Тома 2 — `python -m flicker_worker`.

Команды:
    run       прогнать запрос через конвейер B1→B9
    demo      скриптовая демонстрация: валидный план И блокировка галлюцинации
    selftest  локальные проверки (ядро, интероперабельность, барьеры)
    supervisor  статус/zeroize Тома 1
    maturity  отчёт о зрелости компонентов (§6.2)
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from typing import Any, Optional

from . import MATURITY, FPS1_VERSION, __version__
from .core import CoreError, FlickerCore
from .critic import FpccCritic
from .grammar import SPLIT_MARKER
from .hitl import Decision, HitlGate
from .llm import ROLE_MODELS, OfflineBackend, VllmBackend, build_backend
from .pipeline import FlickerPipeline, PipelineStatus
from .provenance import InMemoryKnowledgeBase
from .replay import verify_file

EXIT_OK = 0
EXIT_REJECTED = 1
EXIT_USAGE = 2
EXIT_CORE = 3
EXIT_CHAIN = 6


def _kb_from_store(path: str, *, create: bool = True):
    """Персистентная база знаний (SQLite) как бэкенд барьера B3.

    Именно персистентность делает provenance осмысленным: аудит обязан
    воспроизводиться post-factum (G4), а `InMemoryKnowledgeBase` умирает
    вместе с процессом и пригодна только для CI и демо.
    """
    from .knowledge import KnowledgeStore
    if not create and not os.path.exists(path):
        raise SystemExit("база знаний не найдена: %s" % path)
    return KnowledgeStore(path)


def _seed_demo_kb(kb, domain_hint: str, *, stale: bool = False) -> None:
    """Наполнить демо-базу. В production факты приходят из источников (§7.5),
    а не генерируются: подстановка «правдоподобных» значений — это и есть
    та галлюцинация, от которой B3 защищает (R7.5.2)."""
    import time as _t
    now = int(_t.time())
    as_of = now - 100_000 if stale else now - 60
    if "block" in domain_hint.lower():
        for o in ("b1", "b2"):
            kb.put_object(o, "block", "wms-inventory", as_of=as_of, confidence=0.99)
        for a in ("(ontable b1)", "(ontable b2)", "(clear b1)", "(clear b2)", "(handempty)"):
            kb.put_atom(a, "wms-inventory", as_of=as_of, confidence=0.99)
    else:
        for o, t in (("t1", "truck"), ("a", "place"), ("b", "place"), ("c", "place")):
            kb.put_object(o, t, "tms-fleet", as_of=as_of, confidence=0.98)
        for a in ("(at t1 a)", "(road a b)", "(road b c)"):
            kb.put_atom(a, "tms-fleet", as_of=as_of, confidence=0.98)


def _kb_for(domain_hint: str, staleness_ok: bool = True) -> InMemoryKnowledgeBase:
    """База знаний для демо/CI.

    В production — GraphRAG поверх Neo4j (§7.5). Интерфейс совпадает, поэтому
    замена не затрагивает конвейер. Здесь намеренно заполняются ВСЕ объекты и
    факты, которые использует офлайн-шаблон: смысл B3 не в том, чтобы всё
    разрешалось, а в том, чтобы неразрешённое вызывало отказ.
    """
    kb = InMemoryKnowledgeBase()
    import time
    now = int(time.time())
    as_of = now - 60 if staleness_ok else now - 100_000  # 100 000 с ≈ 27 ч

    if "block" in domain_hint.lower():
        for o in ("b1", "b2"):
            kb.add_object(o, "wms-inventory", as_of=as_of, confidence=0.99)
        for a in ("(ontable b1)", "(ontable b2)", "(clear b1)", "(clear b2)", "(handempty)"):
            kb.add_atom(a, "wms-inventory", as_of=as_of, confidence=0.99)
    else:
        for o in ("t1", "a", "b", "c"):
            kb.add_object(o, "tms-fleet", as_of=as_of, confidence=0.98)
        for a in ("(at t1 a)", "(road a b)", "(road b c)"):
            kb.add_atom(a, "tms-fleet", as_of=as_of, confidence=0.98)
    return kb


def cmd_run(args: argparse.Namespace) -> int:
    try:
        core = FlickerCore(binary=args.core_bin)
    except CoreError as e:
        print("ОШИБКА ЯДРА: %s" % e, file=sys.stderr)
        return EXIT_CORE

    backend = build_backend(args.backend, mode=args.offline_mode) if args.backend != "vllm" \
        else VllmBackend(base_url=args.vllm_url)
    if args.no_provenance:
        kb = None
    elif args.kb:
        kb = _kb_from_store(args.kb)
        if args.seed_kb:
            _seed_demo_kb(kb, args.request, stale=args.stale_data)
    else:
        kb = _kb_for(args.request, staleness_ok=not args.stale_data)

    pipe = FlickerPipeline(
        backend=backend,
        core=core,
        kb=kb,
        critic=FpccCritic(backend, enable_nli=not args.no_critic),
        hitl=HitlGate(prompt_fn=_make_prompt_fn(args)),
        replay_path=args.replay,
        staleness_seconds=args.staleness,
        max_repair=args.max_repair,
        mode=args.mode,
        seed=args.seed,
        require_provenance=not args.no_provenance,
    )

    out = pipe.run(args.request, operator_id=args.operator,
                   present_to_operator=args.interactive)

    if args.json:
        print(json.dumps(out.to_json(), ensure_ascii=False, indent=2, sort_keys=True))
    else:
        print(out.render())
        if out.presentation and args.interactive:
            print("\nрешение оператора: %s" % (out.decision.decision if out.decision else "—"))

    if args.replay and os.path.exists(args.replay):
        r = verify_file(args.replay)
        if not r.ok:
            print("\nREPLAY CHAIN BROKEN: %s" % r.error, file=sys.stderr)
            return EXIT_CHAIN
        if not args.json:
            print("replay: %d записей, root=%s, целостность OK" % (r.lines, r.root_hash))

    if out.status == PipelineStatus.APPROVED:
        return EXIT_OK
    if out.status == PipelineStatus.AWAITING_OPERATOR:
        return EXIT_OK
    return EXIT_REJECTED


def _make_prompt_fn(args: argparse.Namespace):
    """Функция ввода для шлюза B9 в неинтерактивном режиме.

    R7.7.4: автоматического ИСПОЛНЕНИЯ не существует. `--auto-approve`
    имитирует ВВОД ОПЕРАТОРА для сквозных тестов, а не отключает шлюз: план
    всё равно предъявляется, решение всё равно пишется в replay как
    `operator_confirm` с отпечатком предъявленного плана.

    Ответ выбирается по ТЕКСТУ запроса, а не по порядку вызовов: `HitlGate`
    спрашивает идентификатор оператора только если он не передан, поэтому
    порядковая схема давала «yes» на вопрос об идентификаторе и `abstain`
    на подтверждение.
    """
    if args.interactive and not args.auto_approve:
        return None  # настоящий stdin: оператор вводит сам

    operator = args.operator or "test-operator"
    answer = "yes" if args.auto_approve else "no"

    def prompt_fn(text: str) -> str:
        low = text.lower()
        if "идентификатор оператора" in text or "operator" in low and "подтвердить" not in low:
            return operator
        return answer

    return prompt_fn


def cmd_demo(args: argparse.Namespace) -> int:
    """Демонстрация: обёртка ПРОПУСКАЕТ валидный план и БЛОКИРУЕТ галлюцинацию."""
    print("=" * 72)
    print("FLICKER V30 · демонстрация обёртки анти-галлюцинации")
    print("=" * 72)
    print("backend = offline (maturity=mock) — детерминированная подстановка,")
    print("НЕ языковая модель. Демо показывает работу БАРЬЕРОВ, а не качество")
    print("трансляции ЕЯ→PDDL.\n")

    try:
        core = FlickerCore(binary=args.core_bin)
        st = core.selftest()
    except CoreError as e:
        print("ОШИБКА ЯДРА: %s" % e, file=sys.stderr)
        return EXIT_CORE
    print("[ядро] selftest: %s" % ("OK" if st.ok else "FAIL"))
    if not st.ok:
        return EXIT_CORE

    results = []
    chains: list[tuple[str, str]] = []   # (label, path)

    def chain_for(label: str, idx: int) -> Optional[str]:
        """Отдельная цепь на прогон: replay-цепь — аудит-след ОДНОГО решения.

        Конкатенация нескольких цепей в один файл невалидна по построению
        (seq restarts at GENESIS), и `verify_chain` справедливо её отклоняет.
        """
        if not args.replay:
            return None
        base, ext = os.path.splitext(args.replay)
        path = "%s.%02d-%s%s" % (base or args.replay, idx, label, ext or ".jsonl")
        chains.append((label, path))
        return path

    # --- Сценарий 1: корректный запрос -----------------------------------
    print("\n" + "─" * 72)
    print("СЦЕНАРИЙ 1 · корректный запрос")
    print("─" * 72)
    b1 = OfflineBackend(mode="logistics")
    p1 = FlickerPipeline(backend=b1, core=core, kb=_kb_for("logistics"),
                         replay_path=chain_for('valid', 1), mode="auto")
    o1 = p1.run("Перевезти груз t1 из пункта a в пункт c")
    print(o1.render())
    results.append(("валидный план принят", o1.status == PipelineStatus.AWAITING_OPERATOR))

    # --- Сценарий 2: галлюцинация (числовой флюент, вне FPS-1) -----------
    print("\n" + "─" * 72)
    print("СЦЕНАРИЙ 2 · модель галлюцинирует: числовой флюент вне FPS-1")
    print("─" * 72)
    b2 = OfflineBackend(mode="hallucinate")
    p2 = FlickerPipeline(backend=b2, core=core, kb=_kb_for("logistics"),
                         replay_path=chain_for('hallucination', 2), max_repair=0)
    o2 = p2.run("Посчитать стоимость доставки")
    print(o2.render())
    results.append(("галлюцинация отклонена", o2.status == PipelineStatus.REJECTED))

    # --- Сценарий 3: синтаксически разрушенный выход ---------------------
    print("\n" + "─" * 72)
    print("СЦЕНАРИЙ 3 · синтаксически разрушенный выход (сбой constrained decoding)")
    print("─" * 72)
    b3 = OfflineBackend(mode="malformed")
    p3 = FlickerPipeline(backend=b3, core=core, kb=_kb_for("logistics"),
                         replay_path=chain_for('malformed', 3), max_repair=0)
    o3 = p3.run("Что-нибудь")
    print(o3.render())
    results.append(("невалидный синтаксис отклонён", o3.status == PipelineStatus.REJECTED))

    # --- Сценарий 4: неразрешённая референция (B3 / E3) ------------------
    print("\n" + "─" * 72)
    print("СЦЕНАРИЙ 4 · база знаний пуста: неразрешённая референция (R7.5.2)")
    print("─" * 72)
    b4 = OfflineBackend(mode="logistics")
    p4 = FlickerPipeline(backend=b4, core=core, kb=InMemoryKnowledgeBase(),
                         replay_path=chain_for('unresolved-ref', 4), max_repair=0)
    o4 = p4.run("Перевезти груз")
    print(o4.render())
    results.append(("отказ вместо догадки", o4.status == PipelineStatus.REJECTED))

    # --- Сценарий 5: устаревшие данные (R7.5.3) --------------------------
    print("\n" + "─" * 72)
    print("СЦЕНАРИЙ 5 · данные устарели (as_of старше staleness_bound)")
    print("─" * 72)
    b5 = OfflineBackend(mode="logistics")
    p5 = FlickerPipeline(backend=b5, core=core,
                         kb=_kb_for("logistics", staleness_ok=False),
                         staleness_seconds=900, replay_path=chain_for('stale-data', 5), max_repair=0)
    o5 = p5.run("Перевезти груз")
    print(o5.render())
    results.append(("устаревшие данные отклонены", o5.status == PipelineStatus.REJECTED))

    # --- Сценарий 6: нет базы знаний вообще (§15.4) ----------------------
    print("\n" + "─" * 72)
    print("СЦЕНАРИЙ 6 · GraphRAG недоступен: система останавливается (§15.4)")
    print("─" * 72)
    b6 = OfflineBackend(mode="logistics")
    p6 = FlickerPipeline(backend=b6, core=core, kb=None,
                         replay_path=chain_for('no-graphrag', 6), max_repair=0)
    o6 = p6.run("Перевезти груз")
    print(o6.render())
    results.append(("остановка без provenance", o6.status == PipelineStatus.REJECTED))

    # --- Итог -------------------------------------------------------------
    print("\n" + "=" * 72)
    print("ИТОГ ДЕМО")
    print("=" * 72)
    ok = True
    for name, passed in results:
        print("  [%s] %s" % ("PASS" if passed else "FAIL", name))
        ok = ok and passed
    if chains:
        print("\n  replay-цепи (по одной на прогон — аудит-след отдельного решения):")
        for label, path in chains:
            if not os.path.exists(path):
                print("    [FAIL] %-16s файл не создан" % label)
                ok = False
                continue
            r = verify_file(path)
            print("    [%s] %-16s %2d записей, root=%s%s"
                  % ("PASS" if r.ok else "FAIL", label, r.lines, r.root_hash[:16],
                     "" if r.ok else "  <- %s" % r.error))
            ok = ok and r.ok
    print("\n%s" % ("ВСЕ СЦЕНАРИИ ПРОЙДЕНЫ" if ok else "ЕСТЬ ПРОВАЛЫ"))
    print("\nКлючевое утверждение, которое демо подтверждает:")
    print("  модель ошибалась в 5 сценариях из 6 — и ни одна её ошибка")
    print("  не превратилась в план, готовый к исполнению.")
    return EXIT_OK if ok else EXIT_REJECTED


def cmd_selftest(args: argparse.Namespace) -> int:
    checks: list[tuple[str, bool, str]] = []
    try:
        core = FlickerCore(binary=args.core_bin)
        checks.append(("core binary found", True, core.binary))
        st = core.selftest()
        checks.append(("core selftest (FIPS/RFC/PRNG/canon/replay)", st.ok,
                       "" if st.ok else st.raw_stdout[:200]))
        d = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__)))), "domains", "logistics.pddl")
        p = d.replace("logistics.pddl", "logistics_p1.pddl")
        if os.path.exists(d) and os.path.exists(p):
            pl = core.plan(d, p, mode="best-first")
            good = pl.ok and len(FlickerCore.steps_from_result(pl)) == 2
            checks.append(("end-to-end plan via core (2 steps)", good,
                           "steps=%d" % len(FlickerCore.steps_from_result(pl))))
    except CoreError as e:
        checks.append(("core binary found", False, str(e)))

    # grammar file
    try:
        from .grammar import load_grammar
        g = load_grammar()
        checks.append(("EBNF grammar loadable", len(g) > 1000, "%d chars" % len(g)))
        checks.append(("grammar declares the split marker", SPLIT_MARKER in g, ""))
    except Exception as e:
        checks.append(("EBNF grammar loadable", False, str(e)))

    # pipeline: happy path offline
    try:
        core = FlickerCore(binary=args.core_bin)
        pipe = FlickerPipeline(backend=OfflineBackend(mode="logistics"), core=core,
                               kb=_kb_for("logistics"), max_repair=0)
        out = pipe.run("Перевезти t1 из a в c")
        checks.append(("pipeline reaches HITL on valid input",
                       out.status == PipelineStatus.AWAITING_OPERATOR, out.status))
        checks.append(("plan has 2 steps", len(out.steps) == 2, str(len(out.steps))))
        checks.append(("confidence within [0,1]", 0.0 <= out.confidence <= 1.0,
                       "%.2f" % out.confidence))
        checks.append(("not_verified is non-empty (R7.7.2)",
                       bool(out.presentation and out.presentation.not_verified), ""))
    except Exception as e:
        checks.append(("pipeline happy path", False, "%s: %s" % (type(e).__name__, e)))

    # pipeline: hallucination blocked
    try:
        pipe = FlickerPipeline(backend=OfflineBackend(mode="hallucinate"),
                               core=FlickerCore(binary=args.core_bin),
                               kb=_kb_for("logistics"), max_repair=0)
        out = pipe.run("x")
        checks.append(("hallucination rejected", out.status == PipelineStatus.REJECTED,
                       out.status))
    except Exception as e:
        checks.append(("hallucination rejected", False, str(e)))

    # denied models gate
    try:
        VllmBackend(models={"main": "meta-llama/Llama-3.1-405B"})
        checks.append(("Llama rejected by license-gate", False, "no exception raised"))
    except ValueError as e:
        checks.append(("Llama rejected by license-gate", "DENIED" in str(e), str(e)[:80]))

    ok = all(p for _, p, _ in checks)
    if args.json:
        print(json.dumps({"ok": ok, "component": "flicker-worker",
                          "version": __version__,
                          "checks": [{"check": n, "ok": p, "detail": d} for n, p, d in checks]},
                         ensure_ascii=False, indent=2, sort_keys=True))
    else:
        print("WORKER SELFTEST · v%s · %s" % (__version__, FPS1_VERSION))
        for n, p, d in checks:
            print("  [%s] %s%s" % ("PASS" if p else "FAIL", n,
                                   "" if not d else "  (%s)" % d))
        print("RESULT: %s" % ("ALL PASS" if ok else "FAILURES PRESENT"))
    return EXIT_OK if ok else EXIT_REJECTED


def cmd_redteam(args: argparse.Namespace) -> int:
    """Критерий B1 (§12.6): измерение semantic_escape_rate.

    Категории 4 (E4) и 5 (injection) публикуются ОТДЕЛЬНО и на pass/fail B1
    не влияют: E4 — ожидаемый провал, который система не способна обнаружить
    в принципе, а не дефект реализации.
    """
    import json as _json
    from .redteam import RedTeamSuite, build_scenarios

    scs = build_scenarios(per_category=args.per_category, seed=args.seed)
    if args.limit:
        scs = scs[:args.limit]

    def progress(done: int, total: int) -> None:
        if not args.json:
            print("  … %d/%d" % (done, total), file=sys.stderr, end="\r")

    suite = RedTeamSuite()
    rep = suite.run(scs, progress=progress)

    if args.json:
        print(_json.dumps(rep.to_json(), ensure_ascii=False, indent=2, sort_keys=True))
    else:
        if not args.json:
            print(" " * 24, end="\r")
        print(rep.render())
        if args.replay:
            # canonicalize обязателен: метрики — float, а symbolic_core::json
            # не имеет варианта float (детерминизм G3/G4).
            from .canon import canonicalize
            from .replay import ReplayWriter
            w = ReplayWriter(path=args.replay)
            w.record("redteam_report", canonicalize({
                "semantic_escape_rate": rep.escape_rate(),
                "e4_incomplete_rate": rep.incomplete_rate(),
                "injection_resistance": rep.injection_resistance(),
                "counts": rep.counts(),
                "target": rep.target_escape_rate,
            }))
            print("\n  replay: %s root=%s" % (args.replay, w.root_hash))

    return EXIT_OK if rep.passed() else EXIT_REJECTED


def cmd_iep(args: argparse.Namespace) -> int:
    """Эмпирическая проверка барьеров IEP (§9).

    Проверяется НАБЛЮДАЕМОЕ поведение внутри песочницы, а не факт передачи
    правильных флагов: окружение может проигнорировать флаг, и тогда
    «изоляция включена» было бы ложным утверждением.
    """
    from .iep import IepPolicy, IsolatedExecutionPool

    policy = IepPolicy(use_seccomp=not args.no_seccomp)
    pool = IsolatedExecutionPool(policy)
    env = pool.warm()
    res = pool.verify_isolation()

    if args.json:
        print(json.dumps({"environment": env, "checks": res},
                         ensure_ascii=False, indent=2, sort_keys=True, default=str))
    else:
        print("IEP · проверка изоляции (§9)")
        print("  bwrap:           %s" % env.get("bwrap_path"))
        print("  seccomp helper:  %s" % env.get("seccomp_helper"))
        print("  isolation:       %s" % env.get("isolation_verified"))
        print("  effective flags: %s" % " ".join(env.get("effective_flags") or []))
        for n in env.get("notes") or []:
            print("  ! %s" % n[:150])
        print("")
        for k in sorted(res):
            if k in ("notes", "effective_flags"):
                continue
            v = res[k]
            mark = "PASS" if v is True else ("FAIL" if v is False else " -- ")
            print("  [%s] %-26s %s" % (mark, k, str(v)[:88]))
        print("")
        if res.get("skipped"):
            print("RESULT: ПРОВЕРКИ НЕ ВЫПОЛНЕНЫ — изоляция недоступна в этом окружении.")
            print("        Это НЕ означает, что IEP не работает: SKIP != PASS.")
        else:
            print("RESULT: %s" % ("REQUIRED PASS" if res.get("required_pass") else "FAIL"))
    if res.get("skipped"):
        return EXIT_OK          # отсутствие возможности окружения — не провал кода
    return EXIT_OK if res.get("required_pass") else EXIT_REJECTED


def cmd_maturity(args: argparse.Namespace) -> int:
    data = {"component": "flicker-worker", "version": __version__,
            "fps1": FPS1_VERSION, "maturity": MATURITY}
    if args.json:
        print(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        print("MATURITY REPORT (§6.2) · flicker-worker v%s" % __version__)
        for k, v in sorted(MATURITY.items()):
            print("  %-22s %s" % (k, v))
        print("\nЧестность обязательна: заявлять компонент как реализованный,")
        print("имея maturity=stub/mock, запрещено (R6.2, §16.1 ТЗ).")
        print("В частности: llm_offline=mock — это НЕ языковая модель.")
    return EXIT_OK


def cmd_supervisor(args: argparse.Namespace) -> int:
    from .ipc import SupervisorClient, SupervisorError
    c = SupervisorClient(socket_path=args.socket, session_id=args.session_id,
                         session_key=args.session_key)
    try:
        if args.sup_action == "status":
            r = c.status()
        elif args.sup_action == "zeroize":
            r = c.zeroize()
        elif args.sup_action == "keys":
            r = c.list_keys()
        elif args.sup_action == "attest":
            r = c.attest()
        else:
            r = c.ping()
    except SupervisorError as e:
        print("SUPERVISOR UNAVAILABLE: %s" % e, file=sys.stderr)
        return EXIT_CORE
    print(json.dumps(r.data, ensure_ascii=False, indent=2, sort_keys=True)
          if args.json else r.raw)
    if not r.ok and args.sup_action == "zeroize":
        return 10
    return EXIT_OK if r.ok else EXIT_REJECTED


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="flicker-worker",
        description="FLICKER Том 2 — конвейер B1→B9 вокруг нормативного ядра symbolic-core")
    p.add_argument("--version", action="version",
                   version="flicker-worker %s (%s)" % (__version__, FPS1_VERSION))
    sub = p.add_subparsers(dest="cmd")

    r = sub.add_parser("run", help="прогнать запрос через конвейер")
    r.add_argument("request", help="запрос оператора на естественном языке")
    r.add_argument("--backend", default="auto", choices=["auto", "offline", "vllm"])
    r.add_argument("--offline-mode", default="auto",
                   choices=["auto", "logistics", "blocks", "hallucinate", "empty", "malformed"])
    r.add_argument("--vllm-url", default=None)
    r.add_argument("--core-bin", default=None)
    r.add_argument("--mode", default="auto", choices=["auto", "best-first", "mcts"])
    r.add_argument("--seed", type=int, default=42)
    r.add_argument("--max-repair", type=int, default=3)
    r.add_argument("--staleness", type=int, default=900)
    r.add_argument("--replay", default=None, help="путь JSONL для replay-цепи")
    r.add_argument("--no-provenance", action="store_true",
                   help="отключить B3 (нарушает §15.4 — только для диагностики)")
    r.add_argument("--no-critic", action="store_true")
    r.add_argument("--kb", default=None,
                   help="путь к персистентной БЗ (SQLite); без него — in-memory (только CI/демо)")
    r.add_argument("--seed-kb", action="store_true",
                   help="наполнить БЗ демо-фактами (для первого запуска)")
    r.add_argument("--stale-data", action="store_true",
                   help="демо: сделать факты устаревшими (проверка R7.5.3)")
    r.add_argument("--interactive", action="store_true",
                   help="предъявить план и ждать ввода оператора (B9)")
    r.add_argument("--auto-approve", action="store_true",
                   help="имитировать ввод 'yes' для сквозных тестов (НЕ отключает шлюз)")
    r.add_argument("--operator", default=None)
    r.add_argument("--json", action="store_true")
    r.set_defaults(fn=cmd_run)

    d = sub.add_parser("demo", help="демонстрация блокировки галлюцинаций")
    d.add_argument("--core-bin", default=None)
    d.add_argument("--replay", default=None)
    d.set_defaults(fn=cmd_demo)

    s = sub.add_parser("selftest", help="локальные проверки")
    s.add_argument("--core-bin", default=None)
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_selftest)

    rt = sub.add_parser("redteam",
                        help="критерий B1: semantic_escape_rate (§12.6, >= 500 сценариев)")
    rt.add_argument("--per-category", type=int, default=100,
                    help="сценариев на категорию 1-4 (default 100 -> 520 всего)")
    rt.add_argument("--seed", type=int, default=0xA7)
    rt.add_argument("--limit", type=int, default=None,
                    help="ограничить число сценариев (для быстрой проверки)")
    rt.add_argument("--replay", default=None, help="записать отчёт в replay-цепь")
    rt.add_argument("--json", action="store_true")
    rt.set_defaults(fn=cmd_redteam)

    ie = sub.add_parser("iep", help="эмпирическая проверка изоляции (§9)")
    ie.add_argument("--no-seccomp", action="store_true")
    ie.add_argument("--json", action="store_true")
    ie.set_defaults(fn=cmd_iep)

    m = sub.add_parser("maturity", help="отчёт о зрелости компонентов")
    m.add_argument("--json", action="store_true")
    m.set_defaults(fn=cmd_maturity)

    u = sub.add_parser("supervisor", help="вызов Тома 1")
    u.add_argument("sup_action", nargs="?", default="ping",
                   choices=["ping", "status", "keys", "zeroize", "attest"])
    u.add_argument("--socket", default=None)
    u.add_argument("--session-id", default="worker-session")
    u.add_argument("--session-key", default="dev-session-key")
    u.add_argument("--json", action="store_true")
    u.set_defaults(fn=cmd_supervisor)

    return p


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "cmd", None):
        parser.print_help()
        return EXIT_USAGE
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
