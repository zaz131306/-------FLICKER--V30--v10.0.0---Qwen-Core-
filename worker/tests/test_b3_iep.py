"""Тесты B3 (персистентная база знаний) и IEP (изолированное исполнение).

Запуск:  python3 tests/test_b3_iep.py
"""
from __future__ import annotations

import os
import shutil
import sqlite3
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

class Skip(Exception):
    """Тест не выполнялся: отсутствует требуемая возможность окружения.

    SKIP НЕ ЯВЛЯЕТСЯ PASS. Молчаливый пропуск обязательной проверки — это
    ровно та нечестность, которую запрещает §3.3 ТЗ: отчёт обязан показывать,
    что именно не было проверено.
    """


from flicker_worker.canon import sha256_hex
from flicker_worker.iep import (IepError, IepPolicy, IsolatedExecutionPool,
                                Rlimits, probe_environment, _find_seccomp_helper)
from flicker_worker.knowledge import (BP_SCALE, IntegrityReport, KnowledgeError,
                                      KnowledgeStore, bp_from_float, float_from_bp,
                                      row_hash)
from flicker_worker.provenance import ProvenanceGate

NOW = int(time.time())


# ===========================================================================
#  B3 · Персистентная база знаний
# ===========================================================================

def _tmp_db():
    fd, path = tempfile.mkstemp(prefix="flicker-kb-", suffix=".sqlite3")
    os.close(fd)
    os.unlink(path)          # KnowledgeStore создаст сам
    return path


def test_confidence_roundtrips_through_basis_points():
    """confidence хранится в ЦЕЛЫХ bp: float разрушил бы детерминизм хэша."""
    for v in (0.0, 0.0001, 0.5, 0.98, 1.0):
        assert float_from_bp(bp_from_float(v)) == round(v, 4) or abs(
            float_from_bp(bp_from_float(v)) - v) < 1e-9, v
    assert bp_from_float(1.0) == BP_SCALE
    assert bp_from_float(0.0) == 0
    for bad in (-0.1, 1.1, float("nan")):
        try:
            bp_from_float(bad)
        except KnowledgeError:
            continue
        raise AssertionError("bad confidence must be rejected: %r" % bad)


def test_source_and_as_of_are_mandatory():
    """R7.5.1/R7.5.3: факт без источника или без метки времени недопустим."""
    path = _tmp_db()
    try:
        with KnowledgeStore(path) as kb:
            for kwargs, why in [
                ({"source": "", "as_of": NOW}, "пустой source"),
                ({"source": "   ", "as_of": NOW}, "пробельный source"),
                ({"source": "src", "as_of": None}, "as_of отсутствует"),
                ({"source": "src", "as_of": 0}, "as_of == 0"),
                ({"source": "src", "as_of": -5}, "as_of отрицательный"),
            ]:
                try:
                    kb.put_atom("(at t1 a)", **kwargs)
                except KnowledgeError:
                    continue
                raise AssertionError("must reject %s" % why)
    finally:
        _cleanup(path)


def test_persistence_survives_reopen():
    """Главное свойство: provenance переживает перезапуск процесса."""
    path = _tmp_db()
    try:
        with KnowledgeStore(path) as kb:
            kb.put_object("t1", "truck", "tms-fleet", as_of=NOW - 30, confidence=0.98)
            kb.put_atom("(at t1 a)", "tms-fleet", as_of=NOW - 30, confidence=0.98)
            kb.put_edge("a", "road", "b", "map-service", as_of=NOW - 60, confidence=0.9)

        # Новое соединение — данные на месте
        with KnowledgeStore(path) as kb2:
            o = kb2.lookup_object("t1")
            assert o is not None, "object lost after reopen"
            assert o.source == "tms-fleet"
            assert abs(o.confidence - 0.98) < 1e-9
            a = kb2.lookup_atom("(at t1 a)")
            assert a is not None, "atom lost after reopen"
            assert a.as_of == NOW - 30
            n = kb2.neighbors("a")
            assert len(n) == 1 and n[0]["rel"] == "road"
            assert kb2.counts()["objects"] == 1
            assert kb2.counts()["atoms"] == 1
            assert kb2.counts()["edges"] == 1
    finally:
        _cleanup(path)


def test_row_hash_is_stable_and_sensitivity():
    """row_hash детерминирован и чувствителен к каждому полю."""
    base = row_hash("atom", "(at t1 a)", "tms", NOW, 9800, "")
    assert base == row_hash("atom", "(at t1 a)", "tms", NOW, 9800, "")
    assert len(base) == 64
    assert base != row_hash("atom", "(at t1 a)", "OTHER", NOW, 9800, "")
    assert base != row_hash("atom", "(at t1 a)", "tms", NOW + 1, 9800, "")
    assert base != row_hash("atom", "(at t1 a)", "tms", NOW, 9801, "")
    assert base != row_hash("atom", "(at t1 b)", "tms", NOW, 9800, "")
    assert base != row_hash("OBJECT", "(at t1 a)", "tms", NOW, 9800, "")


def test_integrity_verification_detects_tampering():
    """Подмена provenance ПОСЛЕ записи обнаруживается пересчётом row_hash."""
    path = _tmp_db()
    try:
        with KnowledgeStore(path) as kb:
            kb.put_object("t1", "truck", "tms-fleet", as_of=NOW - 30, confidence=0.98)
            kb.put_atom("(at t1 a)", "tms-fleet", as_of=NOW - 30, confidence=0.98)
            rep = kb.verify_integrity()
            assert rep.ok, rep.detail
            assert rep.rows_checked == 2

        # Прямая подмена в обход API: меняем source, оставляя старый row_hash
        conn = sqlite3.connect(path)
        conn.execute("UPDATE atoms SET source='attacker' WHERE key='(at t1 a)'")
        conn.commit()
        conn.close()

        with KnowledgeStore(path, readonly=True) as kb2:
            rep2 = kb2.verify_integrity()
            assert not rep2.ok, "tampering MUST be detected"
            assert any("atoms:" in m for m in rep2.mismatches), rep2.mismatches
    finally:
        _cleanup(path)


def test_integrity_detects_as_of_tampering():
    """Омолодить факт задним числом нельзя: as_of входит в row_hash."""
    path = _tmp_db()
    try:
        with KnowledgeStore(path) as kb:
            kb.put_atom("(road a b)", "map", as_of=NOW - 100_000, confidence=0.9)
        conn = sqlite3.connect(path)
        conn.execute("UPDATE atoms SET as_of=? WHERE key='(road a b)'", (NOW,))
        conn.commit()
        conn.close()
        with KnowledgeStore(path, readonly=True) as kb2:
            rep = kb2.verify_integrity()
            assert not rep.ok, "as_of tampering MUST be detected"
    finally:
        _cleanup(path)


def test_audit_chain_detects_break():
    path = _tmp_db()
    try:
        with KnowledgeStore(path) as kb:
            for i in range(5):
                kb.put_atom("(a%d)" % i, "src", as_of=NOW - i)
            ok, detail = kb.verify_audit_chain()
            assert ok, detail
            assert "5 audit records" in detail
        # подмена журнала
        conn = sqlite3.connect(path)
        conn.execute("UPDATE audit SET row_hash='%s' WHERE seq=3" % ("f" * 64))
        conn.commit()
        conn.close()
        with KnowledgeStore(path, readonly=True) as kb2:
            ok2, detail2 = kb2.verify_audit_chain()
            assert not ok2, "audit chain break MUST be detected"
            assert "prev_hash mismatch" in detail2
    finally:
        _cleanup(path)


def test_store_works_as_provenance_gate_backend():
    """KnowledgeStore реализует протокол KnowledgeBase -> подставляется в B3."""
    path = _tmp_db()
    try:
        with KnowledgeStore(path) as kb:
            kb.put_object("t1", "truck", "tms", as_of=NOW - 10, confidence=0.99)
            kb.put_atom("(at t1 a)", "tms", as_of=NOW - 10, confidence=0.99)

            gate = ProvenanceGate(kb, staleness_seconds=900)
            rep = gate.check(["t1"], ["(at t1 a)"])
            assert rep.ok, rep.reasons
            assert rep.objects_resolved == ["t1"]
            assert len(rep.atoms_resolved) == 1
            assert rep.atoms_resolved[0].source == "tms"

            # неразрешённая референция -> отказ (R7.5.2)
            rep2 = gate.check(["t1", "ghost"], ["(at t1 a)"])
            assert not rep2.ok
            assert "ghost" in rep2.objects_unresolved
            assert any("R7.5.2" in r for r in rep2.reasons), rep2.reasons

            # устаревший факт -> отказ (R7.5.3)
            kb.put_atom("(road a b)", "map", as_of=NOW - 100_000, confidence=0.9)
            rep3 = gate.check(["t1"], ["(at t1 a)", "(road a b)"])
            assert not rep3.ok
            assert rep3.atoms_stale, "stale atom must be reported"
            assert any("R7.5.3" in r for r in rep3.reasons), rep3.reasons
    finally:
        _cleanup(path)


def test_readonly_store_refuses_writes():
    path = _tmp_db()
    try:
        with KnowledgeStore(path) as kb:
            kb.put_atom("(x)", "s", as_of=NOW)
        with KnowledgeStore(path, readonly=True) as ro:
            assert ro.lookup_atom("(x)") is not None
            for call in (
                lambda: ro.put_atom("(y)", "s", as_of=NOW),
                lambda: ro.put_object("o", "t", "s", as_of=NOW),
                lambda: ro.delete_atom("(x)"),
            ):
                try:
                    call()
                except KnowledgeError:
                    continue
                raise AssertionError("read-only store must refuse writes")
    finally:
        _cleanup(path)


def test_graph_path_is_deterministic_and_correct():
    path = _tmp_db()
    try:
        with KnowledgeStore(path) as kb:
            kb.put_edge("a", "road", "b", "map", as_of=NOW)
            kb.put_edge("b", "road", "c", "map", as_of=NOW)
            kb.put_edge("a", "rail", "c", "map", as_of=NOW)
            assert kb.find_path("a", "a") == []
            p1 = [e["dst"] for e in (kb.find_path("a", "c") or [])]
            p2 = [e["dst"] for e in (kb.find_path("a", "c") or [])]
            assert p1 == p2, "path must be deterministic (G3)"
            assert kb.find_path("a", "nowhere") is None
            # фильтр по свежести отсекает устаревшие рёбра
            kb.put_edge("z", "road", "y", "map", as_of=NOW - 100_000)
            assert kb.find_path("z", "y", max_age=900) is None
    finally:
        _cleanup(path)


def test_neighbors_age_filter_applies_to_both_directions():
    """РЕГРЕССИЯ на SQL-приоритет: `WHERE src=? OR dst=? AND as_of>=?` читается
    как `src=? OR (dst=? AND as_of>=?)`, поэтому рёбра, найденные по src,
    обходили фильтр свежести. Скобки обязательны.

    Безопасностное следствие без правки: устаревшие факты попадали в обход
    графа, ослабляя R7.5.3 (запрет на молчаливое использование stale-данных).
    """
    path = _tmp_db()
    try:
        with KnowledgeStore(path) as kb:
            kb.put_edge("fresh", "road", "x", "map", as_of=NOW - 10)
            kb.put_edge("stale", "road", "y", "map", as_of=NOW - 100_000)
            kb.put_edge("y", "rail", "stale", "map", as_of=NOW - 100_000)

            # по src: свежее видно, устаревшее — нет
            n_fresh = kb.neighbors("fresh", max_age=900)
            assert len(n_fresh) == 1, n_fresh
            n_stale = kb.neighbors("stale", max_age=900)
            assert n_stale == [], "stale edge matched by src bypassed the age filter: %r" % n_stale

            # по dst: та же проверка с другой стороны ребра
            n_y = kb.neighbors("y", max_age=900)
            assert n_y == [], "stale edge matched by dst must also be filtered: %r" % n_y

            # без фильтра видно всё: 'stale' входит в ДВА ребра
            # (как src в stale-road-y и как dst в y-rail-stale)
            assert len(kb.neighbors("stale")) == 2, kb.neighbors("stale")

            # и обход графа не использует устаревшее ребро
            assert kb.find_path("stale", "y", max_age=900) is None
            assert kb.find_path("stale", "y") is not None
    finally:
        _cleanup(path)


def test_load_facts_is_atomic():
    """Ошибка в одной записи откатывает всю пачку."""
    path = _tmp_db()
    try:
        with KnowledgeStore(path) as kb:
            facts = [
                {"kind": "atom", "key": "(p1)", "source": "s", "as_of": NOW},
                {"kind": "atom", "key": "(p2)", "source": "", "as_of": NOW},  # ошибка
                {"kind": "atom", "key": "(p3)", "source": "s", "as_of": NOW},
            ]
            try:
                kb.load_facts(facts)
            except KnowledgeError:
                pass
            else:
                raise AssertionError("bad fact must raise")
            assert kb.counts()["atoms"] == 0, "partial batch must be rolled back"
    finally:
        _cleanup(path)


# ===========================================================================
#  IEP · изолированное исполнение
# ===========================================================================

def test_probe_reports_capabilities_honestly():
    env = probe_environment()
    assert "isolation_verified" in env
    assert "effective_flags" in env
    assert isinstance(env.get("notes"), list)
    if env["bwrap_available"]:
        assert env["effective_flags"], "available bwrap must yield effective flags"


def test_iep_refuses_when_isolation_unavailable():
    """Деградация изоляции запрещена: пул обязан отказать, а не исполнить."""
    pool = IsolatedExecutionPool(bwrap="/nonexistent/bwrap")
    env = pool.warm()
    assert not env["isolation_verified"]
    try:
        pool.run(["/bin/true"])
    except IepError as e:
        assert "ОТКЛОНЕНО" in str(e) or "отказ" in str(e).lower()
    else:
        raise AssertionError("must refuse to run unisolated")
    # с диагностическим флагом — исполняет, но помечает isolated=False
    pool2 = IsolatedExecutionPool(bwrap="/nonexistent/bwrap",
                                  policy=IepPolicy(allow_unisolated=True))
    pool2.warm()
    r = pool2.run(["/bin/echo", "ok"])
    assert r.isolated is False
    assert any("UNISOLATED" in n for n in r.policy_notes)


def _require_isolation():
    env = probe_environment()
    return env.get("isolation_verified", False)


def test_iep_blocks_network():
    if not _require_isolation():
        raise Skip("bwrap isolation unavailable in this environment")
    pool = IsolatedExecutionPool(); pool.warm()
    r = pool.run(["/usr/bin/python3", "-c",
                  "import socket\n"
                  "try:\n"
                  "    s=socket.socket(); s.settimeout(2); s.connect(('1.1.1.1',53))\n"
                  "    print('NET_REACHABLE')\n"
                  "except OSError as e:\n"
                  "    print('NET_BLOCKED', type(e).__name__, e.errno)\n"])
    assert "NET_BLOCKED" in r.stdout, r.stdout + r.stderr
    assert "NET_REACHABLE" not in r.stdout


def test_iep_root_is_readonly_and_tmp_writable():
    if not _require_isolation():
        raise Skip("bwrap isolation unavailable in this environment")
    pool = IsolatedExecutionPool(); pool.warm()
    r = pool.run(["/bin/sh", "-c",
                  "touch /etc/flicker_probe 2>/dev/null && echo WRITABLE || echo READONLY; "
                  "echo x > /tmp/probe && echo TMP_WRITABLE || echo TMP_BLOCKED"])
    assert "READONLY" in r.stdout and "WRITABLE" not in r.stdout.replace("TMP_WRITABLE", "")
    assert "TMP_WRITABLE" in r.stdout


def test_iep_does_not_leak_environment():
    """Секреты вызывающего процесса не наследуются в песочницу."""
    if not _require_isolation():
        raise Skip("bwrap isolation unavailable in this environment")
    os.environ["FLICKER_SESSION_KEY"] = "super-secret-value"
    try:
        pool = IsolatedExecutionPool(); pool.warm()
        r = pool.run(["/bin/sh", "-c", "env | grep -c FLICKER_SESSION_KEY || true"])
        assert r.stdout.strip().startswith("0"), "secret leaked: %r" % r.stdout
    finally:
        del os.environ["FLICKER_SESSION_KEY"]


def test_iep_timeout_enforced():
    if not _require_isolation():
        raise Skip("bwrap isolation unavailable in this environment")
    pool = IsolatedExecutionPool(IepPolicy(timeout_seconds=2.0)); pool.warm()
    t0 = time.time()
    r = pool.run(["/bin/sh", "-c", "sleep 30"])
    assert r.timed_out, "hang must be interrupted"
    assert time.time() - t0 < 10, "timeout not honoured"


def test_iep_rlimit_address_space():
    if not _require_isolation():
        raise Skip("bwrap isolation unavailable in this environment")
    pool = IsolatedExecutionPool(IepPolicy(
        rlimits=Rlimits(address_space_bytes=192 * 1024 * 1024, cpu_seconds=10)))
    pool.warm()
    r = pool.run(["/usr/bin/python3", "-c",
                  "try:\n"
                  "    b=bytearray(1500*1024*1024); b[0]=1; print('ALLOC_OK')\n"
                  "except MemoryError:\n"
                  "    print('ALLOC_BLOCKED')\n"])
    assert "ALLOC_BLOCKED" in r.stdout or r.exit_code != 0, r.stdout + r.stderr


def test_seccomp_blocks_socket_and_ptrace():
    """R9.2: seccomp запрещает socket() и ptrace СИСТЕМНЫМ ВЫЗОВОМ."""
    helper = _find_seccomp_helper()
    if not helper:
        print("SKIP: seccomp helper not built (make seccomp)")
        return
    if not _require_isolation():
        raise Skip("bwrap isolation unavailable in this environment")
    pool = IsolatedExecutionPool(); pool.warm()
    r = pool.run(["/usr/bin/python3", "-c",
                  "import socket, ctypes\n"
                  "try:\n"
                  "    socket.socket(); print('SOCKET_ALLOWED')\n"
                  "except OSError as e:\n"
                  "    print('SOCKET_EPERM', e.errno)\n"
                  "libc = ctypes.CDLL(None, use_errno=True)\n"
                  "print('PTRACE', libc.ptrace(0,0,0,0), ctypes.get_errno())\n"])
    assert r.seccomp_applied, "seccomp helper was not applied"
    assert "SOCKET_EPERM 1" in r.stdout, r.stdout + r.stderr
    assert "SOCKET_ALLOWED" not in r.stdout
    assert "PTRACE -1 1" in r.stdout, r.stdout + r.stderr


def test_seccomp_helper_selftest():
    helper = _find_seccomp_helper()
    if not helper:
        raise Skip("seccomp helper not built (make seccomp)")
    import subprocess
    r = subprocess.run([helper, "--selftest"], capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "SELFTEST OK" in r.stdout


def test_verify_isolation_required_checks_pass():
    if not _require_isolation():
        raise Skip("bwrap isolation unavailable in this environment")
    pool = IsolatedExecutionPool(); pool.warm()
    res = pool.verify_isolation()
    missing = [k for k in ("network_blocked", "root_readonly", "tmp_writable",
                           "env_not_leaked", "timeout_enforced", "isolation_verified")
               if not res.get(k)]
    assert not missing, "failed isolation checks: %s\n%r" % (missing, res)
    assert res["required_pass"] is True


def test_pool_does_not_reuse_processes():
    """R9.4: время жизни процесса — одна задача."""
    if not _require_isolation():
        raise Skip("bwrap isolation unavailable in this environment")
    pool = IsolatedExecutionPool(); pool.warm()
    pids = set()
    for _ in range(3):
        r = pool.run(["/bin/sh", "-c", "echo $$"])
        assert r.ok, r.stderr
        pids.add(r.stdout.strip())
    # Файл-маркер, созданный одной задачей, не виден другой (tmpfs per-run)
    pool.run(["/bin/sh", "-c", "echo leak > /tmp/flicker_state_probe"])
    r2 = pool.run(["/bin/sh", "-c", "cat /tmp/flicker_state_probe 2>/dev/null || echo CLEAN"])
    assert "CLEAN" in r2.stdout, "state leaked between tasks: %r" % r2.stdout


def _cleanup(path):
    for suffix in ("", "-wal", "-shm"):
        try:
            os.unlink(path + suffix)
        except OSError:
            pass


def _run_all() -> int:
    fns = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_") and callable(f)]
    failed = 0
    skipped: list[str] = []
    passed = 0
    for name, fn in fns:
        try:
            fn()
            passed += 1
            print("  PASS  %s" % name)
        except Skip as e:
            skipped.append("%s (%s)" % (name, e))
            print("  SKIP  %s — %s" % (name, e))
        except AssertionError as e:
            failed += 1
            print("  FAIL  %s: %s" % (name, e))
        except Exception as e:
            failed += 1
            print("  ERROR %s: %s: %s" % (name, type(e).__name__, e))

    print("\n%d passed · %d skipped · %d failed  (всего %d)"
          % (passed, len(skipped), failed, len(fns)))
    if skipped:
        # Пропуск = непроверенное требование. В отчёте приёмки это обязано
        # быть видно, а не растворяться в общем «ok».
        print("\nНЕ ПРОВЕРЕНО (требуется другое окружение):")
        for s_ in skipped:
            print("  · %s" % s_)
        print("\nЭти проверки проходят на хосте с доступными user namespaces;")
        print("в CI они обязательны к исполнению (критерий A5/A6, §12).")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(_run_all())
