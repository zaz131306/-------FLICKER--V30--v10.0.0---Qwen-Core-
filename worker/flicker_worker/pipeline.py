"""Конвейер FLICKER: B1 → B9 (§4.1 ТЗ V30).

## Что здесь происходит

Естественный язык оператора проходит девять барьеров и превращается либо в
**формально верифицированный план с аудиторским следом**, либо в **явный отказ**.
Третьего исхода нет: «приблизительного» результата конвейер не выдаёт (R7.2.1).

    B1  constrained decoding      SLM-FORMAL + xgrammar/EBNF      → G1
    B1g structural gate           детектор дрейфа конфигурации
    B2  symbolic parse/type check symbolic-core (через core.py)   → G1
        repair loop ≤ 3           R7.2.1, temperature=0 на ремонте
    B3  provenance binding        объекты и :init ⇒ база знаний   → G5 (снижает)
    B4  grounding                 symbolic-core                   → G2
    B5  search                    best-first / MCTS               → G3
    B6  validation                ЖЁСТКИЙ шлюз R7.4.1             → G2
    B7  FPCC critic               вероятностный, НЕ гарантия
    B8  replay hash-chain         каждое событие                  → G4
    B9  HITL gate                 обязательное подтверждение

## Главное архитектурное свойство

Гарантии G1–G4 обеспечивает **Rust-ядро**, а не этот файл. Компрометация или
сбой воркера не может привести к исполнению невалидного плана: B6 выполняется
в ядре независимо. Поэтому `PipelineOutcome.status == "approved"` возможен
только после того, как ядро вернуло `valid && goal_satisfied`.

## Честность про G5

Конвейер НЕ устраняет семантические галлюцинации (E3) и неполноту модели (E4).
B3 и B7 снижают риск; остаток предъявляется оператору в `not_verified` (R7.7.2)
и измеряется как `semantic_escape_rate` (§12.6).
"""
from __future__ import annotations

import os
import tempfile
import time
from dataclasses import dataclass, field
from typing import Any, Optional

from .canon import canonical_json, canonicalize, sha256_hex
from .core import CoreResult, FlickerCore
from .critic import CriticReport, FpccCritic, Verdict
from .grammar import (EmissionError, load_grammar, split_emission, structural_gate)
from .hitl import Decision, HitlGate, OperatorDecision, PlanPresentation
from .llm import LlmBackend, Role
from .provenance import KnowledgeBase, ProvenanceGate, ProvenanceReport
from .replay import ReplayWriter

__all__ = ["StageStatus", "BarrierResult", "PipelineOutcome", "FlickerPipeline",
           "PipelineStatus", "DEFAULT_MAX_REPAIR"]

#: R7.2.1 — после исчерпания явный отказ, не деградация качества.
DEFAULT_MAX_REPAIR = 3


class PipelineStatus:
    APPROVED = "approved"                # оператор подтвердил валидный план
    AWAITING_OPERATOR = "awaiting_operator"   # план валиден, ждёт подтверждения
    REJECTED = "rejected"                # конвейер отказал (любой барьер)
    ERROR = "error"                      # инфраструктурная ошибка


class StageStatus:
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"
    DEGRADED = "degraded"   # барьер не сработал, но не блокирует (B7, §15.4)


@dataclass
class BarrierResult:
    barrier: str
    status: str
    detail: str = ""
    data: dict = field(default_factory=dict)
    elapsed_ms: int = 0

    @property
    def ok(self) -> bool:
        return self.status in (StageStatus.PASSED, StageStatus.SKIPPED, StageStatus.DEGRADED)

    def to_json(self) -> dict[str, Any]:
        return {"barrier": self.barrier, "status": self.status, "detail": self.detail,
                "elapsed_ms": self.elapsed_ms, "data": self.data}


@dataclass
class PipelineOutcome:
    status: str
    stage_reached: str
    barriers: list[BarrierResult] = field(default_factory=list)
    steps: list[dict] = field(default_factory=list)
    alternatives: list[list[dict]] = field(default_factory=list)
    confidence: float = 0.0
    goal: str = ""
    provenance: list[dict] = field(default_factory=list)
    presentation: Optional[PlanPresentation] = None
    decision: Optional[OperatorDecision] = None
    replay_path: Optional[str] = None
    replay_root_hash: str = ""
    error: str = ""
    error_kind: str = ""
    model_info: dict = field(default_factory=dict)
    validation: dict = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.status in (PipelineStatus.APPROVED, PipelineStatus.AWAITING_OPERATOR)

    def barrier(self, name: str) -> Optional[BarrierResult]:
        for b in self.barriers:
            if b.barrier == name:
                return b
        return None

    def to_json(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "ok": self.ok,
            "stage_reached": self.stage_reached,
            "steps": self.steps,
            "alternatives": self.alternatives,
            "confidence": self.confidence,
            "goal": self.goal,
            "provenance": self.provenance,
            "validation": self.validation,
            "barriers": [b.to_json() for b in self.barriers],
            "decision": self.decision.to_json() if self.decision else None,
            "replay_path": self.replay_path,
            "replay_root_hash": self.replay_root_hash,
            "error": self.error,
            "error_kind": self.error_kind,
            "model_info": self.model_info,
            "plan_fingerprint": (self.presentation.plan_fingerprint
                                 if self.presentation else None),
        }

    def render(self) -> str:
        lines = ["─" * 72,
                 "FLICKER · результат конвейера: %s" % self.status.upper(),
                 "─" * 72,
                 "стадия: %s" % self.stage_reached]
        for b in self.barriers:
            mark = {"passed": "✓", "failed": "✗", "skipped": "·", "degraded": "!"}[b.status]
            lines.append("  %s %-28s %s" % (mark, b.barrier, b.detail[:100]))
        if self.steps:
            lines.append("план (%d шаг(ов)):" % len(self.steps))
            for i, s in enumerate(self.steps, 1):
                lines.append("  %d. %s(%s)" % (i, s.get("action"), ",".join(s.get("args", []) or [])))
        if self.goal:
            lines.append("цель: %s" % self.goal)
        lines.append("уверенность: %.2f" % self.confidence)
        if self.error:
            lines.append("отказ [%s]: %s" % (self.error_kind, self.error))
        if self.replay_root_hash:
            lines.append("replay root: %s" % self.replay_root_hash)
        return "\n".join(lines)


class FlickerPipeline:
    def __init__(self,
                 backend: LlmBackend,
                 core: Optional[FlickerCore] = None,
                 kb: Optional[KnowledgeBase] = None,
                 critic: Optional[FpccCritic] = None,
                 hitl: Optional[HitlGate] = None,
                 replay_path: Optional[str] = None,
                 staleness_seconds: int = 900,
                 min_confidence: float = 0.0,
                 max_repair: int = DEFAULT_MAX_REPAIR,
                 mode: str = "auto",
                 seed: int = 42,
                 require_provenance: bool = True,
                 workdir: Optional[str] = None):
        self.backend = backend
        self.core = core or FlickerCore()
        self.kb = kb
        self.critic = critic if critic is not None else FpccCritic(backend)
        self.hitl = hitl or HitlGate()
        self.replay_path = replay_path
        self.staleness = staleness_seconds
        self.min_confidence = min_confidence
        self.max_repair = max(0, max_repair)
        self.mode = mode
        self.seed = seed
        # §15.4: без provenance барьер G5 отсутствует вовсе — останавливаемся.
        self.require_provenance = require_provenance
        self.workdir = workdir or tempfile.mkdtemp(prefix="flicker-run-")
        self.writer = ReplayWriter(path=replay_path)
        try:
            self.grammar = load_grammar()
        except EmissionError:
            self.grammar = None

    # ------------------------------------------------------------ служебное
    def _rec(self, kind: str, payload: Any) -> None:
        """B8: каждое значимое событие — в replay-цепь.

        `canonicalize` обязателен: `symbolic_core::json` не имеет float
        (двоичная плавающая точка не даёт побайтово стабильной сериализации
        между платформами, что сломало бы G3/G4). Вещественные значения
        (confidence, оценки критика) кодируются строкой фиксированной точности.
        """
        self.writer.record(kind, canonicalize(payload))

    def _t0(self) -> float:
        return time.time()

    @staticmethod
    def _ms(t0: float) -> int:
        return int((time.time() - t0) * 1000)

    def _add(self, out: PipelineOutcome, barrier: str, status: str,
             detail: str = "", data: Optional[dict] = None, elapsed: int = 0) -> BarrierResult:
        b = BarrierResult(barrier=barrier, status=status, detail=detail,
                          data=data or {}, elapsed_ms=elapsed)
        out.barriers.append(b)
        out.stage_reached = barrier
        return b

    def _fail(self, out: PipelineOutcome, barrier: str, kind: str, message: str,
              data: Optional[dict] = None, elapsed: int = 0) -> PipelineOutcome:
        self._add(out, barrier, StageStatus.FAILED, message, data, elapsed)
        out.status = PipelineStatus.REJECTED
        out.error = message
        out.error_kind = kind
        self._rec("pipeline_rejected", {
            "barrier": barrier, "kind": kind, "message": message,
            "data": data or {},
        })
        return out

    # ------------------------------------------------------------------ run
    def run(self, request_text: str, *, operator_id: Optional[str] = None,
            present_to_operator: bool = False) -> PipelineOutcome:
        """Прогнать запрос через все барьеры.

        `present_to_operator=True` — предъявить план и дождаться решения (B9).
        По умолчанию False: конвейер останавливается в `AWAITING_OPERATOR`,
        что делает его пригодным для автоматических тестов.
        """
        out = PipelineOutcome(status=PipelineStatus.REJECTED, stage_reached="init")
        started = self._t0()

        self._rec("request", {
            "text": request_text,
            "text_sha256": sha256_hex(request_text.encode("utf-8")),
            "mode": self.mode,
            "seed": self.seed,
            "max_repair": self.max_repair,
        })
        out.model_info = {
            "backend": getattr(self.backend, "name", "unknown"),
            "backend_maturity": getattr(self.backend, "maturity", "unknown"),
            "formal_model": getattr(self.backend, "models", {}).get(Role.FORMAL, "offline")
                            if hasattr(self.backend, "models") else "offline",
            "grammar_loaded": self.grammar is not None,
        }
        self._rec("model_pin", out.model_info)

        # ── B1 + B1g + repair loop ────────────────────────────────────────
        emission, diag = self._b1_emit_with_repair(request_text, out)
        if emission is None:
            return self._fail(out, "B1/B2 emission", diag_kind(diag), diag or "no emission")

        domain_src, problem_src = emission
        dpath = os.path.join(self.workdir, "domain.pddl")
        ppath = os.path.join(self.workdir, "problem.pddl")
        with open(dpath, "w", encoding="utf-8") as f:
            f.write(domain_src)
        with open(ppath, "w", encoding="utf-8") as f:
            f.write(problem_src)

        # ── B2 · символический parse + type check (нормативный) ───────────
        t = self._t0()
        chk: CoreResult = self.core.check(dpath, ppath)
        if not chk.ok:
            self._rec("b2_rejected", {"kind": chk.kind, "message": chk.message, "pos": chk.pos})
            return self._fail(out, "B2 parse/type-check", chk.kind or "parse",
                              chk.diagnostic_for_llm, elapsed=self._ms(t))
        self._add(out, "B2 parse/type-check", StageStatus.PASSED,
                  "domain '%s' accepted, %s actions, %s objects"
                  % (chk.data.get("domain"), chk.data.get("actions"), chk.data.get("objects")),
                  {"domain": chk.data.get("domain"), "problem": chk.data.get("problem")},
                  self._ms(t))
        self._rec("parse_result", {"ok": True, "domain": chk.data.get("domain"),
                                   "problem": chk.data.get("problem")})

        objects = list(chk.data.get("object_names", []) or [])
        init_atoms = list(chk.data.get("init_atom_list", []) or [])
        out.goal = str(chk.data.get("goal", "") or "")
        out.validation = {"domain": chk.data.get("domain"), "problem": chk.data.get("problem")}

        # ── B3 · provenance binding ───────────────────────────────────────
        prov_rep = self._b3_provenance(objects, init_atoms, out)
        if prov_rep is None and self.require_provenance:
            # уже зафиксировано в _b3_provenance
            return out
        if prov_rep is not None:
            # age_seconds обязателен: оператор видит СВЕЖЕСТЬ данных, а не только
            # момент as_of (R7.5.4). Без него hitl.render печатал "Nones".
            now = int(time.time())
            out.provenance = [
                {"fact": f.key, "source": f.source, "as_of": f.as_of,
                 "age_seconds": max(0, now - f.as_of),
                 "confidence": f.confidence}
                for f in prov_rep.atoms_resolved
            ]

        # ── B4 · grounding ────────────────────────────────────────────────
        t = self._t0()
        gr = self.core.ground(dpath, ppath)
        if not gr.ok:
            return self._fail(out, "B4 grounding", gr.kind or "grounding",
                              gr.diagnostic_for_llm, elapsed=self._ms(t))
        gsize = gr.data.get("ground_actions", 0)
        self._add(out, "B4 grounding", StageStatus.PASSED,
                  "%s ground actions (cap %s)" % (gsize, gr.data.get("cap")),
                  {"size": gsize}, self._ms(t))
        self._rec("grounding", {"size": gsize, "cap": gr.data.get("cap")})

        # ── B5 + B6 · поиск с жёстким шлюзом валидации ────────────────────
        t = self._t0()
        trace = os.path.join(self.workdir, "core-trace.jsonl") if not self.replay_path else None
        pl = self.core.plan(dpath, ppath, mode=self.mode, seed=self.seed, replay=trace)
        if not pl.ok:
            return self._fail(out, "B5/B6 search+validate", pl.kind or "limit",
                              pl.diagnostic_for_llm or "no plan found",
                              {"exit_code": pl.exit_code}, self._ms(t))

        steps = FlickerCore.steps_from_result(pl)
        valid = bool(pl.data.get("validation", {}).get("valid")) if isinstance(pl.data.get("validation"), dict) else False
        goal_ok = bool(pl.data.get("validation", {}).get("goal_satisfied")) if isinstance(pl.data.get("validation"), dict) else False

        # R7.4.1 — независимая перепроверка на стороне воркера. Ядро уже
        # выполнило шлюз; эта проверка защищает от подмены результата между
        # ядром и воркером. Расхождение ⇒ отказ.
        if not (valid and goal_ok):
            return self._fail(out, "B6 validation", "validation",
                              "ядро вернуло план без valid&&goal_satisfied (valid=%s, goal=%s)"
                              % (valid, goal_ok), elapsed=self._ms(t))
        recheck = self.core.validate_steps(dpath, ppath, steps)
        if not recheck.ok:
            return self._fail(out, "B6 validation (re-check)", recheck.kind or "validation",
                              "независимая повторная валидация не прошла: %s"
                              % recheck.diagnostic_for_llm, elapsed=self._ms(t))

        out.steps = steps
        out.validation = {
            "valid": recheck.data.get("valid"),
            "goal_satisfied": recheck.data.get("goal_satisfied"),
            "steps_checked": recheck.data.get("steps_checked"),
            "init_state_hash": recheck.data.get("init_state_hash"),
            "final_state_hash": recheck.data.get("final_state_hash"),
            "mode_used": pl.data.get("stats", {}).get("mode_used") if isinstance(pl.data.get("stats"), dict) else pl.data.get("mode_used"),
        }
        self._add(out, "B5 search", StageStatus.PASSED,
                  "mode=%s expanded=%s generated=%s"
                  % (out.validation.get("mode_used"),
                     (pl.data.get("stats") or {}).get("expanded"),
                     (pl.data.get("stats") or {}).get("generated")),
                  {"steps": len(steps)}, self._ms(t))
        self._add(out, "B6 validation", StageStatus.PASSED,
                  "%s step(s) checked, goal satisfied, final_state=%s"
                  % (out.validation.get("steps_checked"),
                     str(out.validation.get("final_state_hash"))[:16]),
                  dict(out.validation))
        self._rec("search", {"mode": out.validation.get("mode_used"),
                             "seed": self.seed, "steps": len(steps)})
        self._rec("validation", out.validation)

        # ── B7 · FPCC (вероятностный) ─────────────────────────────────────
        conf = self._b7_critic(request_text, steps, prov_rep, out)

        # ── уверенность ───────────────────────────────────────────────────
        out.confidence = max(0.0, min(1.0, conf))

        # ── B9 · HITL ─────────────────────────────────────────────────────
        pres = self.hitl.present(
            request_text, steps,
            provenance=out.provenance,
            confidence=out.confidence,
            alternatives=out.alternatives,
            goal_statement=out.goal,
            validation=out.validation,
            extra_not_verified=self._extra_not_verified(out, prov_rep),
        )
        out.presentation = pres
        self._add(out, "B9 HITL presentation", StageStatus.PASSED,
                  "отпечаток %s, непроверенных пунктов: %d"
                  % (pres.plan_fingerprint[:16], len(pres.not_verified)))
        self._rec("presentation", {"plan_fingerprint": pres.plan_fingerprint,
                                   "confidence": out.confidence,
                                   "not_verified_count": len(pres.not_verified)})

        if present_to_operator:
            dec = self.hitl.request_decision(pres, operator_id=operator_id)
            out.decision = dec
            self._rec("operator_confirm", dec.to_json())
            if not self.hitl.verify_binding(dec, pres):
                # R7.7.3: подтверждение не привязано к предъявленному плану
                return self._fail(out, "B9 binding", "validation",
                                  "подтверждение оператора не соответствует предъявленному плану")
            if dec.decision == Decision.APPROVE:
                out.status = PipelineStatus.APPROVED
            else:
                out.status = PipelineStatus.REJECTED
                out.error = "оператор отклонил план (%s)" % dec.decision
                out.error_kind = "operator"
        else:
            out.status = PipelineStatus.AWAITING_OPERATOR

        out.replay_root_hash = self.writer.root_hash
        self._rec("pipeline_complete", {
            "status": out.status, "steps": len(out.steps),
            "confidence": out.confidence,
            "root_hash": self.writer.root_hash,
            "elapsed_ms": self._ms(started),
        })
        return out

    # ------------------------------------------------------------- барьеры
    def _b1_emit_with_repair(self, request_text: str,
                             out: PipelineOutcome) -> tuple[Optional[tuple[str, str]], Optional[str]]:
        """B1 + структурный шлюз + repair loop (§7.2).

        Возвращает ((domain_src, problem_src), None) при успехе
        или (None, диагностика) при исчерпании попыток.
        """
        prompt = self._build_prompt(request_text)
        last_diag: Optional[str] = None
        t_all = self._t0()

        for attempt in range(self.max_repair + 1):
            t = self._t0()
            res = self.backend.complete(Role.FORMAL, prompt, grammar=self.grammar)
            self._rec("slm_emission", {
                "attempt": attempt,
                "role": Role.FORMAL,
                "backend": res.backend,
                "model": res.model,
                "maturity": res.maturity,
                "grammar_applied": res.grammar_applied,
                "text_sha256": sha256_hex(res.text.encode("utf-8")),
                "finish_reason": res.finish_reason,
                "prompt_sha256": sha256_hex(prompt.encode("utf-8")),
            })

            if not res.ok:
                last_diag = ("модель вернула пустой ответ (finish_reason=%s, backend=%s)"
                             % (res.finish_reason, res.backend))
                self._add(out, "B1 emission (attempt %d)" % attempt, StageStatus.FAILED,
                          last_diag, elapsed=self._ms(t))
                continue

            # B1g · структурный шлюз + детектор дрейфа конфигурации
            violations = structural_gate(res.text)
            if violations and not res.grammar_applied:
                # Выход вне FPS-1 при НЕПРИМЕНЁННОЙ грамматике = дрейф конфига.
                # Это отдельный и более серьёзный сигнал, чем обычная ошибка модели.
                last_diag = ("constrained decoding НЕ применён (grammar_applied=false), "
                             "выход вне FPS-1: " + "; ".join(v.render_for_llm() for v in violations[:3]))
                self._add(out, "B1g drift-detect (attempt %d)" % attempt, StageStatus.FAILED,
                          last_diag, {"violations": [v.code for v in violations]}, self._ms(t))
            elif violations:
                last_diag = "; ".join(v.render_for_llm() for v in violations[:4])
                self._add(out, "B1g structural gate (attempt %d)" % attempt,
                          StageStatus.FAILED, last_diag,
                          {"violations": [v.code for v in violations]}, self._ms(t))
            else:
                try:
                    domain_src, problem_src = split_emission(res.text)
                except EmissionError as e:
                    last_diag = "разбор emission: %s" % e
                    self._add(out, "B1 split (attempt %d)" % attempt, StageStatus.FAILED,
                              last_diag, elapsed=self._ms(t))
                else:
                    self._add(out, "B1 constrained emission (attempt %d)" % attempt,
                              StageStatus.PASSED,
                              "grammar_applied=%s, нарушений FPS-1 нет" % res.grammar_applied,
                              {"backend": res.backend, "model": res.model,
                               "maturity": res.maturity,
                               "domain_chars": len(domain_src),
                               "problem_chars": len(problem_src)},
                              self._ms(t))
                    self._rec("repair_rate", {"attempts_used": attempt,
                                              "max_repair": self.max_repair})
                    return (domain_src, problem_src), None

            # R7.2.2/R7.2.3: итерация пишется в лог; температура остаётся 0 —
            # «попробовать случайность» запрещено, иначе G3 нарушается.
            self._rec("repair_attempt", {"attempt": attempt, "diagnostic": last_diag})
            prompt = self._build_prompt(request_text, diagnostic=last_diag)

        self._rec("repair_exhausted", {"attempts": self.max_repair + 1,
                                       "last_diagnostic": last_diag})
        return None, (last_diag or "не удалось получить валидный emission") + \
            " (исчерпаны %d попыток, R7.2.1 — явный отказ)" % (self.max_repair + 1)

    def _b3_provenance(self, objects: list[str], init_atoms: list[str],
                       out: PipelineOutcome) -> Optional[ProvenanceReport]:
        t = self._t0()
        if self.kb is None:
            msg = ("база знаний не подключена: provenance binding (B3) невыполним. "
                   "По §15.4 отказ GraphRAG останавливает систему — без B3 отсутствует "
                   "единственный барьер против ошибки класса E3")
            if self.require_provenance:
                self._fail(out, "B3 provenance", "provenance", msg, elapsed=self._ms(t))
                return None
            self._add(out, "B3 provenance", StageStatus.SKIPPED, msg, elapsed=self._ms(t))
            return None

        gate = ProvenanceGate(self.kb, staleness_seconds=self.staleness,
                              min_confidence=self.min_confidence)
        rep = gate.check(objects, init_atoms)
        if not rep.ok:
            self._rec("provenance", rep.to_json())
            self._fail(out, "B3 provenance", "provenance",
                       "; ".join(rep.reasons[:4]) or "provenance check failed",
                       {"unresolved_objects": rep.objects_unresolved,
                        "unresolved_atoms": rep.atoms_unresolved,
                        "stale": rep.atoms_stale,
                        "fingerprint": rep.fingerprint}, self._ms(t))
            return None
        self._add(out, "B3 provenance", StageStatus.PASSED,
                  "%d объект(ов), %d факт(ов) разрешены, bound=%ds"
                  % (len(rep.objects_resolved), len(rep.atoms_resolved), self.staleness),
                  {"fingerprint": rep.fingerprint}, self._ms(t))
        self._rec("provenance", rep.to_json())
        return rep

    def _b7_critic(self, request_text: str, steps: list[dict],
                   prov_rep: Optional[ProvenanceReport],
                   out: PipelineOutcome) -> float:
        """Возвращает базовую уверенность с поправкой критика."""
        t = self._t0()
        # Базовая уверенность определяется КОНСТРУКТИВНЫМИ барьерами, а не
        # критиком: G1/G2/G3/G4 уже выполнены, поэтому старт высокий.
        base = 0.80
        if prov_rep is not None and prov_rep.ok:
            base += 0.10
        try:
            rep: CriticReport = self.critic.evaluate(
                request_text, steps,
                provenance_ok=(prov_rep.ok if prov_rep else False),
                unresolved=(prov_rep.objects_unresolved + prov_rep.atoms_unresolved
                            if prov_rep else []))
        except Exception as e:
            self._add(out, "B7 FPCC critic", StageStatus.DEGRADED,
                      "критик недоступен: %s (§15.4 — работа продолжается с пометкой)" % e,
                      {"critic_unavailable": True}, self._ms(t))
            self._rec("fpcc", {"available": False, "error": str(e)})
            return base - 0.10

        if rep.blocks:
            self._rec("fpcc", rep.to_json())
            self._fail(out, "B7 FPCC critic", "consistency",
                       "критик обнаружил противоречие с запросом: %s"
                       % ("; ".join(rep.conflicting_spans[:3]) or rep.detail),
                       rep.to_json(), self._ms(t))
            return 0.0

        status = StageStatus.DEGRADED if not rep.available else StageStatus.PASSED
        self._add(out, "B7 FPCC critic", status,
                  "verdict=%s conf=%.2f flags=%d (вероятностный барьер, в G1–G4 не входит)"
                  % (rep.verdict, rep.confidence, len(rep.heuristic_flags)),
                  rep.to_json(), self._ms(t))
        self._rec("fpcc", rep.to_json())
        return base + rep.confidence_adjustment

    # ------------------------------------------------------------- прочее
    def _build_prompt(self, request_text: str, diagnostic: Optional[str] = None) -> str:
        parts = [
            "You are FLICKER SLM-FORMAL. Translate the operator request into FPS-1 PDDL.",
            "",
            "HARD CONSTRAINTS:",
            "1. Emit EXACTLY two documents separated by the line %s" % "%%FPS1-SPLIT%%",
            "2. First document: (define (domain ...) ...). Second: (define (problem ...) ...).",
            "3. Only these :requirements are allowed: :strips :typing "
            ":negative-preconditions :disjunctive-preconditions "
            ":universal-preconditions :existential-preconditions "
            ":conditional-effects :universal-effects",
            "4. FORBIDDEN: numeric fluents, :functions, :equality, disjunctive EFFECTS, "
            ":durative-action, probabilistic effects, :constants, :derived, :adl.",
            "5. Every object you mention MUST appear in the request or be declared in :objects. "
            "DO NOT invent objects — an unresolved reference causes refusal.",
            "6. Use the nested action form: (:action name (:parameters ...) (:precondition ...) (:effect ...)).",
            "",
            "OPERATOR REQUEST:",
            request_text,
        ]
        if diagnostic:
            parts += [
                "",
                "YOUR PREVIOUS ATTEMPT WAS REJECTED. Fix exactly this and re-emit:",
                diagnostic,
            ]
        return "\n".join(parts)

    @staticmethod
    def _extra_not_verified(out: PipelineOutcome,
                            prov_rep: Optional[ProvenanceReport]) -> list[str]:
        extra = []
        mi = out.model_info
        if mi.get("backend_maturity") == "mock":
            extra.append(
                "МОДЕЛЬ-ЗАГЛУШКА: использован offline-бэкенд (maturity=mock). "
                "Это детерминированная подстановка, НЕ языковая модель. "
                "Результат пригоден только для сквозного теста конвейера.")
        if not mi.get("grammar_loaded"):
            extra.append("EBNF-грамматика FPS-1 не загружена: барьер B1 не активен.")
        if prov_rep is None:
            extra.append("Provenance binding (B3) не выполнен — ошибка класса E3 не контролируется.")
        return extra

    def close(self) -> str:
        """Вернуть root_hash цепи. Вызывается после run()."""
        return self.writer.root_hash


def diag_kind(diag: Optional[str]) -> str:
    if not diag:
        return "emission"
    low = diag.lower()
    if "constrained decoding" in low or "grammar_applied" in low:
        return "config_drift"
    if "пустой ответ" in low:
        return "empty_emission"
    return "fps1_violation"
