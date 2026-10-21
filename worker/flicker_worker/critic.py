"""Барьер B7 · FPCC — Fast-Path Consistency Checker (§7.6 ТЗ).

**ВЕРИЯТНОСТНЫЙ барьер. В гарантии G1–G4 НЕ ВХОДИТ** (R7.6.2).

Это принципиально: FPCC опирается на LLM (CRITIC-NLI) и не может нести
конструктивную гарантию. Его отказ — не доказательство невалидности, его
пропуск — не доказательство корректности. В отчёте оператору оценка подаётся
как «незаведисимая проверка: пройдена / не пройдена / неубедительно», а не как
«план корректен».

R7.6.3: вердикт `neutral` (большинство реальных случаев) трактуется как
«критик не смог подтвердить» и **понижает** confidence, а не игнорируется.

§15.4: при отказе критика система ПРОДОЛЖАЕТ работать с пометкой
`critic_unavailable=true` — в отличие от provenance (B3), отказ которого
останавливает систему, потому что без него барьер G5 отсутствует вовсе.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Optional

from .llm import LlmResult, Role

__all__ = ["Verdict", "CriticReport", "FpccCritic", "CRITIC_SCHEMA"]

#: Схема для constrained decoding критика (configs/vllm_qwen35.yaml).
CRITIC_SCHEMA = {
    "type": "object",
    "properties": {
        "verdict": {"enum": ["entailment", "neutral", "contradiction"]},
        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
        "conflicting_spans": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["verdict", "confidence"],
    "additionalProperties": False,
}


class Verdict:
    ENTAILMENT = "entailment"
    NEUTRAL = "neutral"
    CONTRADICTION = "contradiction"
    UNAVAILABLE = "unavailable"


@dataclass
class CriticReport:
    verdict: str
    confidence: float
    conflicting_spans: list[str] = field(default_factory=list)
    heuristic_flags: list[str] = field(default_factory=list)
    available: bool = True
    detail: str = ""
    raw: dict = field(default_factory=dict)

    @property
    def blocks(self) -> bool:
        """R7.6.1: `contradiction` ⇒ план отклоняется."""
        return self.verdict == Verdict.CONTRADICTION

    @property
    def confidence_adjustment(self) -> float:
        """Вклад критика в итоговую уверенность.

        R7.6.3: neutral ПОНИЖАЕТ уверенность (критик не смог подтвердить).
        Критик вероятностен, поэтому вклад ограничен и не может ни доказать,
        ни опровергнуть план сам по себе.
        """
        if not self.available:
            return -0.10
        if self.verdict == Verdict.ENTAILMENT:
            return +0.10 * max(0.0, min(1.0, self.confidence))
        if self.verdict == Verdict.CONTRADICTION:
            return -1.0
        return -0.05  # neutral / unavailable-verdict

    def to_json(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "confidence": self.confidence,
            "conflicting_spans": list(self.conflicting_spans),
            "heuristic_flags": list(self.heuristic_flags),
            "available": self.available,
            "blocks": self.blocks,
            "confidence_adjustment": self.confidence_adjustment,
            "detail": self.detail,
            "guarantee_class": "probabilistic",
        }


class FpccCritic:
    """NLI-критик + эвристики."""

    def __init__(self, backend=None, enable_nli: bool = True):
        self.backend = backend
        self.enable_nli = enable_nli

    # ---------------------------------------------------------------- NLI
    def _nli(self, request_text: str, plan_text: str) -> CriticReport:
        if self.backend is None or not self.enable_nli:
            return CriticReport(Verdict.UNAVAILABLE, 0.0, available=False,
                                detail="NLI disabled or no backend")
        prompt = (
            "You are a strict consistency checker. Decide whether the PLAN is "
            "entailed by, contradicts, or is neutral with respect to the REQUEST.\n"
            "Answer with JSON matching the schema only.\n\n"
            "REQUEST:\n%s\n\nPLAN:\n%s\n" % (request_text, plan_text)
        )
        try:
            res: LlmResult = self.backend.complete(
                Role.CRITIC, prompt, json_schema=CRITIC_SCHEMA)
        except Exception as e:  # критик не должен ронять конвейер (§15.4)
            return CriticReport(Verdict.UNAVAILABLE, 0.0, available=False,
                                detail="critic backend error: %s" % e)
        if not res.ok:
            return CriticReport(Verdict.UNAVAILABLE, 0.0, available=False,
                                detail="critic returned empty (%s)" % res.finish_reason)
        try:
            data = json.loads(res.text)
        except json.JSONDecodeError:
            # Выход вне схемы = критик непригоден, а не «нейтрален».
            return CriticReport(Verdict.UNAVAILABLE, 0.0, available=False,
                                detail="critic output is not valid JSON",
                                raw={"text": res.text[:500]})
        verdict = str(data.get("verdict", Verdict.NEUTRAL))
        if verdict not in (Verdict.ENTAILMENT, Verdict.NEUTRAL, Verdict.CONTRADICTION):
            verdict = Verdict.NEUTRAL
        try:
            conf = float(data.get("confidence", 0.0))
        except (TypeError, ValueError):
            conf = 0.0
        conf = max(0.0, min(1.0, conf))
        spans = data.get("conflicting_spans") or []
        if not isinstance(spans, list):
            spans = [str(spans)]
        return CriticReport(verdict, conf, conflicting_spans=[str(s) for s in spans],
                            detail="nli", raw=data)

    # ---------------------------------------------------------- эвристики
    @staticmethod
    def heuristics(request_text: str, plan_steps: list[dict], provenance_ok: bool,
                   unresolved: Optional[list[str]] = None) -> list[str]:
        """Дешёвые детерминированные проверки.

        Они НЕ заменяют NLI и не несут гарантии; их задача — поймать очевидные
        расхождения до обращения к модели и дать оператору объяснимые флаги.
        """
        flags = []
        req = (request_text or "").lower()
        if not plan_steps:
            flags.append("EMPTY_PLAN: план пуст — цель либо уже достигнута, либо запрос не понят")
        if not provenance_ok:
            flags.append("PROVENANCE_INCOMPLETE: есть неразрешённые референции (R7.5.2)")
        for u in (unresolved or []):
            # R7.5.2: объект, которого нет в базе знаний, не должен появляться в плане
            if u and u.lower() in json.dumps(plan_steps, ensure_ascii=False).lower():
                flags.append("UNRESOLVED_IN_PLAN: '%s' отсутствует в базе знаний, "
                             "но присутствует в плане" % u)
        # упоминания из запроса, отсутствующие в плане — слабый сигнал
        tokens = {t for t in req.replace(",", " ").replace(".", " ").split() if len(t) > 3}
        blob = json.dumps(plan_steps, ensure_ascii=False).lower()
        missing = sorted(t for t in tokens if t not in blob)
        if missing and plan_steps and len(missing) <= max(3, len(tokens) // 2):
            flags.append("REQUEST_TERMS_ABSENT: в плане не отражены термины запроса: %s"
                         % ", ".join(missing[:8]))
        return flags

    # --------------------------------------------------------------- API
    def evaluate(self, request_text: str, plan_steps: list[dict],
                 provenance_ok: bool = True,
                 unresolved: Optional[list[str]] = None) -> CriticReport:
        plan_text = "\n".join(
            "%d. %s(%s)" % (i + 1, s.get("action", "?"), ", ".join(s.get("args", []) or []))
            for i, s in enumerate(plan_steps)
        ) or "(empty plan)"

        rep = self._nli(request_text, plan_text)
        rep.heuristic_flags = self.heuristics(
            request_text, plan_steps, provenance_ok, unresolved)

        # Эвристика может перевести neutral в contradiction, но не наоборот:
        # детерминированная проверка сильнее вероятностной оценки.
        if any(f.startswith(("UNRESOLVED_IN_PLAN", "PROVENANCE_INCOMPLETE"))
               for f in rep.heuristic_flags):
            if rep.verdict != Verdict.CONTRADICTION:
                rep.verdict = Verdict.CONTRADICTION
                rep.detail = (rep.detail + " | escalated by heuristic").strip(" |")

        return rep
