"""Барьер B9 · Human-in-the-loop gate (§7.7 ТЗ).

R7.7.1  Система не имеет канала прямого воздействия на исполнительные
        механизмы. Архитектурно: в поставке отсутствует клиент исполнительных
        систем, а `HitlGate` не умеет ничего, кроме предъявления и ожидания
        явного подтверждения.
R7.7.2  Оператору предъявляются: план, provenance, confidence, альтернативы
        И явный перечень того, что проверено НЕ было (остаток G5).
R7.7.3  Подтверждение — отдельное действие; в replay пишется `operator_confirm`
        с хэшем ПРЕДЪЯВЛЕННОГО плана. Подтвердить план, отличный от
        предъявленного, невозможно.
R7.7.4  Режим автоматического исполнения ЗАПРЕЩЁН. Конфигурационного флага
        для него не существует.
"""
from __future__ import annotations

import sys
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from .canon import canonical_json, sha256_hex

__all__ = ["PlanPresentation", "OperatorDecision", "HitlGate", "Decision"]


class Decision:
    APPROVE = "approve"
    REJECT = "reject"
    ABSTAIN = "abstain"      # оператор не принял решение (таймаут / отказ)


@dataclass
class PlanPresentation:
    """То, что видит оператор. Обязательные поля — по R7.7.2."""
    request_text: str
    steps: list[dict]
    plan_fingerprint: str
    provenance: list[dict] = field(default_factory=list)
    confidence: float = 0.0
    alternatives: list[list[dict]] = field(default_factory=list)
    #: Явный перечень непроверенного. Пустой список НЕДОПУСТИМ: всегда
    #: остаётся остаток G5 (семантика модели и её полнота).
    not_verified: list[str] = field(default_factory=list)
    goal_statement: str = ""
    validation: dict = field(default_factory=dict)
    created_at: int = field(default_factory=lambda: int(time.time()))

    def to_json(self) -> dict[str, Any]:
        return {
            "request_text": self.request_text,
            "steps": self.steps,
            "plan_fingerprint": self.plan_fingerprint,
            "provenance": self.provenance,
            "confidence": self.confidence,
            "alternatives": self.alternatives,
            "not_verified": self.not_verified,
            "goal_statement": self.goal_statement,
            "validation": self.validation,
            "created_at": self.created_at,
        }

    def render(self) -> str:
        """Человекочитаемое представление. Именно его видит оператор."""
        lines = ["=" * 72, "ПЛАН НА ПОДТВЕРЖДЕНИЕ", "=" * 72]
        lines.append("Запрос: %s" % (self.request_text or "(не указан)"))
        if self.goal_statement:
            lines.append("Формальная цель: %s" % self.goal_statement)
        lines.append("Уверенность: %.2f" % self.confidence)
        lines.append("Отпечаток плана: %s" % self.plan_fingerprint)
        lines.append("")
        lines.append("Шаги (%d):" % len(self.steps))
        if not self.steps:
            lines.append("  (пусто — цель уже достигнута в начальном состоянии)")
        for i, s in enumerate(self.steps, 1):
            lines.append("  %d. %s(%s)" % (i, s.get("action", "?"),
                                            ", ".join(s.get("args", []) or [])))
        if self.alternatives:
            lines.append("")
            lines.append("Альтернативы (%d):" % len(self.alternatives))
            for ai, alt in enumerate(self.alternatives, 1):
                sig = " → ".join("%s(%s)" % (s.get("action", "?"),
                                             ",".join(s.get("args", []) or [])) for s in alt)
                lines.append("  A%d: %s" % (ai, sig or "(пусто)"))
        if self.provenance:
            lines.append("")
            lines.append("Обоснование (provenance):")
            seen = set()
            for p in self.provenance:
                k = (p.get("fact"), p.get("source"), p.get("as_of"))
                if k in seen:
                    continue
                seen.add(k)
                lines.append("  · %s  ← %s (as_of=%s, age=%ss, conf=%s)"
                             % (p.get("fact"), p.get("source"), p.get("as_of"),
                                p.get("age_seconds"), p.get("confidence")))
        lines.append("")
        lines.append("ЧТО НЕ ПРОВЕРЕНО (остаток G5):")
        for nv in (self.not_verified or ["(не заполнено — нарушение R7.7.2)"]):
            lines.append("  ✗ %s" % nv)
        lines.append("=" * 72)
        return "\n".join(lines)


@dataclass
class OperatorDecision:
    decision: str
    operator_id: str
    plan_fingerprint: str
    ts_ms: int
    note: str = ""

    def to_json(self) -> dict[str, Any]:
        return {
            "decision": self.decision,
            "operator_id": self.operator_id,
            "plan_fingerprint": self.plan_fingerprint,
            "ts_ms": self.ts_ms,
            "note": self.note,
        }


#: Обязательный остаток G5 — выводится оператору всегда, даже если всё остальное
#: проверено. Скрыть его нельзя: это то, чего система гарантировать не может.
STANDARD_NOT_VERIFIED = [
    "G5 · Соответствие формальной модели реальному положению дел формально НЕ гарантируется. "
    "Валидатор проверяет план внутри модели, а не модель против мира.",
    "E4 · Полнота доменной модели: если в мире есть ограничение, которого нет в PDDL, "
    "система выдаст формально валидный план, его нарушающий. Обнаружить это автоматически невозможно.",
    "E3 · Корректность трансляции запроса в формальную цель: цель предъявлена выше — "
    "сверьте её с намерением. Идеально валидный план достижения НЕВЕРНОЙ цели хуже отсутствия плана.",
    "FPCC-критик вероятностен и не несёт гарантии: его вердикт не является ни доказательством, "
    "ни опровержением корректности.",
    "Данные provenance актуальны на момент as_of, указанный выше; более поздние изменения не учтены.",
]


class HitlGate:
    """Шлюз подтверждения.

    `prompt_fn` — функция ввода (по умолчанию stdin). В production заменяется
    на аутентифицированный UI-обработчик; контракт тот же.

    ВАЖНО: gate сверяет отпечаток ПРЕДЪЯВЛЕННОГО плана с отпечатком, который
    возвращается в подтверждении. Расхождение ⇒ отказ (R7.7.3).
    """

    def __init__(self, prompt_fn: Optional[Callable[[str], str]] = None,
                 timeout_seconds: Optional[float] = None,
                 require_operator_id: bool = True):
        self._prompt = prompt_fn or (lambda p: input(p))
        self.timeout = timeout_seconds
        self.require_operator_id = require_operator_id

    @staticmethod
    def fingerprint(steps: list[dict]) -> str:
        """Канонический отпечаток плана — то, что хэшируется в operator_confirm."""
        norm = [{"action": s.get("action", ""), "args": list(s.get("args", []) or [])}
                for s in steps]
        return sha256_hex(canonical_json(norm))

    def present(self, request_text: str, steps: list[dict], *,
                provenance: Optional[list[dict]] = None,
                confidence: float = 0.0,
                alternatives: Optional[list[list[dict]]] = None,
                goal_statement: str = "",
                validation: Optional[dict] = None,
                extra_not_verified: Optional[list[str]] = None) -> PlanPresentation:
        not_verified = list(STANDARD_NOT_VERIFIED)
        if extra_not_verified:
            not_verified.extend(extra_not_verified)
        return PlanPresentation(
            request_text=request_text,
            steps=steps,
            plan_fingerprint=self.fingerprint(steps),
            provenance=list(provenance or []),
            confidence=confidence,
            alternatives=list(alternatives or []),
            not_verified=not_verified,
            goal_statement=goal_statement,
            validation=dict(validation or {}),
        )

    def request_decision(self, pres: PlanPresentation,
                         operator_id: Optional[str] = None) -> OperatorDecision:
        """Предъявить план и дождаться явного решения.

        Никакого пути, при котором решение принимается без оператора, не
        существует (R7.7.4): флаг автоисполнения не определён ни здесь, ни в
        конфигурации.
        """
        # Презентация — UI-артефакт, а не данные: уходит в stderr, чтобы
        # stdout оставался машиночитаемым при `--json`.
        print(pres.render(), file=sys.stderr)
        if self.require_operator_id and not operator_id:
            try:
                operator_id = self._prompt("Идентификатор оператора: ").strip()
            except (EOFError, KeyboardInterrupt):
                operator_id = ""
        operator_id = operator_id or "anonymous"

        try:
            answer = self._prompt(
                "\nПодтвердить план? [yes — исполнить / no — отклонить / abstain — воздержаться]: "
            ).strip().lower()
        except (EOFError, KeyboardInterrupt):
            answer = ""

        if answer in ("yes", "y", "подтвердить", "да"):
            decision = Decision.APPROVE
        elif answer in ("no", "n", "отклонить", "нет"):
            decision = Decision.REJECT
        else:
            decision = Decision.ABSTAIN

        return OperatorDecision(
            decision=decision,
            operator_id=operator_id,
            plan_fingerprint=pres.plan_fingerprint,
            ts_ms=int(time.time() * 1000),
            note="answer=%r" % answer,
        )

    @staticmethod
    def verify_binding(decision: OperatorDecision, pres: PlanPresentation) -> bool:
        """R7.7.3: подтверждение обязано быть привязано к ПРЕДЪЯВЛЕННОМУ плану."""
        return decision.plan_fingerprint == pres.plan_fingerprint
