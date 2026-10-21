"""Барьер B1/B2 на стороне воркера — структурный шлюз FPS-1.

## Роль этого модуля (важно не переоценить)

Нормативные гарантии обеспечивает НЕ этот файл:
  · **G1** обеспечивается grammar-constrained decoding в vLLM/xgrammar
    (`grammar/fps1_pddl.ebnf`) — синтаксически невалидный выход непредставим;
  · **G2** обеспечивается `symbolic-core::validator` через `core.py`.

Этот модуль — **defense in depth** и, что важнее, **детектор дрейфа конфигурации**:
если constrained decoding по какой-то причине не применён (сервер без xgrammar,
неверный `guided_decoding_backend`, подмена конфига), выход модели перестанет
быть заведомо валидным, и шлюз это поймает ДО обращения к ядру.

Соответственно: прохождение шлюза НЕ является доказательством валидности,
а непрохождение — достаточное основание для отказа.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Optional

__all__ = [
    "SPLIT_MARKER", "Fps1Violation", "structural_gate", "split_emission",
    "load_grammar", "EmissionError",
]

#: Разделитель домена и задачи в одном emission (Приложение Б, §9).
SPLIT_MARKER = "%%FPS1-SPLIT%%"

#: Требования FPS-1 — точно `pddl::SUPPORTED_REQUIREMENTS`.
SUPPORTED_REQUIREMENTS = frozenset({
    "strips", "typing", "negative-preconditions", "disjunctive-preconditions",
    "universal-preconditions", "existential-preconditions",
    "conditional-effects", "universal-effects",
})

#: Конструкции вне FPS-1. Каждая обязана отклоняться (§4.2 ТЗ).
#: Порядок важен: `disjunctive-effects` проверяется ОТДЕЛЬНО от
#: `disjunctive-preconditions`, который ПОДДЕРЖИВАЕТСЯ.
FORBIDDEN_REQUIREMENTS = {
    "fluents": "числовые флюенты вне FPS-1",
    "equality": "равенство объектов вне FPS-1",
    "disjunctive-effects": "дизъюнктивные ЭФФЕКТЫ вне FPS-1 (недетерминизм несовместим с G2/G3)",
    "durative-actions": "темпоральность вне FPS-1",
    "duration-inequalities": "темпоральность вне FPS-1",
    "continuous-effects": "непрерывные эффекты вне FPS-1",
    "probabilistic-effects": "вероятностные эффекты вне FPS-1, принципиально",
    "adl": ":adl — составное требование, не входит в FPS-1",
    "preferences": "предпочтения вне FPS-1",
    "constraints": "ограничения траектории вне FPS-1",
    "timed-initial-literals": "темпоральность вне FPS-1",
    "object-fluents": "функциональные объекты вне FPS-1",
}

#: Ключевые слова, которых не должно быть в теле домена/задачи.
FORBIDDEN_FORMS = {
    "increase": "числовой эффект (increase) вне FPS-1",
    "decrease": "числовой эффект (decrease) вне FPS-1",
    "assign": "числовой эффект (assign) вне FPS-1",
    "scale-up": "числовой эффект вне FPS-1",
    "scale-down": "числовой эффект вне FPS-1",
    "durative-action": "durative-action вне FPS-1",
    "probabilistic": "вероятностный эффект вне FPS-1",
    "functions": "секция :functions вне FPS-1",
    "derived": "производные предикаты вне FPS-1",
    "constants": "секция :constants вне FPS-1 (объявляйте объекты в задаче)",
}


class EmissionError(ValueError):
    """Выход модели невозможно разобрать на домен и задачу."""


@dataclass(frozen=True)
class Fps1Violation:
    code: str
    message: str
    line: int = 0
    col: int = 0
    #: True, если нарушение относится к требованию/форме вне FPS-1 (semantic),
    #: False — к синтаксису (parse). Соответствует `FlickerError.kind`.
    semantic: bool = True

    @property
    def kind(self) -> str:
        return "semantic" if self.semantic else "parse"

    def render_for_llm(self) -> str:
        """Форма для repair loop (§7.2): точная, actionable, без воды."""
        loc = "" if not self.line else " (line %d)" % self.line
        return "%s%s: %s" % (self.code, loc, self.message)


def _strip_comments(src: str) -> str:
    """Убрать `;`-комментарии, не трогая строки (в PDDL строк нет, но
    осторожность дешёвая)."""
    out = []
    for line in src.split("\n"):
        cut = line.find(";")
        out.append(line if cut < 0 else line[:cut])
    return "\n".join(out)


def _line_of(src: str, idx: int) -> int:
    return src.count("\n", 0, idx) + 1


def structural_gate(emission: str) -> list[Fps1Violation]:
    """Быстрая проверка emission на соответствие FPS-1.

    Возвращает СПИСОК нарушений (пустой = шлюз пройден). Не бросает исключений:
    repair loop нуждается во всех нарушениях сразу, а не только в первом.
    """
    v: list[Fps1Violation] = []
    if not emission or not emission.strip():
        v.append(Fps1Violation("EMPTY_EMISSION", "модель вернула пустой ответ", semantic=False))
        return v

    text = _strip_comments(emission)

    # 1. Баланс скобок
    depth = 0
    for i, ch in enumerate(text):
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth < 0:
                v.append(Fps1Violation(
                    "UNBALANCED_PARENS",
                    "закрывающая скобка без открывающей",
                    line=_line_of(emission, i), semantic=False))
                break
    if depth > 0:
        v.append(Fps1Violation(
            "UNBALANCED_PARENS",
            "не закрыто %d открывающих скобок" % depth, semantic=False))

    # 2. Требования
    for m in re.finditer(r"\(\s*:requirements([^)]*)\)", text):
        body = m.group(1)
        for tok in re.findall(r":[A-Za-z0-9\-]+", body):
            name = tok[1:]
            if name not in SUPPORTED_REQUIREMENTS:
                reason = FORBIDDEN_REQUIREMENTS.get(name, "требование не входит в FPS-1")
                v.append(Fps1Violation(
                    "UNSUPPORTED_REQUIREMENT",
                    "':%s' — %s; поддерживаются: %s"
                    % (name, reason, ", ".join(":" + r for r in sorted(SUPPORTED_REQUIREMENTS))),
                    line=_line_of(emission, m.start(0))))

    # 3. Запрещённые формы в теле
    lowered = text.lower()
    for form, reason in FORBIDDEN_FORMS.items():
        # `:functions`/`:derived`/`:constants` ищем как секции,
        # остальные — как ключевые слова с границей слова
        pattern = r":%s\b" % re.escape(form) if form in ("functions", "derived", "constants") \
            else r"\b%s\b" % re.escape(form)
        m = re.search(pattern, lowered)
        if m:
            # `assign`/`increase`/`decrease` легальны как имена предикатов,
            # поэтому требуем, чтобы токен шёл сразу за '(' — это форма эффекта.
            if form in ("increase", "decrease", "assign", "scale-up", "scale-down"):
                if not re.search(r"\(\s*%s\b" % re.escape(form), lowered):
                    continue
            v.append(Fps1Violation(
                "OUT_OF_SUBSET_FORM",
                "'%s' — %s" % (form, reason),
                line=_line_of(emission, m.start(0))))

    # 4. Равенство как предикат `(= a b)`
    if re.search(r"\(\s*=\s", text):
        v.append(Fps1Violation(
            "EQUALITY_UNSUPPORTED",
            "объектное равенство '(= ...)' вне FPS-1",
            line=_line_of(emission, re.search(r"\(\s*=\s", text).start(0))))

    # 5. Дизъюнктивный ЭФФЕКТ: `(or ...)` внутри `:effect`
    for m in re.finditer(r":effect\s*(.*)", text, re.S):
        tail = m.group(1)
        # грубая, но достаточная эвристика: 'or' как голова списка в эффекте
        if re.search(r"\(\s*or\b", tail):
            v.append(Fps1Violation(
                "DISJUNCTIVE_EFFECT",
                "дизъюнкция в эффекте вне FPS-1 "
                "(НЕ ПУТАТЬ с :disjunctive-preconditions — он поддерживается)",
                line=_line_of(emission, m.start(0))))
        break  # проверяем только первую секцию :effect на действие

    # 6. Структурный минимум
    if "(define" not in lowered:
        v.append(Fps1Violation("NO_DEFINE", "отсутствует '(define ...)'", semantic=False))
    if ":domain" not in lowered:
        v.append(Fps1Violation("NO_DOMAIN_SECTION", "отсутствует секция ':domain'", semantic=False))
    if ":action" not in lowered:
        v.append(Fps1Violation(
            "NO_ACTIONS",
            "домен не объявляет ни одного действия — планировать нечего",
            semantic=False))

    return v


def split_emission(emission: str) -> tuple[str, str]:
    """Разрезать emission на (domain_src, problem_src) по маркеру.

    Маркер фиксируется грамматикой (Приложение Б, §9), поэтому разрез
    детерминирован. Отсутствие маркера — ошибка: «угадать», где заканчивается
    домен, означало бы нарушить R7.5.2 (отказ вместо догадки).
    """
    if SPLIT_MARKER not in emission:
        raise EmissionError(
            "emission does not contain the %r separator; the SLM-FORMAL output "
            "is not grammar-conformed (check guided_decoding_backend)" % SPLIT_MARKER)
    left, right = emission.split(SPLIT_MARKER, 1)
    domain_src, problem_src = left.strip(), right.strip()
    if not domain_src:
        raise EmissionError("domain part is empty")
    if not problem_src:
        raise EmissionError("problem part is empty")
    if "(define" not in domain_src.lower():
        raise EmissionError("domain part does not start a '(define ...)' form")
    # В PDDL задача объявляется как `(define (problem NAME) (:domain D) ...)`.
    # Ключевое слово `problem` здесь БЕЗ двоеточия (в отличие от `:domain`,
    # `:objects`, `:init`, `:goal`). Проверка обязана учитывать обе формы.
    low = problem_src.lower()
    if "(problem" not in low and ":problem" not in low:
        raise EmissionError("problem part has no '(problem ...)' declaration")
    if ":domain" not in low:
        raise EmissionError("problem part has no ':domain' reference")
    if ":goal" not in low:
        raise EmissionError("problem part has no ':goal' section")
    return domain_src, problem_src


def load_grammar(path: Optional[str] = None) -> str:
    """Загрузить EBNF-грамматику FPS-1 для передачи в guided decoding."""
    if path is None:
        here = os.path.dirname(os.path.abspath(__file__))
        repo = os.path.dirname(os.path.dirname(here))
        path = os.path.join(repo, "grammar", "fps1_pddl.ebnf")
    if not os.path.exists(path):
        raise EmissionError("FPS-1 grammar not found at %s" % path)
    with open(path, "r", encoding="utf-8") as f:
        return f.read()
