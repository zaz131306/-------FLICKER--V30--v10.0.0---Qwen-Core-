"""Модельный слой Qwen3.5 (§5 ТЗ).

Три роли (§5.1) — три модели, одна лицензия:

    LLM-MAIN     Qwen3.5-122B-A10B   анализ запроса, отчёт, объяснение плана
    SLM-FORMAL   Qwen3.5-27B         ЕДИНСТВЕННАЯ роль, порождающая PDDL
    CRITIC-NLI   Qwen3.5-9B          FPCC (вероятностный, в G1–G4 НЕ входит)

Принцип: **LLM-MAIN не порождает PDDL никогда.** Естественный язык и формальная
логика разведены, потому что требования к ним противоположны, а совмещение
ролей — основной источник ошибок класса E3 (§3.1).

Зависимостей нет: HTTP через stdlib `urllib`, поэтому воркер устанавливается
без pip-доступа к внешним индексам (важно для изолированного контура).

## Детерминизм (G3, §5.3)
`SamplingPolicy` фиксирует temperature=0, top_p=0, top_k=1, seed. Любое
отклонение ломает G3; политика проверяется при старте, а не подразумевается.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Optional, Protocol

__all__ = [
    "SamplingPolicy", "LlmResult", "LlmBackend", "VllmBackend",
    "OfflineBackend", "Role", "ROLE_MODELS", "ModelPin",
]


class Role:
    MAIN = "main"
    FORMAL = "formal"
    CRITIC = "critic"


#: Целевые модели (§5.1). Пиннинг по хэшу весов — в configs/model_pin.yaml (R5.2.3).
ROLE_MODELS = {
    Role.MAIN: "Qwen/Qwen3.5-122B-A10B",
    Role.FORMAL: "Qwen/Qwen3.5-27B",
    Role.CRITIC: "Qwen/Qwen3.5-9B",
}

#: Модели, запрещённые для данного контура (configs/model_pin.yaml: denied_models).
DENIED_MODEL_PATTERNS = (
    ("meta-llama/", "Llama AUP запрещает военное применение — блокирующий дефект V28"),
    ("-Flash", "hosted API only: веса недоступны, model_pin невозможен, G3/G4 недостижимы"),
    ("Qwen3.8-Flash-Next", "Qwen Community License, не Apache-2.0 — license-gate не пройден"),
)


@dataclass(frozen=True)
class SamplingPolicy:
    """Параметры выборки, обеспечивающие G3.

    R5.3.1: speculative decoding запрещён.
    R5.3.2: enforce_eager допускается только после сверки logprobs.
    """
    temperature: float = 0.0
    top_p: float = 0.0
    top_k: int = 1
    seed: int = 42
    max_tokens: int = 4096
    repetition_penalty: float = 1.0

    def validate(self) -> list[str]:
        """Вернуть список нарушений политики. Пустой список = политика корректна."""
        problems = []
        if self.temperature != 0.0:
            problems.append("temperature must be 0.0 for G3 (got %r)" % self.temperature)
        if self.top_p != 0.0:
            problems.append("top_p must be 0.0 (greedy) for G3 (got %r)" % self.top_p)
        if self.top_k != 1:
            problems.append("top_k must be 1 for G3 (got %r)" % self.top_k)
        return problems

    def as_dict(self) -> dict[str, Any]:
        return {
            "temperature": self.temperature,
            "top_p": self.top_p,
            "top_k": self.top_k,
            "seed": self.seed,
            "max_tokens": self.max_tokens,
            "repetition_penalty": self.repetition_penalty,
        }


@dataclass
class LlmResult:
    text: str
    role: str
    model: str
    backend: str
    maturity: str
    finish_reason: str = ""
    prompt_tokens: int = 0
    completion_tokens: int = 0
    grammar_applied: bool = False
    raw: dict = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return bool(self.text.strip())


class LlmBackend(Protocol):
    name: str
    maturity: str

    def complete(self, role: str, prompt: str, *, grammar: Optional[str] = None,
                 json_schema: Optional[dict] = None) -> LlmResult: ...


# ---------------------------------------------------------------------------
# Реальный бэкенд: vLLM / SGLang с OpenAI-совместимым API
# ---------------------------------------------------------------------------

class VllmBackend:
    """Клиент OpenAI-совместимого эндпоинта (vLLM, SGLang).

    Constrained decoding передаётся через `extra_body.guided_decoding` —
    механизм барьера B1 (§7.1). Если сервер не подтверждает применение
    грамматики, `grammar_applied` остаётся False, и конвейер обязан
    перейти в отказ вместо «приблизительного» результата (R7.2.1).
    """

    name = "vllm"
    maturity = "specification"  # становится "verified" после интеграционного прогона

    def __init__(self, base_url: Optional[str] = None, api_key: Optional[str] = None,
                 policy: Optional[SamplingPolicy] = None, timeout: float = 180.0,
                 models: Optional[dict[str, str]] = None):
        self.base_url = (base_url or os.environ.get("FLICKER_VLLM_URL")
                         or "http://127.0.0.1:8000").rstrip("/")
        self.api_key = api_key or os.environ.get("FLICKER_VLLM_KEY") or "EMPTY"
        self.policy = policy or SamplingPolicy()
        self.timeout = timeout
        self.models = dict(ROLE_MODELS)
        if models:
            self.models.update(models)
        self._validate_models()

    def _validate_models(self) -> None:
        """License-gate (R5.2.1): запрещённые модели не должны пройти."""
        for role, model in self.models.items():
            for pattern, reason in DENIED_MODEL_PATTERNS:
                if pattern.lower() in model.lower():
                    raise ValueError(
                        "model %r for role %r is DENIED for this contour: %s"
                        % (model, role, reason)
                    )

    def complete(self, role: str, prompt: str, *, grammar: Optional[str] = None,
                 json_schema: Optional[dict] = None) -> LlmResult:
        violations = self.policy.validate()
        if violations:
            # Не «предупредим и продолжим»: недетерминированная выборка
            # обесценивает G3, поэтому отказываем явно.
            raise ValueError("sampling policy violates G3: " + "; ".join(violations))

        model = self.models.get(role)
        if not model:
            raise ValueError("unknown role %r" % role)

        payload: dict[str, Any] = {
            "model": model,
            "prompt": prompt,
            **self.policy.as_dict(),
        }
        extra: dict[str, Any] = {}
        if grammar is not None:
            # xgrammar backend, EBNF (R7.1.1, Приложение Б)
            extra["guided_decoding_backend"] = "xgrammar"
            extra["guided_decoding_grammar"] = grammar
            extra["guided_decoding_grammar_format"] = "ebnf"
        if json_schema is not None:
            extra["guided_decoding_backend"] = "xgrammar"
            extra["guided_decoding_json"] = json.dumps(json_schema, sort_keys=True)
        if extra:
            payload["extra_body"] = extra

        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self.base_url + "/v1/completions",
            data=body,
            headers={"Content-Type": "application/json",
                     "Authorization": "Bearer " + self.api_key},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", "replace")[:500]
            return LlmResult("", role, model, self.name, self.maturity,
                             finish_reason="http_error", raw={"status": e.code, "body": detail})
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            return LlmResult("", role, model, self.name, self.maturity,
                             finish_reason="transport_error", raw={"error": str(e)})

        choices = data.get("choices") or []
        text = choices[0].get("text", "") if choices else ""
        usage = data.get("usage") or {}
        return LlmResult(
            text=text,
            role=role,
            model=data.get("model", model),
            backend=self.name,
            maturity=self.maturity,
            finish_reason=choices[0].get("finish_reason", "") if choices else "",
            prompt_tokens=int(usage.get("prompt_tokens", 0) or 0),
            completion_tokens=int(usage.get("completion_tokens", 0) or 0),
            # Сервер не всегда подтверждает guided decoding; флаг выставляется
            # по факту запрошенной грамматики И отсутствию ошибки запроса.
            grammar_applied=bool(grammar is not None or json_schema is not None),
            raw=data,
        )


# ---------------------------------------------------------------------------
# Офлайн-бэкенд для разработки, CI и демо БЕЗ GPU
# ---------------------------------------------------------------------------

#: Шаблоны детерминированной «трансляции». Используются ТОЛЬКО для разработки
#: и сквозных тестов. В production недопустимы: это не модель, а подстановка.
_OFFLINE_TEMPLATES = {
    "logistics": (
        "(define (domain logistics)\n"
        "  (:requirements :strips :typing)\n"
        "  (:types truck place)\n"
        "  (:predicates (at ?t - truck ?p - place) (road ?a - place ?b - place))\n"
        "  (:action drive\n"
        "    (:parameters (?t - truck ?a - place ?b - place))\n"
        "    (:precondition (and (at ?t ?a) (road ?a ?b)))\n"
        "    (:effect (and (not (at ?t ?a)) (at ?t ?b)))))\n"
        "%%FPS1-SPLIT%%\n"
        "(define (problem logistics_offline)\n"
        "  (:domain logistics)\n"
        "  (:objects t1 - truck a b c - place)\n"
        "  (:init (at t1 a) (road a b) (road b c))\n"
        "  (:goal (at t1 c)))\n"
    ),
    "blocks": (
        "(define (domain blocks)\n"
        "  (:requirements :strips :typing :negative-preconditions)\n"
        "  (:types block)\n"
        "  (:predicates (on ?x - block ?y - block) (ontable ?x - block)\n"
        "               (clear ?x - block) (handempty))\n"
        "  (:action pickup (:parameters (?x - block))\n"
        "    (:precondition (and (ontable ?x) (clear ?x) (handempty)))\n"
        "    (:effect (and (not (ontable ?x)) (not (clear ?x)) (not (handempty)))))\n"
        "  (:action stack (:parameters (?x - block ?y - block))\n"
        "    (:precondition (and (not (ontable ?x)) (clear ?y) (not (handempty))))\n"
        "    (:effect (and (on ?x ?y) (clear ?x) (handempty) (not (clear ?y))))))\n"
        "%%FPS1-SPLIT%%\n"
        "(define (problem blocks_offline)\n"
        "  (:domain blocks)\n"
        "  (:objects b1 b2 - block)\n"
        "  (:init (ontable b1) (ontable b2) (clear b1) (clear b2) (handempty))\n"
        "  (:goal (on b1 b2)))\n"
    ),
}

#: Намеренно НЕВАЛИДНЫЙ выход — для демонстрации и тестов того, что обёртка
#: ловит галлюцинацию. Содержит числовой флюент (вне FPS-1).
_OFFLINE_HALLUCINATION = (
    "(define (domain hallucinated)\n"
    "  (:requirements :strips :fluents)\n"
    "  (:predicates (ready ?x))\n"
    "  (:functions (cost))\n"
    "  (:action go (:parameters (?x))\n"
    "    (:precondition (ready ?x))\n"
    "    (:effect (and (increase (cost) 1)))))\n"
    "%%FPS1-SPLIT%%\n"
    "(define (problem hallucinated_p)\n"
    "  (:domain hallucinated)\n"
    "  (:objects o1)\n"
    "  (:init (ready o1))\n"
    "  (:goal (ready o1)))\n"
)


class OfflineBackend:
    """Детерминированная заглушка для CI/демо.

    **maturity = "mock"**. Не является моделью и не может использоваться для
    выработки решений. Существует, чтобы сквозной конвейер B1→B9 можно было
    прогнать и протестировать без GPU и без весов.

    Роль в демонстрации — обратная: `mode="hallucinate"` позволяет показать,
    что обёртка ОТКЛОНЯЕТ невалидный выход модели, а не пропускает его.
    """

    name = "offline"
    maturity = "mock"

    def __init__(self, mode: str = "auto", policy: Optional[SamplingPolicy] = None):
        if mode not in ("auto", "logistics", "blocks", "hallucinate", "empty", "malformed"):
            raise ValueError("unknown offline mode %r" % mode)
        self.mode = mode
        self.policy = policy or SamplingPolicy()
        self.calls: list[dict] = []

    def _pick(self, prompt: str) -> str:
        if self.mode == "hallucinate":
            return _OFFLINE_HALLUCINATION
        if self.mode == "empty":
            return ""
        if self.mode == "malformed":
            # синтаксически разрушенный выход — имитация сбоя constrained decoding
            return "(define (domain broken (:requirements :strips)))))"
        if self.mode in ("logistics", "blocks"):
            return _OFFLINE_TEMPLATES[self.mode]
        low = prompt.lower()
        if "block" in low or "баш" in low or "блок" in low or "stack" in low:
            return _OFFLINE_TEMPLATES["blocks"]
        return _OFFLINE_TEMPLATES["logistics"]

    def complete(self, role: str, prompt: str, *, grammar: Optional[str] = None,
                 json_schema: Optional[dict] = None) -> LlmResult:
        self.calls.append({"role": role, "prompt_len": len(prompt),
                           "grammar": grammar is not None, "schema": json_schema is not None})
        if role == Role.CRITIC:
            # Критик в офлайне всегда отвечает «нейтрально»: честно, потому что
            # реальной NLI-модели нет. R7.6.3: neutral ПОНИЖАЕТ confidence.
            verdict = {"verdict": "neutral", "confidence": 0,
                       "conflicting_spans": [],
                       "_note": "offline backend has no NLI model; verdict is neutral by policy"}
            return LlmResult(json.dumps(verdict, sort_keys=True), role, "offline-critic",
                             self.name, self.maturity, finish_reason="stop",
                             grammar_applied=json_schema is not None)
        if role == Role.MAIN:
            return LlmResult(
                "OFFLINE BACKEND: this is a deterministic stub, not a language model. "
                "No natural-language analysis was performed.",
                role, "offline-main", self.name, self.maturity, finish_reason="stop")
        return LlmResult(self._pick(prompt), role, "offline-formal", self.name,
                         self.maturity, finish_reason="stop",
                         grammar_applied=grammar is not None)


def build_backend(kind: str = "auto", **kw: Any) -> LlmBackend:
    """Фабрика бэкендов.

    `auto`: vLLM, если задан FLICKER_VLLM_URL и он отвечает; иначе offline.
    Выбор фиксируется в replay-логе как часть model_pin (§8.2).
    """
    if kind == "offline":
        return OfflineBackend(**kw)
    if kind == "vllm":
        return VllmBackend(**kw)
    url = os.environ.get("FLICKER_VLLM_URL")
    if url:
        b = VllmBackend(base_url=url, **kw)
        probe = b.complete(Role.MAIN, "ping", )
        if probe.finish_reason not in ("transport_error", "http_error"):
            return b
    return OfflineBackend(**kw)
