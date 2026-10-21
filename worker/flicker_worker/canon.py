"""Каноническая сериализация JSON и криптопримитивы.

БАЙТ-СОВМЕСТИМО с `symbolic-core::json` и `symbolic-core::sha2`.
Это нормативное требование: replay-цепь пишется и Rust-ядром, и Python-воркером,
и `verify_chain` с обеих сторон обязан принимать цепь другой стороны (G4).

Правила канонической формы (см. `json.rs::write_canonical`):
  · ключи объекта — в лексикографическом порядке (BTreeMap)
  · разделители — `,` и `:` без пробелов
  · экранирование: `\\"` `\\\\` `\\n` `\\r` `\\t` `\\b` `\\f`,
    прочие управляющие символы < 0x20 — как `\\u00xx` (строчный hex)
  · non-ASCII НЕ экранируется (буквально, UTF-8)
  · чисел с плавающей точкой НЕТ — только null/bool/int/str/arr/obj
    (см. `json::tests::rejects_floats`: float разрушал бы детерминизм G3)
"""
from __future__ import annotations

import hashlib
import hmac as _hmac
from typing import Any

__all__ = [
    "canonical_json",
    "sha256_hex",
    "hmac_sha256_hex",
    "constant_time_eq",
    "canonicalize",
    "encode_float",
    "FLOAT_PRECISION",
    "JsonError",
]


class JsonError(ValueError):
    """Вход не является допустимым каноническим JSON-значением FLICKER."""


_ESCAPES = {
    '"': '\\"',
    "\\": "\\\\",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
    "\x08": "\\b",
    "\x0c": "\\f",
}


def _encode_string(s: str) -> str:
    out = ['"']
    for ch in s:
        esc = _ESCAPES.get(ch)
        if esc is not None:
            out.append(esc)
        elif ord(ch) < 0x20:
            # строчный hex — точно как `write!(out, "\\u{:04x}", c)` в Rust
            out.append("\\u%04x" % ord(ch))
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def canonical_json(value: Any) -> str:
    """Сериализовать в каноническую форму, совместимую с `Json::to_canonical`.

    Отклоняет float, потому что `symbolic_core::json` их не принимает:
    допуск float здесь создал бы расхождение между языками и нарушил бы G3/G4.
    """
    if value is None:
        return "null"
    if isinstance(value, bool):  # ДО проверки int: bool является подклассом int
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        raise JsonError(
            "float is not representable in FLICKER canonical JSON "
            "(symbolic-core::json rejects floats; determinism G3)"
        )
    if isinstance(value, str):
        return _encode_string(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(canonical_json(v) for v in value) + "]"
    if isinstance(value, dict):
        items = []
        for k in sorted(value.keys()):
            if not isinstance(k, str):
                raise JsonError("object keys must be strings, got %r" % type(k).__name__)
            items.append(_encode_string(k) + ":" + canonical_json(value[k]))
        return "{" + ",".join(items) + "}"
    raise JsonError("unsupported JSON value of type %r" % type(value).__name__)


def sha256_hex(data: bytes | str) -> str:
    """SHA-256, строчный hex — как `sha2::sha256_hex`."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def hmac_sha256_hex(key: bytes | str, msg: bytes | str) -> str:
    """HMAC-SHA256, строчный hex — как `sha2::hmac_sha256` + `to_hex`."""
    if isinstance(key, str):
        key = key.encode("utf-8")
    if isinstance(msg, str):
        msg = msg.encode("utf-8")
    return _hmac.new(key, msg, hashlib.sha256).hexdigest()


def constant_time_eq(a: str, b: str) -> bool:
    """Сравнение, постоянное по времени (зеркало `ct_eq` в Томе 1)."""
    return _hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


# ---------------------------------------------------------------------------
# Кодирование float для аудит-логов
# ---------------------------------------------------------------------------
#
# `symbolic_core::json` НЕ имеет варианта float (см. тест `rejects_floats`):
# двоичная плавающая точка не даёт побайтово стабильной сериализации между
# платформами и компиляторами, что сломало бы G3/G4.
#
# Поэтому вещественные значения (confidence, оценки критика) пишутся в
# replay-цепь строкой фиксированной точности. Это детерминированно,
# недвусмысленно и обратно читаемо.

FLOAT_PRECISION = 6


def encode_float(x: float) -> str:
    """Детерминированное строковое представление float для аудит-логов."""
    return "%.*f" % (FLOAT_PRECISION, x)


def canonicalize(value: Any) -> Any:
    """Рекурсивно подготовить значение к `canonical_json`.

    Заменяет float на строку фиксированной точности. Всё остальное передаёт
    как есть; недопустимые типы отбрасывает `canonical_json`.
    """
    if isinstance(value, bool) or value is None or isinstance(value, (int, str)):
        return value
    if isinstance(value, float):
        return encode_float(value)
    if isinstance(value, (list, tuple)):
        return [canonicalize(v) for v in value]
    if isinstance(value, dict):
        return {k: canonicalize(v) for k, v in value.items()}
    # dataclass / прочее — приводим к строке явно, а не молча
    return str(value)

