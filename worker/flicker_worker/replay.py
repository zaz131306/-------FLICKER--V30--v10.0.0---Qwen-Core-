"""Барьер B8 · Deterministic replay hash-chain (G4).

Формат записи — ТОЧНО как `symbolic_core::replay`:

    event      = {"kind":…, "payload":…, "seq":…, "ts_ms":…}
    event_hash = sha256(canonical_json(event))
    line_hash  = sha256(prev_hash + event_hash)
    line       = {"event":event, "event_hash":…, "line_hash":…, "prev_hash":…, "seq":…}

    GENESIS_PREV_HASH = "0" * 64

Файл — JSONL, одна каноническая строка на запись, append-only (R8.2.1).

Кросс-языковая совместимость проверяется тестом `tests/test_interop.py`:
цепь, записанная Rust-CLI (`flicker-plan --replay`), обязана верифицироваться
здесь, и наоборот.
"""
from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from typing import Any, Optional

from .canon import canonical_json, sha256_hex

__all__ = [
    "GENESIS_PREV_HASH",
    "ReplayRecord",
    "ChainReport",
    "ReplayWriter",
    "verify_chain",
]

GENESIS_PREV_HASH = "0" * 64


@dataclass
class ReplayRecord:
    seq: int
    prev_hash: str
    event_hash: str
    line_hash: str
    line: str


@dataclass
class ChainReport:
    ok: bool
    lines: int
    root_hash: str
    error: Optional[str] = None


@dataclass
class ReplayWriter:
    """Пишет append-only JSONL-цепь.

    `path=None` — накопление в памяти (для тестов и для сухих прогонов).
    """

    path: Optional[str] = None
    seq: int = 0
    prev_hash: str = GENESIS_PREV_HASH
    root_hash: str = GENESIS_PREV_HASH
    lines: list[str] = field(default_factory=list)

    @staticmethod
    def now_ms() -> int:
        return int(time.time() * 1000)

    def record(self, kind: str, payload: Any, ts_ms: Optional[int] = None) -> ReplayRecord:
        """Добавить событие. `payload` обязан быть канонически сериализуем."""
        if ts_ms is None:
            ts_ms = self.now_ms()
        event = {
            "kind": kind,
            "payload": payload,
            "seq": self.seq,
            "ts_ms": ts_ms,
        }
        event_canon = canonical_json(event)
        event_hash = sha256_hex(event_canon)
        prev_hash = self.prev_hash
        line_hash = sha256_hex(prev_hash + event_hash)

        line_obj = {
            "event": event,
            "event_hash": event_hash,
            "line_hash": line_hash,
            "prev_hash": prev_hash,
            "seq": self.seq,
        }
        line_canon = canonical_json(line_obj)

        self.lines.append(line_canon)
        self.prev_hash = line_hash
        self.root_hash = line_hash
        rec = ReplayRecord(
            seq=self.seq,
            prev_hash=prev_hash,
            event_hash=event_hash,
            line_hash=line_hash,
            line=line_canon,
        )
        self.seq += 1

        if self.path is not None:
            self._append(line_canon)
        return rec

    def _append(self, line_canon: str) -> None:
        d = os.path.dirname(os.path.abspath(self.path or ""))
        if d:
            os.makedirs(d, exist_ok=True)
        # append-only: никогда не перезаписываем (R8.2.1)
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(line_canon + "\n")

    def to_jsonl(self) -> str:
        return "".join(l + "\n" for l in self.lines)


def verify_chain(jsonl: str) -> ChainReport:
    """Верифицировать цепь. Зеркало `replay::verify_chain`.

    Обнаруживает: подмену payload, подмену любого хэша, разрыв связности
    prev_hash, некорректный seq, перестановку и повреждённый JSON.

    Усечение цепи (валидный префикс) верифицируется как ok, но root_hash
    отличается — вызывающая сторона ОБЯЗАНА сверять root_hash с записанным
    (см. тест `a4_truncation_changes_root_hash` в Rust).
    """
    prev = GENESIS_PREV_HASH
    count = 0
    root = GENESIS_PREV_HASH

    for idx, raw in enumerate(jsonl.splitlines()):
        raw = raw.strip()
        if not raw:
            continue
        try:
            line = json.loads(raw)
        except Exception as e:
            return ChainReport(False, count, root, "line %d: malformed JSON (%s)" % (idx + 1, e))
        if not isinstance(line, dict):
            return ChainReport(False, count, root, "line %d: not an object" % (idx + 1))

        for k in ("event", "event_hash", "line_hash", "prev_hash", "seq"):
            if k not in line:
                return ChainReport(False, count, root, "line %d: missing field '%s'" % (idx + 1, k))

        # 1. seq обязан совпадать с позицией
        if line["seq"] != idx:
            return ChainReport(False, count, root,
                               "line %d: seq=%r but position=%d" % (idx + 1, line["seq"], idx))
        # 2. связность цепи
        if line["prev_hash"] != prev:
            return ChainReport(False, count, root,
                               "line %d: prev_hash mismatch (expected %s, got %s)"
                               % (idx + 1, prev, line["prev_hash"]))
        # 3. event_hash соответствует фактическому payload
        try:
            recomputed_event = sha256_hex(canonical_json(line["event"]))
        except Exception as e:
            return ChainReport(False, count, root, "line %d: payload not canonicalizable (%s)" % (idx + 1, e))
        if recomputed_event != line["event_hash"]:
            return ChainReport(False, count, root,
                               "line %d: event payload hash mismatch (tampered or serializer drift)" % (idx + 1))
        # 4. line_hash соответствует связке prev+event
        recomputed_line = sha256_hex(line["prev_hash"] + line["event_hash"])
        if recomputed_line != line["line_hash"]:
            return ChainReport(False, count, root,
                               "line %d: line_hash mismatch" % (idx + 1))
        # 5. seq внутри event обязан совпадать с seq строки
        ev = line["event"]
        if isinstance(ev, dict) and ev.get("seq") != line["seq"]:
            return ChainReport(False, count, root,
                               "line %d: event.seq disagrees with line seq" % (idx + 1))

        prev = line["line_hash"]
        root = line["line_hash"]
        count += 1

    return ChainReport(True, count, root, None)


def verify_file(path: str) -> ChainReport:
    with open(path, "r", encoding="utf-8") as f:
        return verify_chain(f.read())
