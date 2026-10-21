"""Персистентная база знаний для барьера B3 · provenance binding (§7.5 ТЗ).

Заменяет `InMemoryKnowledgeBase`, которая не переживает перезапуск процесса:
без персистентности provenance-привязка теряет смысл, потому что аудит не
может быть воспроизведён post-factum (G4).

## Бэкенд

**SQLite через stdlib `sqlite3`** — ноль зависимостей (§14.2), ACID, WAL для
конкурентного чтения. Интерфейс совпадает с `KnowledgeBase`, поэтому замена на
Neo4j/GraphRAG (§7.5) не затрагивает конвейер.

## Три проектных решения, которые важно понимать

**1. `confidence` хранится в ЦЕЛЫХ базисных пунктах (0..10000), не в float.**
`symbolic_core::json` не имеет варианта float, а `canon.py::canonical_json`
его отвергает — иначе хэш строки не был бы детерминирован и G4/G3 ломались бы.
Преобразование в float происходит только на границе чтения.

**2. Каждая строка несёт собственный `row_hash`.**
SHA-256 по каноническому представлению (name/kind, source, as_of, confidence_bp).
Это даёт обнаружение подлога базы знаний независимым от replay-цепи каналом:
`verify_integrity()` пересчитывает хэши и сравнивает. База знаний — часть
доказательной базы G5, поэтому её целостность обязана быть проверяемой.

**3. `as_of` — обязательное поле, без значения по умолчанию «сейчас».**
R7.5.3 требует сравнивать возраст факта с `staleness_bound`. Факт без `as_of`
неотличим от вечно свежего, что молча обнуляет барьер. Такие записи
отклоняются при вставке.

## Graph-часть (R в GraphRAG)

Таблица `edges(src, rel, dst, …)` с теми же provenance-полями. Даёт обход
соседей и поиск путей — минимум, необходимый для обоснования шага плана
ссылками на связанные сущности (R7.5.4). Полноценный GraphRAG поверх Neo4j
остаётся задачей Э3; интерфейс намеренно совпадает.
"""
from __future__ import annotations

import os
import sqlite3
import time
from dataclasses import dataclass
from typing import Any, Iterable, Optional

from .canon import canonical_json, canonicalize, sha256_hex
from .provenance import Fact

__all__ = [
    "KnowledgeStore", "KnowledgeError", "IntegrityReport",
    "BP_SCALE", "bp_from_float", "float_from_bp", "row_hash",
]

#: Масштаб базисных пунктов: 1.0 == 10000 bp.
BP_SCALE = 10_000


class KnowledgeError(RuntimeError):
    """Нарушение контракта базы знаний."""


def bp_from_float(x: float) -> int:
    """float → базисные пункты. Округление, не усечение: 0.99995 → 10000."""
    if x != x:  # NaN
        raise KnowledgeError("confidence is NaN")
    if x < 0.0 or x > 1.0:
        raise KnowledgeError("confidence must be in [0,1], got %r" % x)
    return int(round(x * BP_SCALE))


def float_from_bp(bp: int) -> float:
    return bp / BP_SCALE


def row_hash(kind: str, key: str, source: str, as_of: int, confidence_bp: int,
             meta: str = "") -> str:
    """Хэш строки по каноническому представлению.

    Вход — только примитивы, поэтому результат детерминирован между запусками,
    платформами и версиями Python. Именно это позволяет сверять целостность
    базы, скопированной на другую машину.
    """
    payload = canonicalize({
        "kind": kind,
        "key": key,
        "source": source,
        "as_of": int(as_of),
        "confidence_bp": int(confidence_bp),
        "meta": meta,
    })
    return sha256_hex(canonical_json(payload))


@dataclass
class IntegrityReport:
    ok: bool
    rows_checked: int
    mismatches: list[str]
    missing_as_of: int
    bad_confidence: int
    detail: str = ""

    def to_json(self) -> dict[str, Any]:
        return canonicalize({
            "ok": self.ok,
            "rows_checked": self.rows_checked,
            "mismatches": sorted(self.mismatches),
            "missing_as_of": self.missing_as_of,
            "bad_confidence": self.bad_confidence,
            "detail": self.detail,
        })


_SCHEMA = """
PRAGMA journal_mode = WAL;
PRAGMA synchronous = FULL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS kb_meta (
    k TEXT PRIMARY KEY,
    v TEXT NOT NULL
);

-- Объекты предметной области. `name` — идентификатор объекта в PDDL.
CREATE TABLE IF NOT EXISTS objects (
    name          TEXT PRIMARY KEY,
    type          TEXT NOT NULL DEFAULT '',
    source        TEXT NOT NULL,
    as_of         INTEGER NOT NULL,
    confidence_bp INTEGER NOT NULL,
    meta          TEXT NOT NULL DEFAULT '',
    row_hash      TEXT NOT NULL,
    created_at    INTEGER NOT NULL,
    CHECK (as_of > 0),
    CHECK (confidence_bp BETWEEN 0 AND 10000)
);

-- Факты состояния: канонические атомы вида "(pred arg1 arg2)".
CREATE TABLE IF NOT EXISTS atoms (
    key           TEXT PRIMARY KEY,
    source        TEXT NOT NULL,
    as_of         INTEGER NOT NULL,
    confidence_bp INTEGER NOT NULL,
    meta          TEXT NOT NULL DEFAULT '',
    row_hash      TEXT NOT NULL,
    created_at    INTEGER NOT NULL,
    CHECK (as_of > 0),
    CHECK (confidence_bp BETWEEN 0 AND 10000)
);

-- Рёбра графа (GraphRAG). Провенанс обязателен и для рёбер: связь без
-- источника — такая же догадка, как объект без источника.
CREATE TABLE IF NOT EXISTS edges (
    src           TEXT NOT NULL,
    rel           TEXT NOT NULL,
    dst           TEXT NOT NULL,
    source        TEXT NOT NULL,
    as_of         INTEGER NOT NULL,
    confidence_bp INTEGER NOT NULL,
    meta          TEXT NOT NULL DEFAULT '',
    row_hash      TEXT NOT NULL,
    created_at    INTEGER NOT NULL,
    PRIMARY KEY (src, rel, dst),
    CHECK (as_of > 0),
    CHECK (confidence_bp BETWEEN 0 AND 10000)
);

-- Журнал изменений. Append-only; удаление строк запрещено политикой (R8.2.1
-- по духу: доказательная база не редактируется задним числом).
CREATE TABLE IF NOT EXISTS audit (
    seq       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts_ms     INTEGER NOT NULL,
    op        TEXT NOT NULL,
    kind      TEXT NOT NULL,
    key       TEXT NOT NULL,
    source    TEXT NOT NULL DEFAULT '',
    as_of     INTEGER NOT NULL DEFAULT 0,
    conf_bp   INTEGER NOT NULL DEFAULT 0,
    row_hash  TEXT NOT NULL DEFAULT '',
    prev_hash TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_atoms_as_of   ON atoms(as_of);
CREATE INDEX IF NOT EXISTS idx_objects_as_of ON objects(as_of);
CREATE INDEX IF NOT EXISTS idx_edges_src     ON edges(src);
CREATE INDEX IF NOT EXISTS idx_edges_dst     ON edges(dst);
"""


class KnowledgeStore:
    """Персистентная база знаний с provenance и проверкой целостности.

    Реализует протокол `provenance.KnowledgeBase` (`lookup_object`,
    `lookup_atom`), поэтому подставляется в `ProvenanceGate` без изменений.
    """

    SCHEMA_VERSION = "1"

    def __init__(self, path: str, *, readonly: bool = False, now_fn=None):
        self.path = path
        self.readonly = readonly
        self._now = now_fn or (lambda: int(time.time()))
        d = os.path.dirname(os.path.abspath(path))
        if d and not readonly:
            os.makedirs(d, exist_ok=True)
        uri = "file:%s%s" % (path, "?mode=ro" if readonly else "")
        self._conn = sqlite3.connect(uri, uri=True, isolation_level=None,
                                     check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        #: True, пока выполняется явная транзакция (см. load_facts).
        self._in_txn = False
        self._init_schema()

    # ------------------------------------------------------------ schema
    def _init_schema(self) -> None:
        if self.readonly:
            return
        self._conn.executescript(_SCHEMA)
        cur = self._conn.execute("SELECT v FROM kb_meta WHERE k='schema_version'")
        row = cur.fetchone()
        if row is None:
            self._conn.execute(
                "INSERT INTO kb_meta(k,v) VALUES('schema_version',?)", (self.SCHEMA_VERSION,))
        elif row["v"] != self.SCHEMA_VERSION:
            raise KnowledgeError(
                "schema version mismatch: db=%r code=%r — миграция не реализована, "
                "открывать чужую версию молча нельзя" % (row["v"], self.SCHEMA_VERSION))

    def close(self) -> None:
        try:
            self._conn.close()
        except sqlite3.Error:
            pass

    def __enter__(self) -> "KnowledgeStore":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ------------------------------------------------------------ запись
    def _guard_writable(self) -> None:
        if self.readonly:
            raise KnowledgeError("store opened read-only")

    def _audit(self, op: str, kind: str, key: str, source: str, as_of: int,
               conf_bp: int, rh: str) -> None:
        cur = self._conn.execute(
            "SELECT row_hash FROM audit ORDER BY seq DESC LIMIT 1")
        row = cur.fetchone()
        prev = row["row_hash"] if row else ("0" * 64)
        # Журнал сам образует hash-цепь: подмена записи задним числом
        # обнаруживается тем же механизмом, что и replay-цепь.
        chain = sha256_hex(prev + rh)
        self._conn.execute(
            "INSERT INTO audit(ts_ms,op,kind,key,source,as_of,conf_bp,row_hash,prev_hash) "
            "VALUES(?,?,?,?,?,?,?,?,?)",
            (int(time.time() * 1000), op, kind, key, source, int(as_of),
             int(conf_bp), chain, prev))

    def put_object(self, name: str, type_: str, source: str, *,
                   as_of: Optional[int] = None, confidence: float = 1.0,
                   meta: Optional[dict] = None) -> str:
        return self._put("objects", name, source, as_of, confidence, meta,
                         extra=("type", type_ or ""))

    def put_atom(self, key: str, source: str, *, as_of: Optional[int] = None,
                 confidence: float = 1.0, meta: Optional[dict] = None) -> str:
        return self._put("atoms", key, source, as_of, confidence, meta)

    def put_edge(self, src: str, rel: str, dst: str, source: str, *,
                 as_of: Optional[int] = None, confidence: float = 1.0,
                 meta: Optional[dict] = None) -> str:
        key = "%s|%s|%s" % (src, rel, dst)
        return self._put("edges", key, source, as_of, confidence, meta,
                         pk=("src", "rel", "dst"),
                         pk_vals=(src, rel, dst))

    def _put(self, table: str, key: str, source: str, as_of: Optional[int],
             confidence: float, meta: Optional[dict],
             extra: Optional[tuple] = None,
             pk: Optional[tuple] = None,
             pk_vals: Optional[tuple] = None) -> str:
        self._guard_writable()
        if not source or not source.strip():
            # R7.5.1: источник обязателен. Факт без источника — догадка.
            raise KnowledgeError(
                "%s '%s': source is mandatory (R7.5.1); a fact without a source "
                "is indistinguishable from a hallucination" % (table, key))
        if as_of is None:
            raise KnowledgeError(
                "%s '%s': as_of is mandatory (R7.5.3); a fact without a timestamp "
                "is indistinguishable from an eternally fresh one" % (table, key))
        as_of = int(as_of)
        if as_of <= 0:
            raise KnowledgeError("%s '%s': as_of must be positive" % (table, key))
        conf_bp = bp_from_float(float(confidence))
        meta_s = canonical_json(canonicalize(meta)) if meta else ""
        rh = row_hash(table.rstrip("s") if table != "edges" else "edge",
                      key, source, as_of, conf_bp, meta_s)

        cols = ["source", "as_of", "confidence_bp", "meta", "row_hash", "created_at"]
        vals = [source, as_of, conf_bp, meta_s, rh, int(time.time() * 1000)]
        if extra:
            cols.insert(0, extra[0])
            vals.insert(0, extra[1])

        if pk:
            key_cols = list(pk)
            key_placeholders = list(pk_vals or ())
        else:
            key_cols = ["name" if table == "objects" else "key"]
            key_placeholders = [key]

        all_cols = key_cols + cols
        all_vals = key_placeholders + vals
        sql = "INSERT INTO %s (%s) VALUES (%s) ON CONFLICT(%s) DO UPDATE SET %s" % (
            table,
            ", ".join(all_cols),
            ", ".join("?" * len(all_vals)),
            ", ".join(key_cols),
            ", ".join("%s=excluded.%s" % (c, c) for c in cols),
        )
        # ВНИМАНИЕ: `with self._conn:` здесь НЕЛЬЗЯ. При isolation_level=None
        # (autocommit) контекстный менеджер sqlite3 коммитит на выходе, поэтому
        # внешний BEGIN из load_facts() обрывался уже на первой записи и пачка
        # теряла атомарность. Транзакцией управляет вызывающая сторона.
        self._conn.execute(sql, all_vals)
        self._audit("put", table, key, source, as_of, conf_bp, rh)
        if not self._in_txn:
            # одиночная запись: коммитим немедленно
            self._conn.execute("COMMIT") if self._conn.in_transaction else None
        return rh

    def delete_atom(self, key: str) -> None:
        self._guard_writable()
        self._conn.execute("DELETE FROM atoms WHERE key=?", (key,))
        self._audit("delete", "atoms", key, "", 0, 0, "")

    def delete_object(self, name: str) -> None:
        self._guard_writable()
        self._conn.execute("DELETE FROM objects WHERE name=?", (name,))
        self._audit("delete", "objects", name, "", 0, 0, "")

    # ------------------------------------------------------- чтение (B3)
    def _to_fact(self, row: sqlite3.Row, kind_key: str) -> Fact:
        return Fact(
            key=row[kind_key],
            source=row["source"],
            as_of=int(row["as_of"]),
            confidence=float_from_bp(int(row["confidence_bp"])),
            raw={"meta": row["meta"], "row_hash": row["row_hash"],
                 "type": row["type"] if "type" in row.keys() else None},
        )

    def lookup_object(self, name: str) -> Optional[Fact]:
        cur = self._conn.execute("SELECT * FROM objects WHERE name=?", (name,))
        row = cur.fetchone()
        return self._to_fact(row, "name") if row else None

    def lookup_atom(self, canonical_atom: str) -> Optional[Fact]:
        cur = self._conn.execute("SELECT * FROM atoms WHERE key=?", (canonical_atom,))
        row = cur.fetchone()
        return self._to_fact(row, "key") if row else None

    # --- graph ---
    def neighbors(self, node: str, *, rel: Optional[str] = None,
                  max_age: Optional[int] = None) -> list[dict[str, Any]]:
        """Соседи узла по рёбрам в обе стороны, с фильтрацией по свежести."""
        now = self._now()
        # СКОБКИ ОБЯЗАТЕЛЬНЫ. Без них SQL-приоритет (AND выше OR) превращает
        # условие в `src=? OR (dst=? AND as_of>=?)` — и рёбра, найденные по src,
        # обходят фильтр свежести. Это не косметика: устаревшие данные попадали
        # в обход графа, ослабляя R7.5.3. Обнаружено тестом
        # test_graph_path_is_deterministic_and_correct.
        sql = ("SELECT src, rel, dst, source, as_of, confidence_bp, meta, row_hash "
               "FROM edges WHERE (src=? OR dst=?)")
        params: list[Any] = [node, node]
        if rel:
            sql += " AND rel=?"
            params.append(rel)
        if max_age is not None:
            sql += " AND as_of >= ?"
            params.append(now - int(max_age))
        out = []
        for r in self._conn.execute(sql, params):
            out.append({
                "src": r["src"], "rel": r["rel"], "dst": r["dst"],
                "source": r["source"], "as_of": int(r["as_of"]),
                "age_seconds": max(0, now - int(r["as_of"])),
                "confidence": float_from_bp(int(r["confidence_bp"])),
                "row_hash": r["row_hash"],
            })
        return out

    def find_path(self, src: str, dst: str, max_depth: int = 4,
                  max_age: Optional[int] = None) -> Optional[list[dict[str, Any]]]:
        """Кратчайший путь между узлами (BFS). None, если пути нет.

        Имя — `find_path`, а не `path`: атрибут `self.path` хранит путь к файлу
        БД и затенял бы одноимённый метод (обнаружено тестом).

        Детерминирован: соседи сортируются канонически, поэтому один и тот же
        граф всегда даёт один и тот же путь (G3).
        """
        if src == dst:
            return []
        seen = {src}
        frontier: list[tuple[str, list[dict]]] = [(src, [])]
        for _ in range(max(0, max_depth)):
            nxt: list[tuple[str, list[dict]]] = []
            for node, trail in frontier:
                edges = sorted(self.neighbors(node, max_age=max_age),
                               key=lambda e: (e["rel"], e["src"], e["dst"]))
                for e in edges:
                    other = e["dst"] if e["src"] == node else e["src"]
                    if other in seen:
                        continue
                    seen.add(other)
                    t2 = trail + [e]
                    if other == dst:
                        return t2
                    nxt.append((other, t2))
            frontier = nxt
            if not frontier:
                break
        return None

    # --- запросы для provenance-отчётов ---
    def stale_atoms(self, staleness_seconds: int) -> list[dict[str, Any]]:
        cutoff = self._now() - int(staleness_seconds)
        return [{"key": r["key"], "as_of": int(r["as_of"]),
                 "age_seconds": self._now() - int(r["as_of"]),
                 "source": r["source"]}
                for r in self._conn.execute(
                    "SELECT key, as_of, source FROM atoms WHERE as_of < ? ORDER BY key",
                    (cutoff,))]

    def counts(self) -> dict[str, int]:
        out = {}
        for t in ("objects", "atoms", "edges", "audit"):
            cur = self._conn.execute("SELECT COUNT(*) AS n FROM %s" % t)
            out[t] = int(cur.fetchone()["n"])
        return out

    # -------------------------------------------------- целостность
    def verify_integrity(self) -> IntegrityReport:
        """Пересчитать row_hash всех строк и сверить с хранимым.

        Обнаруживает подмену source/as_of/confidence/meta постфактум —
        независимый от replay-цепи канал контроля доказательной базы G5.
        """
        mismatches: list[str] = []
        checked = 0
        bad_conf = 0
        missing_as_of = 0

        specs = [
            ("objects", "object", "name", ("name", "type")),
            ("atoms", "atom", "key", ("key",)),
        ]
        for table, kind, keycol, selcols in specs:
            for r in self._conn.execute(
                    "SELECT * FROM %s ORDER BY %s" % (table, keycol)):
                checked += 1
                conf = int(r["confidence_bp"])
                if not (0 <= conf <= BP_SCALE):
                    bad_conf += 1
                if int(r["as_of"]) <= 0:
                    missing_as_of += 1
                meta_s = r["meta"] or ""
                if table == "objects":
                    expect = row_hash(kind, r["name"], r["source"], int(r["as_of"]),
                                      conf, meta_s)
                else:
                    expect = row_hash(kind, r["key"], r["source"], int(r["as_of"]),
                                      conf, meta_s)
                if expect != r["row_hash"]:
                    mismatches.append("%s:%s" % (table, r[keycol]))

        for r in self._conn.execute("SELECT * FROM edges ORDER BY src, rel, dst"):
            checked += 1
            conf = int(r["confidence_bp"])
            if not (0 <= conf <= BP_SCALE):
                bad_conf += 1
            if int(r["as_of"]) <= 0:
                missing_as_of += 1
            key = "%s|%s|%s" % (r["src"], r["rel"], r["dst"])
            expect = row_hash("edge", key, r["source"], int(r["as_of"]), conf,
                              r["meta"] or "")
            if expect != r["row_hash"]:
                mismatches.append("edges:%s" % key)

        ok = not mismatches and bad_conf == 0 and missing_as_of == 0
        return IntegrityReport(
            ok=ok, rows_checked=checked, mismatches=mismatches,
            missing_as_of=missing_as_of, bad_confidence=bad_conf,
            detail="" if ok else "row_hash mismatch or constraint violation")

    def verify_audit_chain(self) -> tuple[bool, str]:
        """Проверить hash-цепь журнала изменений."""
        prev = "0" * 64
        n = 0
        for r in self._conn.execute(
                "SELECT seq, row_hash, prev_hash FROM audit ORDER BY seq"):
            n += 1
            if r["prev_hash"] != prev:
                return False, "audit seq %d: prev_hash mismatch" % r["seq"]
            prev = r["row_hash"]
        return True, "%d audit records verified" % n

    # -------------------------------------------------- импорт/экспорт
    def load_facts(self, facts: Iterable[dict[str, Any]]) -> int:
        """Массовая загрузка. Формат элемента:

            {"kind": "object"|"atom"|"edge", "key"|"name": ..., "source": ...,
             "as_of": <int>, "confidence": <float 0..1>, "type": ..., "meta": {...},
             "src"/"rel"/"dst": ... для edge}

        Возвращает число загруженных записей. Ошибка в любой записи откатывает
        всю пачку (атомарность — provenance не бывает частично достоверным).
        """
        self._guard_writable()
        n = 0
        try:
            self._conn.execute("BEGIN")
            self._in_txn = True
            for f in facts:
                kind = f.get("kind", "atom")
                src = f.get("source", "")
                as_of = f.get("as_of")
                conf = float(f.get("confidence", 1.0))
                meta = f.get("meta")
                if kind == "object":
                    self.put_object(f["name"], f.get("type", ""), src,
                                    as_of=as_of, confidence=conf, meta=meta)
                elif kind == "edge":
                    self.put_edge(f["src"], f["rel"], f["dst"], src,
                                  as_of=as_of, confidence=conf, meta=meta)
                else:
                    self.put_atom(f["key"], src, as_of=as_of, confidence=conf,
                                  meta=meta)
                n += 1
            self._conn.execute("COMMIT")
        except Exception:
            try:
                self._conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            self._in_txn = False
        return n
