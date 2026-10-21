"""Барьер B3 · Provenance binding (§7.5 ТЗ).

**Единственный барьер против ошибки класса E3** — расхождения формальной модели
с реальностью. Остальные барьеры (B1, B2, B4, B6) работают внутри модели и
принципиально не способны заметить, что модель описывает не тот мир.

Нормативные требования:
  R7.5.1  каждый объект и каждый факт `:init` обязан разрешаться в запись с
          `source`, `as_of`, `confidence`;
  R7.5.2  неразрешённая референция ⇒ **ОТКАЗ**, не подстановка правдоподобного
          значения. Догадка и есть галлюцинация;
  R7.5.3  факт с `as_of` старше `staleness_bound` ⇒ отказ с причиной «данные
          устарели», а не молчаливое использование;
  R7.5.4  каждый шаг плана несёт `provenance[]` — какие факты из каких
          источников его обеспечили.

G5 этим НЕ обеспечивается (см. §3.2): барьер снижает риск, но не устраняет его.
Он обязан быть явным и проверяемым, а не подразумеваться.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Optional, Protocol

from .canon import canonical_json, canonicalize, sha256_hex

__all__ = [
    "Fact", "ProvenanceReport", "KnowledgeBase", "InMemoryKnowledgeBase",
    "ProvenanceGate", "DEFAULT_STALENESS_SECONDS",
]

#: По умолчанию 15 минут (§7.5, R7.5.3).
DEFAULT_STALENESS_SECONDS = 900


@dataclass(frozen=True)
class Fact:
    """Единица знания с обязательной привязкой к источнику."""
    key: str                 # канонический атом, напр. "(at t1 a)"
    source: str              # система-источник
    as_of: int               # epoch seconds
    confidence: float        # [0, 1]
    raw: dict = field(default_factory=dict)

    def age_seconds(self, now: Optional[int] = None) -> int:
        n = now if now is not None else int(time.time())
        return max(0, n - self.as_of)

    def to_json(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "source": self.source,
            "as_of": self.as_of,
            "confidence": self.confidence,
        }


class KnowledgeBase(Protocol):
    def lookup_object(self, name: str) -> Optional[Fact]: ...
    def lookup_atom(self, canonical_atom: str) -> Optional[Fact]: ...


@dataclass
class ProvenanceReport:
    ok: bool
    objects_resolved: list[str] = field(default_factory=list)
    objects_unresolved: list[str] = field(default_factory=list)
    atoms_resolved: list[Fact] = field(default_factory=list)
    atoms_unresolved: list[str] = field(default_factory=list)
    atoms_stale: list[dict] = field(default_factory=list)
    atoms_low_confidence: list[dict] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    staleness_bound: int = DEFAULT_STALENESS_SECONDS
    min_confidence: float = 0.0
    checked_at: int = field(default_factory=lambda: int(time.time()))

    @property
    def fingerprint(self) -> str:
        """Стабильный отпечаток отчёта — пишется в replay-лог (§8.2)."""
        payload = {
            "ok": self.ok,
            "objects_resolved": sorted(self.objects_resolved),
            "objects_unresolved": sorted(self.objects_unresolved),
            "atoms_resolved": sorted(f.key for f in self.atoms_resolved),
            "atoms_unresolved": sorted(self.atoms_unresolved),
            "atoms_stale": sorted(self.atoms_stale, key=lambda d: str(d.get("key"))),
            "staleness_bound": self.staleness_bound,
            "min_confidence": self.min_confidence,
        }
        # canonicalize обязателен: min_confidence — float, а canonical_json
        # float отвергает (в symbolic_core::json нет варианта float, иначе
        # цепь не была бы байт-совместима с Rust-стороной).
        return sha256_hex(canonical_json(canonicalize(payload)))

    def to_json(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "objects_resolved": sorted(self.objects_resolved),
            "objects_unresolved": sorted(self.objects_unresolved),
            "atoms_resolved": [f.to_json() for f in self.atoms_resolved],
            "atoms_unresolved": sorted(self.atoms_unresolved),
            "atoms_stale": self.atoms_stale,
            "atoms_low_confidence": self.atoms_low_confidence,
            "reasons": self.reasons,
            "staleness_bound": self.staleness_bound,
            "min_confidence": self.min_confidence,
            "fingerprint": self.fingerprint,
        }


class InMemoryKnowledgeBase:
    """База знаний в памяти — для CI, тестов и демо.

    Production-реализация — GraphRAG поверх Neo4j (§7.5, R7.5.1); интерфейс
    совпадает, поэтому замена не затрагивает конвейер.
    """

    def __init__(self, objects: Optional[dict[str, Fact]] = None,
                 atoms: Optional[dict[str, Fact]] = None):
        self._objects: dict[str, Fact] = dict(objects or {})
        self._atoms: dict[str, Fact] = dict(atoms or {})

    # --- пополнение -------------------------------------------------------
    def add_object(self, name: str, source: str, *, as_of: Optional[int] = None,
                   confidence: float = 1.0, **raw: Any) -> None:
        self._objects[name] = Fact(
            key="object:" + name, source=source,
            as_of=as_of if as_of is not None else int(time.time()),
            confidence=confidence, raw=dict(raw))

    def add_atom(self, canonical_atom: str, source: str, *, as_of: Optional[int] = None,
                 confidence: float = 1.0, **raw: Any) -> None:
        self._atoms[canonical_atom] = Fact(
            key=canonical_atom, source=source,
            as_of=as_of if as_of is not None else int(time.time()),
            confidence=confidence, raw=dict(raw))

    def load_facts(self, facts: list[dict[str, Any]]) -> None:
        """Массовая загрузка из JSON-дампа."""
        for f in facts:
            kind = f.get("kind", "atom")
            name = f.get("key") or f.get("name") or ""
            if not name:
                continue
            if kind == "object":
                self.add_object(name, f.get("source", "unknown"),
                                as_of=f.get("as_of"), confidence=float(f.get("confidence", 1.0)))
            else:
                self.add_atom(name, f.get("source", "unknown"),
                              as_of=f.get("as_of"), confidence=float(f.get("confidence", 1.0)))

    # --- KnowledgeBase ----------------------------------------------------
    def lookup_object(self, name: str) -> Optional[Fact]:
        return self._objects.get(name)

    def lookup_atom(self, canonical_atom: str) -> Optional[Fact]:
        return self._atoms.get(canonical_atom)

    def __len__(self) -> int:
        return len(self._objects) + len(self._atoms)


class ProvenanceGate:
    """Проверка привязки модели к источникам данных."""

    def __init__(self, kb: KnowledgeBase,
                 staleness_seconds: int = DEFAULT_STALENESS_SECONDS,
                 min_confidence: float = 0.0,
                 now_fn=None):
        self.kb = kb
        self.staleness = staleness_seconds
        self.min_confidence = min_confidence
        self._now = now_fn or (lambda: int(time.time()))

    def check(self, objects: list[str], init_atoms: list[str]) -> ProvenanceReport:
        rep = ProvenanceReport(ok=True, staleness_bound=self.staleness,
                               min_confidence=self.min_confidence,
                               checked_at=self._now())

        # --- R7.5.1 / R7.5.2: объекты ------------------------------------
        for obj in objects:
            fact = self.kb.lookup_object(obj)
            if fact is None:
                rep.objects_unresolved.append(obj)
                rep.reasons.append(
                    "R7.5.2: объект '%s' не разрешается в базу знаний — ОТКАЗ, "
                    "а не подстановка правдоподобного значения" % obj)
            else:
                if self._stale(fact, rep):
                    pass  # причина уже добавлена
                else:
                    rep.objects_resolved.append(obj)

        # --- R7.5.1 / R7.5.3: факты :init --------------------------------
        for atom in init_atoms:
            fact = self.kb.lookup_atom(atom)
            if fact is None:
                rep.atoms_unresolved.append(atom)
                rep.reasons.append(
                    "R7.5.2: факт '%s' отсутствует в базе знаний" % atom)
                continue
            age = fact.age_seconds(rep.checked_at)
            if age > self.staleness:
                rep.atoms_stale.append({
                    "key": atom, "age_seconds": age,
                    "staleness_bound": self.staleness, "source": fact.source,
                })
                rep.reasons.append(
                    "R7.5.3: факт '%s' устарел (age=%ds > bound=%ds, source=%s)"
                    % (atom, age, self.staleness, fact.source))
                continue
            if fact.confidence < self.min_confidence:
                rep.atoms_low_confidence.append({
                    "key": atom, "confidence": fact.confidence,
                    "min_confidence": self.min_confidence, "source": fact.source,
                })
                rep.reasons.append(
                    "факт '%s' имеет confidence=%.3f < min=%.3f"
                    % (atom, fact.confidence, self.min_confidence))
                continue
            rep.atoms_resolved.append(fact)

        rep.ok = not (rep.objects_unresolved or rep.atoms_unresolved
                      or rep.atoms_stale or rep.atoms_low_confidence)
        return rep

    def _stale(self, fact: Fact, rep: ProvenanceReport) -> bool:
        age = fact.age_seconds(rep.checked_at)
        if age > self.staleness:
            rep.atoms_stale.append({
                "key": fact.key, "age_seconds": age,
                "staleness_bound": self.staleness, "source": fact.source,
            })
            rep.reasons.append(
                "R7.5.3: запись объекта '%s' устарела (age=%ds > bound=%ds)"
                % (fact.key, age, self.staleness))
            return True
        return False

    def provenance_for_step(self, step_canonical: str,
                            supporting_atoms: list[str]) -> list[dict[str, Any]]:
        """R7.5.4: какие факты из каких источников обеспечили этот шаг."""
        out = []
        for a in supporting_atoms:
            fact = self.kb.lookup_atom(a)
            if fact is not None:
                out.append({
                    "step": step_canonical,
                    "fact": fact.key,
                    "source": fact.source,
                    "as_of": fact.as_of,
                    "age_seconds": fact.age_seconds(self._now()),
                    "confidence": fact.confidence,
                })
        return out
