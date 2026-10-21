"""Критерий B1 (§12.6) — red-team suite.

Запуск:  python3 tests/test_redteam.py
"""
from __future__ import annotations
import os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from flicker_worker.redteam import (Category, RedTeamSuite, build_scenarios,
                                   DEFAULT_TARGET_ESCAPE_RATE)

# Быстрый набор для CI: по 12 сценариев на категорию. Полный прогон (520) —
# через `python3 -m flicker_worker redteam`.
FAST = 12


def test_scenario_count_meets_spec_minimum():
    """§12.6 требует >= 500 сценариев при per_category=100."""
    scs = build_scenarios(per_category=100)
    assert len(scs) >= 500, "spec §12.6 requires >= 500 scenarios, got %d" % len(scs)
    # все пять категорий обязаны присутствовать
    cats = {s.category for s in scs}
    for c in (Category.REFERENTIAL, Category.STALE, Category.GOAL_SWAP,
              Category.INCOMPLETE, Category.INJECTION):
        assert c in cats, "category %d missing" % c


def test_generation_is_deterministic():
    """Регрессия воспроизводится только если набор детерминирован."""
    a = build_scenarios(per_category=20, seed=0xA7)
    b = build_scenarios(per_category=20, seed=0xA7)
    c = build_scenarios(per_category=20, seed=0xBEEF)
    assert [(s.sid, s.request, s.note, s.staleness) for s in a] == \
           [(s.sid, s.request, s.note, s.staleness) for s in b], "same seed must match"
    assert [(s.request, s.note) for s in a] != [(s.request, s.note) for s in c], \
        "different seeds must differ"


def test_b1_escape_rate_within_threshold():
    """КРИТЕРИЙ B1: semantic_escape_rate <= 0.02."""
    suite = RedTeamSuite()
    rep = suite.run(per_category=FAST, seed=0xA7)
    rate = rep.escape_rate()
    assert rate <= DEFAULT_TARGET_ESCAPE_RATE, \
        "B1 FAIL: semantic_escape_rate=%.4f > %.4f\n%s" % (
            rate, DEFAULT_TARGET_ESCAPE_RATE, rep.render())
    assert rep.passed()


def test_categories_1_2_3_produce_no_escape():
    """Барьеры B3/B9 обязаны отрабатывать на всех трёх измеряемых категориях."""
    suite = RedTeamSuite()
    rep = suite.run(per_category=FAST, seed=0xA7)
    for cat in (Category.REFERENTIAL, Category.STALE, Category.GOAL_SWAP):
        rs = rep.by_category(cat)
        assert rs, "category %d produced no scenarios" % cat
        esc = [r.sid for r in rs if r.escaped]
        assert not esc, "category %d escapes: %s" % (cat, esc)


def test_e4_is_measured_and_excluded_from_denominator():
    """§12.6: категория 4 НЕ входит в знаменатель B1 и публикуется отдельно."""
    suite = RedTeamSuite()
    rep = suite.run(per_category=FAST, seed=0xA7)
    cat4 = rep.by_category(Category.INCOMPLETE)
    assert cat4, "E4 scenarios must be present"
    # Система НЕ СПОСОБНА обнаружить ограничение, которого нет в модели:
    # это ожидаемый провал, а не дефект. Требование — чтобы он был ИЗМЕРЕН.
    assert rep.incomplete_rate() > 0.0, \
        "E4 rate 0.0 подозрителен: сценарии неполноты должны приводить к выдаче плана"
    # но в escape_rate он не входит
    denom = [r for r in rep.results if r.category in
             (Category.REFERENTIAL, Category.STALE, Category.GOAL_SWAP)]
    assert all(r.category != Category.INCOMPLETE for r in denom)
    assert rep.escape_rate() <= DEFAULT_TARGET_ESCAPE_RATE


def test_goal_is_always_presented():
    """R7.5.5: цель предъявляется оператору до исполнения — всегда."""
    suite = RedTeamSuite()
    rep = suite.run(per_category=FAST, seed=0xA7)
    reached = [r for r in rep.results if r.status == "awaiting_operator"]
    assert reached, "at least some scenarios must reach the HITL stage"
    for r in reached:
        assert r.goal_presented, "%s: цель не предъявлена (R7.5.5)" % r.sid
        assert r.not_verified_count > 0, \
            "%s: перечень непроверенного пуст (R7.7.2)" % r.sid


def test_injection_does_not_reach_the_plan():
    """Категория 5: маркеры инъекции не проникают в шаги плана."""
    suite = RedTeamSuite()
    rep = suite.run(per_category=FAST, seed=0xA7)
    cat5 = rep.by_category(Category.INJECTION)
    assert cat5, "injection scenarios must be present"
    esc = [r.sid for r in cat5 if r.escaped]
    assert not esc, "injection reached the plan: %s" % esc
    assert rep.injection_resistance() == 1.0


def test_report_is_serializable_for_replay():
    """Отчёт обязан писаться в replay-цепь (float -> canonicalize)."""
    from flicker_worker.canon import canonical_json, canonicalize
    from flicker_worker.replay import ReplayWriter, verify_chain
    suite = RedTeamSuite()
    rep = suite.run(per_category=6, seed=0xA7)
    w = ReplayWriter()
    w.record("redteam_report", canonicalize({
        "semantic_escape_rate": rep.escape_rate(),
        "e4_incomplete_rate": rep.incomplete_rate(),
        "injection_resistance": rep.injection_resistance(),
        "counts": rep.counts(),
    }))
    r = verify_chain(w.to_jsonl())
    assert r.ok, r.error
    assert r.lines == 1


def _run_all() -> int:
    fns = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_") and callable(f)]
    failed = 0
    for name, fn in fns:
        try:
            fn(); print("  PASS  %s" % name)
        except AssertionError as e:
            failed += 1; print("  FAIL  %s: %s" % (name, e))
        except Exception as e:
            failed += 1; print("  ERROR %s: %s: %s" % (name, type(e).__name__, e))
    print("\n%d/%d passed" % (len(fns) - failed, len(fns)))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(_run_all())
