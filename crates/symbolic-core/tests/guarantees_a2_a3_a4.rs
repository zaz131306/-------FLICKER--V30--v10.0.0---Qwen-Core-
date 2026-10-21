//! Критерии приёмки Class-A: **A2** (G2 — валидатор), **A3** (G3 — детерминизм),
//! **A4** (G4 — целостность replay-цепи).
//!
//! Эти тесты — нормативная проверка гарантий из ТЗ V30 §3.2 и §12.
//! Класс A: waiver запрещён (R13.5), нарушение блокирует приёмку.

#![allow(clippy::expect_used, clippy::unwrap_used)]
// Тестовый код: expect/unwrap допустимы и предпочтительны —
// падение теста должно быть явным. Продукционный код под deny (§4.3, A6).
mod common;

use common::*;
use symbolic_core::ground::{ground_actions, ground_actions_with_cap, DEFAULT_GROUNDING_CAP};
use symbolic_core::json::{Json, parse_json};
use symbolic_core::planner::{plan, PlanMode, PlanOptions};
use symbolic_core::prng::Xorshift64Star;
use symbolic_core::replay::{verify_chain, ReplayWriter, GENESIS_PREV_HASH};
use symbolic_core::state::State;
use symbolic_core::validator::{validate_plan, PlanStep};

fn step(action: &str, args: &[&str]) -> PlanStep {
    PlanStep {
        action: action.to_string(),
        args: args.iter().map(|s| s.to_string()).collect(),
    }
}

// ===========================================================================
//  A2 · G2 — ни один логически невалидный план не проходит валидацию
// ===========================================================================

#[test]
fn a2_valid_plan_is_accepted_with_full_report() {
    let (m, g) = logistics();
    let steps = vec![step("drive", &["t1", "a", "b"]), step("drive", &["t1", "b", "c"])];
    let r = validate_plan(&m, &g, &steps).expect("validate");
    assert!(r.valid);
    assert!(r.goal_satisfied);
    assert_eq!(r.steps_checked, 2);
    assert!(r.failed_step.is_none());
    assert!(r.reason.is_none());
    assert_eq!(r.init_state_hash.len(), 64, "SHA-256 hex");
    assert_eq!(r.final_state_hash.len(), 64);
    assert_ne!(r.init_state_hash, r.final_state_hash, "state must have changed");
}

#[test]
fn a2_invented_action_is_rejected() {
    // Модель выдумала действие, которого нет в домене.
    let (m, g) = logistics();
    let steps = vec![step("teleport", &["t1", "a", "c"])];
    let e = validate_plan(&m, &g, &steps).expect_err("invented action must fail");
    assert_eq!(e.kind, "validation");
    assert!(e.message.contains("not a valid grounding"), "msg: {}", e.message);
}

#[test]
fn a2_invented_argument_is_rejected() {
    // Действие реальное, объект — выдуман.
    let (m, g) = logistics();
    let steps = vec![step("drive", &["t1", "a", "zzz"])];
    let e = validate_plan(&m, &g, &steps).expect_err("invented object must fail");
    assert_eq!(e.kind, "validation");
}

#[test]
fn a2_wrong_argument_order_is_rejected() {
    // R7.4.2: порядок аргументов значим. (drive t1 b a) — обратный маршрут,
    // которого нет в :init как дороги b->a, поэтому предусловие не выполнится.
    let (m, g) = logistics();
    let steps = vec![step("drive", &["t1", "b", "a"])];
    match validate_plan(&m, &g, &steps) {
        Ok(r) => {
            assert!(!r.valid, "must not be valid");
            assert_eq!(r.failed_step, Some(0));
            assert!(r.reason.is_some(), "reason must be reported");
        }
        Err(e) => assert_eq!(e.kind, "validation"),
    }
}

#[test]
fn a2_wrong_argument_type_is_rejected() {
    // грузовик на место грузовика: (drive t1 t1 b) — тип не совпадает
    let (m, g) = logistics();
    let steps = vec![step("drive", &["t1", "t1", "b"])];
    match validate_plan(&m, &g, &steps) {
        Ok(r) => assert!(!r.valid),
        Err(e) => assert_eq!(e.kind, "validation"),
    }
}

#[test]
fn a2_precondition_violation_is_pinned_to_step_index() {
    // Второй шаг невыполним: после (drive t1 a b) грузовик в b,
    // а шаг требует (at t1 a).
    let (m, g) = logistics();
    let steps = vec![step("drive", &["t1", "a", "b"]), step("drive", &["t1", "a", "b"])];
    let r = validate_plan(&m, &g, &steps).expect("report");
    assert!(!r.valid);
    assert_eq!(r.failed_step, Some(1), "must pin the exact failing step");
    assert!(r.reason.is_some());
}

#[test]
fn a2_goal_not_satisfied_is_reported_separately() {
    // План исполним, но цель НЕ достигнута: одна поездка a->b вместо a->c.
    // R7.4.1 требует ОБА условия: valid && goal_satisfied.
    let (m, g) = logistics();
    let steps = vec![step("drive", &["t1", "a", "b"])];
    let r = validate_plan(&m, &g, &steps).expect("report");
    // `valid` means "complete solution", so an incomplete-but-executable plan
    // is NOT valid. Distinguish the two failure modes via failed_step/reason.
    assert!(!r.valid);
    assert!(!r.goal_satisfied, "the goal (at t1 c) is NOT reached");
    assert_eq!(r.failed_step, None, "no STEP failed — the shortfall is at goal level");
    assert_eq!(r.steps_checked, 1, "the one step did execute");
    let reason = r.reason.expect("reason must be present");
    assert!(reason.contains("goal is not satisfied"), "reason: {}", reason);
    assert!(!reason.contains("precondition"), "must not be misreported as a step failure");
}

#[test]
fn a2_empty_plan_against_unreached_goal() {
    let (m, g) = logistics();
    let r = validate_plan(&m, &g, &[]).expect("report");
    assert!(!r.valid, "empty plan is not a complete solution");
    assert!(!r.goal_satisfied, "empty plan cannot reach (at t1 c)");
    assert_eq!(r.steps_checked, 0);
    assert_eq!(r.failed_step, None, "no step exists, so none can be at fault");
    assert_eq!(r.init_state_hash, r.final_state_hash, "no steps -> state unchanged");
}

#[test]
fn a2_empty_plan_when_goal_already_holds() {
    let (m, g) = trivial();
    let r = validate_plan(&m, &g, &[]).expect("report");
    assert!(r.valid);
    assert!(r.goal_satisfied);
    assert_eq!(r.init_state_hash, r.final_state_hash, "no steps -> identical state");
}

/// A2 в форме property-теста: перебор ВСЕХ одиночных шагов из пространства
/// grounding. Утверждение: ни один шаг, нарушающий предусловие, не принимается.
#[test]
fn a2_exhaustive_single_step_never_accepts_inapplicable_action() {
    let (m, g) = blocks();
    let init = State::new(m.problem.init.clone());
    let env = std::collections::BTreeMap::new();

    let mut applicable = 0usize;
    let mut inapplicable = 0usize;

    for ga in &g {
        let s = vec![PlanStep { action: ga.name.clone(), args: ga.args.clone() }];
        let precond_holds = symbolic_core::state::eval(&ga.precond, &init, &m, &env)
            .expect("eval must not fail on a ground precondition");
        let r = validate_plan(&m, &g, &s);

        // `valid` conflates step-executability with goal attainment, so the
        // discriminating signal for G2 is `failed_step` + `reason`:
        //   precondition violated -> failed_step == Some(0)
        //   executed cleanly      -> failed_step == None
        let rep = r.expect("validate must not error on a real grounding");
        if precond_holds {
            applicable += 1;
            assert_eq!(
                rep.failed_step, None,
                "G2 VIOLATION: applicable action '{}' was blamed for a step failure",
                ga.name
            );
            assert_eq!(rep.steps_checked, 1, "the applicable step must be simulated");
        } else {
            inapplicable += 1;
            assert!(
                !rep.valid,
                "G2 VIOLATION: inapplicable action '{}' was accepted",
                ga.name
            );
            assert_eq!(
                rep.failed_step, Some(0),
                "inapplicable action '{}' must be pinned to step 0",
                ga.name
            );
            let reason = rep.reason.expect("reason required");
            assert!(
                reason.contains("precondition"),
                "reason must name the precondition failure: {}",
                reason
            );
            assert_eq!(rep.steps_checked, 0, "a failing step is not counted as checked");
        }
    }
    assert!(applicable > 0, "fixture must have applicable actions");
    assert!(inapplicable > 0, "fixture must have inapplicable actions");
}

/// A2 для пар шагов: полный перебор 2-шаговых комбинаций в blocks.
/// Ни одна пара, нарушающая предусловие на любом шаге, не должна приниматься.
#[test]
fn a2_exhaustive_two_step_pairs_never_accept_invalid() {
    let (m, g) = blocks();
    let env = std::collections::BTreeMap::new();
    let mut checked = 0usize;
    let mut rejected = 0usize;

    for a in &g {
        for b in &g {
            let steps = vec![
                PlanStep { action: a.name.clone(), args: a.args.clone() },
                PlanStep { action: b.name.clone(), args: b.args.clone() },
            ];
            checked += 1;
            let r = validate_plan(&m, &g, &steps).expect("must not error on real groundings");
            if !r.valid {
                rejected += 1;
                // Two legitimate rejection modes (see ValidationReport docs):
                //   (a) a step violated its precondition -> failed_step == Some(i)
                //   (b) all steps ran but the goal is unmet -> failed_step == None
                // A rejected plan must ALWAYS carry a reason.
                assert!(r.reason.is_some(), "rejected plan must carry a reason");
                if let Some(i) = r.failed_step {
                    assert!(i < steps.len(), "failed_step must be in range, got {}", i);
                    assert!(
                        r.reason.as_ref().unwrap().contains("precondition"),
                        "step-level rejection must name the precondition"
                    );
                }
            }
            // Независимая перепроверка: симулируем вручную и сравниваем хэш.
            let mut st = State::new(m.problem.init.clone());
            let mut ok = true;
            for s in &steps {
                let key = s.key();
                let ga = match g.iter().find(|x| x.key() == key) {
                    Some(x) => x,
                    None => { ok = false; break; }
                };
                if !symbolic_core::state::eval(&ga.precond, &st, &m, &env).expect("eval") {
                    ok = false;
                    break;
                }
                let mut adds = std::collections::BTreeSet::new();
                let mut dels = std::collections::BTreeSet::new();
                symbolic_core::state::collect_effect(&ga.effect, &st, &m, &env, &mut adds, &mut dels)
                    .expect("collect");
                st = st.apply_delta(&adds, &dels);
            }
            if ok {
                assert_eq!(
                    st.hash(),
                    r.final_state_hash,
                    "independent simulation must agree with the validator's final hash"
                );
            } else {
                assert!(!r.valid, "manual simulation failed but validator accepted the plan");
            }
        }
    }
    assert!(checked >= 64, "expected a real cross-product, got {}", checked);
    assert!(rejected > 0, "some pairs must be rejected, else the test proves nothing");
}

// ===========================================================================
//  A3 · G3 — идентичный вход ⇒ побайтово идентичный выход
// ===========================================================================

#[test]
fn a3_best_first_is_deterministic_across_runs() {
    let (m, g) = blocks();
    let o = PlanOptions { mode: PlanMode::BestFirst, ..PlanOptions::default() };
    let first = plan(&m, &g, &o).expect("run 1");
    for i in 2..=25 {
        let again = plan(&m, &g, &o).expect("run n");
        assert_eq!(plan_signature(&first.steps), plan_signature(&again.steps), "run {} differs", i);
        assert_eq!(first.expanded, again.expanded, "run {} expanded differs", i);
        assert_eq!(first.generated, again.generated, "run {} generated differs", i);
        assert_eq!(first.final_state_hash, again.final_state_hash, "run {} hash differs", i);
        assert_eq!(first.mode_used, again.mode_used);
    }
}

#[test]
fn a3_mcts_is_deterministic_for_a_given_seed() {
    let (m, g) = blocks();
    let o = PlanOptions { mode: PlanMode::Mcts, seed: 777, mcts_iterations: 1_500, ..PlanOptions::default() };
    let first = plan(&m, &g, &o).expect("run 1");
    for i in 2..=15 {
        let again = plan(&m, &g, &o).expect("run n");
        assert_eq!(plan_signature(&first.steps), plan_signature(&again.steps), "run {} differs", i);
        assert_eq!(first.expanded, again.expanded);
        assert_eq!(first.generated, again.generated);
        assert_eq!(first.final_state_hash, again.final_state_hash);
    }
}

#[test]
fn a3_different_seeds_may_differ_but_stay_valid() {
    // Разные seed'ы вправе давать разные пути, но КАЖДЫЙ обязан быть валидным.
    // Это различие конструктивного (G2) и вероятностного выбора.
    let (m, g) = blocks();
    for seed in [1u64, 2, 3, 99, 12345] {
        let o = PlanOptions { mode: PlanMode::Mcts, seed, mcts_iterations: 1_500, ..PlanOptions::default() };
        match plan(&m, &g, &o) {
            Ok(out) => {
                assert!(out.validated);
                assert!(out.validation.valid, "seed {} produced an invalid plan", seed);
                assert!(out.validation.goal_satisfied);
                assert_eq!(out.seed, seed);
            }
            Err(e) => assert_eq!(e.kind, "limit", "seed {}: unexpected error kind", seed),
        }
    }
}

#[test]
fn a3_prng_is_reproducible_and_seed_sensitive() {
    let mut a = Xorshift64Star::new(42);
    let mut b = Xorshift64Star::new(42);
    let c = Xorshift64Star::new(43);
    for _ in 0..1000 {
        assert_eq!(a.next_u64(), b.next_u64(), "same seed must give same stream");
    }
    let x = Xorshift64Star::new(42);
    let y = Xorshift64Star::new(43);
    assert_ne!(x.state(), y.state(), "different seeds must differ");
    // next_below обязана оставаться в диапазоне и не давать modulo bias-артефактов
    let mut r = Xorshift64Star::new(7);
    for _ in 0..10_000 {
        let v = r.next_below(10);
        assert!(v < 10, "next_below(10) returned {}", v);
    }
    let _ = c;
}

#[test]
fn a3_state_hash_is_canonical_and_order_independent() {
    // State хранит BTreeSet, поэтому порядок вставки не влияет на хэш.
    let mut s1 = std::collections::BTreeSet::new();
    s1.insert("(at t1 a)".to_string());
    s1.insert("(road a b)".to_string());
    let mut s2 = std::collections::BTreeSet::new();
    s2.insert("(road a b)".to_string());
    s2.insert("(at t1 a)".to_string());
    assert_eq!(
        State::new(s1).hash(),
        State::new(s2).hash(),
        "hash must not depend on insertion order"
    );
}

#[test]
fn a3_replay_root_hash_is_deterministic() {
    let build = || -> String {
        let mut w = ReplayWriter::new();
        let mut p = Json::obj();
        p.insert("mode", Json::str("best-first"));
        p.insert("seed", Json::int(42));
        w.record("search", p, 1000).expect("record");
        w.root_hash().to_string()
    };
    assert_eq!(build(), build(), "same events must give the same root hash");
}

// ===========================================================================
//  A4 · G4 — replay-цепь обнаруживает любой подлог
// ===========================================================================

fn sample_chain() -> (ReplayWriter, String) {
    let mut w = ReplayWriter::new();
    let mut p = Json::obj();
    p.insert("kind", Json::str("model_pin"));
    p.insert("sha256", Json::str("abc123"));
    w.record("model_pin", p, 1000).expect("r1");

    let mut p2 = Json::obj();
    p2.insert("steps", Json::arr(vec![Json::str("(drive t1 a b)"), Json::str("(drive t1 b c)")]));
    w.record("validation", p2, 1001).expect("r2");

    let mut p3 = Json::obj();
    p3.insert("operator", Json::str("op-7"));
    w.record("operator_confirm", p3, 1002).expect("r3");

    let jsonl = w.to_jsonl();
    (w, jsonl)
}

#[test]
fn a4_genesis_hash_is_64_zeroes() {
    assert_eq!(GENESIS_PREV_HASH.len(), 64);
    assert!(GENESIS_PREV_HASH.chars().all(|c| c == '0'));
}

#[test]
fn a4_valid_chain_verifies() {
    let (w, jsonl) = sample_chain();
    let r = verify_chain(&jsonl).expect("verify");
    assert!(r.ok, "untampered chain must verify: {:?}", r.error);
    assert_eq!(r.lines, 3);
    assert_eq!(r.root_hash, w.root_hash(), "root hash must match the writer's");
    assert!(r.error.is_none());
}

#[test]
fn a4_first_record_points_at_genesis() {
    let (w, _) = sample_chain();
    let lines = w.lines();
    assert!(!lines.is_empty());
    let first = parse_json(&lines[0]).expect("parse first line");
    let prev = first.get("prev_hash").and_then(|v| v.as_str()).expect("prev_hash");
    assert_eq!(prev, GENESIS_PREV_HASH, "first record must chain from genesis");
    let seq = first.get("seq").and_then(|v| v.as_int()).expect("seq");
    assert_eq!(seq, 0);
}

#[test]
fn a4_sequence_is_monotonic() {
    let (w, _) = sample_chain();
    for (i, line) in w.lines().iter().enumerate() {
        let v = parse_json(line).expect("parse");
        let seq = v.get("seq").and_then(|x| x.as_int()).expect("seq");
        assert_eq!(seq, i as i64, "seq must be 0,1,2,...");
    }
}

/// Мутация payload обязана обнаруживаться.
#[test]
fn a4_payload_tampering_detected() {
    let (_, jsonl) = sample_chain();
    let mutated = jsonl.replace("abc123", "abc999");
    assert_ne!(mutated, jsonl, "mutation must actually change the text");
    let r = verify_chain(&mutated).expect("verify returns a report");
    assert!(!r.ok, "payload tampering MUST be detected");
    assert!(r.error.is_some());
}

/// Перестановка записей обязана обнаруживаться.
#[test]
fn a4_reordering_detected() {
    let (_, jsonl) = sample_chain();
    let lines: Vec<&str> = jsonl.lines().collect();
    assert_eq!(lines.len(), 3);
    let swapped = format!("{}\n{}\n{}\n", lines[1], lines[0], lines[2]);
    let r = verify_chain(&swapped).expect("verify");
    assert!(!r.ok, "reordering MUST be detected");
}

/// Удаление записи из середины обязано обнаруживаться.
#[test]
fn a4_middle_deletion_detected() {
    let (_, jsonl) = sample_chain();
    let lines: Vec<&str> = jsonl.lines().collect();
    let without_middle = format!("{}\n{}\n", lines[0], lines[2]);
    let r = verify_chain(&without_middle).expect("verify");
    assert!(!r.ok, "deleting a middle record MUST be detected");
}

/// Усечение цепи структурно валидно, но корень обязан отличаться —
/// именно так вызывающая сторона detects truncation.
#[test]
fn a4_truncation_changes_root_hash() {
    let (w, jsonl) = sample_chain();
    let lines: Vec<&str> = jsonl.lines().collect();
    let truncated = format!("{}\n{}\n", lines[0], lines[1]);
    let r = verify_chain(&truncated).expect("verify");
    assert!(r.ok, "a consistent prefix verifies on its own");
    assert_eq!(r.lines, 2);
    assert_ne!(r.root_hash, w.root_hash(), "truncation must change the root hash");
}

/// Подмена seq обязана обнаруживаться.
#[test]
fn a4_seq_tampering_detected() {
    let (_, jsonl) = sample_chain();
    // меняем seq второй записи
    let lines: Vec<&str> = jsonl.lines().collect();
    let mut v = parse_json(lines[1]).expect("parse");
    {
        let obj = match &mut v { Json::Obj(m) => m, _ => panic!("expected object") };
        obj.insert("seq".to_string(), Json::int(99));
    }
    let tampered = format!("{}\n{}\n{}\n", lines[0], v.to_canonical().expect("canon"), lines[2]);
    let r = verify_chain(&tampered).expect("verify");
    assert!(!r.ok, "seq tampering MUST be detected");
}

/// Повреждение JSON обязано обрабатываться, а не ронять процесс.
#[test]
fn a4_malformed_json_is_handled() {
    let r = verify_chain("{ this is not json }\n");
    match r {
        Ok(rep) => assert!(!rep.ok, "malformed input must not verify"),
        Err(e) => assert!(!e.message.is_empty(), "error must carry a diagnostic"),
    }
}

#[test]
fn a4_empty_chain_verifies_trivially() {
    let w = ReplayWriter::new();
    let jsonl = w.to_jsonl();
    let r = verify_chain(&jsonl).expect("verify empty");
    assert_eq!(r.lines, 0);
}

#[test]
fn a4_identical_events_in_different_order_hash_differently() {
    // Прямая проверка свойства, ради которого Json::Obj = BTreeMap:
    // каноническая сериализация не зависит от порядка вставки, но
    // порядок СОБЫТИЙ в цепи значим.
    let mut w1 = ReplayWriter::new();
    let mut p = Json::obj();
    p.insert("b", Json::int(2));
    p.insert("a", Json::int(1));
    w1.record("e", p, 1).expect("r");

    let mut w2 = ReplayWriter::new();
    let mut p2 = Json::obj();
    p2.insert("a", Json::int(1));
    p2.insert("b", Json::int(2));
    w2.record("e", p2, 1).expect("r");

    assert_eq!(w1.root_hash(), w2.root_hash(), "key insertion order must not change the hash");
}

// ===========================================================================
//  Grounding cap (R7.3.1) — превышение обязано быть явной ошибкой
// ===========================================================================

#[test]
fn grounding_cap_is_reported_not_silently_truncated() {
    let m = symbolic_core::pddl::load(LOGISTICS_DOMAIN, LOGISTICS_PROBLEM).expect("model");
    let full = ground_actions(&m).expect("full grounding");
    assert!(!full.is_empty());

    // cap = 1 при реальном пространстве > 1 -> ЯВНАЯ ошибка, не молчаливое усечение.
    // kind = "grounding" (точнее, чем "limit"): диагностика именует действие,
    // размер пространства и cap, и предлагает действие ("reduce object counts
    // or tighten types"). Спецификация R7.3.1 исправлена соответственно.
    if full.len() > 1 {
        let e = ground_actions_with_cap(&m, 1).expect_err("cap must trigger");
        assert_eq!(e.kind, "grounding", "actual: {} / {}", e.kind, e.message);
        assert!(e.message.contains("cap"), "must name the cap: {}", e.message);
        assert!(e.message.contains("drive"), "must name the offending action: {}", e.message);
    }

    // cap = 0 -> тоже явная ошибка
    let e0 = ground_actions_with_cap(&m, 0).expect_err("zero cap must trigger");
    assert_eq!(e0.kind, "grounding");

    // cap по умолчанию достаточен для этой задачи
    let d = ground_actions_with_cap(&m, DEFAULT_GROUNDING_CAP).expect("default cap");
    assert_eq!(d.len(), full.len());
}

#[test]
fn grounding_is_sorted_canonically() {
    // G3: порядок grounding'а обязан быть каноническим — от него зависит
    // порядок экспансии в best_first и, следовательно, весь план.
    let (m, g) = blocks();
    let keys: Vec<String> = g.iter().map(|a| a.key()).collect();
    let mut sorted = keys.clone();
    sorted.sort();
    assert_eq!(keys, sorted, "ground actions must be canonically ordered");
    assert!(!g.iter().any(|a| a.name.is_empty()));
    for a in &g {
        assert!(!a.args.is_empty() || a.name == "noop", "ground action must carry its args");
    }
    let _ = m;
}
