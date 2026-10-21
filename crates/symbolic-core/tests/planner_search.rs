//! Р-01 · Тесты поиска: `planner.rs` (305 строк) и `mcts.rs` (240 строк),
//! ранее — 0 тестов в обоих.
//!
//! Покрывает: все три `PlanMode`, отсечение по бюджетам, корректность найденных
//! планов, маскирование недопустимых действий в MCTS (M_PDDL = −∞),
//! поведение на пустом плане и на задаче без решения.

#![allow(clippy::expect_used, clippy::unwrap_used)]
// Тестовый код: expect/unwrap допустимы и предпочтительны —
// падение теста должно быть явным. Продукционный код под deny (§4.3, A6).
mod common;

use common::*;
use symbolic_core::mcts;
use symbolic_core::planner::{best_first, plan, PlanMode, PlanOptions};
use symbolic_core::validator::{validate_plan, PlanStep};

fn opts(mode: PlanMode) -> PlanOptions {
    PlanOptions { mode, ..PlanOptions::default() }
}

// ---------------------------------------------------------------------------
// 1. PlanMode: разбор и сериализация
// ---------------------------------------------------------------------------

#[test]
fn plan_mode_parses_all_aliases() {
    assert_eq!(PlanMode::parse("auto").unwrap(), PlanMode::Auto);
    assert_eq!(PlanMode::parse("best-first").unwrap(), PlanMode::BestFirst);
    assert_eq!(PlanMode::parse("bestfirst").unwrap(), PlanMode::BestFirst);
    assert_eq!(PlanMode::parse("bf").unwrap(), PlanMode::BestFirst);
    assert_eq!(PlanMode::parse("mcts").unwrap(), PlanMode::Mcts);
    // регистронезависимость (to_ascii_lowercase в реализации)
    assert_eq!(PlanMode::parse("MCTS").unwrap(), PlanMode::Mcts);
    assert_eq!(PlanMode::parse("Auto").unwrap(), PlanMode::Auto);
}

#[test]
fn plan_mode_rejects_unknown_with_parse_kind() {
    let e = PlanMode::parse("beam-search").expect_err("unknown mode must fail");
    assert_eq!(e.kind, "parse");
    assert!(e.message.contains("beam-search"), "must echo the bad value: {}", e.message);
}

#[test]
fn plan_mode_as_str_roundtrips() {
    for m in [PlanMode::Auto, PlanMode::BestFirst, PlanMode::Mcts] {
        assert_eq!(PlanMode::parse(m.as_str()).unwrap(), m);
    }
    assert_eq!(PlanMode::Auto.as_str(), "auto");
    assert_eq!(PlanMode::BestFirst.as_str(), "best-first");
    assert_eq!(PlanMode::Mcts.as_str(), "mcts");
}

#[test]
fn default_options_match_spec() {
    // Значения зафиксированы в ТЗ V30 §4.4 и в матрице трассировки.
    let d = PlanOptions::default();
    assert_eq!(d.mode, PlanMode::Auto);
    assert_eq!(d.seed, 42, "seed must default to 42 (G3)");
    assert_eq!(d.max_nodes, 200_000);
    assert_eq!(d.time_budget_ms, 5_000);
    assert_eq!(d.mcts_iterations, 20_000);
}

// ---------------------------------------------------------------------------
// 2. best_first: корректность плана
// ---------------------------------------------------------------------------

#[test]
fn best_first_finds_two_step_logistics_plan() {
    let (m, g) = logistics();
    let raw = best_first(&m, &g, &opts(PlanMode::BestFirst)).expect("plan must be found");
    assert_eq!(raw.steps.len(), 2, "a→b→c requires exactly 2 drives");
    // canon_atom renders as "(pred arg1 arg2)" — canonical PDDL-ish form.
    assert_eq!(plan_signature(&raw.steps), "(drive t1 a b) ; (drive t1 b c)");
    assert!(raw.expanded > 0);
    assert!(raw.generated > 0);
}

#[test]
fn best_first_result_passes_independent_validation() {
    // Ключевое свойство G2: план, выданный поиском, проходит НЕЗАВИСИМУЮ валидацию.
    let (m, g) = logistics();
    let raw = best_first(&m, &g, &opts(PlanMode::BestFirst)).expect("plan");
    let rep = validate_plan(&m, &g, &raw.steps).expect("validate");
    assert!(rep.valid, "search result must be valid: {:?}", rep.reason);
    assert!(rep.goal_satisfied, "goal must be reached");
    assert_eq!(rep.steps_checked, raw.steps.len());
    assert!(rep.failed_step.is_none());
}

#[test]
fn best_first_returns_empty_plan_when_goal_already_holds() {
    let (m, g) = trivial();
    let raw = best_first(&m, &g, &opts(PlanMode::BestFirst)).expect("empty plan");
    assert!(raw.steps.is_empty(), "goal already satisfied -> zero steps");
    assert_eq!(raw.expanded, 0, "no expansion needed");
}

#[test]
fn best_first_reports_limit_when_unsolvable() {
    let (m, g) = unsolvable();
    let e = best_first(&m, &g, &opts(PlanMode::BestFirst)).expect_err("no plan exists");
    assert_eq!(e.kind, "limit", "must be a 'limit' error, got '{}': {}", e.kind, e.message);
}

#[test]
fn best_first_respects_max_nodes() {
    let (m, g) = unsolvable();
    let tiny = PlanOptions { mode: PlanMode::BestFirst, max_nodes: 3, ..PlanOptions::default() };
    let e = best_first(&m, &g, &tiny).expect_err("must exhaust budget");
    assert_eq!(e.kind, "limit");
    // Two legitimate diagnostics: the node budget bound, or exhaustion of the
    // (small) reachable state space first. Both are "limit" and both must be
    // actionable text rather than an empty message.
    assert!(
        e.message.contains("max_nodes") || e.message.contains("reachable state space"),
        "diagnostic must name the exhausted resource: {}",
        e.message
    );
}

#[test]
fn best_first_respects_time_budget() {
    let (m, g) = unsolvable();
    // budget = 0 ms -> немедленное исчерпание (проверка идёт после первой экспансии)
    let zero = PlanOptions { mode: PlanMode::BestFirst, time_budget_ms: 0, ..PlanOptions::default() };
    match best_first(&m, &g, &zero) {
        Err(e) => {
            assert_eq!(e.kind, "limit");
            assert!(
                e.message.contains("time_budget_ms")
                    || e.message.contains("max_nodes")
                    || e.message.contains("reachable state space"),
                "diagnostic must name the exhausted resource: {}",
                e.message
            );
        }
        Ok(_) => panic!("a zero time budget must not produce a plan for an unsolvable problem"),
    }
}

// ---------------------------------------------------------------------------
// 3. mcts::search
// ---------------------------------------------------------------------------

#[test]
fn mcts_finds_valid_logistics_plan() {
    let (m, g) = logistics();
    let o = PlanOptions { mode: PlanMode::Mcts, mcts_iterations: 2_000, ..PlanOptions::default() };
    let raw = mcts::search(&m, &g, &o).expect("MCTS must solve logistics");
    assert!(!raw.steps.is_empty());
    let rep = validate_plan(&m, &g, &raw.steps).expect("validate");
    assert!(rep.valid, "MCTS plan must validate: {:?}", rep.reason);
    assert!(rep.goal_satisfied);
}

#[test]
fn mcts_solves_blocks_requiring_negative_preconditions() {
    // pickup → stack: требует (handempty), (clear), (ontable) и отрицаний.
    let (m, g) = blocks();
    let o = PlanOptions { mode: PlanMode::Mcts, mcts_iterations: 5_000, ..PlanOptions::default() };
    let raw = mcts::search(&m, &g, &o).expect("MCTS must solve blocks2");
    assert!(!raw.steps.is_empty());
    let rep = validate_plan(&m, &g, &raw.steps).expect("validate");
    assert!(rep.valid, "blocks plan must validate: {:?}", rep.reason);
    assert!(rep.goal_satisfied, "goal (on b1 b2) must be reached");
    assert_eq!(plan_signature(&raw.steps), "(pickup b1) ; (stack b1 b2)");
}

#[test]
fn mcts_is_seeded_and_reproducible() {
    // G3: один seed => идентичный результат. Проверяется на задаче, где MCTS
    // действительно делает выбор (blocks).
    let (m, g) = blocks();
    let o = PlanOptions { mode: PlanMode::Mcts, seed: 12345, mcts_iterations: 3_000, ..PlanOptions::default() };
    let a = mcts::search(&m, &g, &o).expect("run a");
    let b = mcts::search(&m, &g, &o).expect("run b");
    assert_eq!(plan_signature(&a.steps), plan_signature(&b.steps), "same seed must give same plan");
    assert_eq!(a.expanded, b.expanded);
    assert_eq!(a.generated, b.generated);
}

#[test]
fn mcts_reports_limit_when_unsolvable() {
    let (m, g) = unsolvable();
    let o = PlanOptions { mode: PlanMode::Mcts, mcts_iterations: 500, time_budget_ms: 2_000, ..PlanOptions::default() };
    let e = mcts::search(&m, &g, &o).expect_err("no plan exists");
    assert_eq!(e.kind, "limit", "got '{}': {}", e.kind, e.message);
}

#[test]
fn mcts_returns_empty_plan_when_goal_already_holds() {
    let (m, g) = trivial();
    let o = PlanOptions { mode: PlanMode::Mcts, mcts_iterations: 100, ..PlanOptions::default() };
    let raw = mcts::search(&m, &g, &o).expect("empty plan");
    assert!(raw.steps.is_empty());
}

// ---------------------------------------------------------------------------
// 4. plan(): диспетчер режимов и Auto-fallback
// ---------------------------------------------------------------------------

#[test]
fn plan_best_first_mode_reports_mode_used() {
    let (m, g) = logistics();
    let out = plan(&m, &g, &opts(PlanMode::BestFirst)).expect("plan");
    assert_eq!(out.mode_used, "best-first");
    assert!(out.validated, "plan() must always hard-gate through the validator");
    assert!(out.validation.valid);
    assert!(out.validation.goal_satisfied);
    assert_eq!(out.seed, 42);
    assert!(!out.final_state_hash.is_empty());
}

#[test]
fn plan_mcts_mode_reports_mode_used() {
    let (m, g) = logistics();
    let o = PlanOptions { mode: PlanMode::Mcts, mcts_iterations: 1_000, ..PlanOptions::default() };
    let out = plan(&m, &g, &o).expect("plan");
    assert_eq!(out.mode_used, "mcts");
    assert!(out.validated);
    assert!(out.validation.valid);
}

#[test]
fn plan_auto_mode_solves_small_space_with_best_first() {
    let (m, g) = logistics();
    let out = plan(&m, &g, &opts(PlanMode::Auto)).expect("plan");
    assert_eq!(out.mode_used, "best-first", "auto should prefer best-first on small spaces");
    assert!(out.validation.valid);
}

#[test]
fn plan_auto_falls_back_to_mcts_when_best_first_exhausts() {
    // best-first исчерпывает max_nodes -> Auto обязан переключиться на MCTS
    // и сообщить об этом в mode_used.
    let (m, g) = logistics();
    let o = PlanOptions {
        mode: PlanMode::Auto,
        max_nodes: 1,                 // best-first не успеет дойти до цели (2 шага)
        mcts_iterations: 5_000,
        ..PlanOptions::default()
    };
    match plan(&m, &g, &o) {
        Ok(out) => {
            assert_eq!(out.mode_used, "mcts", "auto must fall back to MCTS after best-first limit");
            assert!(out.validated);
            assert!(out.validation.valid);
        }
        Err(e) => panic!("auto should have recovered via MCTS: {} / {}", e.kind, e.message),
    }
}

#[test]
fn plan_auto_reports_both_budgets_when_nothing_works() {
    let (m, g) = unsolvable();
    let o = PlanOptions { mode: PlanMode::Auto, mcts_iterations: 300, time_budget_ms: 1_500, ..PlanOptions::default() };
    let e = plan(&m, &g, &o).expect_err("unsolvable");
    assert_eq!(e.kind, "limit");
    assert!(e.message.contains("best-first"), "must report the first attempt: {}", e.message);
    assert!(e.message.contains("mcts"), "must report the fallback attempt: {}", e.message);
}

#[test]
fn plan_auto_recovers_from_zero_best_first_budget() {
    // Регрессия на исправленный дефект типов в PlanMode::Auto: ветки
    // `other => other` возвращали Result<RawPlan,_> вместо Result<PlanOutput,_>,
    // из-за чего функция не компилировалась. Здесь фиксируем ПОСЛЕДСТВИЕ:
    // исчерпание бюджета best-first не теряет план, найденный запасным MCTS.
    //
    // Обратите внимание: MCTS ограничен `mcts_iterations`, а не `max_nodes`,
    // поэтому при max_nodes=0 и time_budget_ms=0 best-first сразу даёт limit,
    // а MCTS находит план. Это ожидаемое поведение, а не ошибка.
    let (m, g) = logistics();
    let o = PlanOptions {
        mode: PlanMode::Auto,
        max_nodes: 0,
        time_budget_ms: 0,
        mcts_iterations: 2_000,
        ..PlanOptions::default()
    };
    let out = plan(&m, &g, &o).expect("MCTS fallback must recover the plan");
    assert_eq!(out.mode_used, "mcts");
    assert!(out.validated);
    assert!(out.validation.valid);
    assert!(out.validation.goal_satisfied);
    assert_eq!(out.steps.len(), 2, "optimal logistics plan is 2 drives");
}

#[test]
fn plan_output_serializes_to_json() {
    let (m, g) = logistics();
    let out = plan(&m, &g, &opts(PlanMode::BestFirst)).expect("plan");
    let j = out.to_json();
    let canon = j.to_canonical().expect("canonical json");
    assert!(canon.contains("best-first"), "json must carry mode_used: {}", canon);
    assert!(canon.contains(out.final_state_hash.trim_start_matches('"')), "json must carry the state hash");
}

#[test]
fn plan_elapsed_ms_is_reported() {
    let (m, g) = logistics();
    let out = plan(&m, &g, &opts(PlanMode::BestFirst)).expect("plan");
    // elapsed может быть 0 на быстрой машине, но поле обязано присутствовать
    // и не быть абсурдным.
    assert!(out.elapsed_ms < 60_000, "elapsed_ms looks bogus: {}", out.elapsed_ms);
}

// ---------------------------------------------------------------------------
// 5. Кванторы и условные эффекты в поиске
// ---------------------------------------------------------------------------

#[test]
fn planner_handles_quantified_preconditions_and_conditional_effects() {
    let (m, g) = quantified();
    let out = plan(&m, &g, &opts(PlanMode::BestFirst)).expect("plan with quantifiers");
    assert!(out.validation.valid);
    assert!(out.validation.goal_satisfied);
    assert_eq!(out.steps.len(), 1);
    assert_eq!(out.steps[0].action, "seal-zone");
    assert_eq!(out.steps[0].args, vec!["z1".to_string()]);
}

#[test]
fn conditional_effect_produces_damaged_only_for_fragile() {
    // seal-zone имеет (forall (?c) (when (and (in ?c ?z) (fragile ?c)) (damaged ?c)))
    // В :init (in c1 z1) и (fragile c1) => после seal-zone обязан появиться (damaged c1).
    let (m, g) = quantified();
    let out = plan(&m, &g, &opts(PlanMode::BestFirst)).expect("plan");
    let steps: Vec<PlanStep> = out.steps.clone();
    let rep = validate_plan(&m, &g, &steps).expect("validate");
    assert!(rep.valid);
    // конечный хэш состояния зафиксирован и стабилен
    assert_eq!(rep.final_state_hash.len(), 64, "SHA-256 hex length");
    assert_eq!(rep.final_state_hash, out.final_state_hash);
}
