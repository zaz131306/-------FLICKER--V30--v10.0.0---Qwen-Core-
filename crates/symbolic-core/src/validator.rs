//! Deterministic plan validator (containment level L3).
//!
//! Re-executes a plan step by step from the problem's :init state:
//! * every step must exist in the grounding (exact action+args);
//! * preconditions are evaluated in the current state — failure pinpoints
//!   the step index and the failing precondition (machine-readable);
//! * after the last step the goal must hold.
//!
//! This is the hard gate behind the "no invalid plan ever leaves the
//! system" guarantee: neither the planner nor an LLM-proposed plan is
//! trusted until this function returns valid = true.

use std::collections::BTreeMap;

use crate::error::{FlickerError, FlickerResult};
use crate::ground::{render_formula, GroundAction};
use crate::pddl::Model;
use crate::state::{eval, collect_effect, Env, State};

#[derive(Debug, Clone, PartialEq)]
pub struct PlanStep {
    pub action: String,
    pub args: Vec<String>,
}

impl PlanStep {
    pub fn key(&self) -> String {
        crate::pddl::canon_atom(&self.action, &self.args)
    }
}

/// Result of `validate_plan`.
///
/// ## Field semantics — read before consuming
///
/// * `valid` means **"the plan is a complete solution"**: every step executed
///   against the simulated state AND the goal holds in the final state.
///   It does **not** mean merely "all steps are executable".
/// * Consequently `valid` and `goal_satisfied` are **always equal** in the
///   current implementation. Spec R7.4.1 gates on `valid && goal_satisfied`;
///   that conjunction is belt-and-braces, not two independent conditions.
///   Do not infer step-level executability from `valid` alone.
/// * `failed_step` is `Some(i)` **only** when step `i` violated its
///   precondition. When all steps execute but the goal is unmet,
///   `failed_step` is `None` and `reason` describes the goal shortfall.
///   (An earlier revision returned `Some(steps.len())` there — an
///   out-of-range index that panics any consumer doing `steps[failed_step]`.)
/// * `steps_checked` counts steps actually simulated. On a precondition
///   failure at step `i` it equals `i` (the failing step is not counted as
///   checked); on a clean run it equals `steps.len()`.
/// * `init_state_hash` / `final_state_hash` are SHA-256 hex over the canonical
///   state serialization and feed the replay chain (spec §8.2).
#[derive(Debug, Clone, PartialEq)]
pub struct ValidationReport {
    pub valid: bool,
    pub steps_checked: usize,
    pub failed_step: Option<usize>,
    pub reason: Option<String>,
    pub goal_satisfied: bool,
    pub init_state_hash: String,
    pub final_state_hash: String,
}

pub fn validate_plan(
    model: &Model,
    ground: &[GroundAction],
    steps: &[PlanStep],
) -> FlickerResult<ValidationReport> {
    let index: BTreeMap<String, &GroundAction> =
        ground.iter().map(|g| (g.key(), g)).collect();

    let mut st = State::new(model.problem.init.clone());
    let init_hash = st.hash();

    for (i, step) in steps.iter().enumerate() {
        let key = step.key();
        let ga = match index.get(&key) {
            Some(g) => *g,
            None => {
                return Err(FlickerError::validation(format!(
                    "step {}: '{}' is not a valid grounding of any action (check action name and argument types/order)",
                    i, key
                )));
            }
        };
        if !eval(&ga.precond, &st, model, &Env::new())? {
            return Ok(ValidationReport {
                valid: false,
                steps_checked: i,
                failed_step: Some(i),
                reason: Some(format!(
                    "precondition not satisfied in the current state: {}",
                    render_formula(&ga.precond)
                )),
                goal_satisfied: false,
                init_state_hash: init_hash,
                final_state_hash: st.hash(),
            });
        }
        let mut adds = std::collections::BTreeSet::new();
        let mut dels = std::collections::BTreeSet::new();
        collect_effect(&ga.effect, &st, model, &Env::new(), &mut adds, &mut dels)?;
        st = st.apply_delta(&adds, &dels);
    }

    let goal_ok = eval(&model.problem.goal, &st, model, &Env::new())?;
    Ok(ValidationReport {
        valid: goal_ok,
        steps_checked: steps.len(),
        // No individual step failed here — every step executed cleanly and the
        // shortfall is at the GOAL level. Returning `Some(steps.len())` (as an
        // earlier revision did) yields an out-of-range index: a consumer doing
        // `steps[failed_step]` would panic. `None` is the correct encoding of
        // "no step is at fault"; `reason` explains the goal shortfall.
        failed_step: None,
        reason: if goal_ok {
            None
        } else {
            Some(format!(
                "plan executes cleanly but the goal is not satisfied: {}",
                render_formula(&model.problem.goal)
            ))
        },
        goal_satisfied: goal_ok,
        init_state_hash: init_hash,
        final_state_hash: st.hash(),
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::ground::ground_actions;
    use crate::pddl::load;

    const DOMAIN: &str = r#"
(define (domain logistics)
  (:requirements :strips :typing)
  (:types truck place)
  (:predicates (at ?t - truck ?p - place) (road ?a - place ?b - place))
  (:action drive
    :parameters (?t - truck ?a - place ?b - place)
    :precondition (and (at ?t ?a) (road ?a ?b))
    :effect (and (not (at ?t ?a)) (at ?t ?b))))
"#;
    const PROBLEM: &str = r#"
(define (problem lp1)
  (:domain logistics)
  (:objects t1 - truck a b c - place)
  (:init (at t1 a) (road a b) (road b c))
  (:goal (at t1 c)))
"#;

    fn setup() -> (Model, Vec<GroundAction>) {
        let m = load(DOMAIN, PROBLEM).expect("model");
        let g = ground_actions(&m).expect("ground");
        (m, g)
    }

    #[test]
    fn valid_plan_passes() {
        let (m, g) = setup();
        let steps = vec![
            PlanStep { action: "drive".into(), args: vec!["t1".into(), "a".into(), "b".into()] },
            PlanStep { action: "drive".into(), args: vec!["t1".into(), "b".into(), "c".into()] },
        ];
        let r = validate_plan(&m, &g, &steps).expect("report");
        assert!(r.valid);
        assert_eq!(r.steps_checked, 2);
        assert!(r.failed_step.is_none());
    }

    #[test]
    fn precondition_violation_is_pinned() {
        let (m, g) = setup();
        let steps = vec![
            // driving from b before reaching b — precondition fails at step 0
            PlanStep { action: "drive".into(), args: vec!["t1".into(), "b".into(), "c".into()] },
        ];
        let r = validate_plan(&m, &g, &steps).expect("report");
        assert!(!r.valid);
        assert_eq!(r.failed_step, Some(0));
        assert!(r.reason.expect("reason").contains("precondition"));
    }

    #[test]
    fn unknown_grounding_is_error() {
        let (m, g) = setup();
        let steps = vec![PlanStep { action: "drive".into(), args: vec!["t1".into(), "a".into(), "zzz".into()] }];
        let e = validate_plan(&m, &g, &steps).unwrap_err();
        assert_eq!(e.kind, "validation");
    }

    #[test]
    fn goal_not_satisfied_reported() {
        let (m, g) = setup();
        let steps = vec![
            PlanStep { action: "drive".into(), args: vec!["t1".into(), "a".into(), "b".into()] },
        ];
        let r = validate_plan(&m, &g, &steps).expect("report");
        assert!(!r.valid);
        assert!(!r.goal_satisfied);
        // BUGFIX: this used to assert `Some(1)` — an index OUT OF RANGE for a
        // one-step plan (valid indices: 0). Any consumer doing
        // `steps[failed_step]` would panic. No individual step is at fault when
        // every step executed cleanly and only the goal fell short, so the
        // correct encoding is `None` with an explanatory `reason`.
        assert_eq!(r.failed_step, None, "no step is at fault for a goal-level shortfall");
        assert_eq!(r.steps_checked, 1, "the single step did execute");
        let reason = r.reason.expect("reason must explain the shortfall");
        assert!(reason.contains("goal is not satisfied"), "reason: {}", reason);
    }

    #[test]
    fn empty_plan_checked_against_goal() {
        let (m, g) = setup();
        let r = validate_plan(&m, &g, &[]).expect("report");
        assert!(!r.valid); // goal (at t1 c) false in init
    }
}
