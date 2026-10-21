//! Grounding: action schemas × typed objects → ground actions.
//!
//! Deterministic ordering: ground actions are sorted by (name, args).
//! A hard cap prevents combinatorial explosions from being silently
//! absorbed (machine-readable `grounding` error instead).

use std::collections::BTreeMap;

use crate::error::{FlickerError, FlickerResult};
use crate::pddl::{Effect, Formula, Model, Term};

pub const DEFAULT_GROUNDING_CAP: usize = 1_000_000;

#[derive(Debug, Clone)]
pub struct GroundAction {
    pub name: String,
    pub args: Vec<String>,
    pub precond: Formula,
    pub effect: Effect,
    pub opponent: bool,
}

impl GroundAction {
    /// Canonical key: "(name arg1 arg2)" — same convention as atoms.
    pub fn key(&self) -> String {
        crate::pddl::canon_atom(&self.name, &self.args)
    }
}

pub fn ground_actions(model: &Model) -> FlickerResult<Vec<GroundAction>> {
    ground_actions_with_cap(model, DEFAULT_GROUNDING_CAP)
}

pub fn ground_actions_with_cap(model: &Model, cap: usize) -> FlickerResult<Vec<GroundAction>> {
    let mut out: Vec<GroundAction> = Vec::new();
    for act in &model.domain.actions {
        let domains: Vec<Vec<String>> = act
            .params
            .iter()
            .map(|(_, ty)| model.objects_of_type(ty).to_vec())
            .collect();
        let combos = count_combinations(&domains);
        if combos > cap {
            return Err(FlickerError::grounding(format!(
                "action '{}' would ground into {} instantiations (cap {}): reduce object counts or tighten types",
                act.name, combos, cap
            )));
        }
        for combo in enumerate_combinations(&domains) {
            let mut mapping: BTreeMap<String, String> = BTreeMap::new();
            for ((v, _), o) in act.params.iter().zip(combo.iter()) {
                mapping.insert(v.clone(), o.clone());
            }
            out.push(GroundAction {
                name: act.name.clone(),
                args: combo,
                precond: subst_formula(&act.precond, &mapping),
                effect: subst_effect(&act.effect, &mapping),
                opponent: act.opponent,
            });
        }
    }
    // Канонический порядок grounding'а — инвариант G3: от него зависит порядок
    // экспансии в best_first и, следовательно, весь план. `sort_by_key` даёт
    // тот же результат, что и `sort_by(..cmp)`, и не требует ручного компаратора.
    out.sort_by_key(|g| g.key());
    Ok(out)
}

fn count_combinations(domains: &[Vec<String>]) -> usize {
    domains.iter().fold(1usize, |acc, d| acc.saturating_mul(d.len().max(1)))
}

fn enumerate_combinations(domains: &[Vec<String>]) -> Vec<Vec<String>> {
    let mut out: Vec<Vec<String>> = vec![Vec::new()];
    for d in domains {
        if d.is_empty() {
            return Vec::new(); // no instantiation possible
        }
        let mut next = Vec::with_capacity(out.len() * d.len());
        for partial in &out {
            for o in d {
                let mut combo = partial.clone();
                combo.push(o.clone());
                next.push(combo);
            }
        }
        out = next;
    }
    if domains.is_empty() {
        // Zero-arity action: single parameterless instantiation.
        return vec![Vec::new()];
    }
    out
}

pub fn subst_formula(f: &Formula, m: &BTreeMap<String, String>) -> Formula {
    match f {
        Formula::True => Formula::True,
        Formula::Atom(p, args) => Formula::Atom(p.clone(), subst_terms(args, m)),
        Formula::Not(x) => Formula::Not(Box::new(subst_formula(x, m))),
        Formula::And(v) => Formula::And(v.iter().map(|x| subst_formula(x, m)).collect()),
        Formula::Or(v) => Formula::Or(v.iter().map(|x| subst_formula(x, m)).collect()),
        Formula::Forall(vars, body) => {
            // Bound variables shadow the mapping.
            let mut m2 = m.clone();
            for (v, _) in vars {
                m2.remove(v);
            }
            Formula::Forall(vars.clone(), Box::new(subst_formula(body, &m2)))
        }
        Formula::Exists(vars, body) => {
            let mut m2 = m.clone();
            for (v, _) in vars {
                m2.remove(v);
            }
            Formula::Exists(vars.clone(), Box::new(subst_formula(body, &m2)))
        }
    }
}

pub fn subst_effect(e: &Effect, m: &BTreeMap<String, String>) -> Effect {
    match e {
        Effect::Nil => Effect::Nil,
        Effect::Add(p, args) => Effect::Add(p.clone(), subst_terms(args, m)),
        Effect::Del(p, args) => Effect::Del(p.clone(), subst_terms(args, m)),
        Effect::And(v) => Effect::And(v.iter().map(|x| subst_effect(x, m)).collect()),
        Effect::Forall(vars, body) => {
            let mut m2 = m.clone();
            for (v, _) in vars {
                m2.remove(v);
            }
            Effect::Forall(vars.clone(), Box::new(subst_effect(body, &m2)))
        }
        Effect::When(c, body) => {
            Effect::When(Box::new(subst_formula(c, m)), Box::new(subst_effect(body, m)))
        }
    }
}

fn subst_terms(args: &[Term], m: &BTreeMap<String, String>) -> Vec<Term> {
    args.iter()
        .map(|t| match t {
            Term::Var(v) => match m.get(v) {
                Some(o) => Term::Const(o.clone()),
                None => Term::Var(v.clone()), // quantifier-bound variable
            },
            Term::Const(c) => Term::Const(c.clone()),
        })
        .collect()
}

/// Human/LLM-readable rendering of a formula (for validator diagnostics
/// and repair-loop feedback).
pub fn render_formula(f: &Formula) -> String {
    match f {
        Formula::True => "(true)".to_string(),
        Formula::Atom(p, args) => {
            let args: Vec<String> = args
                .iter()
                .map(|t| match t {
                    Term::Var(v) => format!("?{}", v),
                    Term::Const(c) => c.clone(),
                })
                .collect();
            format!("({} {})", p, args.join(" "))
        }
        Formula::Not(x) => format!("(not {})", render_formula(x)),
        Formula::And(v) => format!("(and {})", v.iter().map(render_formula).collect::<Vec<_>>().join(" ")),
        Formula::Or(v) => format!("(or {})", v.iter().map(render_formula).collect::<Vec<_>>().join(" ")),
        Formula::Forall(vars, body) => format!("(forall {} {})", render_vars(vars), render_formula(body)),
        Formula::Exists(vars, body) => format!("(exists {} {})", render_vars(vars), render_formula(body)),
    }
}

fn render_vars(vars: &[(String, String)]) -> String {
    let v: Vec<String> = vars.iter().map(|(n, t)| format!("(?{} - {})", n, t)).collect();
    format!("({})", v.join(" "))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
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

    #[test]
    fn grounding_counts_and_order() {
        let m = load(DOMAIN, PROBLEM).expect("model");
        let g = ground_actions(&m).expect("ground");
        // drive: 1 truck x 3 x 3 places = 9
        assert_eq!(g.len(), 9);
        assert_eq!(g[0].key(), "(drive t1 a a)");
        let keys: Vec<String> = g.iter().map(|a| a.key()).collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted);
    }

    #[test]
    fn substitution_resolves_params() {
        let m = load(DOMAIN, PROBLEM).expect("model");
        let g = ground_actions(&m).expect("ground");
        let a = g.iter().find(|x| x.key() == "(drive t1 a b)").expect("found");
        let s = render_formula(&a.precond);
        assert!(s.contains("(at t1 a)"));
        assert!(s.contains("(road a b)"));
        assert!(!s.contains('?'));
    }

    #[test]
    fn cap_is_enforced() {
        let m = load(DOMAIN, PROBLEM).expect("model");
        let e = ground_actions_with_cap(&m, 4).unwrap_err();
        assert_eq!(e.kind, "grounding");
    }
}
