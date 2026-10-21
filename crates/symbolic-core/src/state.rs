//! World state: a set of canonical ground atoms, plus evaluation and
//! effect application for FPS-1 formulas.
//!
//! Atom canonical form: "(pred arg1 arg2)" (lowercase). The state hash is
//! SHA-256 over the sorted atoms joined by '\n' — identical in Rust and
//! in the Python reference worker (cross-language conformance).

use std::collections::{BTreeMap, BTreeSet};

use crate::error::{FlickerError, FlickerResult};
use crate::pddl::{canon_atom, split_atom, Formula, Model, Term};
use crate::sha2::sha256_hex;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct State {
    pub atoms: BTreeSet<String>,
}

pub type Env = BTreeMap<String, String>;

impl State {
    pub fn new(atoms: BTreeSet<String>) -> Self {
        Self { atoms }
    }

    pub fn has(&self, atom: &str) -> bool {
        self.atoms.contains(atom)
    }

    pub fn hash(&self) -> String {
        let joined: Vec<&str> = self.atoms.iter().map(|s| s.as_str()).collect();
        sha256_hex(joined.join("\n").as_bytes())
    }

    /// Apply precomputed add/del sets. Conflict rule (normative):
    /// if an atom is both added and deleted by one action, the DELETE wins.
    pub fn apply_delta(&self, adds: &BTreeSet<String>, dels: &BTreeSet<String>) -> State {
        let mut atoms = self.atoms.clone();
        for a in adds {
            if !dels.contains(a) {
                atoms.insert(a.clone());
            }
        }
        for d in dels {
            atoms.remove(d);
        }
        State { atoms }
    }
}

fn resolve(term: &Term, env: &Env) -> FlickerResult<String> {
    match term {
        Term::Const(c) => Ok(c.clone()),
        Term::Var(v) => env.get(v).cloned().ok_or_else(|| {
            FlickerError::semantic(format!("unbound variable '?{}' during evaluation", v))
        }),
    }
}

/// Evaluate a (quantified) formula against a state.
pub fn eval(f: &Formula, st: &State, model: &Model, env: &Env) -> FlickerResult<bool> {
    match f {
        Formula::True => Ok(true),
        Formula::Atom(pred, args) => {
            let mut names = Vec::with_capacity(args.len());
            for a in args {
                names.push(resolve(a, env)?);
            }
            Ok(st.has(&canon_atom(pred, &names)))
        }
        Formula::Not(inner) => Ok(!eval(inner, st, model, env)?),
        Formula::And(v) => {
            for x in v {
                if !eval(x, st, model, env)? {
                    return Ok(false);
                }
            }
            Ok(true)
        }
        Formula::Or(v) => {
            for x in v {
                if eval(x, st, model, env)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        Formula::Forall(vars, body) => {
            for combo in enumerate(vars, model)? {
                let mut env2 = env.clone();
                for (v, o) in combo {
                    env2.insert(v, o);
                }
                if !eval(body, st, model, &env2)? {
                    return Ok(false);
                }
            }
            Ok(true)
        }
        Formula::Exists(vars, body) => {
            for combo in enumerate(vars, model)? {
                let mut env2 = env.clone();
                for (v, o) in combo {
                    env2.insert(v, o);
                }
                if eval(body, st, model, &env2)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
    }
}

/// All assignments of quantifier variables over typed object domains,
/// in canonical (sorted) order — determinism requirement.
fn enumerate(vars: &[(String, String)], model: &Model) -> FlickerResult<Vec<Vec<(String, String)>>> {
    let mut out: Vec<Vec<(String, String)>> = vec![Vec::new()];
    for (v, ty) in vars {
        let objs = model.objects_of_type(ty);
        let mut next = Vec::with_capacity(out.len() * objs.len().max(1));
        for partial in &out {
            for o in objs {
                let mut combo = partial.clone();
                combo.push((v.clone(), o.clone()));
                next.push(combo);
            }
        }
        out = next;
        if out.is_empty() {
            // No objects of this type: universal quantification is vacuously
            // true and existential false; represent as a single empty run for
            // forall and zero runs for exists at the caller level. Callers
            // handle empty iteration naturally (forall -> true, exists -> false).
            return Ok(out);
        }
    }
    Ok(out)
}

/// Collect add/del sets of an effect under an environment.
pub fn collect_effect(
    e: &crate::pddl::Effect,
    st: &State,
    model: &Model,
    env: &Env,
    adds: &mut BTreeSet<String>,
    dels: &mut BTreeSet<String>,
) -> FlickerResult<()> {
    use crate::pddl::Effect;
    match e {
        Effect::Nil => Ok(()),
        Effect::Add(pred, args) => {
            let mut names = Vec::with_capacity(args.len());
            for a in args {
                names.push(resolve(a, env)?);
            }
            adds.insert(canon_atom(pred, &names));
            Ok(())
        }
        Effect::Del(pred, args) => {
            let mut names = Vec::with_capacity(args.len());
            for a in args {
                names.push(resolve(a, env)?);
            }
            dels.insert(canon_atom(pred, &names));
            Ok(())
        }
        Effect::And(v) => {
            for x in v {
                collect_effect(x, st, model, env, adds, dels)?;
            }
            Ok(())
        }
        Effect::Forall(vars, body) => {
            for combo in enumerate(vars, model)? {
                let mut env2 = env.clone();
                for (v, o) in combo {
                    env2.insert(v, o);
                }
                collect_effect(body, st, model, &env2, adds, dels)?;
            }
            Ok(())
        }
        Effect::When(cond, body) => {
            if eval(cond, st, model, env)? {
                collect_effect(body, st, model, env, adds, dels)?;
            }
            Ok(())
        }
    }
}

/// Positive atoms of a goal formula, fully grounded over the model.
/// Used for the relaxed goal-count heuristic (h = number of goal atoms
/// not present in the state). Deterministic: sorted set.
pub fn goal_atoms(goal: &Formula, model: &Model) -> FlickerResult<BTreeSet<String>> {
    let mut out = BTreeSet::new();
    collect_positive(goal, model, &Env::new(), &mut out)?;
    Ok(out)
}

fn collect_positive(
    f: &Formula,
    model: &Model,
    env: &Env,
    out: &mut BTreeSet<String>,
) -> FlickerResult<()> {
    match f {
        Formula::True => Ok(()),
        Formula::Atom(pred, args) => {
            let mut names = Vec::with_capacity(args.len());
            for a in args {
                match a {
                    Term::Const(c) => names.push(c.clone()),
                    Term::Var(v) => match env.get(v) {
                        Some(o) => names.push(o.clone()),
                        None => {
                            // Unbound variable: cannot ground; skip (heuristic only).
                            return Ok(());
                        }
                    },
                }
            }
            out.insert(canon_atom(pred, &names));
            Ok(())
        }
        Formula::Not(_) => Ok(()), // relaxed: ignore negated parts
        Formula::And(v) | Formula::Or(v) => {
            for x in v {
                collect_positive(x, model, env, out)?;
            }
            Ok(())
        }
        Formula::Forall(vars, body) | Formula::Exists(vars, body) => {
            for combo in enumerate(vars, model)? {
                let mut env2 = env.clone();
                for (v, o) in combo {
                    env2.insert(v, o);
                }
                collect_positive(body, model, &env2, out)?;
            }
            Ok(())
        }
    }
}

/// Goal satisfaction fraction in [0,1] over relaxed goal atoms.
/// Returns 1.0 when the exact goal formula is satisfied.
pub fn goal_progress(goal: &Formula, st: &State, model: &Model) -> FlickerResult<f64> {
    if eval(goal, st, model, &Env::new())? {
        return Ok(1.0);
    }
    let atoms = goal_atoms(goal, model)?;
    if atoms.is_empty() {
        return Ok(1.0);
    }
    let sat = atoms.iter().filter(|a| st.has(a)).count();
    Ok(sat as f64 / atoms.len() as f64)
}

/// Validate that every atom string is canonical (used at model load edges).
pub fn assert_canonical(atom: &str) -> FlickerResult<()> {
    let (pred, args) = split_atom(atom)?;
    let rebuilt = canon_atom(&pred, &args);
    if rebuilt != atom {
        return Err(FlickerError::semantic(format!(
            "atom '{}' is not canonical (expected '{}')",
            atom, rebuilt
        )));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::pddl::load;

    const DOMAIN: &str = r#"
(define (domain blocks)
  (:requirements :strips :typing :negative-preconditions)
  (:types block)
  (:predicates (on ?x - block ?y - block) (clear ?x - block))
  (:action stack
    :parameters (?a - block ?b - block)
    :precondition (and (clear ?b) (on ?a ?b))
    :effect (and (not (on ?a ?b)) (clear ?a)))
)"#;

    const PROBLEM: &str = r#"
(define (problem p1)
  (:domain blocks)
  (:objects a b - block)
  (:init (on a b) (clear a))
  (:goal (and (clear a) (clear b))))
"#;

    #[test]
    fn eval_atoms_and_negation() {
        let m = load(DOMAIN, PROBLEM).expect("model");
        let st = State::new(m.problem.init.clone());
        let env = Env::new();
        let f = crate::pddl::parse_formula(
            &crate::sexpr::parse_sexps("(and (on a b) (not (clear b)))").expect("s")[0],
        )
        .expect("f");
        assert!(eval(&f, &st, &m, &env).expect("eval"));
    }

    #[test]
    fn forall_semantics() {
        let m = load(DOMAIN, PROBLEM).expect("model");
        let st = State::new(m.problem.init.clone());
        let f = crate::pddl::parse_formula(
            &crate::sexpr::parse_sexps("(forall (?x - block) (or (clear ?x) (on ?x b)))")
                .expect("s")[0],
        )
        .expect("f");
        // a: clear ✓ ; b: (on a b) does not match (on ?x b) with x=b... (on b b) false; clear b false
        assert!(!eval(&f, &st, &m, &Env::new()).expect("eval"));
    }

    #[test]
    fn effect_application_delete_wins() {
        let st = State::new(BTreeSet::from(["(p a)".to_string()]));
        let adds = BTreeSet::from(["(p a)".to_string(), "(q b)".to_string()]);
        let dels = BTreeSet::from(["(p a)".to_string()]);
        let st2 = st.apply_delta(&adds, &dels);
        assert!(!st2.has("(p a)"));
        assert!(st2.has("(q b)"));
    }

    #[test]
    fn state_hash_is_sorted_join_sha256() {
        let st = State::new(BTreeSet::from(["(b x)".to_string(), "(a y)".to_string()]));
        let expect = sha256_hex("(a y)\n(b x)".as_bytes());
        assert_eq!(st.hash(), expect);
    }

    #[test]
    fn goal_progress_partial() {
        let m = load(DOMAIN, PROBLEM).expect("model");
        let st = State::new(m.problem.init.clone());
        let p = goal_progress(&m.problem.goal, &st, &m).expect("progress");
        // goal atoms: clear a ✓, clear b ✗ → 0.5
        assert!((p - 0.5).abs() < 1e-9);
    }
}
