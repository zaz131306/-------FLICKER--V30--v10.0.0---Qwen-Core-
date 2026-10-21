//! Planner portfolio (deterministic):
//! * `best_first` — greedy best-first search over ground states with the
//!   relaxed goal-count heuristic; canonically ordered, reproducible;
//! * `mcts` — seeded UCT search for large state spaces (see mcts.rs);
//! * `auto` (default) — best-first within node budget, then MCTS fallback.
//!
//! Every produced plan is re-validated by validator::validate_plan before
//! being returned — the planner output carries `validated: true` only if
//! the deterministic re-execution succeeded (containment level L3).

use std::collections::{BinaryHeap, HashMap};
use std::time::Instant;

use crate::error::{FlickerError, FlickerResult};
use crate::ground::GroundAction;
use crate::json::Json;
use crate::mcts;
use crate::pddl::Model;
use crate::state::{collect_effect, eval, goal_atoms, State};
use crate::validator::{self, PlanStep, ValidationReport};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanMode {
    Auto,
    BestFirst,
    Mcts,
}

impl PlanMode {
    pub fn parse(s: &str) -> FlickerResult<Self> {
        match s.to_ascii_lowercase().as_str() {
            "auto" => Ok(PlanMode::Auto),
            "best-first" | "bestfirst" | "bf" => Ok(PlanMode::BestFirst),
            "mcts" => Ok(PlanMode::Mcts),
            other => Err(FlickerError::new("parse", format!("unknown plan mode '{}'", other))),
        }
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            PlanMode::Auto => "auto",
            PlanMode::BestFirst => "best-first",
            PlanMode::Mcts => "mcts",
        }
    }
}

#[derive(Debug, Clone)]
pub struct PlanOptions {
    pub mode: PlanMode,
    pub seed: u64,
    pub max_nodes: usize,
    pub time_budget_ms: u64,
    pub mcts_iterations: u32,
}

impl Default for PlanOptions {
    fn default() -> Self {
        Self {
            mode: PlanMode::Auto,
            seed: 42,
            max_nodes: 200_000,
            time_budget_ms: 5_000,
            mcts_iterations: 20_000,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PlanOutput {
    pub steps: Vec<PlanStep>,
    pub mode_used: String,
    pub expanded: u64,
    pub generated: u64,
    pub elapsed_ms: u64,
    pub seed: u64,
    pub validated: bool,
    pub validation: ValidationReport,
    pub final_state_hash: String,
}

impl PlanOutput {
    pub fn to_json(&self) -> Json {
        let steps = Json::arr(
            self.steps
                .iter()
                .map(|s| {
                    let mut o = Json::obj();
                    o.insert("action", Json::str(s.action.clone()));
                    o.insert("args", Json::arr(s.args.iter().cloned().map(Json::str).collect()));
                    o
                })
                .collect(),
        );
        let mut stats = Json::obj();
        stats.insert("mode_used", Json::str(self.mode_used.clone()));
        stats.insert("expanded", Json::int(self.expanded as i64));
        stats.insert("generated", Json::int(self.generated as i64));
        stats.insert("elapsed_ms", Json::int(self.elapsed_ms as i64));
        stats.insert("seed", Json::int(self.seed as i64));
        let mut v = Json::obj();
        v.insert("valid", Json::Bool(self.validation.valid));
        v.insert("steps_checked", Json::int(self.validation.steps_checked as i64));
        v.insert("goal_satisfied", Json::Bool(self.validation.goal_satisfied));
        v.insert("init_state_hash", Json::str(self.validation.init_state_hash.clone()));
        v.insert("final_state_hash", Json::str(self.validation.final_state_hash.clone()));
        if let Some(fs) = &self.validation.failed_step {
            v.insert("failed_step", Json::int(*fs as i64));
        }
        if let Some(r) = &self.validation.reason {
            v.insert("reason", Json::str(r.clone()));
        }
        let mut out = Json::obj();
        out.insert("format", Json::str("flicker-plan/1"));
        out.insert("steps", steps);
        out.insert("stats", stats);
        out.insert("validation", v);
        out
    }
}

pub fn plan(model: &Model, ground: &[GroundAction], opts: &PlanOptions) -> FlickerResult<PlanOutput> {
    let started = Instant::now();
    match opts.mode {
        PlanMode::BestFirst => finish(model, ground, opts, best_first(model, ground, opts)?, "best-first", started),
        PlanMode::Mcts => finish(model, ground, opts, mcts::search(model, ground, opts)?, "mcts", started),
        PlanMode::Auto => {
            match best_first(model, ground, opts) {
                Ok(found) => finish(model, ground, opts, found, "best-first", started),
                Err(e) if e.kind == "limit" => {
                    // Fall back to seeded MCTS for large spaces.
                    match mcts::search(model, ground, opts) {
                        Ok(found) => finish(model, ground, opts, found, "mcts", started),
                        Err(e2) if e2.kind == "limit" => Err(FlickerError::new(
                            "limit",
                            format!(
                                "no plan found within budgets (best-first: {}; mcts: {}); increase max-nodes/time-budget or simplify the domain",
                                e.message, e2.message
                            ),
                        )),
                        // Non-limit error from MCTS: propagate unchanged.
                        Err(e2) => Err(e2),
                    }
                }
                // Non-limit error from best-first: propagate unchanged.
                Err(e) => Err(e),
            }
        }
    }
}

fn finish(
    model: &Model,
    ground: &[GroundAction],
    opts: &PlanOptions,
    raw: RawPlan,
    mode_used: &str,
    started: Instant,
) -> FlickerResult<PlanOutput> {
    // Hard gate: re-validate whatever the search produced.
    let validation = validator::validate_plan(model, ground, &raw.steps)?;
    if !validation.valid {
        // A search that believes it succeeded but fails validation is an
        // internal defect — surface it loudly instead of returning a plan.
        return Err(FlickerError::validation(format!(
            "internal error: planner produced a plan that failed validation ({:?})",
            validation.reason
        )));
    }
    Ok(PlanOutput {
        final_state_hash: validation.final_state_hash.clone(),
        steps: raw.steps,
        mode_used: mode_used.to_string(),
        expanded: raw.expanded,
        generated: raw.generated,
        elapsed_ms: started.elapsed().as_millis() as u64,
        seed: opts.seed,
        validated: true,
        validation,
    })
}

/// Unvalidated search result. Every consumer MUST pass this through
/// `validator::validate_plan` before use (spec R7.4.1) — `planner::plan`
/// does so via `finish()`.
#[derive(Debug, Clone, PartialEq)]
pub struct RawPlan {
    pub steps: Vec<PlanStep>,
    pub expanded: u64,
    pub generated: u64,
}

// ---------------------------------------------------------------------------
// Greedy best-first search
// ---------------------------------------------------------------------------

#[derive(PartialEq, Eq)]
struct HeapItem {
    h: u32,
    depth: u32,
    seq: u64,
    state_hash: String,
}

impl Ord for HeapItem {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // min-heap on (h, depth, seq)
        other
            .h
            .cmp(&self.h)
            .then(other.depth.cmp(&self.depth))
            .then(other.seq.cmp(&self.seq))
    }
}
impl PartialOrd for HeapItem {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

pub fn best_first(model: &Model, ground: &[GroundAction], opts: &PlanOptions) -> FlickerResult<RawPlan> {
    let started = Instant::now();
    let gatoms = goal_atoms(&model.problem.goal, model)?;
    let init = State::new(model.problem.init.clone());

    let h = |st: &State| -> u32 {
        gatoms.iter().filter(|a| !st.has(a)).count() as u32
    };

    if eval(&model.problem.goal, &init, model, &std::collections::BTreeMap::new())? {
        return Ok(RawPlan { steps: Vec::new(), expanded: 0, generated: 0 });
    }

    let init_hash = init.hash();
    let mut states: HashMap<String, State> = HashMap::new();
    states.insert(init_hash.clone(), init);
    let mut parent: HashMap<String, Option<(String, usize)>> = HashMap::new();
    parent.insert(init_hash.clone(), None);

    let mut open = BinaryHeap::new();
    let mut closed: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut seq: u64 = 0;
    let init_h = h(states.get(&init_hash).ok_or_else(|| {
        FlickerError::semantic("best-first: initial state missing from the state table")
    })?);
    open.push(HeapItem { h: init_h, depth: 0, seq, state_hash: init_hash.clone() });
    let mut expanded: u64 = 0;
    let mut generated: u64 = 0;

    while let Some(item) = open.pop() {
        if closed.contains(&item.state_hash) {
            continue;
        }
        if expanded >= opts.max_nodes as u64 {
            return Err(FlickerError::limit(format!(
                "best-first exhausted max_nodes={} without reaching the goal",
                opts.max_nodes
            )));
        }
        if started.elapsed().as_millis() as u64 > opts.time_budget_ms {
            return Err(FlickerError::limit(format!(
                "best-first exceeded time_budget_ms={} without reaching the goal",
                opts.time_budget_ms
            )));
        }
        closed.insert(item.state_hash.clone());
        expanded += 1;

        let st = states
            .get(&item.state_hash)
            .ok_or_else(|| {
                FlickerError::semantic(format!(
                    "best-first: open-list entry '{}' has no state record",
                    item.state_hash
                ))
            })?
            .clone();
        // Deterministic expansion order: ground actions are pre-sorted.
        for (ai, ga) in ground.iter().enumerate() {
            if !eval(&ga.precond, &st, model, &std::collections::BTreeMap::new())? {
                continue;
            }
            let mut adds = std::collections::BTreeSet::new();
            let mut dels = std::collections::BTreeSet::new();
            collect_effect(&ga.effect, &st, model, &std::collections::BTreeMap::new(), &mut adds, &mut dels)?;
            let next = st.apply_delta(&adds, &dels);
            generated += 1;
            let nhash = next.hash();
            if closed.contains(&nhash) {
                continue;
            }
            if !states.contains_key(&nhash) {
                states.insert(nhash.clone(), next.clone());
                parent.insert(nhash.clone(), Some((item.state_hash.clone(), ai)));
            }
            if eval(&model.problem.goal, &next, model, &std::collections::BTreeMap::new())? {
                // Reconstruct.
                let mut steps_rev: Vec<PlanStep> = Vec::new();
                let mut cur = nhash.clone();
                while let Some(Some((ph, ai2))) = parent.get(&cur).cloned() {
                    let g = &ground[ai2];
                    steps_rev.push(PlanStep { action: g.name.clone(), args: g.args.clone() });
                    cur = ph;
                }
                steps_rev.reverse();
                return Ok(RawPlan { steps: steps_rev, expanded, generated });
            }
            seq += 1;
            let nh = h(&next);
            open.push(HeapItem {
                h: nh,
                depth: item.depth + 1,
                seq,
                state_hash: nhash,
            });
        }
    }

    Err(FlickerError::limit(
        "best-first exhausted the reachable state space without reaching the goal (plan may not exist)",
    ))
}
