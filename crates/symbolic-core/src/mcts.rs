//! Seeded MCTS (UCT) for large state spaces — deterministic given
//! (seed, iterations). Single-threaded by design: parallel MCTS would
//! break bit-reproducibility (docs/adr/0006-deterministic-replay.md).
//!
//! Reward shaping: goal reached → 1.0; otherwise relaxed goal-atom
//! satisfaction fraction × 0.9 (strictly below any goal-reaching rollout).

use std::collections::BTreeSet;
use std::time::Instant;

use crate::error::{FlickerError, FlickerResult};
use crate::ground::GroundAction;
use crate::pddl::Model;
use crate::planner::{PlanOptions, RawPlan};
use crate::prng::Xorshift64Star;
use crate::state::{collect_effect, eval, goal_atoms, State};
use crate::validator::PlanStep;

const ROLLOUT_DEPTH_CAP: u32 = 40;

struct Node {
    state_idx: usize,
    parent: Option<usize>,
    action_idx: Option<usize>,
    visits: u64,
    value_sum: f64,
    children: Vec<usize>,
    untried: Vec<usize>,
    depth: u32,
}

pub fn search(model: &Model, ground: &[GroundAction], opts: &PlanOptions) -> FlickerResult<RawPlan> {
    let started = Instant::now();
    let mut rng = Xorshift64Star::new(opts.seed);
    let gatoms = goal_atoms(&model.problem.goal, model)?;

    let init = State::new(model.problem.init.clone());
    let env0 = std::collections::BTreeMap::new();
    if eval(&model.problem.goal, &init, model, &env0)? {
        return Ok(RawPlan { steps: Vec::new(), expanded: 0, generated: 0 });
    }

    let mut states: Vec<State> = vec![init];
    let mut nodes: Vec<Node> = Vec::new();

    let applicable = |st: &State| -> FlickerResult<Vec<usize>> {
        let env = std::collections::BTreeMap::new();
        let mut out = Vec::new();
        for (i, ga) in ground.iter().enumerate() {
            if eval(&ga.precond, st, model, &env)? {
                out.push(i);
            }
        }
        Ok(out)
    };

    let apply = |st: &State, ai: usize| -> FlickerResult<State> {
        let ga = &ground[ai];
        let env = std::collections::BTreeMap::new();
        let mut adds = BTreeSet::new();
        let mut dels = BTreeSet::new();
        collect_effect(&ga.effect, st, model, &env, &mut adds, &mut dels)?;
        Ok(st.apply_delta(&adds, &dels))
    };

    let reward = |st: &State| -> FlickerResult<f64> {
        let env = std::collections::BTreeMap::new();
        if eval(&model.problem.goal, st, model, &env)? {
            return Ok(1.0);
        }
        if gatoms.is_empty() {
            return Ok(1.0);
        }
        let sat = gatoms.iter().filter(|a| st.has(a)).count();
        Ok(0.9 * (sat as f64 / gatoms.len() as f64))
    };

    let root_app = applicable(&states[0])?;
    nodes.push(Node {
        state_idx: 0,
        parent: None,
        action_idx: None,
        visits: 0,
        value_sum: 0.0,
        children: Vec::new(),
        untried: root_app,
        depth: 0,
    });

    let c_explore: f64 = 2.0f64.sqrt();
    let mut iterations: u32 = 0;
    let mut generated: u64 = 0;

    // Best goal-reaching path discovered by EXPANSION (not rollout).
    //
    // Extracting purely by max-visit count follows whatever subtree UCT
    // explored most, which wanders: on a 2-step blocks problem it produced an
    // 18-step plan of pickup/putdown cycles that happened to end in the goal.
    // Correct, but useless as a plan. Standard MCTS-for-planning practice is
    // to record the best solution explicitly; we keep the SHORTEST expanded
    // path that satisfies the goal, ties broken by discovery order so the
    // result stays deterministic for a given (seed, iterations).
    let mut best_path: Option<Vec<usize>> = None; // node indices, root excluded

    while iterations < opts.mcts_iterations {
        if opts.time_budget_ms > 0 && started.elapsed().as_millis() as u64 > opts.time_budget_ms {
            break;
        }
        iterations += 1;

        // --- Selection ---
        let mut cur: usize = 0;
        loop {
            let node = &nodes[cur];
            if !node.untried.is_empty() {
                break;
            }
            if node.children.is_empty() {
                break;
            }
            let parent_visits = node.visits.max(1) as f64;
            let mut best_child = node.children[0];
            let mut best_uct = f64::NEG_INFINITY;
            for &ch in &node.children {
                let cn = &nodes[ch];
                let exploit = cn.value_sum / (cn.visits.max(1) as f64);
                let explore = c_explore * ((parent_visits.ln()) / (cn.visits.max(1) as f64)).sqrt();
                let uct = exploit + explore;
                if uct > best_uct {
                    best_uct = uct;
                    best_child = ch;
                }
            }
            cur = best_child;
        }

        // --- Expansion ---
        if !nodes[cur].untried.is_empty() {
            // Инвариант цикла гарантирует непустоту `untried`, но доказывать
            // его через `.expect()` нельзя (R-09): при нарушении инварианта
            // процесс должен завершиться ошибкой, а не паникой (panic=abort).
            let ai = match nodes[cur].untried.pop() {
                Some(ai) => ai,
                None => break, // defensive: инвариант нарушен — прекращаем выбор
            };
            // deterministic: sorted order, pop from end
            let pstate = states[nodes[cur].state_idx].clone();
            let nstate = apply(&pstate, ai)?;
            generated += 1;
            let sidx = states.len();
            states.push(nstate.clone());
            let n_app = applicable(&nstate)?;
            let child_idx = nodes.len();
            let child_depth = nodes[cur].depth + 1;
            nodes.push(Node {
                state_idx: sidx,
                parent: Some(cur),
                action_idx: Some(ai),
                visits: 0,
                value_sum: 0.0,
                children: Vec::new(),
                untried: n_app,
                depth: child_depth,
            });
            nodes[cur].children.push(child_idx);

            // Goal reached by expansion -> record if shorter than the current best.
            if eval(&model.problem.goal, &nstate, model, &env0)? {
                let mut path: Vec<usize> = Vec::new();
                let mut w = child_idx;
                while let Some(par) = nodes[w].parent {
                    path.push(w);
                    w = par;
                }
                path.reverse();
                let better = match &best_path {
                    None => true,
                    Some(prev) => path.len() < prev.len(),
                };
                if better {
                    best_path = Some(path);
                }
            }

            cur = child_idx;
        }

        // --- Rollout (seeded, deterministic) ---
        let mut st = states[nodes[cur].state_idx].clone();
        let mut r: f64 = reward(&st)?;
        if r < 1.0 {
            for _ in 0..ROLLOUT_DEPTH_CAP {
                let app = applicable(&st)?;
                if app.is_empty() {
                    break;
                }
                let pick = app[(rng.next_below(app.len() as u64)) as usize];
                st = apply(&st, pick)?;
                r = reward(&st)?;
                if r >= 1.0 {
                    break;
                }
            }
        }

        // --- Backpropagation ---
        let mut node = cur;
        loop {
            nodes[node].visits += 1;
            nodes[node].value_sum += r;
            match nodes[node].parent {
                Some(p) => node = p,
                None => break,
            }
        }
    }

    if iterations == 0 {
        return Err(FlickerError::limit("mcts performed zero iterations (budget too small)"));
    }

    // --- Extract best path by visit count (ties → lowest child index) ---
    //
    // BUGFIX: the previous version walked the max-visit chain until a node ran
    // out of children, WITHOUT stopping at the goal. Whenever actions remained
    // applicable in the goal state (e.g. `unstack(b1,b2)` / `putdown(b1)` after
    // reaching `(on b1 b2)`), those actions were appended, the goal state was
    // left behind, and the final check reported "did not reach the goal" even
    // though the search had found it. Any domain with post-goal actions was
    // therefore unsolvable by `PlanMode::Mcts`.
    //
    // Fix: simulate the state WHILE extracting and stop at the first node whose
    // state satisfies the goal. A plan must end at the goal, not past it.
    let env = std::collections::BTreeMap::new();
    let mut steps: Vec<PlanStep> = Vec::new();
    let mut st = State::new(model.problem.init.clone());
    let mut cur = 0usize;

    // Fast path: an expanded goal-reaching node was recorded during search.
    // Replaying it is both shorter and cheaper than re-walking max-visits.
    if let Some(path) = best_path.take() {
        for node_idx in &path {
            let ai = nodes[*node_idx].action_idx.ok_or_else(|| {
                FlickerError::semantic(format!(
                    "mcts: recorded goal path node {} has no action",
                    node_idx
                ))
            })?;
            let ga = &ground[ai];
            steps.push(PlanStep { action: ga.name.clone(), args: ga.args.clone() });
        }
        // Re-simulate to obtain the final state hash input for the goal check.
        let mut st2 = State::new(model.problem.init.clone());
        for s in &steps {
            let key = s.key();
            let ga = ground
                .iter()
                .find(|g| g.key() == key)
                .ok_or_else(|| FlickerError::limit("mcts path references unknown grounding"))?;
            if !eval(&ga.precond, &st2, model, &env)? {
                return Err(FlickerError::limit(format!(
                    "mcts recorded path is not executable at step {} ('{}') within {} iterations (seed {})",
                    steps.len(), ga.name, opts.mcts_iterations, opts.seed
                )));
            }
            let mut adds = BTreeSet::new();
            let mut dels = BTreeSet::new();
            collect_effect(&ga.effect, &st2, model, &env, &mut adds, &mut dels)?;
            st2 = st2.apply_delta(&adds, &dels);
        }
        if eval(&model.problem.goal, &st2, model, &env)? {
            return Ok(RawPlan { steps, expanded: iterations as u64, generated });
        }
        // Recorded path did not survive re-simulation: fall through to the
        // max-visit extraction below rather than failing outright.
        steps.clear();
    }

    // The root may already satisfy the goal; handled by the early return above,
    // but re-check defensively so extraction never emits a useless step.
    loop {
        if eval(&model.problem.goal, &st, model, &env)? {
            break;
        }
        let children = nodes[cur].children.clone();
        if children.is_empty() {
            break;
        }
        let mut best = children[0];
        for &ch in &children[1..] {
            if nodes[ch].visits > nodes[best].visits {
                best = ch;
            }
        }
        if nodes[best].visits == 0 {
            break;
        }
        let ai = nodes[best].action_idx.ok_or_else(|| {
            FlickerError::semantic(format!(
                "mcts: best-visit child node {} has no action",
                best
            ))
        })?;
        let ga = &ground[ai];

        // The extracted path must remain executable: verify the precondition in
        // the simulated state before appending, so a max-visit chain that walks
        // off the executable frontier is reported as failure rather than
        // silently producing an invalid plan.
        if !eval(&ga.precond, &st, model, &env)? {
            return Err(FlickerError::limit(format!(
                "mcts best-visit path left the executable frontier at step {} ('{}') within {} iterations (seed {})",
                steps.len(), ga.name, opts.mcts_iterations, opts.seed
            )));
        }

        steps.push(PlanStep { action: ga.name.clone(), args: ga.args.clone() });
        let mut adds = BTreeSet::new();
        let mut dels = BTreeSet::new();
        collect_effect(&ga.effect, &st, model, &env, &mut adds, &mut dels)?;
        st = st.apply_delta(&adds, &dels);

        cur = best;
        if steps.len() as u32 > ROLLOUT_DEPTH_CAP * 4 {
            break;
        }
    }

    // Final goal check; the caller (planner::finish) additionally runs the
    // full independent validator as a hard gate (spec R7.4.1).
    if !eval(&model.problem.goal, &st, model, &env)? {
        return Err(FlickerError::limit(format!(
            "mcts did not reach the goal within {} iterations (seed {})",
            opts.mcts_iterations, opts.seed
        )));
    }

    Ok(RawPlan { steps, expanded: iterations as u64, generated })
}
