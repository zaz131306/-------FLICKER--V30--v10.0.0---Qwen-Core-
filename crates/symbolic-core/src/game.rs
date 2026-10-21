//! Adversarial Decision Module (ADM) kernel: deterministic alpha-beta
//! minimax over a two-player zero-sum game tree.
//!
//! Scope note (docs/adr/0007): v10 ships the *game kernel* with a worked
//! pursuit-evasion example. Binding PDDL actions to player roles
//! (`:opponent`) is specified in the AST and parser but the PDDL↔ADM
//! adapter is a roadmap item — this module intentionally makes no claims
//! about adversarial PDDL planning yet.

use crate::prng::Xorshift64Star;

pub type Score = i64;

pub const WIN: Score = 1_000_000;
pub const LOSS: Score = -1_000_000;

pub trait Game {
    type State: Clone;
    type Move: Clone + PartialEq + std::fmt::Debug;

    fn initial_state(&self) -> Self::State;
    fn legal_moves(&self, state: &Self::State, max_player: bool) -> Vec<Self::Move>;
    fn apply(&self, state: &Self::State, m: &Self::Move, max_player: bool) -> Self::State;
    fn is_terminal(&self, state: &Self::State) -> bool;
    /// Score from the MAX player's perspective.
    fn evaluate(&self, state: &Self::State) -> Score;
}

#[derive(Debug, Clone, PartialEq)]
pub struct SearchResult<M> {
    pub best: Option<M>,
    pub score: Score,
    pub nodes: u64,
    pub depth: u32,
}

/// Alpha-beta minimax. Deterministic: move ordering comes from
/// `legal_moves` and ties resolve to the earliest move.
pub fn search<G: Game>(game: &G, state: &G::State, depth: u32) -> SearchResult<G::Move> {
    let mut nodes = 0u64;
    let (best, score) = negamax(game, state, depth, true, LOSS - 1, WIN + 1, &mut nodes);
    SearchResult { best, score, nodes, depth }
}

fn negamax<G: Game>(
    game: &G,
    state: &G::State,
    depth: u32,
    max_player: bool,
    mut alpha: Score,
    beta: Score,
    nodes: &mut u64,
) -> (Option<G::Move>, Score) {
    *nodes += 1;
    if game.is_terminal(state) {
        let s = game.evaluate(state);
        return (None, if max_player { s } else { -s });
    }
    if depth == 0 {
        let s = game.evaluate(state);
        return (None, if max_player { s } else { -s });
    }

    let moves = game.legal_moves(state, max_player);
    if moves.is_empty() {
        let s = game.evaluate(state);
        return (None, if max_player { s } else { -s });
    }

    let mut best_move: Option<G::Move> = None;
    let mut best_score = LOSS - 1;
    for m in &moves {
        let next = game.apply(state, m, max_player);
        // Zero-sum: negate the child's score. For the min player the
        // negation is what makes this a single-code-path minimax.
        let (_, child) = negamax(game, &next, depth - 1, !max_player, -beta, -alpha, nodes);
        let score = -child;
        if score > best_score {
            best_score = score;
            best_move = Some(m.clone());
        }
        if best_score > alpha {
            alpha = best_score;
        }
        if alpha >= beta {
            break;
        }
    }
    (best_move, best_score)
}

/// Deterministic self-play rollout used by tests and by the demo:
/// picks moves with a seeded PRNG so runs are reproducible.
pub fn random_rollout<G: Game>(
    game: &G,
    state: &G::State,
    seed: u64,
    max_steps: u32,
) -> (G::State, Score, u32) {
    let mut rng = Xorshift64Star::new(seed);
    let mut st = state.clone();
    let mut max_player = true;
    let mut steps = 0u32;
    while steps < max_steps && !game.is_terminal(&st) {
        let moves = game.legal_moves(&st, max_player);
        if moves.is_empty() {
            break;
        }
        let idx = rng.next_below(moves.len() as u64) as usize;
        let m = moves[idx].clone();
        st = game.apply(&st, &m, max_player);
        max_player = !max_player;
        steps += 1;
    }
    let score = game.evaluate(&st);
    (st, score, steps)
}

// ---------------------------------------------------------------------------
// Worked example: pursuit-evasion on a grid (used by tests and the CLI demo)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GridPursuit {
    pub width: u32,
    pub height: u32,
    pub walls: Vec<(i32, i32)>,
    pub capture_distance: i32,
    pub max_depth: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GridState {
    pub pursuer: (i32, i32),
    pub evader: (i32, i32),
    pub ply: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GridMove {
    Stay,
    Up,
    Down,
    Left,
    Right,
}

const ALL_MOVES: [GridMove; 5] =
    [GridMove::Stay, GridMove::Up, GridMove::Down, GridMove::Left, GridMove::Right];

impl GridPursuit {
    fn delta(m: &GridMove) -> (i32, i32) {
        match m {
            GridMove::Stay => (0, 0),
            GridMove::Up => (0, -1),
            GridMove::Down => (0, 1),
            GridMove::Left => (-1, 0),
            GridMove::Right => (1, 0),
        }
    }

    fn inside(&self, p: (i32, i32)) -> bool {
        p.0 >= 0 && p.1 >= 0 && (p.0 as u32) < self.width && (p.1 as u32) < self.height
    }

    fn blocked(&self, p: (i32, i32)) -> bool {
        self.walls.contains(&p)
    }

    fn distance(&self, s: &GridState) -> i32 {
        (s.pursuer.0 - s.evader.0).abs() + (s.pursuer.1 - s.evader.1).abs()
    }
}

impl Game for GridPursuit {
    type State = GridState;
    type Move = GridMove;

    fn initial_state(&self) -> GridState {
        GridState { pursuer: (0, 0), evader: (self.width as i32 - 1, self.height as i32 - 1), ply: 0 }
    }

    fn legal_moves(&self, state: &GridState, _max_player: bool) -> Vec<GridMove> {
        let pos = if _max_player { state.pursuer } else { state.evader };
        let mut out = Vec::new();
        for m in ALL_MOVES.iter() {
            let (dx, dy) = Self::delta(m);
            let np = (pos.0 + dx, pos.1 + dy);
            if self.inside(np) && !self.blocked(np) {
                out.push(m.clone());
            }
        }
        out
    }

    fn apply(&self, state: &GridState, m: &GridMove, max_player: bool) -> GridState {
        let (dx, dy) = Self::delta(m);
        let mut next = state.clone();
        if max_player {
            let np = (state.pursuer.0 + dx, state.pursuer.1 + dy);
            if self.inside(np) && !self.blocked(np) {
                next.pursuer = np;
            }
        } else {
            let np = (state.evader.0 + dx, state.evader.1 + dy);
            if self.inside(np) && !self.blocked(np) && np != state.pursuer {
                next.evader = np;
            }
        }
        next.ply = state.ply + 1;
        next
    }

    fn is_terminal(&self, state: &GridState) -> bool {
        self.distance(state) <= self.capture_distance || state.ply >= self.max_depth
    }

    fn evaluate(&self, state: &GridState) -> Score {
        let d = self.distance(state);
        if d <= self.capture_distance {
            // Earlier capture is better for MAX.
            return WIN - (state.ply as Score);
        }
        if state.ply >= self.max_depth {
            return LOSS + (state.ply as Score);
        }
        // Otherwise: closer is better.
        -(d as Score) * 10
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn game() -> GridPursuit {
        GridPursuit {
            width: 5,
            height: 5,
            walls: vec![(2, 1), (2, 2), (2, 3)],
            capture_distance: 0,
            max_depth: 24,
        }
    }

    #[test]
    fn determinism_same_state_same_result() {
        let g = game();
        let s = g.initial_state();
        let r1 = search(&g, &s, 6);
        let r2 = search(&g, &s, 6);
        assert_eq!(r1.best, r2.best);
        assert_eq!(r1.score, r2.score);
        assert_eq!(r1.nodes, r2.nodes);
    }

    #[test]
    fn deeper_search_never_worse_for_max() {
        let g = game();
        let s = g.initial_state();
        let shallow = search(&g, &s, 4);
        let deep = search(&g, &s, 8);
        assert!(deep.score >= shallow.score);
    }

    #[test]
    fn pursuer_captures_when_adjacent() {
        let g = GridPursuit { width: 3, height: 3, walls: vec![], capture_distance: 0, max_depth: 12 };
        let s = GridState { pursuer: (0, 0), evader: (1, 0), ply: 0 };
        let r = search(&g, &s, 6);
        assert!(r.score >= WIN - 12, "expected capture, got {}", r.score);
    }

    #[test]
    fn rollout_is_seeded() {
        let g = game();
        let s = g.initial_state();
        let (_, sc1, st1) = random_rollout(&g, &s, 7, 20);
        let (_, sc2, st2) = random_rollout(&g, &s, 7, 20);
        assert_eq!(sc1, sc2);
        assert_eq!(st1, st2);
    }

    #[test]
    fn walls_respected() {
        let g = game();
        let s = GridState { pursuer: (1, 0), evader: (4, 4), ply: 0 };
        for m in g.legal_moves(&s, true) {
            let n = g.apply(&s, &m, true);
            assert!(!g.blocked(n.pursuer));
        }
    }
}
