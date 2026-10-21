//! FLICKER symbolic core — deterministic neuro-symbolic foundation.
//!
//! Design rules (see docs/adr/):
//! * std-only: zero third-party dependencies (supply-chain cleanliness);
//! * determinism: every search is either canonically ordered or seeded;
//! * honesty: guarantees are stated only where enforced by construction
//!   (plan validation, replay hash-chains), never where merely intended.
//!
//! The core implements the FPS-1 subset of PDDL (Flicker-PDDL Subset v1):
//! STRIPS + typing + negative preconditions + quantified preconditions
//! (forall/exists/and/or/not) + universal/conditional effects
//! (forall/when). Numeric fluents, object equality and disjunctive
//! effects are OUT of scope for v10 and rejected at parse time with a
//! machine-readable diagnostic (used by the NL→PDDL repair loop).

pub mod error;
pub mod game;
pub mod ground;
pub mod json;
pub mod mcts;
pub mod pddl;
pub mod planner;
pub mod prng;
pub mod replay;
pub mod sexpr;
pub mod sha2;
pub mod state;
pub mod validator;

pub use error::{FlickerError, FlickerResult};

/// Version of the normative semantics implemented by this crate.
pub const FPS1_VERSION: &str = "FPS-1/1.0";

/// Crate semantic version (mirrors Cargo workspace version).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
