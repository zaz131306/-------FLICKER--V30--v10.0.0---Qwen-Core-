//! Error model with machine-readable diagnostics.
//!
//! Every error carries a `kind` string and optional source position so that
//! the NL→PDDL repair loop (worker side) can feed precise, actionable
//! feedback to the translation model instead of a generic failure.

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pos {
    pub line: usize,
    pub col: usize,
}

impl fmt::Display for Pos {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.line, self.col)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlickerError {
    /// Stable machine-readable kind: parse | type | grounding | semantic |
    /// validation | io | limit | crypto | ipc
    pub kind: String,
    pub message: String,
    pub pos: Option<Pos>,
}

impl FlickerError {
    pub fn new(kind: &str, message: impl Into<String>) -> Self {
        Self { kind: kind.to_string(), message: message.into(), pos: None }
    }
    pub fn at(kind: &str, message: impl Into<String>, pos: Pos) -> Self {
        Self { kind: kind.to_string(), message: message.into(), pos: Some(pos) }
    }
    pub fn parse(message: impl Into<String>, pos: Pos) -> Self {
        Self::at("parse", message, pos)
    }
    pub fn type_error(message: impl Into<String>, pos: Pos) -> Self {
        Self::at("type", message, pos)
    }
    pub fn semantic(message: impl Into<String>) -> Self {
        Self::new("semantic", message)
    }
    pub fn grounding(message: impl Into<String>) -> Self {
        Self::new("grounding", message)
    }
    pub fn limit(message: impl Into<String>) -> Self {
        Self::new("limit", message)
    }
    pub fn io(message: impl Into<String>) -> Self {
        Self::new("io", message)
    }
    pub fn validation(message: impl Into<String>) -> Self {
        Self::new("validation", message)
    }
}

impl fmt::Display for FlickerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.pos {
            Some(p) => write!(f, "[{} @ {}] {}", self.kind, p, self.message),
            None => write!(f, "[{}] {}", self.kind, self.message),
        }
    }
}

impl std::error::Error for FlickerError {}

pub type FlickerResult<T> = Result<T, FlickerError>;
