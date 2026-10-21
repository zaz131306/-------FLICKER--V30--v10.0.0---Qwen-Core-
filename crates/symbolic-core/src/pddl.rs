//! FPS-1: Flicker-PDDL Subset v1 — AST, parser, type checker.
//!
//! Supported: `:strips :typing :negative-preconditions
//! :disjunctive-preconditions :universal-preconditions
//! :existential-preconditions :conditional-effects :universal-effects`.
//! Rejected with machine-readable diagnostics: numeric fluents, object
//! equality, durative actions, `:constants`, derived predicates.
//!
//! Extension for adversarial planning (ADM): an action may carry the
//! keyword `:opponent` marking it as an opponent move (see game.rs /
//! docs/adr/0007).

use std::collections::BTreeMap;
use std::collections::BTreeSet;

use crate::error::{FlickerError, FlickerResult, Pos};
use crate::sexpr::{parse_sexps, Sexp};

pub const SUPPORTED_REQUIREMENTS: &[&str] = &[
    "strips",
    "typing",
    "negative-preconditions",
    "disjunctive-preconditions",
    "universal-preconditions",
    "existential-preconditions",
    "conditional-effects",
    "universal-effects",
];

// ---------------------------------------------------------------------------
// AST
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Term {
    Var(String),
    Const(String),
}

impl Term {
    pub fn name(&self) -> &str {
        match self {
            Term::Var(s) | Term::Const(s) => s,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Formula {
    True,
    Atom(String, Vec<Term>),
    Not(Box<Formula>),
    And(Vec<Formula>),
    Or(Vec<Formula>),
    Forall(Vec<(String, String)>, Box<Formula>),
    Exists(Vec<(String, String)>, Box<Formula>),
}

#[derive(Debug, Clone, PartialEq)]
pub enum Effect {
    Nil,
    Add(String, Vec<Term>),
    Del(String, Vec<Term>),
    And(Vec<Effect>),
    Forall(Vec<(String, String)>, Box<Effect>),
    When(Box<Formula>, Box<Effect>),
}

#[derive(Debug, Clone)]
pub struct Action {
    pub name: String,
    /// (variable, type)
    pub params: Vec<(String, String)>,
    pub precond: Formula,
    pub effect: Effect,
    /// ADM extension: action models an opponent move.
    pub opponent: bool,
}

#[derive(Debug, Clone, Default)]
pub struct TypeTable {
    /// type -> parent type ("object" is the implicit root).
    parents: BTreeMap<String, String>,
}

impl TypeTable {
    /// Empty type table. `"object"` is the implicit root and is never stored.
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, ty: &str, parent: &str) -> FlickerResult<()> {
        if let Some(prev) = self.parents.get(ty) {
            if prev != parent {
                return Err(FlickerError::semantic(format!(
                    "type '{}' declared twice with different parents ('{}' and '{}'); FPS-1 supports single inheritance",
                    ty, prev, parent
                )));
            }
            return Ok(());
        }
        self.parents.insert(ty.to_string(), parent.to_string());
        Ok(())
    }

    pub fn known(&self, ty: &str) -> bool {
        ty == "object" || self.parents.contains_key(ty)
    }

    pub fn is_subtype(&self, a: &str, b: &str) -> bool {
        if b == "object" {
            return true;
        }
        let mut cur = a;
        let mut guard = 0;
        loop {
            if cur == b {
                return true;
            }
            match self.parents.get(cur) {
                Some(p) => {
                    cur = p;
                    guard += 1;
                    if guard > 256 {
                        return false; // cyclic declaration guarded elsewhere, be safe
                    }
                }
                None => return cur == "object" && b == "object",
            }
        }
    }

    pub fn names(&self) -> Vec<String> {
        self.parents.keys().cloned().collect()
    }
}

#[derive(Debug, Clone)]
pub struct Domain {
    pub name: String,
    pub requirements: Vec<String>,
    pub types: TypeTable,
    /// predicate -> typed parameter list
    pub predicates: BTreeMap<String, Vec<(String, String)>>,
    pub actions: Vec<Action>,
}

#[derive(Debug, Clone)]
pub struct Problem {
    pub name: String,
    pub domain_name: String,
    /// object -> declared type
    pub objects: BTreeMap<String, String>,
    /// ground atoms in canonical string form "(pred a b)"
    pub init: BTreeSet<String>,
    pub goal: Formula,
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

pub fn parse_domain(src: &str) -> FlickerResult<Domain> {
    let tops = parse_sexps(src)?;
    let top = tops
        .into_iter()
        .next()
        .ok_or_else(|| FlickerError::parse("empty domain file", Pos { line: 1, col: 1 }))?;
    let items = expect_list(&top, "domain definition")?;
    if !items.first().map(|s| s.is_atom("define")).unwrap_or(false) {
        return Err(FlickerError::at(
            "parse",
            "expected '(define ...)'",
            *top.pos(),
        ));
    }

    let mut name = String::new();
    let mut requirements: Vec<String> = Vec::new();
    let mut types = TypeTable::new();
    let mut predicates: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
    let mut actions: Vec<Action> = Vec::new();

    for sect in &items[1..] {
        let sect_items = expect_list(sect, "domain section")?;
        let key = sect_items
            .first()
            .and_then(|s| s.atom_str())
            .map(|k| k.trim_start_matches(':'))
            .ok_or_else(|| FlickerError::at("parse", "domain section must start with a keyword", *sect.pos()))?;
        match key {
            "domain" => {
                name = sect_items
                    .get(1)
                    .and_then(|s| s.atom_str())
                    .ok_or_else(|| FlickerError::at("parse", "missing domain name", *sect.pos()))?
                    .to_string();
            }
            "requirements" => {
                for r in &sect_items[1..] {
                    let rname = r
                        .atom_str()
                        .ok_or_else(|| FlickerError::at("parse", "requirement must be an atom", *r.pos()))?
                        .trim_start_matches(':')
                        .to_string();
                    if !SUPPORTED_REQUIREMENTS.contains(&rname.as_str()) {
                        return Err(FlickerError::at(
                            "semantic",
                            format!(
                                "requirement ':{}' is not in the FPS-1 subset (supported: {})",
                                rname,
                                SUPPORTED_REQUIREMENTS.join(", ")
                            ),
                            *r.pos(),
                        ));
                    }
                    requirements.push(rname);
                }
            }
            "types" => {
                parse_typed_list(&sect_items[1..], |child, parent| {
                    types.insert(child, parent)
                })?;
            }
            "constants" => {
                return Err(FlickerError::at(
                    "semantic",
                    ":constants are not supported in FPS-1 v1; declare objects in the problem",
                    *sect.pos(),
                ));
            }
            "predicates" => {
                for p in &sect_items[1..] {
                    let p_items = expect_list(p, "predicate declaration")?;
                    let pname = p_items
                        .first()
                        .and_then(|s| s.atom_str())
                        .ok_or_else(|| FlickerError::at("parse", "predicate must start with a name", *p.pos()))?
                        .to_string();
                    let params = parse_typed_pairs(p_items.get(1..).unwrap_or(&[]))?;
                    if predicates.insert(pname.clone(), params).is_some() {
                        return Err(FlickerError::at(
                            "semantic",
                            format!("predicate '{}' declared twice", pname),
                            *p.pos(),
                        ));
                    }
                }
            }
            "function" | "functions" => {
                return Err(FlickerError::at(
                    "semantic",
                    "numeric fluents/functions are not supported in FPS-1 v1",
                    *sect.pos(),
                ));
            }
            "action" => {
                actions.push(parse_action(sect_items, *sect.pos())?);
            }
            "derived" => {
                return Err(FlickerError::at(
                    "semantic",
                    "derived predicates are not supported in FPS-1 v1",
                    *sect.pos(),
                ));
            }
            other => {
                return Err(FlickerError::at(
                    "parse",
                    format!("unknown domain section '{}'", other),
                    *sect.pos(),
                ));
            }
        }
    }

    if name.is_empty() {
        return Err(FlickerError::semantic("domain has no name"));
    }
    if !requirements.iter().any(|r| r == "typing") {
        // Untyped domains are accepted; everything implicitly has type object.
    }
    Ok(Domain { name, requirements, types, predicates, actions })
}

pub fn parse_problem(src: &str) -> FlickerResult<Problem> {
    let tops = parse_sexps(src)?;
    let top = tops
        .into_iter()
        .next()
        .ok_or_else(|| FlickerError::parse("empty problem file", Pos { line: 1, col: 1 }))?;
    let items = expect_list(&top, "problem definition")?;
    if !items.first().map(|s| s.is_atom("define")).unwrap_or(false) {
        return Err(FlickerError::at("parse", "expected '(define ...)'", *top.pos()));
    }

    let mut name = String::new();
    let mut domain_name = String::new();
    let mut objects: BTreeMap<String, String> = BTreeMap::new();
    let mut init: BTreeSet<String> = BTreeSet::new();
    let mut goal: Option<Formula> = None;

    for sect in &items[1..] {
        let sect_items = expect_list(sect, "problem section")?;
        let key = sect_items
            .first()
            .and_then(|s| s.atom_str())
            .map(|k| k.trim_start_matches(':'))
            .ok_or_else(|| FlickerError::at("parse", "problem section must start with a keyword", *sect.pos()))?;
        match key {
            "problem" => {
                name = sect_items
                    .get(1)
                    .and_then(|s| s.atom_str())
                    .ok_or_else(|| FlickerError::at("parse", "missing problem name", *sect.pos()))?
                    .to_string();
            }
            "domain" => {
                domain_name = sect_items
                    .get(1)
                    .and_then(|s| s.atom_str())
                    .ok_or_else(|| FlickerError::at("parse", "missing domain reference", *sect.pos()))?
                    .to_string();
            }
            "objects" => {
                parse_typed_list(sect_items.get(1..).unwrap_or(&[]), |child, parent| {
                    if objects.insert(child.to_string(), parent.to_string()).is_some() {
                        return Err(FlickerError::semantic(format!("object '{}' declared twice", child)));
                    }
                    Ok(())
                })?;
            }
            "init" => {
                for f in sect_items.get(1..).unwrap_or(&[]) {
                    if let Some(lit) = f.list_items() {
                        if lit.first().map(|s| s.is_atom("not")).unwrap_or(false) {
                            return Err(FlickerError::at(
                                "semantic",
                                "negated literals are not allowed in :init (closed-world assumption)",
                                *f.pos(),
                            ));
                        }
                    }
                    if f.is_atom("=") {
                        return Err(FlickerError::at(
                            "semantic",
                            "equality in :init is not supported in FPS-1 v1",
                            *f.pos(),
                        ));
                    }
                    let atom = parse_atom(f)?;
                    let names: Vec<String> = atom.1.iter().map(|t| t.name().to_string()).collect();
                    init.insert(canon_atom(&atom.0, &names));
                }
            }
            "goal" => {
                let body = sect_items
                    .get(1)
                    .ok_or_else(|| FlickerError::at("parse", "empty :goal section", *sect.pos()))?;
                goal = Some(parse_formula(body)?);
            }
            "metric" => {
                // Accepted and ignored in v10 (plans are validated, not cost-optimized).
            }
            other => {
                return Err(FlickerError::at(
                    "parse",
                    format!("unknown problem section '{}'", other),
                    *sect.pos(),
                ));
            }
        }
    }

    if name.is_empty() || domain_name.is_empty() {
        return Err(FlickerError::semantic("problem must declare :problem name and :domain reference"));
    }
    let goal = goal.ok_or_else(|| FlickerError::semantic("problem has no :goal"))?;
    Ok(Problem { name, domain_name, objects, init, goal })
}

fn expect_list<'a>(s: &'a Sexp, what: &str) -> FlickerResult<&'a [Sexp]> {
    s.list_items().ok_or_else(|| {
        FlickerError::at("parse", format!("expected a list for {}", what), *s.pos())
    })
}

/// Parses the PDDL typed-list idiom: `a b - t c - u` (and untyped `a b c`).
fn parse_typed_list(items: &[Sexp], mut sink: impl FnMut(&str, &str) -> FlickerResult<()>) -> FlickerResult<()> {
    let mut pending: Vec<String> = Vec::new();
    let mut i = 0;
    while i < items.len() {
        let it = &items[i];
        if it.is_atom("-") {
            i += 1;
            let ty = items
                .get(i)
                .and_then(|s| s.atom_str())
                .ok_or_else(|| FlickerError::at("parse", "expected type after '-'", *it.pos()))?
                .to_string();
            for p in pending.drain(..) {
                sink(&p, &ty)?;
            }
        } else {
            let nm = it
                .atom_str()
                .ok_or_else(|| FlickerError::at("parse", "expected a name in typed list", *it.pos()))?
                .to_string();
            pending.push(nm);
        }
        i += 1;
    }
    for p in pending.drain(..) {
        sink(&p, "object")?;
    }
    Ok(())
}

fn parse_typed_pairs(items: &[Sexp]) -> FlickerResult<Vec<(String, String)>> {
    let mut out = Vec::new();
    parse_typed_list(items, |child, parent| {
        // `parse_typed_list` yields raw atom text, so variables arrive as "?x".
        // `Term::Var` is constructed WITHOUT the leading '?' (see parse_formula /
        // split_atom, which use strip_prefix('?')). Scopes are keyed by the
        // stripped form, so parameters and quantifier variables must be
        // normalized here or every lookup fails with "unbound variable".
        let name = child.strip_prefix('?').unwrap_or(child);
        if name.is_empty() {
            return Err(FlickerError::semantic("empty variable name in typed list"));
        }
        out.push((name.to_string(), parent.to_string()));
        Ok(())
    })?;
    Ok(out)
}

/// Parses an action body in EITHER legal PDDL spelling:
///
/// ```text
/// flat    (:action a :parameters (?x - t) :precondition (p ?x) :effect ...)
/// nested  (:action a (:parameters (?x - t)) (:precondition (p ?x)) (:effect ...))
/// ```
///
/// Both must be accepted. Supporting only the flat form breaks the B1/B2
/// contract (spec R7.1.3, acceptance criterion A7): `grammar/fps1_pddl.ebnf`
/// emits the NESTED form, so a grammar-constrained SLM emission would be
/// rejected by the parser and no plan could ever be produced.
fn parse_action(items: &[Sexp], pos: Pos) -> FlickerResult<Action> {
    // items[0] == ":action"
    let name = items
        .get(1)
        .and_then(|s| s.atom_str())
        .ok_or_else(|| FlickerError::at("parse", "action without a name", pos))?
        .to_string();

    let mut params: Vec<(String, String)> = Vec::new();
    let mut precond = Formula::True;
    let mut effect = Effect::Nil;
    let mut opponent = false;

    let mut i = 2;
    while i < items.len() {
        // Normalize both spellings to (keyword, optional body, items consumed).
        let nested = matches!(&items[i], Sexp::List(_, _));
        let key: &str;
        let body: Option<&Sexp>;
        let mut advance: usize = if nested { 1 } else { 2 };

        if nested {
            let sub = match &items[i] {
                Sexp::List(v, _) => v.as_slice(),
                Sexp::Atom(_, _) => unreachable!("nested checked above"),
            };
            key = sub
                .first()
                .and_then(|s| s.atom_str())
                .map(|k| k.trim_start_matches(':'))
                .ok_or_else(|| {
                    FlickerError::at("parse", "expected action keyword", *items[i].pos())
                })?;
            body = sub.get(1);
        } else {
            key = items[i]
                .atom_str()
                .map(|k| k.trim_start_matches(':'))
                .ok_or_else(|| {
                    FlickerError::at("parse", "expected action keyword", *items[i].pos())
                })?;
            // Flag keywords carry no body in flat form either.
            if key == "opponent" {
                advance = 1;
                body = None;
            } else {
                body = items.get(i + 1);
            }
        }

        if key == "opponent" {
            opponent = true;
            i += advance;
            continue;
        }

        let body = body.ok_or_else(|| {
            FlickerError::at("parse", format!("missing :{} body", key), *items[i].pos())
        })?;

        match key {
            "parameters" => {
                let inner = expect_list(body, "parameters")?;
                params = parse_typed_pairs(inner)?;
            }
            "precondition" => {
                precond = parse_formula(body)?;
            }
            "effect" => {
                effect = parse_effect(body)?;
            }
            other => {
                return Err(FlickerError::at(
                    "parse",
                    format!("unknown action keyword '{}'", other),
                    *items[i].pos(),
                ));
            }
        }
        i += advance;
    }

    Ok(Action { name, params, precond, effect, opponent })
}

pub fn parse_formula(s: &Sexp) -> FlickerResult<Formula> {
    if let Some(atom_name) = s.atom_str() {
        // bare atom without arguments is not allowed except literal 'and' with no args
        return Err(FlickerError::at(
            "parse",
            format!("bare symbol '{}' where a formula was expected", atom_name),
            *s.pos(),
        ));
    }
    let items = expect_list(s, "formula")?;
    let head = items
        .first()
        .and_then(|x| x.atom_str())
        .ok_or_else(|| FlickerError::at("parse", "formula must start with an operator or predicate", *s.pos()))?;
    match head {
        "and" => {
            let mut v = Vec::new();
            for c in &items[1..] {
                v.push(parse_formula(c)?);
            }
            if v.is_empty() {
                Ok(Formula::True)
            } else if v.len() == 1 {
                v.pop().ok_or_else(|| {
                    FlickerError::semantic("single-element list became empty during parsing")
                })
            } else {
                Ok(Formula::And(v))
            }
        }
        "or" => {
            let mut v = Vec::new();
            for c in &items[1..] {
                v.push(parse_formula(c)?);
            }
            if v.is_empty() {
                return Err(FlickerError::at("parse", "empty 'or'", *s.pos()));
            }
            Ok(Formula::Or(v))
        }
        "not" => {
            if items.len() != 2 {
                return Err(FlickerError::at("parse", "'not' takes exactly one argument", *s.pos()));
            }
            Ok(Formula::Not(Box::new(parse_formula(&items[1])?)))
        }
        "forall" | "exists" => {
            if items.len() != 3 {
                return Err(FlickerError::at(
                    "parse",
                    format!("'{}' takes a variable list and a body", head),
                    *s.pos(),
                ));
            }
            let vars = expect_list(&items[1], "quantifier variables")?;
            let pairs = parse_typed_pairs(vars)?;
            if pairs.is_empty() {
                return Err(FlickerError::at("parse", "empty quantifier variable list", *items[1].pos()));
            }
            let body = parse_formula(&items[2])?;
            if head == "forall" {
                Ok(Formula::Forall(pairs, Box::new(body)))
            } else {
                Ok(Formula::Exists(pairs, Box::new(body)))
            }
        }
        "imply" | "=>" | "iff" | "=" | "either" => Err(FlickerError::at(
            "semantic",
            format!("operator '{}' is not supported in FPS-1 v1", head),
            *s.pos(),
        )),
        pred => {
            let mut args = Vec::new();
            for a in &items[1..] {
                let nm = a
                    .atom_str()
                    .ok_or_else(|| FlickerError::at("parse", "predicate argument must be a symbol", *a.pos()))?
                    .to_string();
                if let Some(rest) = nm.strip_prefix('?') {
                    if rest.is_empty() {
                        return Err(FlickerError::at("parse", "empty variable name", *a.pos()));
                    }
                    args.push(Term::Var(rest.to_string()));
                } else {
                    args.push(Term::Const(nm));
                }
            }
            Ok(Formula::Atom(pred.to_string(), args))
        }
    }
}

pub fn parse_effect(s: &Sexp) -> FlickerResult<Effect> {
    let items = expect_list(s, "effect")?;
    let head = items
        .first()
        .and_then(|x| x.atom_str())
        .ok_or_else(|| FlickerError::at("parse", "effect must start with an operator or predicate", *s.pos()))?;
    match head {
        "and" => {
            let mut v = Vec::new();
            for c in &items[1..] {
                v.push(parse_effect(c)?);
            }
            Ok(Effect::And(v))
        }
        "not" => {
            if items.len() != 2 {
                return Err(FlickerError::at("parse", "'not' effect takes exactly one argument", *s.pos()));
            }
            let atom = parse_atom(&items[1])?;
            Ok(Effect::Del(atom.0, atom.1))
        }
        "forall" => {
            if items.len() != 3 {
                return Err(FlickerError::at("parse", "'forall' effect takes variables and body", *s.pos()));
            }
            let vars = expect_list(&items[1], "quantifier variables")?;
            let pairs = parse_typed_pairs(vars)?;
            if pairs.is_empty() {
                return Err(FlickerError::at("parse", "empty quantifier variable list", *items[1].pos()));
            }
            let body = parse_effect(&items[2])?;
            Ok(Effect::Forall(pairs, Box::new(body)))
        }
        "when" => {
            if items.len() != 3 {
                return Err(FlickerError::at("parse", "'when' takes a condition and an effect", *s.pos()));
            }
            let cond = parse_formula(&items[1])?;
            let eff = parse_effect(&items[2])?;
            Ok(Effect::When(Box::new(cond), Box::new(eff)))
        }
        "oneof" | "forall-effect-x" => Err(FlickerError::at(
            "semantic",
            "disjunctive/probabilistic effects are not supported in FPS-1 v1",
            *s.pos(),
        )),
        pred => {
            let atom = parse_atom(s)?;
            let _ = pred;
            Ok(Effect::Add(atom.0, atom.1))
        }
    }
}

fn parse_atom(s: &Sexp) -> FlickerResult<(String, Vec<Term>)> {
    let items = expect_list(s, "atomic formula")?;
    let name = items
        .first()
        .and_then(|x| x.atom_str())
        .ok_or_else(|| FlickerError::at("parse", "atom must start with a predicate name", *s.pos()))?
        .to_string();
    let mut args = Vec::new();
    for a in &items[1..] {
        let nm = a
            .atom_str()
            .ok_or_else(|| FlickerError::at("parse", "predicate argument must be a symbol", *a.pos()))?
            .to_string();
        if let Some(rest) = nm.strip_prefix('?') {
            if rest.is_empty() {
                return Err(FlickerError::at("parse", "empty variable name", *a.pos()));
            }
            args.push(Term::Var(rest.to_string()));
        } else {
            args.push(Term::Const(nm));
        }
    }
    Ok((name, args))
}

/// Canonical atom string: "(pred arg1 arg2)" — the cross-language state
/// representation (must match worker/flicker_worker/pddlref.py).
pub fn canon_atom(pred: &str, args: &[String]) -> String {
    let mut s = String::with_capacity(pred.len() + args.len() * 4 + 3);
    s.push('(');
    s.push_str(pred);
    for a in args {
        s.push(' ');
        s.push_str(a);
    }
    s.push(')');
    s
}

// ---------------------------------------------------------------------------
// Type checking / semantic analysis
// ---------------------------------------------------------------------------

/// Combined, type-checked model of a domain + problem.
#[derive(Debug, Clone)]
pub struct Model {
    pub domain: Domain,
    pub problem: Problem,
    /// type -> objects of that type (transitively, including subtypes)
    pub objects_by_type: BTreeMap<String, Vec<String>>,
    /// object -> declared type
    pub object_types: BTreeMap<String, String>,
}

impl Model {
    pub fn objects(&self) -> Vec<&str> {
        self.object_types.keys().map(|s| s.as_str()).collect()
    }

    pub fn objects_of_type(&self, ty: &str) -> &[String] {
        static EMPTY: Vec<String> = Vec::new();
        self.objects_by_type.get(ty).map(|v| v.as_slice()).unwrap_or(&EMPTY)
    }

    pub fn is_subtype(&self, a: &str, b: &str) -> bool {
        self.domain.types.is_subtype(a, b)
    }
}

pub fn build_model(domain: Domain, problem: Problem) -> FlickerResult<Model> {
    if problem.domain_name != domain.name {
        return Err(FlickerError::semantic(format!(
            "problem references domain '{}' but loaded domain is '{}'",
            problem.domain_name, domain.name
        )));
    }

    // Type cycle detection.
    for t in domain.types.names() {
        let mut cur = t.clone();
        let mut seen = BTreeSet::new();
        loop {
            if !seen.insert(cur.clone()) {
                return Err(FlickerError::semantic(format!("type hierarchy has a cycle at '{}'", t)));
            }
            match domain.types.parents.get(&cur) {
                Some(p) => {
                    if p == "object" {
                        break;
                    }
                    if !domain.types.known(p) {
                        return Err(FlickerError::semantic(format!(
                            "type '{}' has undeclared parent '{}'",
                            cur, p
                        )));
                    }
                    cur = p.clone();
                }
                None => break,
            }
        }
    }

    // Validate predicate parameter types.
    for (pname, params) in &domain.predicates {
        for (_, ty) in params {
            if !domain.types.known(ty) {
                return Err(FlickerError::semantic(format!(
                    "predicate '{}' uses undeclared type '{}'",
                    pname, ty
                )));
            }
        }
    }

    // Objects: declared types must exist.
    let mut object_types = BTreeMap::new();
    for (obj, ty) in &problem.objects {
        if !domain.types.known(ty) {
            return Err(FlickerError::semantic(format!(
                "object '{}' has undeclared type '{}'",
                obj, ty
            )));
        }
        object_types.insert(obj.clone(), ty.clone());
    }

    // objects_by_type (transitive).
    let mut objects_by_type: BTreeMap<String, Vec<String>> = BTreeMap::new();
    objects_by_type.insert("object".to_string(), object_types.keys().cloned().collect());
    for ty in domain.types.names() {
        let mut list: Vec<String> = Vec::new();
        for (obj, oty) in &object_types {
            if domain.types.is_subtype(oty, &ty) {
                list.push(obj.clone());
            }
        }
        list.sort();
        objects_by_type.insert(ty, list);
    }
    for v in objects_by_type.values_mut() {
        v.sort();
    }

    // Validate action signatures, preconditions, effects.
    for act in &domain.actions {
        let mut scope: BTreeMap<String, String> = BTreeMap::new();
        for (v, ty) in &act.params {
            if !domain.types.known(ty) {
                return Err(FlickerError::semantic(format!(
                    "action '{}' parameter '?'{}' has undeclared type '{}'",
                    act.name, v, ty
                )));
            }
            if scope.insert(v.clone(), ty.clone()).is_some() {
                return Err(FlickerError::semantic(format!(
                    "action '{}' declares parameter '?{}' twice",
                    act.name, v
                )));
            }
        }
        check_formula(
            &act.precond,
            &scope,
            &domain,
            &object_types,
            &format!("action '{}' precondition", act.name),
        )?;
        check_effect(
            &act.effect,
            &scope,
            &domain,
            &object_types,
            &format!("action '{}' effect", act.name),
        )?;
    }

    // Validate init atoms.
    for atom in &problem.init {
        let (pred, args) = split_atom(atom)?;
        let sig = domain.predicates.get(&pred).ok_or_else(|| {
            FlickerError::semantic(format!(":init uses undeclared predicate '{}'", pred))
        })?;
        if sig.len() != args.len() {
            return Err(FlickerError::semantic(format!(
                ":init atom '{}' has arity {}, predicate '{}' expects {}",
                atom,
                args.len(),
                pred,
                sig.len()
            )));
        }
        for (arg, (_, pty)) in args.iter().zip(sig.iter()) {
            let oty = object_types.get(arg).ok_or_else(|| {
                FlickerError::semantic(format!(":init atom '{}' uses undeclared object '{}'", atom, arg))
            })?;
            if !domain.types.is_subtype(oty, pty) {
                return Err(FlickerError::semantic(format!(
                    ":init atom '{}' type error: object '{}' has type '{}', predicate '{}' expects '{}'",
                    atom, arg, oty, pred, pty
                )));
            }
        }
    }

    // Validate goal.
    let empty_scope = BTreeMap::new();
    check_formula(&problem.goal, &empty_scope, &domain, &object_types, "goal")?;

    Ok(Model { domain, problem, objects_by_type, object_types })
}

pub fn split_atom(atom: &str) -> FlickerResult<(String, Vec<String>)> {
    let inner = atom
        .strip_prefix('(')
        .and_then(|s| s.strip_suffix(')'))
        .ok_or_else(|| FlickerError::semantic(format!("malformed atom '{}'", atom)))?;
    let mut parts = inner.split_whitespace();
    let pred = parts
        .next()
        .ok_or_else(|| FlickerError::semantic(format!("empty atom '{}'", atom)))?
        .to_string();
    let args: Vec<String> = parts.map(|s| s.to_string()).collect();
    Ok((pred, args))
}

fn check_formula(
    f: &Formula,
    scope: &BTreeMap<String, String>,
    domain: &Domain,
    objects: &BTreeMap<String, String>,
    ctx: &str,
) -> FlickerResult<()> {
    match f {
        Formula::True => Ok(()),
        Formula::Atom(pred, args) => check_atom(pred, args, scope, domain, objects, ctx),
        Formula::Not(inner) => check_formula(inner, scope, domain, objects, ctx),
        Formula::And(v) | Formula::Or(v) => {
            for x in v {
                check_formula(x, scope, domain, objects, ctx)?;
            }
            Ok(())
        }
        Formula::Forall(vars, body) | Formula::Exists(vars, body) => {
            let mut scope2 = scope.clone();
            for (v, ty) in vars {
                if !domain.types.known(ty) {
                    return Err(FlickerError::semantic(format!(
                        "{}: quantifier variable '?{}' has undeclared type '{}'",
                        ctx, v, ty
                    )));
                }
                scope2.insert(v.clone(), ty.clone());
            }
            check_formula(body, &scope2, domain, objects, ctx)
        }
    }
}

fn check_atom(
    pred: &str,
    args: &[Term],
    scope: &BTreeMap<String, String>,
    domain: &Domain,
    objects: &BTreeMap<String, String>,
    ctx: &str,
) -> FlickerResult<()> {
    let sig = domain.predicates.get(pred).ok_or_else(|| {
        FlickerError::semantic(format!("{}: undeclared predicate '{}'", ctx, pred))
    })?;
    if sig.len() != args.len() {
        return Err(FlickerError::semantic(format!(
            "{}: predicate '{}' expects {} arguments, got {}",
            ctx,
            pred,
            sig.len(),
            args.len()
        )));
    }
    for (arg, (_, pty)) in args.iter().zip(sig.iter()) {
        match arg {
            Term::Var(v) => {
                let vty = scope.get(v).ok_or_else(|| {
                    FlickerError::semantic(format!("{}: unbound variable '?{}' in atom '{}'", ctx, v, pred))
                })?;
                if !domain.types.is_subtype(vty, pty) {
                    return Err(FlickerError::semantic(format!(
                        "{}: type error in '{}': '?{}' has type '{}', expected subtype of '{}'",
                        ctx, pred, v, vty, pty
                    )));
                }
            }
            Term::Const(c) => {
                let cty = objects.get(c).ok_or_else(|| {
                    FlickerError::semantic(format!("{}: undeclared object '{}' in atom '{}'", ctx, c, pred))
                })?;
                if !domain.types.is_subtype(cty, pty) {
                    return Err(FlickerError::semantic(format!(
                        "{}: type error in '{}': object '{}' has type '{}', expected subtype of '{}'",
                        ctx, pred, c, cty, pty
                    )));
                }
            }
        }
    }
    Ok(())
}

fn check_effect(
    e: &Effect,
    scope: &BTreeMap<String, String>,
    domain: &Domain,
    objects: &BTreeMap<String, String>,
    ctx: &str,
) -> FlickerResult<()> {
    match e {
        Effect::Nil => Ok(()),
        Effect::Add(pred, args) | Effect::Del(pred, args) => {
            check_atom(pred, args, scope, domain, objects, ctx)
        }
        Effect::And(v) => {
            for x in v {
                check_effect(x, scope, domain, objects, ctx)?;
            }
            Ok(())
        }
        Effect::Forall(vars, body) => {
            let mut scope2 = scope.clone();
            for (v, ty) in vars {
                if !domain.types.known(ty) {
                    return Err(FlickerError::semantic(format!(
                        "{}: effect quantifier '?{}' has undeclared type '{}'",
                        ctx, v, ty
                    )));
                }
                scope2.insert(v.clone(), ty.clone());
            }
            check_effect(body, &scope2, domain, objects, ctx)
        }
        Effect::When(cond, body) => {
            check_formula(cond, scope, domain, objects, ctx)?;
            check_effect(body, scope, domain, objects, ctx)
        }
    }
}

/// Parse + typecheck domain and problem sources in one call.
pub fn load(domain_src: &str, problem_src: &str) -> FlickerResult<Model> {
    let d = parse_domain(domain_src)?;
    let p = parse_problem(problem_src)?;
    build_model(d, p)
}

/// Domain-only check (used by the repair loop before a problem exists).
pub fn check_domain(domain_src: &str) -> FlickerResult<Domain> {
    let d = parse_domain(domain_src)?;
    // Reuse build_model machinery with an empty matching problem for type checks.
    let p = Problem {
        name: "check".to_string(),
        domain_name: d.name.clone(),
        objects: BTreeMap::new(),
        init: BTreeSet::new(),
        goal: Formula::True,
    };
    build_model(d.clone(), p)?;
    Ok(d)
}
