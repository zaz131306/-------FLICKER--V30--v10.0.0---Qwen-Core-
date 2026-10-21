//! Р-01 · Тесты парсера FPS-1 (`pddl.rs`, 986 строк, ранее 0 тестов).
//!
//! Покрывает: разбор домена/задачи, обе синтаксические формы `:action`,
//! типизированные списки, кванторы, условные эффекты, отклонение конструкций
//! вне FPS-1, канонизацию атомов и диагностику с позицией.
//!
//! Соответствие критериям приёмки: A7 (grammar ⊆ parser), частично A1.

#![allow(clippy::expect_used, clippy::unwrap_used)]
// Тестовый код: expect/unwrap допустимы и предпочтительны —
// падение теста должно быть явным. Продукционный код под deny (§4.3, A6).
use symbolic_core::pddl::{
    self, canon_atom, check_domain, parse_domain, parse_problem, split_atom, Domain, Effect,
    Formula, Term, SUPPORTED_REQUIREMENTS,
};

/// Домен в "плоской" форме `:action` (без внутренних скобок вокруг ключей).
const DOMAIN_FLAT: &str = r#"
(define (domain logistics)
  (:requirements :strips :typing)
  (:types truck place)
  (:predicates (at ?t - truck ?p - place) (road ?a - place ?b - place))
  (:action drive
    :parameters (?t - truck ?a - place ?b - place)
    :precondition (and (at ?t ?a) (road ?a ?b))
    :effect (and (not (at ?t ?a)) (at ?t ?b))))
"#;

/// Тот же домен в "вложенной" форме — обе формы легальны в PDDL.
const DOMAIN_NESTED: &str = r#"
(define (domain logistics)
  (:requirements :strips :typing)
  (:types truck place)
  (:predicates (at ?t - truck ?p - place) (road ?a - place ?b - place))
  (:action drive
    (:parameters (?t - truck ?a - place ?b - place))
    (:precondition (and (at ?t ?a) (road ?a ?b)))
    (:effect (and (not (at ?t ?a)) (at ?t ?b)))))
"#;

const PROBLEM: &str = r#"
(define (problem lp1)
  (:domain logistics)
  (:objects t1 - truck a b c - place)
  (:init (at t1 a) (road a b) (road b c))
  (:goal (at t1 c)))
"#;

// ---------------------------------------------------------------------------
// 1. Базовый разбор
// ---------------------------------------------------------------------------

#[test]
fn parses_flat_action_form() {
    let d: Domain = parse_domain(DOMAIN_FLAT).expect("flat form must parse");
    assert_eq!(d.name, "logistics");
    assert_eq!(d.actions.len(), 1);
    assert_eq!(d.actions[0].name, "drive");
}

#[test]
fn parses_nested_action_form() {
    let d = parse_domain(DOMAIN_NESTED).expect("nested form must parse");
    assert_eq!(d.actions.len(), 1);
    assert_eq!(d.actions[0].name, "drive");
}

/// Обе синтаксические формы обязаны давать СЕМАНТИЧЕСКИ идентичный домен.
/// Это ключевое свойство: constrained decoding (B1) может породить любую из форм,
/// а валидатор (B6) не должен зависеть от выбора.
#[test]
fn both_action_forms_are_equivalent() {
    let flat = parse_domain(DOMAIN_FLAT).expect("flat");
    let nested = parse_domain(DOMAIN_NESTED).expect("nested");

    assert_eq!(flat.name, nested.name);
    assert_eq!(flat.requirements, nested.requirements);
    assert_eq!(flat.actions.len(), nested.actions.len());

    let a = &flat.actions[0];
    let b = &nested.actions[0];
    assert_eq!(a.name, b.name);
    assert_eq!(a.params, b.params, "parameters must match across forms");
    assert_eq!(a.precond, b.precond, "precondition must match across forms");
    assert_eq!(a.effect, b.effect, "effect must match across forms");
    assert_eq!(a.opponent, b.opponent);
}

#[test]
fn requirements_are_collected_without_colon() {
    let d = parse_domain(DOMAIN_FLAT).expect("parse");
    assert_eq!(d.requirements, vec!["strips".to_string(), "typing".to_string()]);
    // Двоеточие снято: иначе сравнение с SUPPORTED_REQUIREMENTS невозможно.
    assert!(d.requirements.iter().all(|r| !r.starts_with(':')));
}

#[test]
fn supported_requirements_are_exactly_the_fps1_set() {
    // Нормативный контракт (Приложение Б, §4.2 ТЗ): 8 требований, closed list.
    let expected = [
        "strips",
        "typing",
        "negative-preconditions",
        "disjunctive-preconditions",
        "universal-preconditions",
        "existential-preconditions",
        "conditional-effects",
        "universal-effects",
    ];
    assert_eq!(SUPPORTED_REQUIREMENTS.len(), expected.len());
    for e in expected {
        assert!(
            SUPPORTED_REQUIREMENTS.contains(&e),
            "FPS-1 must support :{}",
            e
        );
    }
}

// ---------------------------------------------------------------------------
// 2. Типизированные списки и нормализация переменных
// ---------------------------------------------------------------------------

/// Регрессия на исправленный дефект: `parse_typed_pairs` обязан снимать `?`,
/// иначе scope параметров не совпадает с `Term::Var` и любой домен с действием
/// падает в "unbound variable".
#[test]
fn action_parameters_have_question_mark_stripped() {
    let d = parse_domain(DOMAIN_FLAT).expect("parse");
    let params = &d.actions[0].params;
    assert_eq!(params.len(), 3);
    assert_eq!(
        params,
        &vec![
            ("t".to_string(), "truck".to_string()),
            ("a".to_string(), "place".to_string()),
            ("b".to_string(), "place".to_string()),
        ]
    );
    for (v, _) in params {
        assert!(!v.starts_with('?'), "parameter '{}' must not keep '?'", v);
    }
}

#[test]
fn predicate_parameters_have_question_mark_stripped() {
    let d = parse_domain(DOMAIN_FLAT).expect("parse");
    let at = d.predicates.get("at").expect("predicate 'at'");
    assert_eq!(at.len(), 2);
    assert_eq!(at[0].1, "truck");
    assert_eq!(at[1].1, "place");
    for (v, _) in at {
        assert!(!v.starts_with('?'), "predicate param '{}' must not keep '?'", v);
    }
}

#[test]
fn type_table_hierarchy_and_subtype() {
    let clean = r#"
(define (domain hier)
  (:requirements :strips :typing)
  (:types vehicle)
  (:types car - vehicle)
  (:predicates (moving ?v - vehicle))
  (:action go (:parameters (?c - car)) (:precondition (moving ?c)) (:effect (and))))
"#;
    let d = parse_domain(clean).expect("hierarchy must parse");
    assert!(d.types.known("vehicle"));
    assert!(d.types.known("car"));
    assert!(d.types.known("object"), "'object' is the implicit root");
    assert!(!d.types.known("bicycle"));
    assert!(d.types.is_subtype("car", "vehicle"));
    assert!(d.types.is_subtype("car", "object"));
    assert!(d.types.is_subtype("vehicle", "object"));
    assert!(!d.types.is_subtype("vehicle", "car"), "not reversible");
}

#[test]
fn untyped_parameters_default_to_object() {
    let src = r#"
(define (domain untyped)
  (:requirements :strips)
  (:predicates (on ?x ?y))
  (:action move (:parameters (?x ?y)) (:precondition (on ?x ?y)) (:effect (and (not (on ?x ?y))))))
"#;
    let d = parse_domain(src).expect("untyped must parse");
    assert_eq!(d.actions[0].params, vec![
        ("x".to_string(), "object".to_string()),
        ("y".to_string(), "object".to_string()),
    ]);
}

// ---------------------------------------------------------------------------
// 3. Задача: объекты, init, goal
// ---------------------------------------------------------------------------

#[test]
fn parses_problem_objects_and_init() {
    let p = parse_problem(PROBLEM).expect("parse problem");
    assert_eq!(p.name, "lp1");
    assert_eq!(p.domain_name, "logistics");

    // `t1 - truck a b c - place` — группировка типизированного списка
    assert_eq!(p.objects.get("t1").map(String::as_str), Some("truck"));
    assert_eq!(p.objects.get("a").map(String::as_str), Some("place"));
    assert_eq!(p.objects.get("b").map(String::as_str), Some("place"));
    assert_eq!(p.objects.get("c").map(String::as_str), Some("place"));
    assert_eq!(p.objects.len(), 4);

    // init хранится в канонической строковой форме
    assert!(p.init.contains(&canon_atom("at", &["t1".into(), "a".into()])));
    assert!(p.init.contains(&canon_atom("road", &["a".into(), "b".into()])));
    assert!(p.init.contains(&canon_atom("road", &["b".into(), "c".into()])));
    assert_eq!(p.init.len(), 3);
}

#[test]
fn goal_is_parsed_as_formula() {
    let p = parse_problem(PROBLEM).expect("parse");
    match &p.goal {
        Formula::Atom(pred, args) => {
            assert_eq!(pred, "at");
            assert_eq!(args.len(), 2);
            assert!(matches!(&args[0], Term::Const(c) if c == "t1"));
            assert!(matches!(&args[1], Term::Const(c) if c == "c"));
        }
        other => panic!("expected Atom goal, got {:?}", other),
    }
}

#[test]
fn problem_domain_mismatch_is_detected() {
    let d = parse_domain(DOMAIN_FLAT).expect("domain");
    let bad_problem = r#"
(define (problem x)
  (:domain other-domain)
  (:objects t1 - truck a - place)
  (:init (at t1 a))
  (:goal (at t1 a)))
"#;
    let p = parse_problem(bad_problem).expect("problem parses");
    let err = pddl::build_model(d, p).expect_err("domain name mismatch must fail");
    assert_eq!(err.kind, "semantic", "actual kind: {}", err.kind);
}

// ---------------------------------------------------------------------------
// 4. Формулы: отрицание, дизъюнкция, кванторы
// ---------------------------------------------------------------------------

#[test]
fn negative_precondition_parses() {
    let src = r#"
(define (domain neg)
  (:requirements :strips :typing :negative-preconditions)
  (:types box)
  (:predicates (open ?b - box) (locked ?b - box))
  (:action close (:parameters (?b - box))
    (:precondition (and (open ?b) (not (locked ?b))))
    (:effect (and (not (open ?b))))))
"#;
    let d = parse_domain(src).expect("negative precond must parse");
    match &d.actions[0].precond {
        Formula::And(v) => {
            assert_eq!(v.len(), 2);
            assert!(matches!(&v[1], Formula::Not(_)));
        }
        other => panic!("expected And, got {:?}", other),
    }
}

#[test]
fn disjunctive_precondition_parses() {
    let src = r#"
(define (domain disj)
  (:requirements :strips :typing :disjunctive-preconditions)
  (:types loc)
  (:predicates (here ?l - loc) (there ?l - loc))
  (:action go (:parameters (?l - loc))
    (:precondition (or (here ?l) (there ?l)))
    (:effect (and (here ?l)))))
"#;
    let d = parse_domain(src).expect("disjunctive precond must parse");
    assert!(matches!(d.actions[0].precond, Formula::Or(_)));
}

#[test]
fn quantified_preconditions_parse_with_stripped_vars() {
    let src = r#"
(define (domain quant)
  (:requirements :strips :typing :universal-preconditions :existential-preconditions)
  (:types obj box)
  (:predicates (in ?o - obj ?b - box) (free ?b - box) (broken ?o - obj))
  (:action seal (:parameters (?b - box))
    (:precondition (and (forall (?o - obj) (not (broken ?o)))
                        (exists (?f - box) (free ?f))))
    (:effect (and (not (free ?b))))))
"#;
    let d = parse_domain(src).expect("quantifiers must parse");
    match &d.actions[0].precond {
        Formula::And(v) => {
            assert_eq!(v.len(), 2);
            match &v[0] {
                Formula::Forall(vars, _) => {
                    assert_eq!(vars.len(), 1);
                    assert_eq!(vars[0].0, "o", "quantifier var must be stripped of '?'");
                    assert_eq!(vars[0].1, "obj");
                }
                other => panic!("expected Forall, got {:?}", other),
            }
            assert!(matches!(&v[1], Formula::Exists(_, _)));
        }
        other => panic!("expected And, got {:?}", other),
    }
}

#[test]
fn conditional_and_universal_effects_parse() {
    let src = r#"
(define (domain cond)
  (:requirements :strips :typing :conditional-effects :universal-effects)
  (:types obj box)
  (:predicates (fragile ?o - obj) (damaged ?o - obj) (in ?o - obj ?b - box) (empty ?b - box))
  (:action slam (:parameters (?b - box))
    (:precondition (empty ?b))
    (:effect (and (when (empty ?b) (not (empty ?b)))
                  (forall (?o - obj) (when (fragile ?o) (damaged ?o)))))))
"#;
    let d = parse_domain(src).expect("conditional/universal effects must parse");
    match &d.actions[0].effect {
        Effect::And(v) => {
            assert_eq!(v.len(), 2);
            assert!(matches!(&v[0], Effect::When(_, _)));
            match &v[1] {
                Effect::Forall(vars, _) => {
                    assert_eq!(vars[0].0, "o", "effect quantifier var must be stripped");
                }
                other => panic!("expected Effect::Forall, got {:?}", other),
            }
        }
        other => panic!("expected Effect::And, got {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// 5. Отклонение конструкций вне FPS-1 (§4.2 ТЗ)
//
// Это нормативное требование: каждая отклонённая конструкция обязана давать
// machine-readable диагностику, которую repair loop (B2, §7.2) возвращает в SLM.
// ---------------------------------------------------------------------------

fn reject(src: &str, expected_kind: &str, label: &str) {
    match parse_domain(src) {
        Ok(_) => panic!("{} must be REJECTED but was accepted", label),
        Err(e) => {
            assert_eq!(
                e.kind, expected_kind,
                "{}: expected kind '{}', got '{}' ({})",
                label, expected_kind, e.kind, e.message
            );
            assert!(
                !e.message.is_empty(),
                "{}: diagnostic message must not be empty (repair loop needs it)",
                label
            );
        }
    }
}

#[test]
fn rejects_numeric_fluents() {
    reject(
        r#"(define (domain f) (:requirements :strips :fluents)
           (:predicates (p)) (:functions (cost)) (:action a (:parameters ()) (:precondition (p)) (:effect (and))))"#,
        "semantic",
        "numeric fluents",
    );
}

#[test]
fn rejects_unsupported_requirement() {
    reject(
        r#"(define (domain f) (:requirements :strips :adl)
           (:predicates (p)) (:action a (:parameters ()) (:precondition (p)) (:effect (and))))"#,
        "semantic",
        ":adl requirement",
    );
}

#[test]
fn rejects_durative_actions() {
    reject(
        r#"(define (domain f) (:requirements :strips :durative-actions)
           (:predicates (p))
           (:durative-action a (:parameters ()) (:duration (= ?d 5))
             (:condition (at start (p))) (:effect (and (at end (p))))))"#,
        "semantic",
        "durative actions",
    );
}

#[test]
fn rejects_constants_section() {
    reject(
        r#"(define (domain f) (:requirements :strips :typing)
           (:types t) (:constants c - t) (:predicates (p ?x - t))
           (:action a (:parameters (?x - t)) (:precondition (p ?x)) (:effect (and))))"#,
        "semantic",
        ":constants",
    );
}

#[test]
fn rejects_derived_predicates() {
    reject(
        r#"(define (domain f) (:requirements :strips)
           (:predicates (p) (q))
           (:derived (q) (p))
           (:action a (:parameters ()) (:precondition (p)) (:effect (and))))"#,
        "semantic",
        ":derived",
    );
}

#[test]
fn rejects_disjunctive_effects() {
    // ВАЖНО не путать: :disjunctive-preconditions ПОДДЕРЖИВАЕТСЯ,
    // дизъюнктивные ЭФФЕКТЫ — нет (недетерминизм несовместим с G2/G3).
    reject(
        r#"(define (domain f) (:requirements :strips :disjunctive-effects)
           (:predicates (p) (q))
           (:action a (:parameters ()) (:precondition (p)) (:effect (or (q) (p)))))"#,
        "semantic",
        "disjunctive effects",
    );
}

#[test]
fn rejects_empty_domain_file() {
    let e = parse_domain("").expect_err("empty input must fail");
    assert_eq!(e.kind, "parse");
}

#[test]
fn rejects_missing_define_wrapper() {
    let e = parse_domain("(domain foo)").expect_err("must require (define ...)");
    assert_eq!(e.kind, "parse");
}

#[test]
fn rejects_undeclared_predicate_in_precondition() {
    let src = r#"
(define (domain f)
  (:requirements :strips :typing)
  (:types t)
  (:predicates (known ?x - t))
  (:action a (:parameters (?x - t)) (:precondition (unknown ?x)) (:effect (and))))
"#;
    let d = parse_domain(src).expect("parses structurally");
    let prob = r#"
(define (problem p) (:domain f) (:objects o - t) (:init (known o)) (:goal (known o)))
"#;
    let p = parse_problem(prob).expect("problem");
    let e = pddl::build_model(d, p).expect_err("undeclared predicate must fail");
    assert_eq!(e.kind, "semantic");
    assert!(e.message.contains("undeclared predicate"), "msg: {}", e.message);
}

#[test]
fn rejects_type_error_in_atom() {
    let src = r#"
(define (domain f)
  (:requirements :strips :typing)
  (:types truck place)
  (:predicates (at ?t - truck ?p - place))
  (:action a (:parameters (?p - place)) (:precondition (at ?p ?p)) (:effect (and))))
"#;
    let d = parse_domain(src).expect("parses");
    let prob = r#"(define (problem p) (:domain f) (:objects t1 - truck a - place)
                    (:init (at t1 a)) (:goal (at t1 a)))"#;
    let p = parse_problem(prob).expect("problem");
    let e = pddl::build_model(d, p).expect_err("type error must fail");
    assert_eq!(e.kind, "semantic");
    assert!(e.message.contains("type error"), "msg: {}", e.message);
}

#[test]
fn rejects_unbound_variable_in_precondition() {
    // Регрессия: этот тест ловит исходный дефект нормализации '?'.
    // При корректной нормализации '?zz' действительно не объявлен -> ошибка.
    let src = r#"
(define (domain f)
  (:requirements :strips :typing)
  (:types t)
  (:predicates (p ?x - t))
  (:action a (:parameters (?x - t)) (:precondition (p ?zz)) (:effect (and))))
"#;
    let d = parse_domain(src).expect("parses");
    let prob = r#"(define (problem q) (:domain f) (:objects o - t) (:init (p o)) (:goal (p o)))"#;
    let p = parse_problem(prob).expect("problem");
    let e = pddl::build_model(d, p).expect_err("unbound var must fail");
    assert_eq!(e.kind, "semantic");
    assert!(e.message.contains("unbound variable"), "msg: {}", e.message);
}

#[test]
fn rejects_duplicate_parameter() {
    let src = r#"
(define (domain f)
  (:requirements :strips :typing)
  (:types t)
  (:predicates (p ?x - t))
  (:action a (:parameters (?x - t ?x - t)) (:precondition (p ?x)) (:effect (and))))
"#;
    let d = parse_domain(src).expect("parses");
    let prob = r#"(define (problem q) (:domain f) (:objects o - t) (:init (p o)) (:goal (p o)))"#;
    let p = parse_problem(prob).expect("problem");
    let e = pddl::build_model(d, p).expect_err("duplicate param must fail");
    assert_eq!(e.kind, "semantic");
    assert!(e.message.contains("twice"), "msg: {}", e.message);
}

// ---------------------------------------------------------------------------
// 6. Канонизация атомов (основа G3: State хранит BTreeSet канонических строк)
// ---------------------------------------------------------------------------

#[test]
fn canon_atom_is_stable_and_order_sensitive() {
    let a = canon_atom("at", &["t1".into(), "a".into()]);
    let b = canon_atom("at", &["t1".into(), "a".into()]);
    assert_eq!(a, b, "canon_atom must be deterministic");

    // Порядок аргументов значим: его изменение даёт ДРУГОЙ атом.
    let swapped = canon_atom("at", &["a".into(), "t1".into()]);
    assert_ne!(a, swapped, "argument order must be significant");
}

#[test]
fn split_atom_roundtrips_canon_atom() {
    let atom = canon_atom("road", &["a".into(), "b".into()]);
    let (pred, args) = split_atom(&atom).expect("split");
    assert_eq!(pred, "road");
    assert_eq!(args, vec!["a".to_string(), "b".to_string()]);
    assert_eq!(canon_atom(&pred, &args), atom, "roundtrip must be exact");
}

#[test]
fn split_atom_handles_zero_args() {
    let atom = canon_atom("ready", &[]);
    let (pred, args) = split_atom(&atom).expect("split");
    assert_eq!(pred, "ready");
    assert!(args.is_empty());
}

// ---------------------------------------------------------------------------
// 7. Позиционная диагностика (нужна для repair loop, §7.2)
// ---------------------------------------------------------------------------

#[test]
fn syntax_error_carries_position() {
    // Незакрытая скобка -> ошибка с Pos
    let e = parse_domain("(define (domain f (:requirements :strips))").expect_err("unbalanced");
    assert_eq!(e.kind, "parse");
    assert!(e.pos.is_some(), "parse error must carry a position for the repair loop");
    let pos = e.pos.unwrap();
    assert!(pos.line >= 1 && pos.col >= 1, "pos must be 1-based: {:?}", pos);
}

#[test]
fn requirement_error_carries_position() {
    let e = parse_domain(
        r#"(define (domain f)
  (:requirements :strips :fluents)
  (:predicates (p)))"#,
    )
    .expect_err("unsupported requirement");
    assert_eq!(e.kind, "semantic");
    assert!(e.pos.is_some(), "semantic error should carry position");
}

#[test]
fn check_domain_matches_parse_domain() {
    // check_domain — публичная точка входа CLI `flicker-plan check`
    let d1 = check_domain(DOMAIN_FLAT).expect("check_domain");
    let d2 = parse_domain(DOMAIN_FLAT).expect("parse_domain");
    assert_eq!(d1.name, d2.name);
    assert_eq!(d1.requirements, d2.requirements);
    assert_eq!(d1.actions.len(), d2.actions.len());
}

// ---------------------------------------------------------------------------
// 8. load() — сквозная сборка модели
// ---------------------------------------------------------------------------

#[test]
fn load_builds_full_model() {
    let m = pddl::load(DOMAIN_FLAT, PROBLEM).expect("load");
    assert_eq!(m.domain.name, "logistics");
    assert_eq!(m.problem.name, "lp1");
    assert_eq!(m.object_types.len(), 4);
    assert!(m.objects_by_type.contains_key("truck"));
    assert!(m.objects_by_type.contains_key("place"));
    assert_eq!(m.objects_by_type["place"], vec!["a", "b", "c"]);
    assert_eq!(m.objects_by_type["truck"], vec!["t1"]);
}

#[test]
fn model_object_typing_and_type_hierarchy() {
    let m = pddl::load(DOMAIN_FLAT, PROBLEM).expect("load");

    // `Model::is_subtype` delegates to `TypeTable::is_subtype`, i.e. it compares
    // TYPES, not object names. Object typing lives in `object_types`.
    assert_eq!(m.object_types.get("t1").map(String::as_str), Some("truck"));
    assert_eq!(m.object_types.get("a").map(String::as_str), Some("place"));

    // type hierarchy
    assert!(m.is_subtype("truck", "object"));
    assert!(m.is_subtype("place", "object"));
    assert!(!m.is_subtype("truck", "place"));

    // objects_of_type is the correct way to enumerate by type
    assert_eq!(m.objects_of_type("truck"), &["t1".to_string()]);
    assert_eq!(
        m.objects_of_type("place"),
        &["a".to_string(), "b".to_string(), "c".to_string()]
    );
    assert!(m.objects_of_type("nonexistent").is_empty());
}

#[test]
fn model_objects_listing_is_sorted() {
    // Детерминизм (G3): перечисление объектов обязано быть канонически
    // упорядочено, иначе порядок grounding'а зависит от обхода BTreeMap.
    let m = pddl::load(DOMAIN_FLAT, PROBLEM).expect("load");
    let objs = m.objects();
    let mut sorted = objs.clone();
    sorted.sort();
    assert_eq!(objs, sorted, "objects() must be canonically ordered");
}

#[test]
fn comments_and_case_insensitivity() {
    // PDDL регистронезависимен; комментарии ';' обязаны игнорироваться.
    let src = r#"; leading comment
(DEFINE (DOMAIN MixedCase)          ; inline comment
  (:REQUIREMENTS :strips :typing)
  (:types Thing)
  (:predicates (Ready ?x - Thing))
  (:action Do (:parameters (?x - Thing))
    (:precondition (READY ?x))
    (:effect (and (not (ready ?x))))))
"#;
    let d = parse_domain(src).expect("case-insensitive parse with comments");
    assert_eq!(d.name, "mixedcase", "atoms are lowercased at lex time");
    assert_eq!(d.actions.len(), 1);
}

#[test]
fn unbalanced_parens_are_rejected() {
    // Genuinely unbalanced: the final `)` closing `(define` is missing.
    let src = r#"
(define (domain broken
  (:requirements :strips :typing)
  (:types loc)
  (:predicates (at ?l - loc))
  (:action move (:parameters (?l - loc)) (:precondition (at ?l)) (:effect (and))))
"#;
    let e = parse_domain(src).expect_err("missing closing paren must fail");
    assert_eq!(e.kind, "parse", "actual: {} / {}", e.kind, e.message);
}

#[test]
fn multiple_actions_all_parsed() {
    let ok = r#"
(define (domain multi)
  (:requirements :strips :typing)
  (:types loc agent)
  (:predicates (at ?a - agent ?l - loc) (adj ?x - loc ?y - loc) (tired ?a - agent))
  (:action move (:parameters (?a - agent ?x - loc ?y - loc))
    (:precondition (and (at ?a ?x) (adj ?x ?y) (not (tired ?a))))
    (:effect (and (not (at ?a ?x)) (at ?a ?y))))
  (:action rest (:parameters (?a - agent ?l - loc))
    (:precondition (and (at ?a ?l) (tired ?a)))
    (:effect (and (not (tired ?a))))))
"#;
    let d = parse_domain(ok).expect("two actions must parse");
    assert_eq!(d.actions.len(), 2);
    assert_eq!(d.actions[0].name, "move");
    assert_eq!(d.actions[1].name, "rest");
    // оба действия разобраны полностью, не только первое
    assert_eq!(d.actions[0].params.len(), 3);
    assert_eq!(d.actions[1].params.len(), 2);
    assert!(!matches!(d.actions[1].effect, Effect::Nil), "rest must have an effect");
}

#[test]
fn opponent_flag_defaults_false_and_parses() {
    let src = r#"
(define (domain adv)
  (:requirements :strips :typing)
  (:types loc)
  (:predicates (occupied ?l - loc))
  (:action block (:parameters (?l - loc)) :opponent
    (:precondition (and)) (:effect (and (occupied ?l)))))
"#;
    match parse_domain(src) {
        Ok(d) => assert!(d.actions[0].opponent, ":opponent must set the flag"),
        Err(e) => panic!(":opponent (ADM extension) should parse: {} {}", e.kind, e.message),
    }
}
