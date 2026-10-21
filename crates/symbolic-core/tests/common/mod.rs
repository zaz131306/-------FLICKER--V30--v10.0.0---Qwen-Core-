//! Общие фикстуры для интеграционных тестов `symbolic-core`.
//!
//! Каталог `tests/common/` не компилируется как отдельный test target,
//! поэтому подключается через `mod common;` из каждого теста.

#![allow(clippy::expect_used, clippy::unwrap_used)]
// Тестовый код: expect/unwrap допустимы и предпочтительны —
// падение теста должно быть явным. Продукционный код под deny (§4.3, A6).
#![allow(dead_code)]

use symbolic_core::ground::{ground_actions, GroundAction};
use symbolic_core::pddl::{self, Model};

/// Логистика: грузовик ездит по дороге между точками.
/// План существует и требует ровно 2 шага (a→b→c).
pub const LOGISTICS_DOMAIN: &str = r#"
(define (domain logistics)
  (:requirements :strips :typing)
  (:types truck place)
  (:predicates (at ?t - truck ?p - place) (road ?a - place ?b - place))
  (:action drive
    (:parameters (?t - truck ?a - place ?b - place))
    (:precondition (and (at ?t ?a) (road ?a ?b)))
    (:effect (and (not (at ?t ?a)) (at ?t ?b)))))
"#;

pub const LOGISTICS_PROBLEM: &str = r#"
(define (problem lp1)
  (:domain logistics)
  (:objects t1 - truck a b c - place)
  (:init (at t1 a) (road a b) (road b c))
  (:goal (at t1 c)))
"#;

/// Задача, в которой цель УЖЕ достигнута в `:init` — план должен быть пустым.
pub const TRIVIAL_PROBLEM: &str = r#"
(define (problem lp0)
  (:domain logistics)
  (:objects t1 - truck a b - place)
  (:init (at t1 a) (road a b))
  (:goal (at t1 a)))
"#;

/// Задача БЕЗ решения: дороги из `a` в `c` нет.
pub const UNSOLVABLE_PROBLEM: &str = r#"
(define (problem lp_none)
  (:domain logistics)
  (:objects t1 - truck a c - place)
  (:init (at t1 a))
  (:goal (at t1 c)))
"#;

/// Блоки: классический towers-of-hanoi-подобный домен с отрицательными
/// предусловиями. Требует поиска глубже 2 шагов.
pub const BLOCKS_DOMAIN: &str = r#"
(define (domain blocks)
  (:requirements :strips :typing :negative-preconditions)
  (:types block)
  (:predicates (on ?x - block ?y - block) (ontable ?x - block)
               (clear ?x - block) (handempty))
  (:action pickup
    (:parameters (?x - block))
    (:precondition (and (ontable ?x) (clear ?x) (handempty)))
    (:effect (and (not (ontable ?x)) (not (clear ?x)) (not (handempty)))))
  (:action putdown
    (:parameters (?x - block))
    (:precondition (and (not (ontable ?x)) (not (handempty))))
    (:effect (and (ontable ?x) (clear ?x) (handempty))))
  (:action stack
    (:parameters (?x - block ?y - block))
    (:precondition (and (not (ontable ?x)) (clear ?y) (not (handempty))))
    (:effect (and (on ?x ?y) (clear ?x) (handempty) (not (clear ?y)))))
  (:action unstack
    (:parameters (?x - block ?y - block))
    (:precondition (and (on ?x ?y) (clear ?x) (handempty)))
    (:effect (and (not (on ?x ?y)) (not (clear ?x)) (clear ?y) (ontable ?x)))))
"#;

pub const BLOCKS_PROBLEM: &str = r#"
(define (problem blocks2)
  (:domain blocks)
  (:objects b1 b2 - block)
  (:init (ontable b1) (ontable b2) (clear b1) (clear b2) (handempty))
  (:goal (on b1 b2)))
"#;

/// Домен с кванторами и условными эффектами — проверяет, что планировщик
/// работает не только с чистым STRIPS.
pub const QUANT_DOMAIN: &str = r#"
(define (domain warehouse)
  (:requirements :strips :typing :negative-preconditions
                 :universal-preconditions :conditional-effects)
  (:types crate pallet zone)
  (:predicates (in ?c - crate ?z - zone) (sealed ?z - zone)
               (fragile ?c - crate) (damaged ?c - crate) (allclear))
  (:action seal-zone
    (:parameters (?z - zone))
    (:precondition (and (forall (?c - crate) (not (damaged ?c))) (not (sealed ?z))))
    (:effect (and (sealed ?z)
                  (forall (?c - crate) (when (and (in ?c ?z) (fragile ?c)) (damaged ?c)))))))
"#;

pub const QUANT_PROBLEM: &str = r#"
(define (problem wh1)
  (:domain warehouse)
  (:objects c1 c2 - crate z1 - zone)
  (:init (in c1 z1) (fragile c1) (allclear))
  (:goal (sealed z1)))
"#;

pub fn logistics() -> (Model, Vec<GroundAction>) {
    build(LOGISTICS_DOMAIN, LOGISTICS_PROBLEM)
}

pub fn trivial() -> (Model, Vec<GroundAction>) {
    build(LOGISTICS_DOMAIN, TRIVIAL_PROBLEM)
}

pub fn unsolvable() -> (Model, Vec<GroundAction>) {
    build(LOGISTICS_DOMAIN, UNSOLVABLE_PROBLEM)
}

pub fn blocks() -> (Model, Vec<GroundAction>) {
    build(BLOCKS_DOMAIN, BLOCKS_PROBLEM)
}

pub fn quantified() -> (Model, Vec<GroundAction>) {
    build(QUANT_DOMAIN, QUANT_PROBLEM)
}

pub fn build(domain_src: &str, problem_src: &str) -> (Model, Vec<GroundAction>) {
    let m = pddl::load(domain_src, problem_src).expect("model must build");
    let g = ground_actions(&m).expect("grounding must succeed");
    assert!(!g.is_empty(), "grounding produced no actions");
    (m, g)
}

/// Каноническая строковая форма плана — для сравнения на детерминизм.
pub fn plan_signature(steps: &[symbolic_core::validator::PlanStep]) -> String {
    steps
        .iter()
        .map(|s| s.key())
        .collect::<Vec<_>>()
        .join(" ; ")
}
