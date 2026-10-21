;; FLICKER V30 — blocks с отрицательными предусловиями (:negative-preconditions)
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
