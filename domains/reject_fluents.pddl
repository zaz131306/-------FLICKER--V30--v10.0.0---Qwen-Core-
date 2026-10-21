;; НАМЕРЕННО вне FPS-1: :fluents обязаны отклоняться барьером B2 с kind=semantic
(define (domain bad_fluents)
  (:requirements :strips :fluents)
  (:predicates (p))
  (:functions (cost))
  (:action a (:parameters ()) (:precondition (p)) (:effect (and))))
