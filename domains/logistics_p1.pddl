;; Задача: перевезти t1 из a в c через b. Оптимальный план — 2 шага.
(define (problem logistics_p1)
  (:domain logistics)
  (:objects t1 - truck a b c - place)
  (:init (at t1 a) (road a b) (road b c))
  (:goal (at t1 c)))
