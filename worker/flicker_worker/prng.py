"""Детерминированный ГПСЧ — зеркало `symbolic_core::prng::Xorshift64Star`.

Нужен там, где воспроизводимость важна вне ядра: генерация red-team сценариев
(§12.6) и любых тестовых корпусов. Алгоритм и семантика `next_below`
(Lemire, без modulo bias) совпадают с Rust-реализацией, поэтому один и тот же
seed даёт одну и ту же последовательность в обоих языках.

Python не имеет u64-типа, поэтому все операции маскируются в 64 бита.
"""
from __future__ import annotations

__all__ = ["Xorshift", "M64"]

M64 = 0xFFFF_FFFF_FFFF_FFFF


class Xorshift:
    """xorshift64* — тот же алгоритм, что `Xorshift64Star` в `prng.rs`."""

    __slots__ = ("_state",)

    def __init__(self, seed: int):
        # Seed 0 вырождает xorshift в постоянный ноль — в Rust-реализации
        # то же ограничение; нормализуем одинаково с обеих сторон.
        s = seed & M64
        self._state = s if s != 0 else 0x9E37_79B9_7F4A_7C15

    def next_u64(self) -> int:
        x = self._state
        x ^= (x >> 12) & M64
        x &= M64
        x ^= (x << 25) & M64
        x &= M64
        x ^= (x >> 27) & M64
        x &= M64
        self._state = x
        return (x * 0x2545_F491_4F6C_DD1D) & M64

    def next_below(self, n: int) -> int:
        """Равномерно в [0, n) без modulo bias (метод Lemire).

        Зеркало `Xorshift64Star::next_below`: умножение в 128 бит, отбрасывание
        младших 64 бит, отклонение первых значений для выравнивания.
        """
        if n <= 0:
            return 0
        n &= M64
        x = self.next_u64()
        m = x * n                      # до 128 бит — Python держит точно
        low = m & M64
        if low < n:
            t = ((~n) + 1) & M64       # (-n) mod 2^64
            t = t % n
            while low < t:
                x = self.next_u64()
                m = x * n
                low = m & M64
        return (m >> 64) & M64

    # --- удобные обёртки для генераторов сценариев ---
    def below(self, n: int) -> int:
        """То же, что `next_below`, но имя короче для читаемости."""
        return self.next_below(n)

    def choice(self, xs):
        if not xs:
            raise IndexError("choice from empty sequence")
        return xs[self.next_below(len(xs))]

    def chance(self, pct: int) -> bool:
        return self.next_below(100) < pct

    def state(self) -> int:
        return self._state
