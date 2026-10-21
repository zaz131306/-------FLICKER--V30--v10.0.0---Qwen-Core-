//! Deterministic PRNG (xorshift64*) — the single source of randomness for
//! MCTS. Seeded runs are bit-reproducible (single-threaded by design,
//! see docs/adr/0006-deterministic-replay.md).
//!
//! The same recurrence is implemented in the Python reference worker;
//! conformance is pinned by tests/vectors/prng.json.

#[derive(Debug, Clone)]
pub struct Xorshift64Star {
    state: u64,
}

impl Xorshift64Star {
    /// Seed MUST be non-zero; seed 0 is remapped to a fixed non-zero value.
    pub fn new(seed: u64) -> Self {
        let s = if seed == 0 { 0x9E3779B97F4A7C15 } else { seed };
        Self { state: s }
    }

    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }

    /// Uniform value in [0, n) without modulo bias (Lemire's method).
    pub fn next_below(&mut self, n: u64) -> u64 {
        if n == 0 {
            return 0;
        }
        let x = self.next_u64();
        let mut m = (x as u128) * (n as u128);
        let mut l = m as u64;
        if l < n {
            let t = (!n).wrapping_add(1) % n;
            while l < t {
                let x2 = self.next_u64();
                m = (x2 as u128) * (n as u128);
                l = m as u64;
            }
        }
        (m >> 64) as u64
    }

    pub fn state(&self) -> u64 {
        self.state
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_sequence() {
        let mut a = Xorshift64Star::new(42);
        let mut b = Xorshift64Star::new(42);
        for _ in 0..1000 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }

    #[test]
    fn different_seeds_diverge() {
        let mut a = Xorshift64Star::new(1);
        let mut b = Xorshift64Star::new(2);
        assert_ne!(a.next_u64(), b.next_u64());
    }

    #[test]
    fn zero_seed_remapped() {
        let mut a = Xorshift64Star::new(0);
        assert_ne!(a.state, 0);
        assert!(a.next_u64() != 0);
    }

    #[test]
    fn below_range() {
        let mut r = Xorshift64Star::new(7);
        for _ in 0..10_000 {
            let v = r.next_below(10);
            assert!(v < 10);
        }
        assert_eq!(r.next_below(0), 0);
        assert_eq!(r.next_below(1), 0);
    }
}
