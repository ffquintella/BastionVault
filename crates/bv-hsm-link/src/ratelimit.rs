//! Per-client request-rate limit for the gateway.

use std::time::Instant;

/// A token bucket holding at most one second's worth of requests.
///
/// Time is passed in, so the tests drive it with constructed instants and
/// never sleep.
#[derive(Debug)]
pub(crate) struct TokenBucket {
    capacity: f64,
    refill_per_sec: f64,
    tokens: f64,
    last: Instant,
}

impl TokenBucket {
    /// A full bucket admitting `per_second` requests per second (at least 1).
    pub(crate) fn new(per_second: u32, now: Instant) -> Self {
        let rate = f64::from(per_second.max(1));
        Self { capacity: rate, refill_per_sec: rate, tokens: rate, last: now }
    }

    /// Takes one token if there is one.
    pub(crate) fn try_take(&mut self, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_per_sec).min(self.capacity);
        self.last = self.last.max(now);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn admits_a_burst_of_one_second_then_refuses() {
        let t0 = Instant::now();
        let mut bucket = TokenBucket::new(3, t0);
        assert!(bucket.try_take(t0));
        assert!(bucket.try_take(t0));
        assert!(bucket.try_take(t0));
        assert!(!bucket.try_take(t0), "the fourth request in the same instant must be refused");
    }

    #[test]
    fn refills_at_the_configured_rate_and_caps_at_capacity() {
        let t0 = Instant::now();
        let mut bucket = TokenBucket::new(2, t0);
        assert!(bucket.try_take(t0));
        assert!(bucket.try_take(t0));
        assert!(!bucket.try_take(t0));
        // Half a second at 2/s refills exactly one token.
        let t1 = t0 + Duration::from_millis(500);
        assert!(bucket.try_take(t1));
        assert!(!bucket.try_take(t1));
        // A long idle period refills to capacity, not beyond.
        let t2 = t1 + Duration::from_secs(60);
        assert!(bucket.try_take(t2));
        assert!(bucket.try_take(t2));
        assert!(!bucket.try_take(t2));
    }

    #[test]
    fn a_clock_going_backwards_does_not_mint_tokens() {
        let t0 = Instant::now() + Duration::from_secs(10);
        let mut bucket = TokenBucket::new(1, t0);
        assert!(bucket.try_take(t0));
        assert!(!bucket.try_take(t0 - Duration::from_secs(5)));
        assert!(!bucket.try_take(t0));
    }

    #[test]
    fn zero_is_treated_as_one_per_second() {
        let t0 = Instant::now();
        let mut bucket = TokenBucket::new(0, t0);
        assert!(bucket.try_take(t0));
        assert!(!bucket.try_take(t0));
    }
}
