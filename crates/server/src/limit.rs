//! Per client request limit. Signatures cannot be guessed, so this is not
//! what keeps approvals safe; it keeps one noisy client from starving others.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Instant;

const MAX_TRACKED: usize = 50_000;

pub struct Limiter {
    per_minute: u32,
    buckets: Mutex<HashMap<IpAddr, (f64, Instant)>>,
}

impl Limiter {
    /// `per_minute` of zero disables the limit.
    pub fn new(per_minute: u32) -> Self {
        Limiter {
            per_minute,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Token bucket: a full minute of budget may be spent at once, then it
    /// refills evenly.
    pub fn allow(&self, client: IpAddr, now: Instant) -> bool {
        if self.per_minute == 0 {
            return true;
        }
        let capacity = f64::from(self.per_minute);
        let mut buckets = self.buckets.lock().unwrap_or_else(|p| p.into_inner());
        if buckets.len() >= MAX_TRACKED && !buckets.contains_key(&client) {
            // Forget clients whose budget has fully refilled.
            buckets.retain(|_, (tokens, last)| {
                *tokens + now.duration_since(*last).as_secs_f64() * capacity / 60.0 < capacity
            });
            if buckets.len() >= MAX_TRACKED {
                return false;
            }
        }
        let (tokens, last) = buckets.entry(client).or_insert((capacity, now));
        let refill = now.saturating_duration_since(*last).as_secs_f64() * capacity / 60.0;
        *tokens = (*tokens + refill).min(capacity);
        *last = now;
        if *tokens >= 1.0 {
            *tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn budget_is_per_client_and_refills() {
        let limiter = Limiter::new(60);
        let a: IpAddr = "10.0.0.1".parse().unwrap();
        let b: IpAddr = "10.0.0.2".parse().unwrap();
        let start = Instant::now();
        assert!((0..60).all(|_| limiter.allow(a, start)));
        assert!(!limiter.allow(a, start));
        assert!(limiter.allow(b, start), "another client is unaffected");
        assert!(
            limiter.allow(a, start + Duration::from_secs(1)),
            "one token per second"
        );
        assert!(!limiter.allow(a, start + Duration::from_secs(1)));
        assert!((0..60).all(|_| limiter.allow(a, start + Duration::from_secs(600))));
    }

    #[test]
    fn zero_disables() {
        let limiter = Limiter::new(0);
        let a: IpAddr = "10.0.0.1".parse().unwrap();
        assert!((0..10_000).all(|_| limiter.allow(a, Instant::now())));
    }
}
