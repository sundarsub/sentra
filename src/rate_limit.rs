use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Per-identity rate limiter using sliding window algorithm
pub struct RateLimiter {
    /// Maximum commands per window
    max_commands: u32,
    /// Window duration
    window: Duration,
    /// Command timestamps per identity
    timestamps: HashMap<String, Vec<Instant>>,
}

impl RateLimiter {
    /// Create a new rate limiter
    pub fn new(max_commands: u32, window_seconds: u64) -> Self {
        RateLimiter {
            max_commands,
            window: Duration::from_secs(window_seconds),
            timestamps: HashMap::new(),
        }
    }

    /// Check if an identity is rate limited
    /// Returns Ok(remaining) if allowed, Err(wait_seconds) if rate limited
    pub fn check(&mut self, identity: &str) -> Result<u32, u64> {
        let now = Instant::now();
        let window_start = now - self.window;

        // Get or create timestamps for this identity
        let timestamps = self.timestamps.entry(identity.to_string()).or_default();

        // Remove timestamps outside the window
        timestamps.retain(|&t| t > window_start);

        let count = timestamps.len() as u32;

        if count >= self.max_commands {
            // Calculate when the oldest command will expire
            if let Some(&oldest) = timestamps.first() {
                let wait = (oldest + self.window).duration_since(now);
                return Err(wait.as_secs() + 1);
            }
            return Err(self.window.as_secs());
        }

        Ok(self.max_commands - count)
    }

    /// Record a command execution for an identity
    pub fn record(&mut self, identity: &str) {
        let timestamps = self.timestamps.entry(identity.to_string()).or_default();
        timestamps.push(Instant::now());
    }

    /// Get current usage for an identity
    pub fn usage(&self, identity: &str) -> (u32, u32) {
        let now = Instant::now();
        let window_start = now - self.window;

        let count = self.timestamps
            .get(identity)
            .map(|ts| ts.iter().filter(|&&t| t > window_start).count() as u32)
            .unwrap_or(0);

        (count, self.max_commands)
    }

    /// Get window duration in seconds
    pub fn window_seconds(&self) -> u64 {
        self.window.as_secs()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_rate_limiter_allows_within_limit() {
        let mut limiter = RateLimiter::new(5, 60);

        for _ in 0..5 {
            assert!(limiter.check("user1").is_ok());
            limiter.record("user1");
        }
    }

    #[test]
    fn test_rate_limiter_blocks_over_limit() {
        let mut limiter = RateLimiter::new(3, 60);

        for _ in 0..3 {
            limiter.record("user1");
        }

        assert!(limiter.check("user1").is_err());
    }

    #[test]
    fn test_rate_limiter_per_identity() {
        let mut limiter = RateLimiter::new(2, 60);

        limiter.record("user1");
        limiter.record("user1");
        limiter.record("user2");

        assert!(limiter.check("user1").is_err());
        assert!(limiter.check("user2").is_ok());
    }

    #[test]
    fn test_rate_limiter_window_expiry() {
        let mut limiter = RateLimiter::new(2, 1); // 1 second window

        limiter.record("user1");
        limiter.record("user1");

        assert!(limiter.check("user1").is_err());

        // Wait for window to expire
        thread::sleep(Duration::from_secs(2));

        assert!(limiter.check("user1").is_ok());
    }
}
