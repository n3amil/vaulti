//! Hybrid logical clock stamps for last-writer-wins merging.
//!
//! Ordered by (wall-clock ms, counter, device id): a device's stamps always
//! increase even if its clock goes backwards, and ties between devices are
//! broken deterministically.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Stamp {
    pub ms: u64,
    pub ctr: u32,
    pub device: Uuid,
}

impl Stamp {
    pub const ZERO: Stamp = Stamp { ms: 0, ctr: 0, device: Uuid::nil() };

    pub fn secs(&self) -> u64 {
        self.ms / 1000
    }

    /// Unique text form, e.g. to name one version of an entry.
    pub fn id(&self) -> String {
        format!("{}-{}-{}", self.ms, self.ctr, self.device.simple())
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Clock {
    pub last: Stamp,
}

impl Clock {
    pub fn new(device: Uuid) -> Self {
        Self { last: Stamp { device, ..Stamp::ZERO } }
    }

    pub fn tick(&mut self) -> Stamp {
        let now = now_ms();
        let (ms, ctr) = if now > self.last.ms { (now, 0) } else { (self.last.ms, self.last.ctr + 1) };
        self.last = Stamp { ms, ctr, device: self.last.device };
        self.last
    }

    /// Advance past a stamp seen from another device.
    pub fn observe(&mut self, s: Stamp) {
        if (s.ms, s.ctr) > (self.last.ms, self.last.ctr) {
            self.last = Stamp { ms: s.ms, ctr: s.ctr, device: self.last.device };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn monotonic_and_observes() {
        let mut c = Clock::new(Uuid::new_v4());
        let a = c.tick();
        let b = c.tick();
        assert!(b > a);
        let future = Stamp { ms: a.ms + 1_000_000, ctr: 5, device: Uuid::new_v4() };
        c.observe(future);
        let d = c.tick();
        assert!(d.ms == future.ms && d.ctr == 6);
    }
}
