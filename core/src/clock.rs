//! Wall clock that also works in the browser (WebAssembly has no `SystemTime`).

use std::time::Duration;

#[cfg(not(target_arch = "wasm32"))]
use std::time::{SystemTime, UNIX_EPOCH};
#[cfg(target_arch = "wasm32")]
use web_time::{SystemTime, UNIX_EPOCH};

/// `None` if the clock is before 1970 (callers fall back to 0).
pub(crate) fn since_epoch() -> Option<Duration> {
    SystemTime::now().duration_since(UNIX_EPOCH).ok()
}
