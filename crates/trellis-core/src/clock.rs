//! Clocks. All deadline authority is CLOCK_BOOTTIME nanoseconds (spec §3.1);
//! UTC is informational only and may regress without authority change.

/// CLOCK_BOOTTIME id on Linux.
const CLOCK_BOOTTIME: libc::clockid_t = 7;

pub trait Clock: Send {
    /// CLOCK_BOOTTIME nanoseconds.
    fn boot_ns(&mut self) -> u64;
    /// Informational UTC instant (YYYY-MM-DDTHH:mm:ss.sssZ).
    fn wall_utc(&mut self) -> String;
}

/// Real host clock.
pub struct BootClock;

impl Clock for BootClock {
    fn boot_ns(&mut self) -> u64 {
        boottime_ns()
    }
    fn wall_utc(&mut self) -> String {
        wall_utc_now()
    }
}

pub fn boottime_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe {
        libc::clock_gettime(CLOCK_BOOTTIME, &mut ts);
    }
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

pub fn wall_utc_now() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let ms = now.as_millis() as u64;
    let secs = ms / 1000;
    let sub = ms % 1000;
    let (y, mo, d, h, mi, s) = civil_from_unix(secs);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        y, mo, d, h, mi, s, sub
    )
}

fn civil_from_unix(secs: u64) -> (u64, u64, u64, u64, u64, u64) {
    let days = secs / 86400;
    let rem = secs % 86400;
    let (h, mi, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    // Howard Hinnant's civil-from-days algorithm.
    let z = days as i64 + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mo <= 2 { y + 1 } else { y };
    (y as u64, mo, d, h, mi, s)
}

/// Deterministic clock for the conformance harness: BOOTTIME is set exactly
/// by `timer(t)`; UTC defaults to the fixture instant and only changes via
/// `wall(t)`.
pub struct FakeClock {
    pub now: u64,
    pub wall: String,
}

impl FakeClock {
    pub fn new() -> Self {
        FakeClock {
            now: 0,
            wall: crate::fixtures::wall_time().to_string(),
        }
    }
}

impl Default for FakeClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for FakeClock {
    fn boot_ns(&mut self) -> u64 {
        self.now
    }
    fn wall_utc(&mut self) -> String {
        self.wall.clone()
    }
}
