//! C entry points for the hash-based signature benchmark (`app_pq_bench`).

use app_pq_bench::{Error, Report, Scheme, Stats, Step};
use cty::c_char;

#[repr(C)]
pub struct PqBenchStats {
    pub median_ns: u64,
    pub min_ns: u64,
    pub max_ns: u64,
}

#[repr(C)]
pub struct PqBenchReport {
    pub iterations: u32,
    pub signature_bytes: u32,
    pub public_key_bytes: u32,
    pub keygen: PqBenchStats,
    pub sign: PqBenchStats,
    pub verify: PqBenchStats,
}

pub const PQ_BENCH_OK: i32 = 0;
pub const PQ_BENCH_UNKNOWN_SCHEME: i32 = -1;
pub const PQ_BENCH_NO_ITERATIONS: i32 = -2;
pub const PQ_BENCH_VERIFY_FAILED: i32 = -3;

/// Number of schemes; valid scheme indexes are below this.
#[no_mangle]
pub extern "C" fn pq_bench_scheme_count() -> u32 {
    Scheme::ALL.len() as u32
}

/// The scheme's short name as a static NUL-terminated string, or NULL for an unknown index.
#[no_mangle]
pub extern "C" fn pq_bench_scheme_name(scheme: u32) -> *const c_char {
    match Scheme::ALL.get(scheme as usize) {
        Some(scheme) => scheme.name().as_ptr() as *const c_char,
        None => core::ptr::null(),
    }
}

/// For the SHA-256 row, the number of 64-byte blocks its sign step hashes; 0 for a signature
/// scheme or an unknown index.
#[no_mangle]
pub extern "C" fn pq_bench_scheme_blocks(scheme: u32) -> u32 {
    match Scheme::ALL.get(scheme as usize) {
        Some(Scheme::Sha256) => app_pq_bench::HASH_BLOCKS,
        _ => 0,
    }
}

/// Times `iterations` key generations, signatures and verifications of one scheme.
///
/// `now_ns` returns a monotonic time in nanoseconds. `progress(step, iteration)` is called
/// before each step (0 keygen, 1 sign, 2 verify), outside the timed part. On success fills `out` and returns
/// `PQ_BENCH_OK`; otherwise returns a negative `PQ_BENCH_*` code and leaves `out` unchanged.
///
/// # Safety
/// `out` must point to a writable `PqBenchReport`.
#[no_mangle]
pub unsafe extern "C" fn pq_bench_run(
    scheme: u32,
    iterations: u32,
    now_ns: extern "C" fn() -> u64,
    progress: extern "C" fn(step: u32, iteration: u32),
    out: *mut PqBenchReport,
) -> i32 {
    let Some(&scheme) = Scheme::ALL.get(scheme as usize) else {
        return PQ_BENCH_UNKNOWN_SCHEME;
    };
    match scheme.run(
        iterations,
        &mut || now_ns(),
        &mut |step: Step, iteration| progress(step as u32, iteration),
    ) {
        Ok(report) => {
            *out = report.into();
            PQ_BENCH_OK
        }
        Err(Error::NoIterations) => PQ_BENCH_NO_ITERATIONS,
        Err(Error::VerifyFailed) => PQ_BENCH_VERIFY_FAILED,
    }
}

impl From<Stats> for PqBenchStats {
    fn from(stats: Stats) -> Self {
        Self {
            median_ns: stats.median_ns,
            min_ns: stats.min_ns,
            max_ns: stats.max_ns,
        }
    }
}

impl From<Report> for PqBenchReport {
    fn from(report: Report) -> Self {
        Self {
            iterations: report.iterations,
            signature_bytes: report.signature_bytes as u32,
            public_key_bytes: report.public_key_bytes as u32,
            keygen: report.keygen.into(),
            sign: report.sign.into(),
            verify: report.verify.into(),
        }
    }
}
