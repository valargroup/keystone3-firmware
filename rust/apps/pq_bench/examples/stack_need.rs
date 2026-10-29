//! Measures how much stack each scheme needs on the host, to size the device's stack: fills
//! unused stack below the current frame with a pattern, runs the scheme once, then finds the
//! deepest byte the run overwrote. `stack_need` prints one line per scheme.

use app_pq_bench::Scheme;

const PAINTED: usize = 900 * 1024;
const PATTERN: u8 = 0xa5;

#[inline(never)]
fn measure(scheme: Scheme) -> usize {
    let marker = 0u8;
    let top = core::ptr::addr_of!(marker) as usize - 256;
    let bottom = top - PAINTED;
    // SAFETY: the thread has a 1 MB stack and this region lies below the live frames, in stack
    // the thread has not used yet.
    unsafe {
        for address in bottom..top {
            core::ptr::write_volatile(address as *mut u8, PATTERN);
        }
    }
    let start = std::time::Instant::now();
    scheme
        .run(1, &mut || start.elapsed().as_nanos() as u64, &mut |_, _| {})
        .unwrap();
    let deepest = (bottom..top)
        .find(|&address| unsafe { core::ptr::read_volatile(address as *const u8) } != PATTERN)
        .unwrap_or(top);
    top - deepest + 256
}

fn main() {
    for scheme in Scheme::ALL {
        let used = std::thread::Builder::new()
            .stack_size(1024 * 1024)
            .spawn(move || measure(scheme))
            .unwrap()
            .join()
            .unwrap();
        println!(
            "{:16} {:>4} KB",
            scheme.name().to_str().unwrap(),
            used.div_ceil(1024)
        );
    }
}
