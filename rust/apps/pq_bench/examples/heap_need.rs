//! Measures the most heap each scheme holds at once on the host, to tell whether its working
//! memory fits in the device's on-chip RAM. `heap_need` prints one line per scheme.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use app_pq_bench::Scheme;

struct Counting;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let live = LIVE.fetch_add(layout.size(), Ordering::Relaxed) + layout.size();
        PEAK.fetch_max(live, Ordering::Relaxed);
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

fn main() {
    for scheme in Scheme::ALL {
        let before = LIVE.load(Ordering::Relaxed);
        PEAK.store(before, Ordering::Relaxed);
        let start = std::time::Instant::now();
        scheme
            .run(1, &mut || start.elapsed().as_nanos() as u64, &mut |_, _| {})
            .unwrap();
        println!(
            "{:28} {:>4} KB",
            scheme.name().to_str().unwrap(),
            (PEAK.load(Ordering::Relaxed) - before).div_ceil(1024)
        );
    }
}
