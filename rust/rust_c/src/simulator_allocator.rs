use core::alloc::{GlobalAlloc, Layout};
use core::ptr;

pub struct SimulatorAllocator;

extern "C" {
    pub fn RustMalloc(size: i32) -> *mut cty::c_void;
    pub fn RustFree(p: *mut cty::c_void);
}

#[global_allocator]
static SIMULATOR_ALLOCATOR: SimulatorAllocator = SimulatorAllocator;

unsafe impl GlobalAlloc for SimulatorAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if layout.size() > i32::MAX as usize {
            return ptr::null_mut();
        }
        RustMalloc(layout.size() as i32) as *mut u8
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        RustFree(ptr as *mut cty::c_void)
    }
}
