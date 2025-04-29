#![allow(missing_docs)]
use kernel::prelude::*;
use kernel::alloc::Allocator;
use kernel::page::PAGE_SIZE;

extern "C" {
    pub fn load_hypervisor(virt: *mut u32, phys: u64) -> i32;
}
extern "C" {
    fn rust_virt_to_phys(ptr: *const core::ffi::c_void) -> u64;
}

module! {
    type: Hypervisor,
    name: "testhypervisor",
    author: "Benjamin Gallois",
    description: "A simple VMX hypervisor module in Rust",
    license: "GPL",
}

struct Hypervisor {
    phys: u64,
}

impl kernel::Module for Hypervisor {
    fn init(_module: &'static ThisModule) -> Result<Self> {

        // Allocate one page of memory (disabled due to linking error during module load).
        // Get the physical address directly from the Page abstraction (available in kernel 6.15+).
        // let phys = Page::into_phys(page); // Will be available in kernel 6.15+

        // This should be possible to do it pure Rust see top.
        pr_info!("Starting Allocation\n");
        let layout = unsafe { core::alloc::Layout::from_size_align_unchecked(1, PAGE_SIZE) };
        let virt = kernel::alloc::allocator::Kmalloc::alloc(layout, GFP_KERNEL | __GFP_ZERO)?;
        let virt_pts = virt.as_ptr();
        pr_info!("Page Allocated\n");
        let phys = unsafe { rust_virt_to_phys(virt_pts as *const core::ffi::c_void) };
        let res = unsafe {load_hypervisor(virt_pts as *mut u32, phys)};
        if res == 0 {
            pr_info!("Hypervisor Started\n");
        }
        else {
            pr_info!("Hypervisor Failed {} \n", res);
        }
        Ok(Hypervisor{phys})
    }
}
