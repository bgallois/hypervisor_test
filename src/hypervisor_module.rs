#![allow(missing_docs)]
use kernel::prelude::*;
//use kernel::page::Page;
//use kernel::page::PAGE_SHIFT;

extern "C" {
    pub fn load_hypervisor(virt: *mut u32, phys: u64) -> i32;
}
extern "C" {
    fn rust_virt_to_phys(ptr: *const core::ffi::c_void) -> u64;
}
extern "C" {
    fn linux_kmalloc(size: usize) -> *mut u8;
}

module! {
    type: Hypervisor,
    name: "testhypervisor",
    author: "Benjamin Gallois",
    description: "A simple VMX hypervisor module in Rust",
    license: "GPL",
}

struct Hypervisor;

impl kernel::Module for Hypervisor {
    fn init(_module: &'static ThisModule) -> Result<Self> {

        // Allocate one page of memory (disabled due to linking error during module load).
        // let page = Page::alloc_page(GFP_KERNEL); // Should work, but causes unresolved symbol at module loading
        // Get the physical address directly from the Page abstraction (available in kernel 6.15+).
        // let phys = Page::into_phys(page); // Will be available in kernel 6.15+
        // let virt = page.as_ptr() as *mut u32;

        // This should be possible to do it pure Rust see top.
        let virt = unsafe {linux_kmalloc(1usize) };
        let phys = unsafe { rust_virt_to_phys(virt as *const core::ffi::c_void) };
        let res = unsafe {load_hypervisor(virt as *mut u32, phys)};
        Ok(Hypervisor)
    }
}
