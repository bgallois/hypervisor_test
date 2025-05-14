#![allow(missing_docs)]
use kernel::prelude::*;
use kernel::alloc::Allocator;
use kernel::page::PAGE_SIZE;

extern "C" {
    pub fn load_hypervisor(virt_vmx: *mut u32, phys_vmx: u64, virt_vmcs: *mut u32, phys_vmcs: u64, virt_stack: *mut u32, stack_top: u64) -> i32;
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
    phys_vmcs: u64,
    stack: u64,
}

impl kernel::Module for Hypervisor {
    fn init(_module: &'static ThisModule) -> Result<Self> {

        // Allocate one page of memory (disabled due to linking error during module load).
        // Get the physical address directly from the Page abstraction (available in kernel 6.15+).
        // let phys = Page::into_phys(page); // Will be available in kernel 6.15+

        // This should be possible to do it pure Rust see top.
        pr_info!("Starting VMX Allocation\n");
        let layout = unsafe { core::alloc::Layout::from_size_align_unchecked(PAGE_SIZE, PAGE_SIZE) };
        let virt = kernel::alloc::allocator::Kmalloc::alloc(layout, GFP_KERNEL | __GFP_ZERO)?;
        let virt_pts = virt.as_ptr();
        let phys = unsafe { rust_virt_to_phys(virt_pts as *const core::ffi::c_void) };
        pr_info!("VMX Allocated\n");

        pr_info!("Starting VMCS Allocation\n");
        let virt_vmcs = kernel::alloc::allocator::Kmalloc::alloc(layout, GFP_KERNEL | __GFP_ZERO)?;
        let virt_pts_vmcs = virt_vmcs.as_ptr();
        let phys_vmcs = unsafe { rust_virt_to_phys(virt_pts_vmcs as *const core::ffi::c_void) };
        pr_info!("VMCS Allocated\n");

        pr_info!("Starting STACK Allocation\n");
        let virt_stack = kernel::alloc::allocator::Kmalloc::alloc(layout, GFP_KERNEL | __GFP_ZERO)?;
        let virt_pts_stack = virt_stack.as_ptr();
        let stack_top = unsafe {(virt_pts_stack as *mut u8).add(PAGE_SIZE)};
        let stack_top = stack_top as u64;
        pr_info!("STACK Allocated\n");

        let res = unsafe {load_hypervisor(virt_pts as *mut u32, phys, virt_pts_vmcs as *mut u32, phys_vmcs, virt_pts_stack as *mut u32, stack_top)};
        if res == 0 {
            pr_info!("Hypervisor Started\n");
        }
        else {
            pr_info!("Hypervisor Failed {} \n", res);
        }
        Ok(Hypervisor{phys, phys_vmcs, stack: virt_pts_stack as *mut u8 as u64})
    }
}
