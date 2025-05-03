#![doc = include_str!("../README.md")]
#![no_std]

use core::panic::PanicInfo;

/// Custom panic handler required in `#![no_std]` environments.
///
/// In kernel modules or bare-metal code, we define our own panic handler
/// since the standard library is unavailable. This implementation simply
/// enters an infinite loop.
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

pub mod vmcs;
pub mod vmx;

/// Entry point to load and run the hypervisor logic.
///
/// # Safety
/// This function is marked as `unsafe` and `extern "C"` because it is
/// called from C code (the kernel module entry point). It expects:
/// - `virt`: A virtual address pointer to the allocated VMXON region.
/// - `phys`: A physical address of the same region.
///
/// Returns:
/// - `0` on success
/// - An error code if any part of the process fails
///
/// The function:
/// 1. Builds a new `Hypervisor` instance.
/// 2. Enables VMX operation with the given memory region.
/// 3. Disables VMX on completion to clean up.
#[unsafe(no_mangle)]
pub extern "C" fn load_hypervisor(
    virt_vmx: *mut u32,
    phys_vmx: u64,
    virt_vmcs: *mut u32,
    phys_vmcs: u64,
    virt_stack: *mut u32,
    stack_top: u64,
    guest: u64,
    virt_gdt: *mut u32,
    virt_tss: *mut u32,
) -> i32 {
    let hypervisor = match vmx::HypervisorBuilder::build() {
        Ok(hypervisor) => hypervisor,
        Err(e) => return e.repr(),
    };
    match hypervisor.enable(virt_vmx, phys_vmx) {
        Ok(_) => 0,
        Err(e) => return e.repr() + 100,
    };
    match hypervisor.load_vm(virt_vmcs, phys_vmcs, stack_top, guest, virt_gdt, virt_tss) {
        Ok(_) => 0,
        Err(e) => return e.repr() + 1_000,
    }
}
