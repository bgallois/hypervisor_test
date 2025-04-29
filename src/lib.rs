#![no_std]
#![warn(missing_docs)]

use core::panic::PanicInfo;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

pub mod vmx;

#[unsafe(no_mangle)]
pub extern "C" fn load_hypervisor(virt: *mut u32, phys: u64) -> i32 {
    let hypervisor = match vmx::HypervisorBuilder::build() {
        Ok(hypervisor) => hypervisor,
        Err(_) => return -1,
    };
    if hypervisor.enable(virt, phys).is_ok() {
        0
    } else {
        -1
    }
}
