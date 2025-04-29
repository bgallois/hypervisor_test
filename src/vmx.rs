use core::ptr;
use x86::current::paging::BASE_PAGE_SIZE;
use x86::current::vmx::vmxon;
use x86::msr;
use x86::msr::rdmsr;
use x86::msr::wrmsr;
use x86::vmx::VmFail;

pub enum Error {
    CpuNotSupported,
    VMXBIOSLock,
}

impl Default for Vmxon {
    fn default() -> Self {
        let mut revision_id = unsafe { rdmsr(msr::IA32_VMX_BASIC) as u32 };
        revision_id &= !(1 << 31);
        Self {
            revision_id,
            data: [0u8; BASE_PAGE_SIZE - 4],
        }
    }
}

#[repr(C, align(4096))]
pub struct Vmxon {
    pub revision_id: u32,
    pub data: [u8; BASE_PAGE_SIZE - 4],
}

pub struct Hypervisor {
    pub vmxon: Vmxon,
}

impl Hypervisor {
    pub fn enable(&self, virt: *mut u32, phys: u64) -> Result<(), VmFail> {
        unsafe {
            ptr::write_bytes(virt as *mut u8, 0, 1);
            ptr::write(virt, self.vmxon.revision_id);
            vmxon(phys)
        }
    }
}

impl Default for Hypervisor {
    fn default() -> Self {
        Self {
            vmxon: Default::default(),
        }
    }
}

pub struct HypervisorBuilder {}

impl HypervisorBuilder {
    pub fn build() -> Result<Hypervisor, Error> {
        if Self::can_vmx() {
            Self::set_lock()?;
            Self::set_cr0();
            Self::set_cr4();
            Ok(Hypervisor::default())
        } else {
            Err(Error::CpuNotSupported)
        }
    }

    /// Checks whether the current CPU supports Intel VT-x (VMX) and is a hypervisor is running.
    fn can_vmx() -> bool {
        const CPUID_PROCESSOR_INFO: u32 = 0x1;
        const VMX_AVAILABLE_BIT: u32 = 1 << 5;
        const HYPERVISOR_PRESENT_BIT: u32 = 1 << 31;
        let result = unsafe { core::arch::x86_64::__cpuid(CPUID_PROCESSOR_INFO) };
        (result.ecx & VMX_AVAILABLE_BIT != 0) && (result.ecx & HYPERVISOR_PRESENT_BIT == 0)
    }

    /// Sets the CR4 control register with VMX-compatible values.
    ///
    /// This function configures the `CR4` (Control Register 4) according to the
    /// Intel VMX requirements. Specifically, it uses the model-specific registers (MSRs)
    /// `IA32_VMX_CR4_FIXED0` and `IA32_VMX_CR4_FIXED1` to determine the fixed bits that
    /// must be set or cleared when enabling VMX operation.
    ///
    /// The logic works as follows:
    /// - `fixed0` indicates which bits **must be set to 1** in CR4.
    /// - `fixed1` indicates which bits **can be set to 1**; bits set to 0 here must be 0 in CR4.
    ///
    /// The function:
    /// 1. Reads the current value of CR4.
    /// 2. Ensures all bits required by `fixed0` are set.
    /// 3. Ensures any bits not allowed by `fixed1` are cleared.
    /// 4. Writes the sanitized value back to CR4.
    fn set_cr4() {
        let fixed0 = unsafe { msr::rdmsr(msr::IA32_VMX_CR4_FIXED0) };
        let fixed1 = unsafe { msr::rdmsr(msr::IA32_VMX_CR4_FIXED1) };
        let mut cr4 = unsafe { x86::controlregs::cr4() };
        cr4 |= x86::controlregs::Cr4::from_bits_truncate(fixed0 as usize);
        cr4 &= x86::controlregs::Cr4::from_bits_truncate(fixed1 as usize);
        unsafe {
            x86::controlregs::cr4_write(cr4);
        }
    }

    /// Sets the CR0 control register with VMX-compliant values.
    ///
    /// This function configures the `CR0` (Control Register 0) to satisfy Intel's
    /// requirements for enabling VMX (Virtual Machine Extensions). According to
    /// the Intel SDM, certain bits in CR0 must have fixed values before executing
    /// the `VMXON` instruction.
    ///
    /// It reads two model-specific registers (MSRs):
    /// - `IA32_VMX_CR0_FIXED0`: Bits that **must be set to 1**.
    /// - `IA32_VMX_CR0_FIXED1`: Bits that **must be allowed to be 1** (i.e., any 0s must be cleared).
    ///
    /// The function:
    /// 1. Reads the current CR0 value.
    /// 2. ORs in bits required to be 1 (from `FIXED0`).
    /// 3. ANDs out bits not allowed to be 1 (from `FIXED1`).
    /// 4. Writes the final value back to CR0.
    fn set_cr0() {
        let fixed0 = unsafe { msr::rdmsr(msr::IA32_VMX_CR0_FIXED0) };
        let fixed1 = unsafe { msr::rdmsr(msr::IA32_VMX_CR0_FIXED1) };
        let mut cr0 = unsafe { x86::controlregs::cr0() };
        cr0 |= x86::controlregs::Cr0::from_bits_truncate(fixed0 as usize);
        cr0 &= x86::controlregs::Cr0::from_bits_truncate(fixed1 as usize);
        unsafe {
            x86::controlregs::cr0_write(cr0);
        }
    }

    /// Sets the lock bit in the IA32_FEATURE_CONTROL MSR to enable and lock VMX settings.
    ///
    /// The IA32_FEATURE_CONTROL MSR is used to control certain CPU features related to VMX (Virtual Machine Extensions)
    /// and SMX (Secure Mode Extensions). This function ensures that:
    /// 1. The **lock bit** is set, which prevents further modifications to the MSR once the lock is applied.
    /// 2. The **VMX-enabled outside SMX bit** is also set, which allows the VMX operation outside of SMX mode.
    ///
    /// The function performs the following checks and actions:
    /// - If the lock bit is not set, it sets both the lock bit and the VMX-enabled outside SMX bit, then writes the updated
    ///   value back to the IA32_FEATURE_CONTROL MSR.
    /// - If the lock bit is already set but the VMX-enabled outside SMX bit is not set, the function returns an error
    ///   (`Error::VMXBIOSLock`), indicating that the system is locked but the necessary configuration for VMX is not enabled.
    /// - If the lock bit is already set and the VMX-enabled outside SMX bit is also set, the function does nothing and returns success.
    ///
    /// # Returns
    /// - `Ok(())`: If the lock bit is set successfully or if the configuration is already correct.
    /// - `Err(Error::VMXBIOSLock)`: If the lock bit is set, but VMX is not enabled outside of SMX, preventing the hypervisor from starting.
    pub fn set_lock() -> Result<(), Error> {
        let mut control = unsafe { msr::rdmsr(msr::IA32_FEATURE_CONTROL) };
        const IA32_FEATURE_CONTROL_LOCK_BIT: u64 = 1 << 0;
        const IA32_FEATURE_CONTROL_VMX_ENABLED_OUTSIDE_SMX_BIT: u64 = 1 << 2;
        if (control & IA32_FEATURE_CONTROL_LOCK_BIT) == 0 {
            control |=
                IA32_FEATURE_CONTROL_VMX_ENABLED_OUTSIDE_SMX_BIT | IA32_FEATURE_CONTROL_LOCK_BIT;
            unsafe { wrmsr(msr::IA32_FEATURE_CONTROL, control) };
            return Ok(());
        } else if (control & IA32_FEATURE_CONTROL_VMX_ENABLED_OUTSIDE_SMX_BIT) == 0 {
            return Err(Error::VMXBIOSLock);
        }
        Ok(())
    }
}
