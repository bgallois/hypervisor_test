//! # VMX Module
//!
//! This module implements core support for Intel® Virtual Machine Extensions (VMX),
//! allowing entry into VMX root mode from a Rust-based Linux kernel module.
//!
//! It forms the foundation of a minimal hypervisor written entirely in safe, expressive Rust.
//! The code handles:
//!
//! - Verifying CPU support for virtualization
//! - Setting up model-specific registers (MSRs)
//! - Configuring control registers (CR0, CR4)
//! - Initializing the VMXON region
//! - Executing the `VMXON` and `VMXOFF` instructions
//!
//! ## Design Goals
//!
//! - ✅ **Pure Rust**: All hypervisor logic is written in Rust (aside from a temporary C shim for physical address translation).
//! - 🔒 **Safe Abstractions**: Dangerous operations are wrapped with clear and minimal unsafe blocks.
//! - ⚙️ **Bare-metal Control**: Direct access to CPU features like MSRs, CRs, and x86 instructions via the `x86` crate.
//! - 🧩 **Modular & Extensible**: Clean separation of responsibilities between this crate and the kernel module interface.
use crate::vmcs::VmcsField;
use core::ptr;
use x86::current::paging::BASE_PAGE_SIZE;
use x86::current::vmx::vmxoff;
use x86::current::vmx::vmxon;
use x86::dtables;
use x86::msr;
use x86::msr::rdmsr;
use x86::msr::wrmsr;
use x86::vmx::VmFail;

#[derive(Default)]
pub struct UnpackedGdtEntry {
    /// The base of the segment.
    pub base: u64,
    /// The limit of the segment.
    pub limit: u64,
    /// The access rights of the segment.
    pub access_rights: u32,
    /// The segment selector.
    pub selector: u16,
}
#[derive(Debug, Clone, Copy)]
#[allow(unused)]
#[repr(packed)]
pub struct GdtEntry {
    /// Low 16 bits of the segment limit.
    pub limit_low: u16,
    /// Low 16 bits of the segment base.
    pub base_low: u16,
    /// Middle 8 bits of the segment base.
    pub base_middle: u8,
    /// Various flags used to set segment type and access rights.
    pub access: u8,
    /// The low 4 bits are part of the limit. The high 4 bits are the
    /// granularity of the segment and the size.
    pub granularity: u8,
    /// High 8 bits of the segment base.
    pub base_high: u8,
}

/// Represents the possible errors encountered during hypervisor initialization.
///
/// Each variant maps to a unique integer code and is designed to be easily
/// convertible to a C-compatible error code (`i32`). These codes are returned
/// from the exposed FFI interface to signal structured failures to the kernel module.
#[repr(i32)]
pub enum Error {
    /// The CPU does not support VMX operation.
    /// (CPUID.1:ECX[5] is not set)
    CpuNotSupported = 10,
    /// The IA32_FEATURE_CONTROL MSR is locked and does not allow VMX outside SMX.
    VMXBIOSLock = 20,
    /// The provided VMXON memory region is not 4KB aligned.
    MemoryIsNotAligned = 30,
    /// VMXON failed and VM-instruction error was returned (VMfailValid).
    /// Indicates a specific failure code is available in VM-instruction error MSR.
    VmFailValid = 40,
    /// VMXON failed and no further error information is available (VMfailInvalid).
    /// Likely indicates an incorrect setup of the VMXON region or control state.
    VmFailInvalid = 41,
}

/// Represents the default initialization of a VMXON region.
///
/// The `Default` implementation for `Vmxon` reads the `IA32_VMX_BASIC`
/// MSR to extract the VMCS revision identifier. This revision ID is
/// stored in the first 4 bytes of the VMXON region, and the remaining
/// memory is zeroed out as required by Intel's VMX specifications.
///
/// This structure is used to initialize VMX operation on Intel processors.
///
/// # Returns
///
/// Returns a properly initialized `Vmxon` structure that can be used
/// to enter VMX operation via the `VMXON` instruction.
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

/// A 4KB-aligned memory structure used to enable VMX operation.
///
/// The `Vmxon` region is required by Intel processors to enter VMX root mode
/// and must meet strict alignment and initialization constraints:
///
/// - Must be exactly 4096 bytes in size.
/// - Must be aligned on a 4096-byte boundary.
/// - The first 4 bytes must contain the VMCS revision ID from `IA32_VMX_BASIC`.
/// - The remaining bytes must be zeroed.
///
/// This struct is laid out in C-compatible format to match hardware expectations.
///
/// # Safety
///
/// This structure must reside in physically contiguous, non-paged memory
/// for correct operation of VMXON. Improper initialization or alignment
/// will result in `VMFailInvalid` or `VMFailValid` errors when issuing the instruction.
#[repr(C, align(4096))]
#[derive(Clone)]
pub struct Vmxon {
    /// The VMCS revision identifier required by the VMXON instruction.
    pub revision_id: u32,
    /// A padding array zeroed to meet the expected 4KB total size.
    pub data: [u8; BASE_PAGE_SIZE - 4],
}

/// A minimal hypervisor structure that holds VMX state.
///
/// The `Hypervisor` struct encapsulates the necessary data required
/// to manage VMX root mode operation on Intel CPUs. Currently, it includes
/// only the `Vmxon` region, which is required to enter VMX operation via the `VMXON` instruction.
///
/// This structure acts as the entry point for managing virtualization lifecycle
/// and can be extended in future stages (in its own module) to include VMCS structures, control state,
/// and guest/host context information.
pub struct Hypervisor {
    /// A properly aligned and initialized `Vmxon` structure used to enable VMX.
    pub vmxon: Vmxon,
}

impl Hypervisor {
    /// Checks if a given address is 4KB page-aligned.
    ///
    /// # Arguments
    ///
    /// * `n` - The address to check.
    ///
    /// # Returns
    ///
    /// `true` if the address is 4KB-aligned, `false` otherwise.
    const fn is_page_aligned(&self, n: u64) -> bool {
        n & 0xfff == 0
    }

    /// Enables VMX operation by writing to the VMXON region and executing the `VMXON` instruction.
    ///
    /// # Arguments
    ///
    /// * `virt` - Pointer to the virtual memory location of the VMXON region.
    /// * `phys` - Physical address of the VMXON region.
    ///
    /// # Returns
    ///
    /// `Ok(())` if VMX is successfully enabled, or an `Error` variant if something fails.
    pub fn enable(&self, virt: *mut u32, phys: u64) -> Result<(), Error> {
        if !self.is_page_aligned(virt as u64) {
            return Err(Error::MemoryIsNotAligned);
        }
        if !self.is_page_aligned(phys) {
            return Err(Error::MemoryIsNotAligned);
        }
        unsafe {
            //ptr::write(virt as *mut Vmxon, self.vmxon.clone()); // Relocation error with my
            // compiler but should work
            ptr::write(virt, self.vmxon.revision_id);
            match vmxon(phys) {
                Ok(_) => Ok(()),
                Err(e) => match e {
                    VmFail::VmFailValid => Err(Error::VmFailValid),
                    VmFail::VmFailInvalid => Err(Error::VmFailInvalid),
                },
            }
        }
    }

    pub fn disable(&self) -> Result<(), Error> {
        unsafe {
            match vmxoff() {
                Ok(_) => Ok(()),
                Err(e) => match e {
                    VmFail::VmFailValid => Err(Error::VmFailValid),
                    VmFail::VmFailInvalid => Err(Error::VmFailInvalid),
                },
            }
        }
    }

    fn vmwrite(&self, field: VmcsField, value: u64) -> Result<(), Error> {
        match unsafe { x86::bits64::vmx::vmwrite(field as u32, value) } {
            Ok(_) => Ok(()),
            Err(e) => match e {
                VmFail::VmFailValid => Err(Error::VmFailValid),
                VmFail::VmFailInvalid => Err(Error::VmFailInvalid),
            },
        }
    }

    fn vmread(&self, field: VmcsField) -> Result<u64, Error> {
        match unsafe { x86::bits64::vmx::vmread(field as u32) } {
            Ok(value) => Ok(value),
            Err(e) => match e {
                VmFail::VmFailValid => Err(Error::VmFailValid),
                VmFail::VmFailInvalid => Err(Error::VmFailInvalid),
            },
        }
    }

    fn init_host_state(
        &self,
        /*tr_selector: u64,
        tr_base: u64,
        host_gdt_base: u64,*/
        stack_top: u64,
    ) -> Result<(), Error> {
        /*self.vmwrite(
            VmcsField::HostCr0,
            unsafe { x86::controlregs::cr0() }.bits() as u64,
        )?;
        self.vmwrite(VmcsField::HostCr3, unsafe { x86::controlregs::cr3() })?;
        self.vmwrite(
            VmcsField::HostCr4,
            unsafe { x86::controlregs::cr4() }.bits() as u64,
        )?;
        self.vmwrite(
            VmcsField::HostCsSelector,
            u64::from(x86::segmentation::cs().bits()),
        )?;
        self.vmwrite(
            VmcsField::HostDsSelector,
            u64::from(x86::segmentation::ds().bits()),
        )?;
        self.vmwrite(
            VmcsField::HostEsSelector,
            u64::from(x86::segmentation::es().bits()),
        )?;
        self.vmwrite(
            VmcsField::HostFsSelector,
            u64::from(x86::segmentation::fs().bits()),
        )?;
        self.vmwrite(
            VmcsField::HostGsSelector,
            u64::from(x86::segmentation::gs().bits()),
        )?;
        self.vmwrite(
            VmcsField::HostSsSelector,
            u64::from(x86::segmentation::ss().bits()),
        )?;
        self.vmwrite(VmcsField::HostGsBase, 0)?;*/
        //self.vmwrite(VmcsField::HostTrSelector, tr_selector)?;
        //self.vmwrite(VmcsField::HostTrBase, tr_base)?;
        //self.vmwrite(VmcsField::HostGdtrBase, host_gdt_base)?;
        self.vmwrite(VmcsField::HostRsp, stack_top)?;
        //self.vmwrite(VmcsField::HostIdtrBase, TODO)?;
        //self.vmwrite(VmcsField::HostFsBase, TODO)?;
        //self.vmwrite(VmcsField::HostRip, TODO)?;
        Ok(())
    }

    pub fn unpack_gdt_entry(&self, gdt: &[GdtEntry], selector: u16) -> UnpackedGdtEntry {
        const GDT_ENTRY_ACCESS_PRESENT: u8 = 1 << 7;
        const VMX_INFO_SEGMENT_UNUSABLE: u32 = 1 << 16;

        let mut unpacked: UnpackedGdtEntry = Default::default();

        let index: usize = usize::from(selector) / core::mem::size_of::<u64>();
        if index == 0 {
            unpacked.access_rights |= VMX_INFO_SEGMENT_UNUSABLE;
            return unpacked;
        }

        unpacked.selector = selector;
        unpacked.limit =
            u64::from(gdt[index].limit_low) | ((u64::from(gdt[index].granularity) & 0x0f) << 16);
        unpacked.base = u64::from(gdt[index].base_low);
        unpacked.base = (u64::from(gdt[index].base_high) << 24)
            | (u64::from(gdt[index].base_middle) << 16)
            | u64::from(gdt[index].base_low);

        unpacked.access_rights = u32::from(gdt[index].access);
        unpacked.access_rights |= u32::from((gdt[index].granularity) & 0xf0) << 8;
        unpacked.access_rights &= 0xf0ff;
        if (gdt[index].access & GDT_ENTRY_ACCESS_PRESENT) == 0 {
            unpacked.access_rights |= VMX_INFO_SEGMENT_UNUSABLE;
        }
        unpacked
    }

    fn init_guest_state(&self) -> Result<(), Error> {
        self.vmwrite(VmcsField::VmcsLinkPointer, !0)?;

        let mut guest_idtr: dtables::DescriptorTablePointer<u64> = Default::default();
        unsafe {
            dtables::sidt(&mut guest_idtr);
        }
        self.vmwrite(VmcsField::GuestIdtrLimit, u64::from(guest_idtr.limit))?;
        self.vmwrite(VmcsField::GuestIdtrBase, guest_idtr.base as u64)?;

        let mut guest_gdtr: dtables::DescriptorTablePointer<u64> = Default::default();
        unsafe {
            dtables::sgdt(&mut guest_gdtr);
        }
        self.vmwrite(VmcsField::GuestGdtrLimit, u64::from(guest_gdtr.limit))?;
        self.vmwrite(VmcsField::GuestGdtrBase, guest_gdtr.base as u64)?;

        /*let bytes = usize::from(guest_gdtr.limit) + 1;
        let gdt = unsafe {
            core::slice::from_raw_parts(
                guest_gdtr.base as *const GdtEntry,
                bytes / core::mem::size_of::<GdtEntry>(),
            )
        };

        let cs_unpacked = self.unpack_gdt_entry(gdt, x86::segmentation::cs().bits());
        self.vmwrite(VmcsField::GuestCsSelector, u64::from(cs_unpacked.selector))?;
        self.vmwrite(VmcsField::GuestCsLimit, cs_unpacked.limit)?;
        self.vmwrite(
            VmcsField::GuestCsArBytes,
            u64::from(cs_unpacked.access_rights),
        )?;
        self.vmwrite(VmcsField::GuestCsBase, cs_unpacked.base)?;

        let ds = x86::segmentation::ds();
        let ds_unpacked = self.unpack_gdt_entry(gdt, ds.bits());
        self.vmwrite(VmcsField::GuestDsSelector, u64::from(ds_unpacked.selector))?;
        self.vmwrite(VmcsField::GuestDsLimit, ds_unpacked.limit)?;
        self.vmwrite(
            VmcsField::GuestDsArBytes,
            u64::from(ds_unpacked.access_rights),
        )?;
        self.vmwrite(VmcsField::GuestDsBase, ds_unpacked.base)?;

        let es_unpacked = self.unpack_gdt_entry(gdt, x86::segmentation::es().bits());
        self.vmwrite(VmcsField::GuestEsSelector, u64::from(es_unpacked.selector))?;
        self.vmwrite(VmcsField::GuestEsLimit, es_unpacked.limit)?;
        self.vmwrite(
            VmcsField::GuestEsArBytes,
            u64::from(es_unpacked.access_rights),
        )?;
        self.vmwrite(VmcsField::GuestEsBase, es_unpacked.base)?;

        let fs_unpacked = self.unpack_gdt_entry(gdt, x86::segmentation::fs().bits());
        self.vmwrite(VmcsField::GuestFsSelector, u64::from(fs_unpacked.selector))?;
        self.vmwrite(VmcsField::GuestFsLimit, fs_unpacked.limit)?;
        self.vmwrite(
            VmcsField::GuestFsArBytes,
            u64::from(fs_unpacked.access_rights),
        )?;
        self.vmwrite(VmcsField::GuestFsBase, fs_unpacked.base)?;

        let gs_unpacked = self.unpack_gdt_entry(gdt, x86::segmentation::gs().bits());
        self.vmwrite(VmcsField::GuestGsSelector, u64::from(gs_unpacked.selector))?;
        self.vmwrite(VmcsField::GuestGsLimit, gs_unpacked.limit)?;
        self.vmwrite(
            VmcsField::GuestGsArBytes,
            u64::from(gs_unpacked.access_rights),
        )?;
        self.vmwrite(VmcsField::GuestGsBase, gs_unpacked.base)?;

        let ss_unpacked = self.unpack_gdt_entry(gdt, x86::segmentation::ss().bits());
        self.vmwrite(VmcsField::GuestSsSelector, u64::from(ss_unpacked.selector))?;
        self.vmwrite(VmcsField::GuestSsLimit, ss_unpacked.limit)?;
        self.vmwrite(
            VmcsField::GuestSsArBytes,
            u64::from(ss_unpacked.access_rights),
        )?;
        self.vmwrite(VmcsField::GuestSsBase, ss_unpacked.base)?;

        let tr = unsafe { x86::task::tr() };
        let tr_unpacked = self.unpack_gdt_entry(gdt, tr.bits());
        self.vmwrite(VmcsField::GuestTrSelector, u64::from(tr_unpacked.selector))?;
        self.vmwrite(VmcsField::GuestTrLimit, tr_unpacked.limit)?;
        if tr_unpacked.access_rights != (1 << 16) as u32 {
            self.vmwrite(
                VmcsField::GuestTrArBytes,
                u64::from(tr_unpacked.access_rights),
            )?;
        } else {
            self.vmwrite(VmcsField::GuestTrArBytes, (1 << 7) | 0xb)?;
        }
        self.vmwrite(VmcsField::GuestTrBase, tr_unpacked.base)?;

        let ldtr = unsafe { x86::dtables::ldtr() };
        let ldtr_unpacked = self.unpack_gdt_entry(gdt, ldtr.bits());
        self.vmwrite(
            VmcsField::GuestLdtrSelector,
            u64::from(ldtr_unpacked.selector),
        )?;
        self.vmwrite(VmcsField::GuestLdtrLimit, ldtr_unpacked.limit)?;
        self.vmwrite(
            VmcsField::GuestLdtrArBytes,
            u64::from(ldtr_unpacked.access_rights),
        )?;
        self.vmwrite(VmcsField::GuestLdtrBase, ldtr_unpacked.base)?;*/

        let cr4 = unsafe { x86::controlregs::cr4() };
        self.vmwrite(VmcsField::GuestCr4, cr4.bits() as u64)?;
        let cr3 = unsafe { x86::controlregs::cr3() };
        self.vmwrite(VmcsField::GuestCr3, cr3)?;
        let cr0 = unsafe { x86::controlregs::cr0() };
        self.vmwrite(VmcsField::GuestCr0, cr0.bits() as u64)?;
        self.vmwrite(VmcsField::GuestIA32Debugctl, unsafe {
            msr::rdmsr(msr::IA32_DEBUGCTL)
        })?;
        //let dr7 = unsafe { x86::debugregs::dr7() };
        //self.vmwrite(VmcsField::GuestDr7, dr7.0 as u64)?;

        Ok(())
    }

    fn adjust_control(&self, msr: u32, control: u32) -> u64 {
        let value = unsafe { msr::rdmsr(msr) };
        let allowed0 = value as u32;
        let allowed1 = (value >> 32) as u32;
        let adjusted = (control | allowed1) & (allowed0 | allowed1);
        (allowed1 as u64) << 32 | adjusted as u64
    }

    fn init_vm_control(&self) -> Result<(), Error> {
        self.vmwrite(
            VmcsField::PinBasedVmExecControl,
            self.adjust_control(msr::IA32_VMX_PINBASED_CTLS, 0),
        )?;

        self.vmwrite(VmcsField::VmxPreemptionTimerValue, 0xfffff)?;

        self.vmwrite(
            VmcsField::CpuBasedVmExecControl,
            self.adjust_control(msr::IA32_VMX_PROCBASED_CTLS, 1 << 28),
        )?;

        self.vmwrite(
            VmcsField::VmExitControls,
            self.adjust_control(msr::IA32_VMX_EXIT_CTLS, (1 << 9) | (1 << 24)),
        )?;

        self.vmwrite(
            VmcsField::VmEntryControls,
            self.adjust_control(msr::IA32_VMX_ENTRY_CTLS, 1 << 9),
        )?;

        Ok(())
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
        cr4 |= x86::controlregs::Cr4::CR4_ENABLE_VME;
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
