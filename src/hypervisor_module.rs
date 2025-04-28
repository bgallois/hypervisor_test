#![allow(missing_docs)]
use kernel::prelude::*;

extern "C" {
    pub fn load_hypervisor();
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
         unsafe {
            load_hypervisor();
        }
        pr_info!("Our hypervisor is starting...\n");
        Ok(Hypervisor)
    }
}
