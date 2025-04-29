obj-m += hypervisor_module.o
hypervisor_module-y := src/hypervisor_module.o src/libhypervisor_test.o src/virt_to_phys_shim.o

KERNELDIR :=./linux/ # Should be replaced to the kernel build
PWD := $(shell pwd)

RUST_RELEASE := release
RUST_LIB_NAME := hypervisor_test
RUST_LIB_PATH := target/$(RUST_RELEASE)/lib$(RUST_LIB_NAME).a
RUST_FILES := src/*.rs

-include $(RUST_LIB_PATH:.a=.d)

all: hypervisor_module.ko

hypervisor_module.ko: libhypervisor_test.o
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

$(RUST_LIB_PATH):
	cargo rustc --release -- --emit=obj

libhypervisor_test.o: $(RUST_LIB_PATH)
	@cp target/$(RUST_RELEASE)/deps/hypervisor_test-*.o src/$@
	@echo "cmd_target/$(RUST_RELEASE)/deps/hypervisor_test-*.o := cp $< src/$@" > src/.libhypervisor_test.o.cmd

clean:
	cargo clean
	rm -rf *.o *~ core .depend *.mod.o .*.cmd *.ko *.mod.c *.mod
	rm -rf *.tmp_versions *.markers .*.symvers modules.order
	rm -rf Module.symvers
	rm -rf *.rmeta
