#include <linux/io.h>
#include <linux/module.h>

uintptr_t rust_virt_to_phys(void *addr) {
    return virt_to_phys(addr);
}
EXPORT_SYMBOL(rust_virt_to_phys);

void *linux_kmalloc(uintptr_t bytes) {
	void *ptr = kmalloc(bytes, GFP_KERNEL);
    if (ptr != NULL) {
        memset(ptr, 0, bytes);
    }
    return ptr;
}
EXPORT_SYMBOL(linux_kmalloc);
