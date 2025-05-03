#!/bin/bash

set -e
make clean
make LLVM=1
sudo insmod hypervisor_module.ko
sudo rmmod hypervisor_module.ko
sudo dmesg
