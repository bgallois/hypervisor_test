#!/bin/bash

set -e
make clean
make
sudo insmod hypervisor_module.ko
sudo rmmod hypervisor_module.ko
sudo dmesg
