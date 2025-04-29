# 🚀 Minimal Hypervisor in Rust - A Step-by-Step Guide

Welcome to the **Minimal Hypervisor in Rust** repository! This project is dedicated to building a **simple hypervisor** using **pure Rust** on **Linux**. Over the course of multiple blog posts, we’ll walk through the process of constructing a minimal hypervisor from scratch, starting with enabling **VMX** (Virtual Machine Extensions) on Intel CPUs and working our way toward a fully functional virtual machine environment.

The goal is to build everything in **Rust**, without relying on existing high-level frameworks. By the end of the series, you'll understand how hypervisors work, how to interact directly with low-level CPU features, and how to integrate **Rust** seamlessly into the **Linux kernel**.

> **Blog Series**: This repository is part of a blog series where I explain each step in detail. If you want to learn more about the concepts and the process, be sure to check out the [blog](https://www.gallois.cc/blog/blog.html)! 📚

## 🧑‍💻 Repository Overview

This repository contains everything you need to get started with building a **minimal hypervisor** in **Rust**. The code is designed to be **100% Rust**, with no dependencies on external hypervisor frameworks. Here’s a breakdown of the key components:

### 🔑 **Key Concepts**

1. **VMCS (Virtual Machine Control Structure)**: The **VMCS** is a critical data structure for managing the state and control of a virtual machine. In this implementation, we use **pure Rust** to handle the VMCS layout, manage memory for the VMCS, and transition between **VMX root** and **non-root mode**.

2. **VMX Operations**: We activate **VMX** directly on the processor by issuing the **VMXON** instruction. All low-level interactions, including setting control registers, configuring **MSRs**, and managing the VMCS, are written in **Rust**. This allows us to maintain a fully **Rust-based hypervisor** without external C code or frameworks.

### 🏗️ **Architecture**

* **Rust Kernel Module**: A **Rust**-based kernel module that allocates memory, prepares the **VMXON** region, and interfaces with the hypervisor logic.
* **Hypervisor Crate**: This crate contains the core logic for managing the **VMCS**, setting processor control registers, and performing **VMXON**. It is compiled into a shared object and linked with the kernel module.

All the operations, including **VMCS** management, register manipulation, and instruction execution (like **VMXON**), are written using **Rust**. The focus is on leveraging **Rust's memory safety** and type system to create a secure, efficient hypervisor implementation.

### 🔧 **How to Build**

1. **Clone the repository**:

   ```bash
   git clone git@github.com:bgallois/hypervisor_test.git
   cd hypervisor_test.git
   ```

2. **Build the kernel module**:

   ```bash
   make
   ```

3. **Load the kernel module**:

   ```bash
   sudo insmod hypervisor_module.ko
   ```

4. After loading the module, the CPU should be prepared for **VMX** operations! 🎉

## 🌱 Long-Term Vision

The end goal of this project is to develop a **fully functional hypervisor** in **Rust**, focusing on **low-level CPU virtualization features** and memory safety. In the future, we plan to:

* Implement **VMCS management** in its entirety, supporting multiple virtual machines.
* Add guest memory management and I/O handling.

All of this will be done using **pure Rust**, maintaining a clean, memory-safe codebase.
