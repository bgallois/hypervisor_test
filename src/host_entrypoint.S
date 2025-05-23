.intel_syntax noprefix

.global _guest_first_entry
_guest_first_entry:

    lea rdi, [rip+.guest_enters_here]
    mov rax, 0x0000681e // vmwrite Guest rip
    vmwrite rax, rdi
    jc .errorc
    jz .errorz

    mov rdi, rsp
    mov rax, 0x0000681c // vmwrite Guest rsp
    vmwrite rax, rdi
    jc .errorc
    jz .errorz

    vmlaunch
    jc .errorc
    jz .errorz
.errorz:
    mov rax, 1
    ret
.errorc:
    mov rax, 2
    ret
.guest_enters_here:
    xor rax, rax
    cpuid
    hlt

.global host_entrypoint
host_entrypoint:


	push rax
	push rbx
	push rcx
	push rdx
	push rbp
	push rsi
	push rdi
	push r8
	push r9
	push r10
	push r11
	push r12
	push r13
	push r14
	push r15


    call handle_vm_exit

	pop r15
	pop r14
	pop r13
	pop r12
	pop r11
	pop r10
	pop r9
	pop r8
	pop rdi
	pop rsi
	pop rbp
	pop rdx
	pop rcx
	pop rbx
	pop rax


    vmresume

	push rax
	push rbx
	push rcx
	push rdx
	push rbp
	push rsi
	push rdi
	push r8
	push r9
	push r10
	push r11
	push r12
	push r13
	push r14
	push r15

    mov rcx, rsp

    pushf
    pop rdx
    call vmresume_failure
    int3


.global platform_halt
platform_halt:
    cli
    hlt
    jmp platform_halt

