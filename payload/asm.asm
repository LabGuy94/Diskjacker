.code
JmpToOriginal PROC
	;Standard x64 prolouge but we pop an extra 8 bytes for the return address so it jmps back to the original function
    add     rsp, 28h
    pop     rdi
    jmp     r9
JmpToOriginal ENDP
END