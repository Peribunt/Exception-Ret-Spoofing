.code

InitSpoofCall PROC
mov rsi, rcx
mov rdi, rdx
ret
InitSpoofCall ENDP

SpoofCall PROC
mov rax, 0deadbeef00000001h ;Move a recognizable magic number into RAX
sti							;Deliberately cause an access violation to trap to our handler
SpoofCall ENDP

END
