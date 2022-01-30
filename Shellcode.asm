.code

SpoofCall PROC
mov rax, 0deadbeef00000001h ;Move a recognizable magic number into RAX
mov qword ptr[ rax ], 0     ;Deliberately cause an access violation to trap to our handler
SpoofCall ENDP

END
