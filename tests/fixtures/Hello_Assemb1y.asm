.8086
.model small
.stack 100h

.data
    key         db 'Hello'
    KEY_LEN     equ $ - key

    cipher      db 01Ch, 029h, 03Bh, 02Dh, 017h, 022h, 003h, 060h
                db 012h, 003h, 028h, 003h, 036h, 03Bh, 003h, 01Ah
                db 027h, 022h, 022h, 00Dh, 028h, 00Ah, 060h, 018h
                db 033h, 022h, 00Dh, 021h, 060h, 00Eh, 06Ch, 01Bh
    FLAG_LEN    equ $ - cipher

    input_buf   db 64, 0, 64 dup (0)
    msg_prompt  db 'Input flag: $'
    msg_ok      db 13, 10, 'Correct!', 13, 10, '$'
    msg_bad     db 13, 10, 'Wrong!', 13, 10, '$'

.code
main proc
    mov ax, @data
    mov ds, ax

    lea dx, msg_prompt
    mov ah, 09h
    int 21h

    lea dx, input_buf
    mov ah, 0Ah
    int 21h

    cmp byte ptr [input_buf+1], FLAG_LEN
    jne failed

    lea si, input_buf+2
    lea di, cipher
    xor bx, bx
    mov cx, FLAG_LEN

check_loop:
    mov al, [si]
    xor al, key[bx]
    add al, 3

    cmp al, [di]
    jne failed

    inc si
    inc di

    inc bx
    cmp bx, KEY_LEN
    jb key_ready
    xor bx, bx

key_ready:
    loop check_loop

    lea dx, msg_ok
    mov ah, 09h
    int 21h
    mov ax, 4C00h
    int 21h

failed:
    lea dx, msg_bad
    mov ah, 09h
    int 21h
    mov ax, 4C01h
    int 21h
main endp
end main
