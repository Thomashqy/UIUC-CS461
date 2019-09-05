.global _main
.section .text

_main:

push	%ebp
mov	%esp,%ebp
xor    %eax,%eax
push   %eax
push   $0x0068732f
push   $0x6e69622f
mov    %esp,%ebx
push   %eax
push   %ebx
mov    %esp,%ecx
mov    $0xb,%eax
int    $0x80

leave
ret
