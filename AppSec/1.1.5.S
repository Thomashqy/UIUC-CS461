.section .data
shell:
.asciz	"/bin/sh"

.global _main
.section .text

_main:

push	%ebp
mov	%esp,%ebp

# filename = "/bin/sh"
mov	$shell,%ebx

# argv[0] = "/bin/sh", argv[1] = NULL
push	$0
push	%ebx
mov	%esp,%ecx

# envp = NULL
mov	$0,%edx

# system call number = 11
xor	%eax,%eax
mov	$11,%eax
int	$0x80

leave
ret
