[CPU intelnop]
[bits 64]

section .text
align 32
global _xorinto_gpr
_xorinto_gpr:
%define dst  rdi
%define src1 rsi
%define src2 rdx
%define n rcx
%define r0 r12
%define r1 rax
%define r2 rbx
%define e1 eax
%define e2 ebx
%define a1 al
%define a2 bl
%define w1 ax
%define w2 bx

%define todo n
%define i r8

  add dst, n
  add src1, n
  add src2, n
  neg n
  ._dispatch:
    cmp n, 0
    je ._done

    cmp n, -8
    jge ._byqw
  
    cmp n, -4
    jge ._bydw
  
    cmp n, -2
    jge ._byw
 
    cmp n, -1
    je ._bybyte


  ._byqw:  
    mov  r1, [n + src1]     ; r1 = src1[i]
    mov  r2, [n + src2]     ; r2 = src2[i]
    xor  r1, r2             ; r1 ^= r2
    mov  [n + dst], r1      ; dst[i] = r1
    add  n, 8               ; n -= 8
    cmp  n, 8
    jle  ._byqw
    jmp  ._dispatch
 
  ._bydw:
    mov  e1, [n + src1]
    mov  e2, [n + src2]
    xor  e1, e2
    mov  [n + dst], e1
    add  n, 4
    jmp  ._dispatch

  ._byw:
    mov  w1, [n + src1]
    mov  w2, [n + src2]
    xor  w1, w2
    mov  [n + dst], w1
    add  n, 2
    jz   ._done

  ._bybyte:
    mov  a1, [n + src1]     
    mov  a2, [n + src2]     
    xor  a1, a2             
    mov  [n + dst], a1      
    inc  n                  

  ._done:
    ret


global _xorinto_sse
_xorinto_sse:

; Safety condition:
;   d mod 8 == s1 mod 8 == s2 mod 8
; (Initial unaligned prefix.)

  mov r0, dst
  and r0, 7
  mov r1, src1
  and r1, 7
  cmp r0, r2
  jne ._misaligned
  mov r0, src2
  and r0, 7
  cmp r0, r2
  jne ._misaligned
  ;  (d & 7) == (s1 & 7) == (s2 & 7)
  jnz ._alignedx16
  ; r0 is the misaligned prefix

  ._prefix:
    mov a1, [src1+i]
    mov a2, [src2+i]
    xor a1, a2
    mov [dst+i], a1
    inc i
    dec r0
  jnz ._prefix

  sub n, todo
  jz ._done

  ._alignedx16:
    movdqu xmm0, [src1+i]
    movdqu xmm1, [src2+i]
    pxor   xmm0, xmm1
    movdqu [dst+i], xmm0
    add i, 16
    sub n, 16
    cmp n, 16
    jnge ._alignedx16

  ._mopup:
  ._misaligned:
    add src2, i
    add src1, i
    add dst, i
    call _xorinto_gpr

  ._done:
  ret

global _xorinto_avx2
_xorinto_avx2:

  cmp rcx, 128
  jl  ._lt128

  .by128:
    sub n, 128
    vmovdqu ymm0, [src1+0 ]
    vmovdqu ymm1, [src1+32]
    vmovdqu ymm2, [src1+64]
    vmovdqu ymm3, [src1+96]
    add src1, 128
    vpxor   ymm0, ymm0, [src2+0 ]
    vpxor   ymm1, ymm1, [src2+32]
    vpxor   ymm2, ymm2, [src2+64]
    vpxor   ymm3, ymm3, [src2+96]
    add src2, 128
    vmovdqu [dst+0 ], ymm0
    vmovdqu [dst+32], ymm1
    vmovdqu [dst+64], ymm2
    vmovdqu [dst+96], ymm3
    add dst, 128
    cmp n, 128
    jge .by128

  ._lt128:
  cmp rcx, 32
  jl ._lt32

  .by32:
    sub n, 32
    vmovdqu ymm0, [src1]
    add src1, 32
    vpxor   ymm0, ymm0, [src2]
    add src2, 32
    vmovdqu [dst], ymm0
    add dst, 32

  ._lt32:

  



  
