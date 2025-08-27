// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !cgo

#include "go_asm.h"
#include "textflag.h"

TEXT ·_mkcgo_asm_CCCryptorCreateWithMode(SB),NOSPLIT,$0-104
	// Set up arguments for the syscall
	MOVD	p0+0(FP), R0
	MOVD	p1+8(FP), R1
	MOVD	p2+16(FP), R2
	MOVD	p3+24(FP), R3
	MOVD	p4+32(FP), R4
	MOVD	p5+40(FP), R5
	MOVD	p6+48(FP), R6
	MOVD	p7+56(FP), R7
	MOVD	p8+64(FP), R8
	MOVD	p9+72(FP), R9
	MOVD	p10+80(FP), R10
	MOVD	p11+88(FP), R11

	// Add enough space to contain the stack arguments 
	// + 16 bytes as scratch space 
	// + optionally 8 bytes for alignment
	SUB	$32, RSP
	MOVD	R8, 0(RSP)
	MOVW	R9, 8(RSP)
	MOVW	R10, 12(RSP)
	MOVD	R11, 16(RSP)

	BL	_mkcgo_CCCryptorCreateWithMode(SB)

	ADD $32, RSP

	MOVW	R0, r1+96(FP)	// return value

    RET

TEXT ·syscallNRaw(SB),NOSPLIT,$16-8
	STP	(R19, R20), 16(RSP) // save old R19, R20
	MOVD	R0, R19	// save struct pointer
	MOVD	RSP, R20	// save stack pointer
	SUB	$16, RSP // reserve 16 bytes for sp-8 where fp may be saved.

	MOVD	libcCallInfo_args(R19), R12
	// Do we have more than 8 arguments?
	MOVD	libcCallInfo_n(R19), R0
	CMP	$0,	R0; BEQ	_0args
	CMP	$1,	R0; BEQ	_1args
	CMP	$2,	R0; BEQ	_2args
	CMP	$3,	R0; BEQ	_3args
	CMP	$4,	R0; BEQ	_4args
	CMP	$5,	R0; BEQ	_5args
	CMP	$6,	R0; BEQ	_6args
	CMP	$7,	R0; BEQ	_7args
	CMP	$8,	R0; BEQ	_8args

	// Reserve stack space for remaining args
	SUB	$8, R0, R2
	ADD	$1, R2, R3 // make even number of words for stack alignment
	AND	$~1, R3
	LSL	$3, R3
	SUB	R3, RSP

	// R4: size of stack arguments (n-8)*8
	// R5: &args[8]
	// R6: loop counter, from 0 to (n-8)*8
	// R7: scratch
	// R8: copy of RSP - (R2)(RSP) assembles as (R2)(ZR)
	SUB	$8, R0, R4
	LSL	$3, R4
	ADD	$(8*8), R12, R5
	MOVD	$0, R6
	MOVD	RSP, R8
stackargs:
	MOVD	(R6)(R5), R7
	MOVD	R7, (R6)(R8)
	ADD	$8, R6
	CMP	R6, R4
	BNE	stackargs

_8args:
	MOVD	(7*8)(R12), R7
_7args:
	MOVD	(6*8)(R12), R6
_6args:
	MOVD	(5*8)(R12), R5
_5args:
	MOVD	(4*8)(R12), R4
_4args:
	MOVD	(3*8)(R12), R3
_3args:
	MOVD	(2*8)(R12), R2
_2args:
	MOVD	(1*8)(R12), R1
_1args:
	MOVD	(0*8)(R12), R0
_0args:

	// If fn is declared as vararg, we have to pass the vararg arguments on the stack.
	// (Because ios decided not to adhere to the standard arm64 calling convention, sigh...)
	// The only libSystem calls we support with vararg are open, fcntl, ioctl,
	// which are all of the form fn(x, y, ...), and openat, which is of the form fn(x, y, z, ...).
	// So we just need to put the  3rd and the 4th arg on the stack as well.
	// Note that historically openat has been called with syscall6, so we need to handle that case too.
	// If we ever have other vararg libSystem calls, we might need to handle more cases.
	MOVD	libcCallInfo_n(R19), R12
	CMP	$3,	R12; BNE 2(PC);
	MOVD	R2, (RSP)
	CMP $4, R12; BNE 2(PC);
	MOVD	R3, (RSP)
	CMP $6, R12; BNE 2(PC);
	MOVD	R3, (RSP)

	MOVD	libcCallInfo_fn(R19), R12
	BL	(R12)

	MOVD	R20, RSP			// free stack space

	MOVD	R0, libcCallInfo_r1(R19)	// save r1
	MOVD	R1, libcCallInfo_r2(R19)	// save r2

	// Restore callee-saved registers.
	LDP	16(RSP), (R19, R20)
    RET
