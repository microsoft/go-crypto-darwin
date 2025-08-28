// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !cgo

#include "go_asm.h"
#include "textflag.h"

TEXT ·syscallNRaw(SB),NOSPLIT,$16-8
	MOVQ	SP, AX
	MOVQ	AX, 8(SP)
	MOVQ	args+0(FP), DI
	MOVQ	DI, 0(SP)

	MOVQ	libcCallInfo_fn(DI), R13
	MOVQ	libcCallInfo_n(DI), CX
	MOVQ	libcCallInfo_args(DI), R10

	// Fast version, do not store args on the stack.
	CMPL	CX, $0;	JE	_0args
	CMPL	CX, $1;	JE	_1args
	CMPL	CX, $2;	JE	_2args
	CMPL	CX, $3;	JE	_3args
	CMPL	CX, $4;	JE	_4args
	CMPL	CX, $5;	JE	_5args
	CMPL	CX, $6;	JE	_6args

	// Reserve stack space for remaining args
	MOVQ	CX, R12
	SUBQ	$6, R12
	ADDQ	$1, R12 // make even number of words for stack alignment
	ANDQ	$~1, R12
	SHLQ	$3, R12
	SUBQ	R12, SP

	// Copy args to the stack.
	// CX: count of stack arguments (n-6)
	// SI: &args[6]
	// DI: copy of RSP
	SUBQ	$6, CX
	MOVQ	R10, SI
	ADDQ	$(8*6), SI
	MOVQ	SP, DI
	CLD
	REP; MOVSQ

_6args:
	MOVQ	(5*8)(R10), R9
_5args:
	MOVQ	(4*8)(R10), R8
_4args:
	MOVQ	(3*8)(R10), CX
_3args:
	MOVQ	(2*8)(R10), DX
_2args:
	MOVQ	(1*8)(R10), SI
_1args:
	MOVQ	(0*8)(R10), DI
_0args:

	XORL	AX, AX	    // vararg: say "no float args"

	// Call stdcall function.
	CALL	R13

	ADDQ	R12, SP		// free stack space

	// Return result.
	MOVQ	0(SP), DI
	MOVQ	8(SP), SP
	MOVQ	AX, libcCallInfo_r1(DI)
	MOVQ    DX, libcCallInfo_r2(DI)

	RET
