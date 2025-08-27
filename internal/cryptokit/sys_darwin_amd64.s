// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !cgo

#include "go_asm.h"
#include "textflag.h"

#define maxArgs 42

TEXT ·syscallNRaw(SB),NOSPLIT,$16
	MOVQ	SP, AX
	MOVQ	AX, 8(SP)
	MOVQ	DI, 0(SP)

	MOVQ	libcCallInfo_fn(DI), R13
	MOVQ	libcCallInfo_n(DI), CX
	MOVQ	libcCallInfo_args(DI), DI

	SUBQ	$(maxArgs*8), SP	// room for args

	// Fast version, do not store args on the stack.
	CMPL	CX, $0;	JE	_0args
	CMPL	CX, $1;	JE	_1args
	CMPL	CX, $2;	JE	_2args
	CMPL	CX, $3;	JE	_3args
	CMPL	CX, $4;	JE	_4args
	CMPL	CX, $5;	JE	_5args
	CMPL	CX, $6;	JE	_6args
	CMPL	CX, $7;	JE	_7args
	CMPL	CX, $8;	JE	_8args
	CMPL	CX, $9;	JE	_9args

	// Check we have enough room for args.
	CMPL	CX, $maxArgs
	JLE	2(PC)
	INT	$3			// not enough room -> crash

	// Copy args to the stack.
	MOVQ	DI, SI
	MOVQ	SP, DI
	CLD
	REP; MOVSQ
	MOVQ	SP, DI

_9args:
	MOVQ	72(DI), R12
_8args:
	MOVQ	56(DI), R11
_7args:
	MOVQ	48(DI), R10
_6args:
	MOVQ	40(DI), R9
_5args:
	MOVQ	32(DI), R8
_4args:
	MOVQ	24(DI), CX
_3args:
	MOVQ	16(DI), DX
_2args:
	MOVQ	8(DI), SI
_1args:
	MOVQ	0(DI), DI
_0args:

	XORL	AX, AX	      // vararg: say "no float args"

	// Call stdcall function.
	CALL	R13

	ADDQ	$(maxArgs*8), SP

	// Return result.
	MOVQ	0(SP), DI
	MOVQ	8(SP), SP
	MOVQ	AX, libcCallInfo_r1(DI)
	MOVQ    DX, libcCallInfo_r2(DI)

	RET
