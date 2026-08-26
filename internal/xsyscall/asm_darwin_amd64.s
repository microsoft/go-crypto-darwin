// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !cgo

#include "go_asm.h"
#include "textflag.h"

TEXT ·syscallNSystemStack_trampoline(SB), NOSPLIT|NOFRAME, $0-0
	// Keep SP aligned for the nested host-ABI call and reserve space for the
	// generated bindings' stack arguments.
	SUBQ $264, SP

	MOVQ libcCallInfo_fn(DI), R11
	MOVQ libcCallInfo_n(DI), CX
	MOVQ libcCallInfo_args(DI), R10

	CMPL CX, $0; JE trampoline_0args
	CMPL CX, $1; JE trampoline_1args
	CMPL CX, $2; JE trampoline_2args
	CMPL CX, $3; JE trampoline_3args
	CMPL CX, $4; JE trampoline_4args
	CMPL CX, $5; JE trampoline_5args
	CMPL CX, $6; JE trampoline_6args

	SUBQ $6, CX
	MOVQ R10, SI
	ADDQ $(8*6), SI
	MOVQ SP, DI
	CLD
	REP; MOVSQ

trampoline_6args:
	MOVQ (5*8)(R10), R9
trampoline_5args:
	MOVQ (4*8)(R10), R8
trampoline_4args:
	MOVQ (3*8)(R10), CX
trampoline_3args:
	MOVQ (2*8)(R10), DX
trampoline_2args:
	MOVQ (1*8)(R10), SI
trampoline_1args:
	MOVQ (0*8)(R10), DI
trampoline_0args:
	XORL AX, AX
	CALL R11

	ADDQ $264, SP
	RET
