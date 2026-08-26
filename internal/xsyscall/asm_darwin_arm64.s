// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !cgo

#include "go_asm.h"
#include "textflag.h"

TEXT ·syscallNSystemStack_trampoline(SB), NOSPLIT|NOFRAME, $0-0
	// Reserve outgoing stack arguments while keeping SP restoration independent
	// of registers clobbered by the foreign call.
	SUB $256, RSP
	MOVD R30, 248(RSP)
	MOVD R0, R9

	MOVD libcCallInfo_args(R9), R12
	MOVD libcCallInfo_fn(R9), R13

	MOVD libcCallInfo_n(R9), R0
	CMP  $0, R0; BEQ trampoline_0args
	CMP  $1, R0; BEQ trampoline_1args
	CMP  $2, R0; BEQ trampoline_2args
	CMP  $3, R0; BEQ trampoline_3args
	CMP  $4, R0; BEQ trampoline_4args
	CMP  $5, R0; BEQ trampoline_5args
	CMP  $6, R0; BEQ trampoline_6args
	CMP  $7, R0; BEQ trampoline_7args
	CMP  $8, R0; BEQ trampoline_8args

	SUB  $8, R0, R4
	LSL  $3, R4
	ADD  $(8*8), R12, R5
	MOVD $0, R6
	MOVD RSP, R8

trampoline_stackargs:
	MOVD (R6)(R5), R7
	MOVD R7, (R6)(R8)
	ADD  $8, R6
	CMP  R6, R4
	BNE  trampoline_stackargs

trampoline_8args:
	MOVD (7*8)(R12), R7
trampoline_7args:
	MOVD (6*8)(R12), R6
trampoline_6args:
	MOVD (5*8)(R12), R5
trampoline_5args:
	MOVD (4*8)(R12), R4
trampoline_4args:
	MOVD (3*8)(R12), R3
trampoline_3args:
	MOVD (2*8)(R12), R2
trampoline_2args:
	MOVD (1*8)(R12), R1
trampoline_1args:
	MOVD (0*8)(R12), R0
trampoline_0args:
	BL (R13)

	MOVD 248(RSP), R30
	ADD $256, RSP
	RET
