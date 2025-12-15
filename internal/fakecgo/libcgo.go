// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2022 The Ebitengine Authors

//go:build !cgo && darwin

package fakecgo

type (
	size_t uintptr
	// Sources:
	// Darwin (32 bytes) - https://github.com/apple/darwin-xnu/blob/2ff845c2e033bd0ff64b5b6aa6063a1f8f65aa32/bsd/sys/_types.h#L74
	sigset_t       [128]byte
	pthread_attr_t [64]byte
	pthread_t      int
	pthread_key_t  uint64
)

// for pthread_sigmask:

type sighow int32

const (
	SIG_BLOCK   sighow = 0
	SIG_UNBLOCK sighow = 1
	SIG_SETMASK sighow = 2
)

type G struct {
	stacklo uintptr
	stackhi uintptr
}

type ThreadStart struct {
	g   *G
	tls *uintptr
	fn  uintptr
}
