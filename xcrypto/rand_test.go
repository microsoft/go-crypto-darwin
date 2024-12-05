// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package xcrypto_test

import (
	"testing"

	"github.com/microsoft/go-crypto-darwin/xcrypto"
)

func TestRand(t *testing.T) {
	_, err := xcrypto.RandReader.Read(make([]byte, 5))
	if err != nil {
		t.Fatal(err)
	}
}

func TestAllocations(t *testing.T) {
	n := int(testing.AllocsPerRun(10, func() {
		buf := make([]byte, 32)
		xcrypto.RandReader.Read(buf)
		sink ^= buf[0]
	}))
	want := 1
	if compareCurrentVersion("go1.24") >= 0 {
		// The go1.24 compiler is able to optimize the allocation away.
		// See cgo_go124.go for more information.
		want = 0
	}
	if n > want {
		t.Errorf("allocs = %d, want %d", n, want)
	}
}
