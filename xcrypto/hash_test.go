// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package xcrypto_test

import (
	"bytes"
	"crypto"
	"encoding"
	"errors"
	"hash"
	"io"
	"runtime"
	"testing"

	"github.com/microsoft/go-crypto-darwin/xcrypto"
)

func cryptoToHash(h crypto.Hash) func() hash.Hash {
	switch h {
	case crypto.MD5:
		return xcrypto.NewMD5
	case crypto.SHA1:
		return xcrypto.NewSHA1
	case crypto.SHA224:
		return xcrypto.NewSHA224
	case crypto.SHA256:
		return xcrypto.NewSHA256
	case crypto.SHA384:
		return xcrypto.NewSHA384
	case crypto.SHA512:
		return xcrypto.NewSHA512
	// case crypto.SHA3_224:
	// 	return func() hash.Hash { return xcrypto.NewSHA3_224() }
	case crypto.SHA3_256:
		return func() hash.Hash { return xcrypto.NewSHA3_256() }
	case crypto.SHA3_384:
		return func() hash.Hash { return xcrypto.NewSHA3_384() }
	case crypto.SHA3_512:
		return func() hash.Hash { return xcrypto.NewSHA3_512() }
	}
	return nil
}

var hashes = [...]crypto.Hash{
	crypto.MD5,
	crypto.SHA1,
	crypto.SHA224,
	crypto.SHA256,
	crypto.SHA384,
	crypto.SHA512,
	// crypto.SHA3_224,
	crypto.SHA3_256,
	crypto.SHA3_384,
	crypto.SHA3_512,
}

func TestHash(t *testing.T) {
	msg := []byte("testing")
	for _, ch := range hashes {
		t.Run(ch.String(), func(t *testing.T) {
			t.Parallel()
			if !xcrypto.SupportsHash(ch) {
				t.Skip("not supported")
			}
			h := cryptoToHash(ch)()
			initSum := h.Sum(nil)
			n, err := h.Write(msg)
			if err != nil {
				t.Fatal(err)
			}
			if n != len(msg) {
				t.Errorf("got: %d, want: %d", n, len(msg))
			}
			// Test that passing and empty slice don't panic.
			h.Write(nil)
			h.Write([]byte{})
			sum := h.Sum(nil)
			if size := h.Size(); len(sum) != size {
				t.Errorf("got: %d, want: %d", len(sum), size)
			}
			if bytes.Equal(sum, initSum) {
				t.Error("Write didn't change internal hash state")
			}
			h.Reset()
			sum = h.Sum(nil)
			if !bytes.Equal(sum, initSum) {
				t.Errorf("got:%x want:%x", sum, initSum)
			}
		})
	}
}

func TestHash_BinaryMarshaler(t *testing.T) {
	t.Skip("Marshalling is not supported")
	msg := []byte("testing")
	for _, ch := range hashes {
		t.Run(ch.String(), func(t *testing.T) {
			t.Parallel()
			if !xcrypto.SupportsHash(ch) {
				t.Skip("hash not supported")
			}

			hashMarshaler, ok := cryptoToHash(ch)().(interface {
				hash.Hash
				encoding.BinaryMarshaler
			})
			if !ok {
				t.Skip("BinaryMarshaler not supported")
			}

			if _, err := hashMarshaler.Write(msg); err != nil {
				t.Fatalf("Write failed: %v", err)
			}

			state, err := hashMarshaler.MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary failed: %v", err)
			}

			hashUnmarshaler := cryptoToHash(ch)().(interface {
				hash.Hash
				encoding.BinaryUnmarshaler
			})
			if err := hashUnmarshaler.UnmarshalBinary(state); err != nil {
				t.Fatalf("UnmarshalBinary failed: %v", err)
			}

			if actual, actual2 := hashMarshaler.Sum(nil), hashUnmarshaler.Sum(nil); !bytes.Equal(actual, actual2) {
				t.Errorf("0x%x != appended 0x%x", actual, actual2)
			}
		})
	}
}

func TestHash_BinaryAppender(t *testing.T) {
	for _, ch := range hashes {
		t.Run(ch.String(), func(t *testing.T) {
			t.Parallel()
			if !xcrypto.SupportsHash(ch) {
				t.Skip("not supported")
			}

			hashWithBinaryAppender, ok := cryptoToHash(ch)().(interface {
				hash.Hash
				AppendBinary(b []byte) ([]byte, error)
			})

			// Create a slice with 10 elements
			prebuiltSlice := make([]byte, 10)
			// Fill the slice with some data
			for i := range prebuiltSlice {
				prebuiltSlice[i] = byte(i)
			}

			// Clone the prebuilt slice for comparison
			prebuiltSliceClone := append([]byte(nil), prebuiltSlice...)

			// Append binary data to the prebuilt slice
			state, err := hashWithBinaryAppender.AppendBinary(prebuiltSlice)
			if err != nil {
				if errors.Is(err, errors.ErrUnsupported) {
					t.Skip("AppendBinary not supported")
				}
				t.Errorf("could not append binary: %v", err)
			}

			// Ensure the first 10 elements are still the same
			if !bytes.Equal(state[:10], prebuiltSliceClone) {
				t.Errorf("prebuilt slice modified: got %v, want %v", state[:10], prebuiltSliceClone)
			}

			// Use only the newly appended part of the slice
			appendedState := state[10:]

			h2, ok := cryptoToHash(ch)().(interface {
				hash.Hash
				encoding.BinaryUnmarshaler
			})
			if !ok {
				t.Skip("not supported")
			}

			if err := h2.UnmarshalBinary(appendedState); err != nil {
				t.Errorf("could not unmarshal: %v", err)
			}
			if actual, actual2 := hashWithBinaryAppender.Sum(nil), h2.Sum(nil); !bytes.Equal(actual, actual2) {
				t.Errorf("0x%x != appended 0x%x", actual, actual2)
			}
		})
	}
}

func TestHash_Clone(t *testing.T) {
	msg := []byte("testing")
	for _, ch := range hashes {
		t.Run(ch.String(), func(t *testing.T) {
			t.Parallel()
			if !xcrypto.SupportsHash(ch) {
				t.Skip("not supported")
			}
			h := cryptoToHash(ch)().(xcrypto.HashCloner)
			_, err := h.Write(msg)
			if err != nil {
				t.Fatal(err)
			}

			h3, err := h.Clone()
			if err != nil {
				t.Fatalf("Clone failed: %v", err)
			}
			prefix := []byte("tmp")
			writeToHash(t, h, prefix)
			h2, err := h.Clone()
			if err != nil {
				t.Fatalf("Clone failed: %v", err)
			}
			prefixSum := h.Sum(nil)
			if !bytes.Equal(prefixSum, h2.Sum(nil)) {
				t.Fatalf("%T Clone results are inconsistent", h)
			}
			suffix := []byte("tmp2")
			writeToHash(t, h, suffix)
			writeToHash(t, h3, append(prefix, suffix...))
			compositeSum := h3.Sum(nil)
			if !bytes.Equal(h.Sum(nil), compositeSum) {
				t.Fatalf("%T Clone results are inconsistent", h)
			}
			if !bytes.Equal(h2.Sum(nil), prefixSum) {
				t.Fatalf("%T Clone results are inconsistent", h)
			}
			writeToHash(t, h2, suffix)
			if !bytes.Equal(h.Sum(nil), compositeSum) {
				t.Fatalf("%T Clone results are inconsistent", h)
			}
			if !bytes.Equal(h2.Sum(nil), compositeSum) {
				t.Fatalf("%T Clone results are inconsistent", h)
			}
		})
	}
}

func TestHash_ByteWriter(t *testing.T) {
	msg := []byte("testing")
	for _, ch := range hashes {
		t.Run(ch.String(), func(t *testing.T) {
			t.Parallel()
			if !xcrypto.SupportsHash(ch) {
				t.Skip("not supported")
			}
			bwh := cryptoToHash(ch)().(interface {
				hash.Hash
				io.ByteWriter
			})
			initSum := bwh.Sum(nil)
			for i := range len(msg) {
				bwh.WriteByte(msg[i])
			}
			bwh.Reset()
			sum := bwh.Sum(nil)
			if !bytes.Equal(sum, initSum) {
				t.Errorf("got:%x want:%x", sum, initSum)
			}
		})
	}
}

func TestHash_StringWriter(t *testing.T) {
	msg := []byte("testing")
	for _, ch := range hashes {
		t.Run(ch.String(), func(t *testing.T) {
			t.Parallel()
			if !xcrypto.SupportsHash(ch) {
				t.Skip("not supported")
			}
			h := cryptoToHash(ch)()
			initSum := h.Sum(nil)
			h.(io.StringWriter).WriteString(string(msg))
			h.Reset()
			sum := h.Sum(nil)
			if !bytes.Equal(sum, initSum) {
				t.Errorf("got:%x want:%x", sum, initSum)
			}
		})
	}
}

func TestHash_OneShot(t *testing.T) {
	msg := []byte("testing")
	var tests = []struct {
		h       crypto.Hash
		oneShot func([]byte) []byte
	}{
		{crypto.SHA1, func(p []byte) []byte {
			b := xcrypto.SHA1(p)
			return b[:]
		}},
		{crypto.SHA224, func(p []byte) []byte {
			b := xcrypto.SHA224(p)
			return b[:]
		}},
		{crypto.SHA256, func(p []byte) []byte {
			b := xcrypto.SHA256(p)
			return b[:]
		}},
		{crypto.SHA384, func(p []byte) []byte {
			b := xcrypto.SHA384(p)
			return b[:]
		}},
		{crypto.SHA512, func(p []byte) []byte {
			b := xcrypto.SHA512(p)
			return b[:]
		}},
		// {crypto.SHA3_224, func(p []byte) []byte {
		// 	b := xcrypto.SumSHA3_224(p)
		// 	return b[:]
		// }},
		{crypto.SHA3_256, func(p []byte) []byte {
			b := xcrypto.SumSHA3_256(p)
			return b[:]
		}},
		{crypto.SHA3_384, func(p []byte) []byte {
			b := xcrypto.SumSHA3_384(p)
			return b[:]
		}},
		{crypto.SHA3_512, func(p []byte) []byte {
			b := xcrypto.SumSHA3_512(p)
			return b[:]
		}},
	}
	for _, tt := range tests {
		t.Run(tt.h.String(), func(t *testing.T) {
			if !xcrypto.SupportsHash(tt.h) {
				t.Skip("not supported")
			}
			got := tt.oneShot(msg)
			h := cryptoToHash(tt.h)()
			h.Write(msg)
			want := h.Sum(nil)
			if !bytes.Equal(got, want) {
				t.Errorf("got:%x want:%x", got, want)
			}
		})
	}
}

type cgoData struct {
	Data [16]byte
	Ptr  *cgoData
}

func TestCgo(t *testing.T) {
	// Test that Write does not cause cgo to scan the entire cgoData struct for pointers.
	// The scan (if any) should be limited to the [16]byte.
	defer func() {
		if err := recover(); err != nil {
			t.Error(err)
		}
	}()
	d := new(cgoData)
	d.Ptr = d
	h := xcrypto.NewSHA256()
	h.Write(d.Data[:])
	h.Sum(nil)

	xcrypto.SHA256(d.Data[:])
}

func verifySHA256(token, salt string) [32]byte {
	return xcrypto.SHA256([]byte(token + salt))
}

func TestIssue71943(t *testing.T) {
	// https://github.com/golang/go/issues/71943
	if Asan() {
		t.Skip("skipping allocations test with sanitizers")
	}
	n := int(testing.AllocsPerRun(10, func() {
		runtime.KeepAlive(verifySHA256("teststring", "test"))
	}))
	want := 0
	if n > want {
		t.Errorf("allocs = %d, want %d", n, want)
	}
}

func TestHashOneShotAllocations(t *testing.T) {
	if Asan() {
		t.Skip("skipping allocations test with sanitizers")
	}
	msg := []byte("testing")
	n := int(testing.AllocsPerRun(10, func() {
		sink ^= xcrypto.SHA1(msg)[0]
		sink ^= xcrypto.SHA224(msg)[0]
		sink ^= xcrypto.SHA256(msg)[0]
		sink ^= xcrypto.SHA512(msg)[0]
	}))
	want := 0
	if n > want {
		t.Errorf("allocs = %d, want %d", n, want)
	}
}

func TestHashAllocations(t *testing.T) {
	if Asan() {
		t.Skip("skipping allocations test with sanitizers")
	}
	msg := []byte("testing")

	sha1Hash := xcrypto.NewSHA1()
	sha224Hash := xcrypto.NewSHA224()
	sha256Hash := xcrypto.NewSHA256()
	sha512Hash := xcrypto.NewSHA512()

	sum := make([]byte, sha512Hash.Size())
	n := int(testing.AllocsPerRun(10, func() {
		sha1Hash.Write(msg)
		sha224Hash.Write(msg)
		sha256Hash.Write(msg)
		sha512Hash.Write(msg)

		sha1Hash.Sum(sum[:0])
		sha224Hash.Sum(sum[:0])
		sha256Hash.Sum(sum[:0])
		sha512Hash.Sum(sum[:0])

		sha1Hash.Reset()
		sha224Hash.Reset()
		sha256Hash.Reset()
		sha512Hash.Reset()
	}))
	want := 0
	if n > want {
		t.Errorf("allocs = %d, want %d", n, want)
	}
}

func TestHashNewAllocations(t *testing.T) {
	if Asan() || OptimizationOff() {
		t.Skip("skipping allocations test with sanitizers")
	}
	n := int(testing.AllocsPerRun(10, func() {
		sha1Hash := xcrypto.NewSHA1()
		sha224Hash := xcrypto.NewSHA224()
		sha256Hash := xcrypto.NewSHA256()
		sha512Hash := xcrypto.NewSHA512()

		sha1Hash.Reset()
		sha224Hash.Reset()
		sha256Hash.Reset()
		sha512Hash.Reset()
	}))
	want := 0
	if n > want {
		t.Errorf("allocs = %d, want %d", n, want)
	}
}

func TestHashStructAllocations(t *testing.T) {
	if Asan() {
		t.Skip("skipping allocations test with sanitizers")
	}
	msg := []byte("testing")

	sum := make([]byte, xcrypto.NewSHA512().Size())
	n := int(testing.AllocsPerRun(10, func() {
		md5Hash := xcrypto.NewMD5()
		sha1Hash := xcrypto.NewSHA1()
		sha224Hash := xcrypto.NewSHA224()
		sha256Hash := xcrypto.NewSHA256()
		sha512Hash := xcrypto.NewSHA512()

		md5Hash.Write(msg)
		sha1Hash.Write(msg)
		sha224Hash.Write(msg)
		sha256Hash.Write(msg)
		sha512Hash.Write(msg)

		md5Hash.Sum(sum[:0])
		sha1Hash.Sum(sum[:0])
		sha224Hash.Sum(sum[:0])
		sha256Hash.Sum(sum[:0])
		sha512Hash.Sum(sum[:0])

		md5Hash.Reset()
		sha1Hash.Reset()
		sha224Hash.Reset()
		sha256Hash.Reset()
		sha512Hash.Reset()
	}))
	want := 5
	if n > want {
		t.Errorf("allocs = %d, want %d", n, want)
	}
}

func TestHashAllocationsWithTypeAsserts(t *testing.T) {
	if Asan() || OptimizationOff() {
		t.Skip("skipping allocations test with sanitizers")
	}
	allocs := testing.AllocsPerRun(100, func() {
		h := xcrypto.NewSHA256()
		h.Write([]byte{1, 2, 3})
		marshaled, _ := h.(encoding.BinaryMarshaler).MarshalBinary()
		marshaled, _ = h.(encoding.BinaryAppender).AppendBinary(marshaled[:0])
		h.(encoding.BinaryUnmarshaler).UnmarshalBinary(marshaled)
	})
	const maxAllocs = 2
	if allocs > float64(maxAllocs) {
		t.Fatalf("allocs = %v; want <= %v", allocs, maxAllocs)
	}
}

func BenchmarkNewSHA256(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		xcrypto.NewSHA256()
	}
}

func BenchmarkHash8Bytes(b *testing.B) {
	benchmarkSize(b, 8)
}

func BenchmarkHash1K(b *testing.B) {
	benchmarkSize(b, 1024)
}

func BenchmarkHash8K(b *testing.B) {
	benchmarkSize(b, 8192)
}

func BenchmarkHash256K(b *testing.B) {
	benchmarkSize(b, 256*1024)
}

func BenchmarkHash1M(b *testing.B) {
	benchmarkSize(b, 1024*1024)
}

func benchmarkSize(b *testing.B, size int) {
	var bench = xcrypto.NewSHA256()
	buf := make([]byte, size)
	sum := make([]byte, bench.Size())
	b.Run("New", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(size))
		for i := 0; i < b.N; i++ {
			bench.Reset()
			bench.Write(buf)
			bench.Sum(sum[:0])
		}
	})
	b.Run("NewSteps", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(size))
		step := size / 8
		if step == 0 {
			step = 1
		}
		for i := 0; i < b.N; i++ {
			bench.Reset()
			for j := 0; j < size; j += step {
				bench.Write(buf[j : j+step])
			}
			bench.Sum(sum[:0])
		}
	})
	b.Run("Sum256", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(size))
		for i := 0; i < b.N; i++ {
			xcrypto.SHA256(buf)
		}
	})
}

// stubHash is a hash.Hash implementation that does nothing.
type stubHash struct{}

func newStubHash() hash.Hash {
	return new(stubHash)
}

func (h *stubHash) Write(p []byte) (int, error) { return 0, nil }
func (h *stubHash) Sum(in []byte) []byte        { return in }
func (h *stubHash) Reset()                      {}
func (h *stubHash) Size() int                   { return 0 }
func (h *stubHash) BlockSize() int              { return 0 }

// Helper function for writing. Verifies that Write does not error.
func writeToHash(t *testing.T, h hash.Hash, p []byte) {
	t.Helper()

	before := make([]byte, len(p))
	copy(before, p)

	n, err := h.Write(p)
	if err != nil || n != len(p) {
		t.Errorf("Write returned error; got (%v, %v), want (nil, %v)", err, n, len(p))
	}

	if !bytes.Equal(p, before) {
		t.Errorf("Write modified input slice; got %x, want %x", p, before)
	}
}
