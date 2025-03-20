// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package xcrypto_test

import (
	"bytes"
	"crypto"
	"encoding"
	"fmt"
	"hash"
	"io"
	"strings"
	"testing"

	"github.com/microsoft/go-crypto-darwin/xcrypto"
)

func cryptoToHash(h crypto.Hash) func() hash.Hash {
	switch h {
	case crypto.MD4:
		return xcrypto.NewMD4
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
		// 	return xcrypto.NewSHA3_224
		// case crypto.SHA3_256:
		// 	return xcrypto.NewSHA3_256
		// case crypto.SHA3_384:
		// 	return xcrypto.NewSHA3_384
		// case crypto.SHA3_512:
		// 	return xcrypto.NewSHA3_512
	}
	return nil
}

var hashes = [...]crypto.Hash{
	crypto.MD4,
	crypto.MD5,
	crypto.SHA1,
	crypto.SHA224,
	crypto.SHA256,
	crypto.SHA384,
	crypto.SHA512,
	// crypto.SHA3_224,
	// crypto.SHA3_256,
	// crypto.SHA3_384,
	// crypto.SHA3_512,
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
				if strings.Contains(err.Error(), "hash state is not marshallable") {
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
			h := cryptoToHash(ch)()
			_, err := h.Write(msg)
			if err != nil {
				t.Fatal(err)
			}
			// We don't define an interface for the Clone method to avoid other
			// packages from depending on it. Use type assertion to call it.
			h2 := h.(interface{ Clone() hash.Hash }).Clone()
			h.Write(msg)
			h2.Write(msg)
			if actual, actual2 := h.Sum(nil), h2.Sum(nil); !bytes.Equal(actual, actual2) {
				t.Errorf("%s(%q) = 0x%x != cloned 0x%x", ch.String(), msg, actual, actual2)
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
		// 	b := xcrypto.SHA3_224(p)
		// 	return b[:]
		// }},
		// {crypto.SHA3_256, func(p []byte) []byte {
		// 	b := xcrypto.SHA3_256(p)
		// 	return b[:]
		// }},
		// {crypto.SHA3_384, func(p []byte) []byte {
		// 	b := xcrypto.SHA3_384(p)
		// 	return b[:]
		// }},
		// {crypto.SHA3_512, func(p []byte) []byte {
		// 	b := xcrypto.SHA3_512(p)
		// 	return b[:]
		// }},
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

type sha256Test struct {
	out       string
	in        string
	halfState string // marshaled hash state after first half of in written, used by TestGoldenMarshal
}

var golden256 = []sha256Test{
	{"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "", "sha\x03j\t\xe6g\xbbg\xae\x85<n\xf3r\xa5O\xf5:Q\x0eR\u007f\x9b\x05h\x8c\x1f\x83٫[\xe0\xcd\x19\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"},
	{"ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb", "a", "sha\x03j\t\xe6g\xbbg\xae\x85<n\xf3r\xa5O\xf5:Q\x0eR\u007f\x9b\x05h\x8c\x1f\x83٫[\xe0\xcd\x19\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"},
	{"fb8e20fc2e4c3f248c60c39bd652f3c1347298bb977b8b4d5903b85055620603", "ab", "sha\x03j\t\xe6g\xbbg\xae\x85<n\xf3r\xa5O\xf5:Q\x0eR\u007f\x9b\x05h\x8c\x1f\x83٫[\xe0\xcd\x19a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"},
	{"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "abc", "sha\x03j\t\xe6g\xbbg\xae\x85<n\xf3r\xa5O\xf5:Q\x0eR\u007f\x9b\x05h\x8c\x1f\x83٫[\xe0\xcd\x19a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"},
	{"88d4266fd4e6338d13b845fcf289579d209c897823b9217da3e161936f031589", "abcd", "sha\x03j\t\xe6g\xbbg\xae\x85<n\xf3r\xa5O\xf5:Q\x0eR\u007f\x9b\x05h\x8c\x1f\x83٫[\xe0\xcd\x19ab\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02"},
	{"36bbe50ed96841d10443bcb670d6554f0a34b761be67ec9c4a8ad2c0c44ca42c", "abcde", "sha\x03j\t\xe6g\xbbg\xae\x85<n\xf3r\xa5O\xf5:Q\x0eR\u007f\x9b\x05h\x8c\x1f\x83٫[\xe0\xcd\x19ab\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02"},
	{"bef57ec7f53a6d40beb640a780a639c83bc29ac8a9816f1fc6c5c6dcd93c4721", "abcdef", "sha\x03j\t\xe6g\xbbg\xae\x85<n\xf3r\xa5O\xf5:Q\x0eR\u007f\x9b\x05h\x8c\x1f\x83٫[\xe0\xcd\x19abc\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03"},
	{"7d1a54127b222502f5b79b5fb0803061152a44f92b37e23c6527baf665d4da9a", "abcdefg", "sha\x03j\t\xe6g\xbbg\xae\x85<n\xf3r\xa5O\xf5:Q\x0eR\u007f\x9b\x05h\x8c\x1f\x83٫[\xe0\xcd\x19abc\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03"},
	{"9c56cc51b374c3ba189210d5b6d4bf57790d351c96c47c02190ecf1e430635ab", "abcdefgh", "sha\x03j\t\xe6g\xbbg\xae\x85<n\xf3r\xa5O\xf5:Q\x0eR\u007f\x9b\x05h\x8c\x1f\x83٫[\xe0\xcd\x19abcd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04"},
	{"19cc02f26df43cc571bc9ed7b0c4d29224a3ec229529221725ef76d021c8326f", "abcdefghi", "sha\x03j\t\xe6g\xbbg\xae\x85<n\xf3r\xa5O\xf5:Q\x0eR\u007f\x9b\x05h\x8c\x1f\x83٫[\xe0\xcd\x19abcd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04"},
	{"72399361da6a7754fec986dca5b7cbaf1c810a28ded4abaf56b2106d06cb78b0", "abcdefghij", "sha\x03j\t\xe6g\xbbg\xae\x85<n\xf3r\xa5O\xf5:Q\x0eR\u007f\x9b\x05h\x8c\x1f\x83٫[\xe0\xcd\x19abcde\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05"},
	{"a144061c271f152da4d151034508fed1c138b8c976339de229c3bb6d4bbb4fce", "Discard medicine more than two years old.", "sha\x03j\t\xe6g\xbbg\xae\x85<n\xf3r\xa5O\xf5:Q\x0eR\u007f\x9b\x05h\x8c\x1f\x83٫[\xe0\xcd\x19Discard medicine mor\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x14"},
	{"6dae5caa713a10ad04b46028bf6dad68837c581616a1589a265a11288d4bb5c4", "He who has a shady past knows that nice guys finish last.", "sha\x03j\t\xe6g\xbbg\xae\x85<n\xf3r\xa5O\xf5:Q\x0eR\u007f\x9b\x05h\x8c\x1f\x83٫[\xe0\xcd\x19He who has a shady past know\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1c"},
	{"ae7a702a9509039ddbf29f0765e70d0001177914b86459284dab8b348c2dce3f", "I wouldn't marry him with a ten foot pole.", "sha\x03j\t\xe6g\xbbg\xae\x85<n\xf3r\xa5O\xf5:Q\x0eR\u007f\x9b\x05h\x8c\x1f\x83٫[\xe0\xcd\x19I wouldn't marry him \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x15"},
	{"6748450b01c568586715291dfa3ee018da07d36bb7ea6f180c1af6270215c64f", "Free! Free!/A trip/to Mars/for 900/empty jars/Burma Shave", "sha\x03j\t\xe6g\xbbg\xae\x85<n\xf3r\xa5O\xf5:Q\x0eR\u007f\x9b\x05h\x8c\x1f\x83٫[\xe0\xcd\x19Free! Free!/A trip/to Mars/f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1c"},
	{"14b82014ad2b11f661b5ae6a99b75105c2ffac278cd071cd6c05832793635774", "The days of the digital watch are numbered.  -Tom Stoppard", "sha\x03j\t\xe6g\xbbg\xae\x85<n\xf3r\xa5O\xf5:Q\x0eR\u007f\x9b\x05h\x8c\x1f\x83٫[\xe0\xcd\x19The days of the digital watch\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1d"},
	{"7102cfd76e2e324889eece5d6c41921b1e142a4ac5a2692be78803097f6a48d8", "Nepal premier won't resign.", "sha\x03j\t\xe6g\xbbg\xae\x85<n\xf3r\xa5O\xf5:Q\x0eR\u007f\x9b\x05h\x8c\x1f\x83٫[\xe0\xcd\x19Nepal premier\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\r"},
	{"23b1018cd81db1d67983c5f7417c44da9deb582459e378d7a068552ea649dc9f", "For every action there is an equal and opposite government program.", "sha\x03j\t\xe6g\xbbg\xae\x85<n\xf3r\xa5O\xf5:Q\x0eR\u007f\x9b\x05h\x8c\x1f\x83٫[\xe0\xcd\x19For every action there is an equa\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00!"},
	{"8001f190dfb527261c4cfcab70c98e8097a7a1922129bc4096950e57c7999a5a", "His money is twice tainted: 'taint yours and 'taint mine.", "sha\x03j\t\xe6g\xbbg\xae\x85<n\xf3r\xa5O\xf5:Q\x0eR\u007f\x9b\x05h\x8c\x1f\x83٫[\xe0\xcd\x19His money is twice tainted: \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1c"},
	{"8c87deb65505c3993eb24b7a150c4155e82eee6960cf0c3a8114ff736d69cad5", "There is no reason for any individual to have a computer in their home. -Ken Olsen, 1977", "sha\x03j\t\xe6g\xbbg\xae\x85<n\xf3r\xa5O\xf5:Q\x0eR\u007f\x9b\x05h\x8c\x1f\x83٫[\xe0\xcd\x19There is no reason for any individual to hav\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00,"},
	{"bfb0a67a19cdec3646498b2e0f751bddc41bba4b7f30081b0b932aad214d16d7", "It's a tiny change to the code and not completely disgusting. - Bob Manchek", "sha\x03j\t\xe6g\xbbg\xae\x85<n\xf3r\xa5O\xf5:Q\x0eR\u007f\x9b\x05h\x8c\x1f\x83٫[\xe0\xcd\x19It's a tiny change to the code and no\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00%"},
	{"7f9a0b9bf56332e19f5a0ec1ad9c1425a153da1c624868fda44561d6b74daf36", "size:  a.out:  bad magic", "sha\x03j\t\xe6g\xbbg\xae\x85<n\xf3r\xa5O\xf5:Q\x0eR\u007f\x9b\x05h\x8c\x1f\x83٫[\xe0\xcd\x19size:  a.out\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\f"},
	{"b13f81b8aad9e3666879af19886140904f7f429ef083286195982a7588858cfc", "The major problem is with sendmail.  -Mark Horton", "sha\x03j\t\xe6g\xbbg\xae\x85<n\xf3r\xa5O\xf5:Q\x0eR\u007f\x9b\x05h\x8c\x1f\x83٫[\xe0\xcd\x19The major problem is wit\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x18"},
	{"b26c38d61519e894480c70c8374ea35aa0ad05b2ae3d6674eec5f52a69305ed4", "Give me a rock, paper and scissors and I will move the world.  CCFestoon", "sha\x03j\t\xe6g\xbbg\xae\x85<n\xf3r\xa5O\xf5:Q\x0eR\u007f\x9b\x05h\x8c\x1f\x83٫[\xe0\xcd\x19Give me a rock, paper and scissors a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00$"},
	{"049d5e26d4f10222cd841a119e38bd8d2e0d1129728688449575d4ff42b842c1", "If the enemy is within range, then so are you.", "sha\x03j\t\xe6g\xbbg\xae\x85<n\xf3r\xa5O\xf5:Q\x0eR\u007f\x9b\x05h\x8c\x1f\x83٫[\xe0\xcd\x19If the enemy is within \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x17"},
	{"0e116838e3cc1c1a14cd045397e29b4d087aa11b0853fc69ec82e90330d60949", "It's well we cannot hear the screams/That we create in others' dreams.", "sha\x03j\t\xe6g\xbbg\xae\x85<n\xf3r\xa5O\xf5:Q\x0eR\u007f\x9b\x05h\x8c\x1f\x83٫[\xe0\xcd\x19It's well we cannot hear the scream\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00#"},
	{"4f7d8eb5bcf11de2a56b971021a444aa4eafd6ecd0f307b5109e4e776cd0fe46", "You remind me of a TV show, but that's all right: I watch it anyway.", "sha\x03j\t\xe6g\xbbg\xae\x85<n\xf3r\xa5O\xf5:Q\x0eR\u007f\x9b\x05h\x8c\x1f\x83٫[\xe0\xcd\x19You remind me of a TV show, but th\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\""},
	{"61c0cc4c4bd8406d5120b3fb4ebc31ce87667c162f29468b3c779675a85aebce", "C is as portable as Stonehedge!!", "sha\x03j\t\xe6g\xbbg\xae\x85<n\xf3r\xa5O\xf5:Q\x0eR\u007f\x9b\x05h\x8c\x1f\x83٫[\xe0\xcd\x19C is as portable\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10"},
	{"1fb2eb3688093c4a3f80cd87a5547e2ce940a4f923243a79a2a1e242220693ac", "Even if I could be Shakespeare, I think I should still choose to be Faraday. - A. Huxley", "sha\x03j\t\xe6g\xbbg\xae\x85<n\xf3r\xa5O\xf5:Q\x0eR\u007f\x9b\x05h\x8c\x1f\x83٫[\xe0\xcd\x19Even if I could be Shakespeare, I think I sh\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00,"},
	{"395585ce30617b62c80b93e8208ce866d4edc811a177fdb4b82d3911d8696423", "The fugacity of a constituent in a mixture of gases at a given temperature is proportional to its mole fraction.  Lewis-Randall Rule", "sha\x03\x93\x14\xc8z\x87\x0e\vo\xf1E\x0f\xa4V\xb2a\x00\x87\xb5ǔ\xfc\xeaV\u009eg\xbc\x17\xb1\x85њem\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00B"},
	{"4f9b189a13d030838269dce846b16a1ce9ce81fe63e65de2f636863336a98fe6", "How can you write a big system without C++?  -Paul Glick", "sha\x03j\t\xe6g\xbbg\xae\x85<n\xf3r\xa5O\xf5:Q\x0eR\u007f\x9b\x05h\x8c\x1f\x83٫[\xe0\xcd\x19How can you write a big syst\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1c"},
}

var golden224 = []sha256Test{
	{"d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f", "", "sha\x02\xc1\x05\x9e\xd86|\xd5\a0p\xdd\x17\xf7\x0eY9\xff\xc0\v1hX\x15\x11d\xf9\x8f\xa7\xbe\xfaO\xa4\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"},
	{"abd37534c7d9a2efb9465de931cd7055ffdb8879563ae98078d6d6d5", "a", "sha\x02\xc1\x05\x9e\xd86|\xd5\a0p\xdd\x17\xf7\x0eY9\xff\xc0\v1hX\x15\x11d\xf9\x8f\xa7\xbe\xfaO\xa4\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"},
	{"db3cda86d4429a1d39c148989566b38f7bda0156296bd364ba2f878b", "ab", "sha\x02\xc1\x05\x9e\xd86|\xd5\a0p\xdd\x17\xf7\x0eY9\xff\xc0\v1hX\x15\x11d\xf9\x8f\xa7\xbe\xfaO\xa4a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"},
	{"23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7", "abc", "sha\x02\xc1\x05\x9e\xd86|\xd5\a0p\xdd\x17\xf7\x0eY9\xff\xc0\v1hX\x15\x11d\xf9\x8f\xa7\xbe\xfaO\xa4a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"},
	{"a76654d8e3550e9a2d67a0eeb6c67b220e5885eddd3fde135806e601", "abcd", "sha\x02\xc1\x05\x9e\xd86|\xd5\a0p\xdd\x17\xf7\x0eY9\xff\xc0\v1hX\x15\x11d\xf9\x8f\xa7\xbe\xfaO\xa4ab\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02"},
	{"bdd03d560993e675516ba5a50638b6531ac2ac3d5847c61916cfced6", "abcde", "sha\x02\xc1\x05\x9e\xd86|\xd5\a0p\xdd\x17\xf7\x0eY9\xff\xc0\v1hX\x15\x11d\xf9\x8f\xa7\xbe\xfaO\xa4ab\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02"},
	{"7043631cb415556a275a4ebecb802c74ee9f6153908e1792a90b6a98", "abcdef", "sha\x02\xc1\x05\x9e\xd86|\xd5\a0p\xdd\x17\xf7\x0eY9\xff\xc0\v1hX\x15\x11d\xf9\x8f\xa7\xbe\xfaO\xa4abc\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03"},
	{"d1884e711701ad81abe0c77a3b0ea12e19ba9af64077286c72fc602d", "abcdefg", "sha\x02\xc1\x05\x9e\xd86|\xd5\a0p\xdd\x17\xf7\x0eY9\xff\xc0\v1hX\x15\x11d\xf9\x8f\xa7\xbe\xfaO\xa4abc\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03"},
	{"17eb7d40f0356f8598e89eafad5f6c759b1f822975d9c9b737c8a517", "abcdefgh", "sha\x02\xc1\x05\x9e\xd86|\xd5\a0p\xdd\x17\xf7\x0eY9\xff\xc0\v1hX\x15\x11d\xf9\x8f\xa7\xbe\xfaO\xa4abcd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04"},
	{"aeb35915346c584db820d2de7af3929ffafef9222a9bcb26516c7334", "abcdefghi", "sha\x02\xc1\x05\x9e\xd86|\xd5\a0p\xdd\x17\xf7\x0eY9\xff\xc0\v1hX\x15\x11d\xf9\x8f\xa7\xbe\xfaO\xa4abcd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04"},
	{"d35e1e5af29ddb0d7e154357df4ad9842afee527c689ee547f753188", "abcdefghij", "sha\x02\xc1\x05\x9e\xd86|\xd5\a0p\xdd\x17\xf7\x0eY9\xff\xc0\v1hX\x15\x11d\xf9\x8f\xa7\xbe\xfaO\xa4abcde\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05"},
	{"19297f1cef7ddc8a7e947f5c5a341e10f7245045e425db67043988d7", "Discard medicine more than two years old.", "sha\x02\xc1\x05\x9e\xd86|\xd5\a0p\xdd\x17\xf7\x0eY9\xff\xc0\v1hX\x15\x11d\xf9\x8f\xa7\xbe\xfaO\xa4Discard medicine mor\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x14"},
	{"0f10c2eb436251f777fbbd125e260d36aecf180411726c7c885f599a", "He who has a shady past knows that nice guys finish last.", "sha\x02\xc1\x05\x9e\xd86|\xd5\a0p\xdd\x17\xf7\x0eY9\xff\xc0\v1hX\x15\x11d\xf9\x8f\xa7\xbe\xfaO\xa4He who has a shady past know\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1c"},
	{"4d1842104919f314cad8a3cd20b3cba7e8ed3e7abed62b57441358f6", "I wouldn't marry him with a ten foot pole.", "sha\x02\xc1\x05\x9e\xd86|\xd5\a0p\xdd\x17\xf7\x0eY9\xff\xc0\v1hX\x15\x11d\xf9\x8f\xa7\xbe\xfaO\xa4I wouldn't marry him \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x15"},
	{"a8ba85c6fe0c48fbffc72bbb2f03fcdbc87ae2dc7a56804d1590fb3b", "Free! Free!/A trip/to Mars/for 900/empty jars/Burma Shave", "sha\x02\xc1\x05\x9e\xd86|\xd5\a0p\xdd\x17\xf7\x0eY9\xff\xc0\v1hX\x15\x11d\xf9\x8f\xa7\xbe\xfaO\xa4Free! Free!/A trip/to Mars/f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1c"},
	{"5543fbab26e67e8885b1a852d567d1cb8b9bfe42e0899584c50449a9", "The days of the digital watch are numbered.  -Tom Stoppard", "sha\x02\xc1\x05\x9e\xd86|\xd5\a0p\xdd\x17\xf7\x0eY9\xff\xc0\v1hX\x15\x11d\xf9\x8f\xa7\xbe\xfaO\xa4The days of the digital watch\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1d"},
	{"65ca107390f5da9efa05d28e57b221657edc7e43a9a18fb15b053ddb", "Nepal premier won't resign.", "sha\x02\xc1\x05\x9e\xd86|\xd5\a0p\xdd\x17\xf7\x0eY9\xff\xc0\v1hX\x15\x11d\xf9\x8f\xa7\xbe\xfaO\xa4Nepal premier\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\r"},
	{"84953962be366305a9cc9b5cd16ed019edc37ac96c0deb3e12cca116", "For every action there is an equal and opposite government program.", "sha\x02\xc1\x05\x9e\xd86|\xd5\a0p\xdd\x17\xf7\x0eY9\xff\xc0\v1hX\x15\x11d\xf9\x8f\xa7\xbe\xfaO\xa4For every action there is an equa\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00!"},
	{"35a189ce987151dfd00b3577583cc6a74b9869eecf894459cb52038d", "His money is twice tainted: 'taint yours and 'taint mine.", "sha\x02\xc1\x05\x9e\xd86|\xd5\a0p\xdd\x17\xf7\x0eY9\xff\xc0\v1hX\x15\x11d\xf9\x8f\xa7\xbe\xfaO\xa4His money is twice tainted: \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1c"},
	{"2fc333713983edfd4ef2c0da6fb6d6415afb94987c91e4069eb063e6", "There is no reason for any individual to have a computer in their home. -Ken Olsen, 1977", "sha\x02\xc1\x05\x9e\xd86|\xd5\a0p\xdd\x17\xf7\x0eY9\xff\xc0\v1hX\x15\x11d\xf9\x8f\xa7\xbe\xfaO\xa4There is no reason for any individual to hav\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00,"},
	{"cbe32d38d577a1b355960a4bc3c659c2dc4670859a19777a875842c4", "It's a tiny change to the code and not completely disgusting. - Bob Manchek", "sha\x02\xc1\x05\x9e\xd86|\xd5\a0p\xdd\x17\xf7\x0eY9\xff\xc0\v1hX\x15\x11d\xf9\x8f\xa7\xbe\xfaO\xa4It's a tiny change to the code and no\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00%"},
	{"a2dc118ce959e027576413a7b440c875cdc8d40df9141d6ef78a57e1", "size:  a.out:  bad magic", "sha\x02\xc1\x05\x9e\xd86|\xd5\a0p\xdd\x17\xf7\x0eY9\xff\xc0\v1hX\x15\x11d\xf9\x8f\xa7\xbe\xfaO\xa4size:  a.out\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\f"},
	{"d10787e24052bcff26dc484787a54ed819e4e4511c54890ee977bf81", "The major problem is with sendmail.  -Mark Horton", "sha\x02\xc1\x05\x9e\xd86|\xd5\a0p\xdd\x17\xf7\x0eY9\xff\xc0\v1hX\x15\x11d\xf9\x8f\xa7\xbe\xfaO\xa4The major problem is wit\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x18"},
	{"62efcf16ab8a893acdf2f348aaf06b63039ff1bf55508c830532c9fb", "Give me a rock, paper and scissors and I will move the world.  CCFestoon", "sha\x02\xc1\x05\x9e\xd86|\xd5\a0p\xdd\x17\xf7\x0eY9\xff\xc0\v1hX\x15\x11d\xf9\x8f\xa7\xbe\xfaO\xa4Give me a rock, paper and scissors a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00$"},
	{"3e9b7e4613c59f58665104c5fa86c272db5d3a2ff30df5bb194a5c99", "If the enemy is within range, then so are you.", "sha\x02\xc1\x05\x9e\xd86|\xd5\a0p\xdd\x17\xf7\x0eY9\xff\xc0\v1hX\x15\x11d\xf9\x8f\xa7\xbe\xfaO\xa4If the enemy is within \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x17"},
	{"5999c208b8bdf6d471bb7c359ac5b829e73a8211dff686143a4e7f18", "It's well we cannot hear the screams/That we create in others' dreams.", "sha\x02\xc1\x05\x9e\xd86|\xd5\a0p\xdd\x17\xf7\x0eY9\xff\xc0\v1hX\x15\x11d\xf9\x8f\xa7\xbe\xfaO\xa4It's well we cannot hear the scream\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00#"},
	{"3b2d67ff54eabc4ef737b14edf87c64280ef582bcdf2a6d56908b405", "You remind me of a TV show, but that's all right: I watch it anyway.", "sha\x02\xc1\x05\x9e\xd86|\xd5\a0p\xdd\x17\xf7\x0eY9\xff\xc0\v1hX\x15\x11d\xf9\x8f\xa7\xbe\xfaO\xa4You remind me of a TV show, but th\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\""},
	{"d0733595d20e4d3d6b5c565a445814d1bbb2fd08b9a3b8ffb97930c6", "C is as portable as Stonehedge!!", "sha\x02\xc1\x05\x9e\xd86|\xd5\a0p\xdd\x17\xf7\x0eY9\xff\xc0\v1hX\x15\x11d\xf9\x8f\xa7\xbe\xfaO\xa4C is as portable\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10"},
	{"43fb8aeed8a833175c9295c1165415f98c866ef08a4922959d673507", "Even if I could be Shakespeare, I think I should still choose to be Faraday. - A. Huxley", "sha\x02\xc1\x05\x9e\xd86|\xd5\a0p\xdd\x17\xf7\x0eY9\xff\xc0\v1hX\x15\x11d\xf9\x8f\xa7\xbe\xfaO\xa4Even if I could be Shakespeare, I think I sh\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00,"},
	{"ec18e66e93afc4fb1604bc2baedbfd20b44c43d76e65c0996d7851c6", "The fugacity of a constituent in a mixture of gases at a given temperature is proportional to its mole fraction.  Lewis-Randall Rule", "sha\x02\xea\xc9\xc2e\xddH\x0f\\.\xeb\xc4G\xda\xea\xd5TX\x17\xca3l\xfaV\x9d\x9d\x056\x85&1\rDem\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00B"},
	{"86ed2eaa9c75ba98396e5c9fb2f679ecf0ea2ed1e0ee9ceecb4a9332", "How can you write a big system without C++?  -Paul Glick", "sha\x02\xc1\x05\x9e\xd86|\xd5\a0p\xdd\x17\xf7\x0eY9\xff\xc0\v1hX\x15\x11d\xf9\x8f\xa7\xbe\xfaO\xa4How can you write a big syst\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1c"},
}

func TestGolden(t *testing.T) {
	for _, g := range golden256 {
		s := fmt.Sprintf("%x", xcrypto.SHA256([]byte(g.in)))
		if s != g.out {
			t.Fatalf("Sum256 function: sha256(%s) = %s want %s", g.in, s, g.out)
		}
		c := xcrypto.NewSHA256()
		for j := 0; j < 3; j++ {
			if j < 2 {
				io.WriteString(c, g.in)
			} else {
				io.WriteString(c, g.in[:len(g.in)/2])
				c.Sum(nil)
				io.WriteString(c, g.in[len(g.in)/2:])
			}
			s := fmt.Sprintf("%x", c.Sum(nil))
			if s != g.out {
				t.Fatalf("sha256[%d](%s) = %s want %s", j, g.in, s, g.out)
			}
			c.Reset()
		}
	}
	for _, g := range golden224 {
		s := fmt.Sprintf("%x", xcrypto.SHA224([]byte(g.in)))
		if s != g.out {
			t.Fatalf("Sum224 function: sha224(%s) = %s want %s", g.in, s, g.out)
		}
		c := xcrypto.NewSHA224()
		for j := 0; j < 3; j++ {
			if j < 2 {
				io.WriteString(c, g.in)
			} else {
				io.WriteString(c, g.in[:len(g.in)/2])
				c.Sum(nil)
				io.WriteString(c, g.in[len(g.in)/2:])
			}
			s := fmt.Sprintf("%x", c.Sum(nil))
			if s != g.out {
				t.Fatalf("sha224[%d](%s) = %s want %s", j, g.in, s, g.out)
			}
			c.Reset()
		}
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

func TestHashAllocations(t *testing.T) {
	if Asan() {
		t.Skip("skipping allocations test with sanitizers")
	}
	msg := []byte("testing")
	n := int(testing.AllocsPerRun(10, func() {
		sink ^= xcrypto.MD4(msg)[0]
		sink ^= xcrypto.MD5(msg)[0]
		sink ^= xcrypto.SHA1(msg)[0]
		sink ^= xcrypto.SHA224(msg)[0]
		sink ^= xcrypto.SHA256(msg)[0]
		sink ^= xcrypto.SHA512(msg)[0]
	}))
	want := 6
	if compareCurrentVersion("go1.24") >= 0 {
		// The go1.24 compiler is able to optimize the allocation away.
		// See cgo_go124.go for more information.
		want = 0
	}
	if n > want {
		t.Errorf("allocs = %d, want %d", n, want)
	}
}

func BenchmarkHash8Bytes(b *testing.B) {
	b.StopTimer()
	h := xcrypto.NewSHA256()
	sum := make([]byte, h.Size())
	size := 8
	buf := make([]byte, size)
	b.StartTimer()
	b.SetBytes(int64(size))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		h.Reset()
		h.Write(buf)
		h.Sum(sum[:0])
	}
}

func BenchmarkSHA256(b *testing.B) {
	b.StopTimer()
	size := 8
	buf := make([]byte, size)
	b.StartTimer()
	b.SetBytes(int64(size))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		xcrypto.SHA256(buf)
	}
}

func BenchmarkNewSHA256(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		xcrypto.NewSHA256()
	}
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
