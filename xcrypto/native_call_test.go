// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build darwin

package xcrypto_test

import (
	"bytes"
	"context"
	"crypto/cipher"
	"encoding/binary"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"testing"
	"time"

	"github.com/microsoft/go-crypto-darwin/internal/security"
	"github.com/microsoft/go-crypto-darwin/xcrypto"
)

const randomTestMode = "GO_DARWIN_TEST_RANDOM_MODE"

func buildRandomInterposer(t *testing.T) string {
	t.Helper()
	compiler, err := exec.LookPath("clang")
	if err != nil {
		t.Skipf("native call tests require clang: %v", err)
	}
	arch := runtime.GOARCH
	if arch == "amd64" {
		arch = "x86_64"
	}
	library := filepath.Join(t.TempDir(), "random_interpose.dylib")
	cmd := exec.Command(compiler, "-dynamiclib", "-arch", arch, "-framework", "Security",
		"-o", library, filepath.Join("testdata", "random_interpose.c"))
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building native test helper: %v\n%s", err, output)
	}
	return library
}

func runRandomSubprocess(t *testing.T, name, library, mode string) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if old := os.Getenv("DYLD_INSERT_LIBRARIES"); old != "" {
		library += ":" + old
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "-test.run=^"+name+"$")
	cmd.Env = append(os.Environ(), randomTestMode+"="+mode, "DYLD_INSERT_LIBRARIES="+library)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("native call subprocess: %v\n%s", err, output)
	}
}

func TestGCMNonceReadFailure(t *testing.T) {
	if os.Getenv(randomTestMode) == "" {
		library := buildRandomInterposer(t)
		for _, mode := range []string{"failure", "partial"} {
			t.Run(mode, func(t *testing.T) {
				runRandomSubprocess(t, "TestGCMNonceReadFailure", library, mode)
			})
		}
		return
	}
	block, err := xcrypto.NewAESCipher(make([]byte, 16))
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := block.(interface {
		NewGCM(nonceSize, tagSize int) (cipher.AEAD, error)
	}).NewGCM(gcmStandardNonceSize, gcmTagSize)
	if err != nil {
		t.Fatal(err)
	}
	nonce := bytes.Repeat([]byte{0xa5}, gcm.NonceSize())
	_, wantErr := xcrypto.RandReader.Read(nonce)
	if wantErr == nil {
		t.Fatal("native RNG failure was not injected")
	}
	plaintext := []byte("message")
	out := bytes.Repeat([]byte{0xa5}, len(plaintext)+gcm.Overhead())
	wantOut := bytes.Clone(out)
	defer func() {
		got, ok := recover().(error)
		if !ok || got.Error() != wantErr.Error() {
			t.Errorf("panic = %v, want %v", got, wantErr)
		}
		if !bytes.Equal(out, wantOut) {
			t.Error("encryption changed output after nonce generation failed")
		}
	}()
	gcm.(interface {
		SealWithRandomNonce(out, nonce, plaintext, additionalData []byte)
	}).SealWithRandomNonce(out, nonce, plaintext, nil)
}

//go:noinline
func randomWithFinalizer(entered, release *os.File, finalized chan struct{}) int32 {
	buf := new([4096]byte)
	binary.LittleEndian.PutUint32(buf[:4], uint32(entered.Fd()))
	binary.LittleEndian.PutUint32(buf[4:8], uint32(release.Fd()))
	runtime.SetFinalizer(buf, func(*[4096]byte) { close(finalized) })
	return security.SecRandomCopyBytes(security.KSecRandomDefault, buf[:])
}

func TestNativeBufferLifetime(t *testing.T) {
	if os.Getenv(randomTestMode) != "lifetime" {
		runRandomSubprocess(t, "TestNativeBufferLifetime", buildRandomInterposer(t), "lifetime")
		return
	}
	oldGC := debug.SetGCPercent(-1)
	defer debug.SetGCPercent(oldGC)
	runtime.GC()
	enteredRead, enteredWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	releaseRead, releaseWrite, err := os.Pipe()
	if err != nil {
		enteredRead.Close()
		enteredWrite.Close()
		t.Fatal(err)
	}
	for _, f := range []*os.File{enteredRead, enteredWrite, releaseRead, releaseWrite} {
		t.Cleanup(func() {
			if err := f.Close(); err != nil {
				t.Errorf("closing native test pipe: %v", err)
			}
		})
	}
	finalized := make(chan struct{})
	result := make(chan int32, 1)
	go func() {
		result <- randomWithFinalizer(enteredWrite, releaseRead, finalized)
	}()
	entered := make(chan error, 1)
	go func() {
		var signal [1]byte
		_, err := io.ReadFull(enteredRead, signal[:])
		entered <- err
	}()
	select {
	case err := <-entered:
		if err != nil {
			t.Fatal(err)
		}
	case status := <-result:
		t.Fatalf("native call did not block: status %d", status)
	case <-time.After(5 * time.Second):
		t.Fatal("native call did not signal entry")
	}
	premature := false
	for range 5 {
		runtime.GC()
		select {
		case <-finalized:
			premature = true
		case <-time.After(10 * time.Millisecond):
		}
		if premature {
			break
		}
	}
	// Never let the helper access the buffer if it was already finalized.
	signal := byte(1)
	if premature {
		signal = 0
	}
	if _, err := releaseWrite.Write([]byte{signal}); err != nil {
		t.Fatal(err)
	}
	select {
	case status := <-result:
		if premature {
			t.Fatal("Go buffer finalized before the native call returned")
		}
		if status != 0 {
			t.Fatalf("native call returned status %d", status)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("native call did not return")
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		runtime.GC()
		select {
		case <-finalized:
			return
		case <-time.After(10 * time.Millisecond):
		}
	}
	t.Fatal("buffer was not finalized after the native call returned")
}
