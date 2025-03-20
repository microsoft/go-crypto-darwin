//go:build !asan

package xcrypto_test

func Asan() bool {
	return false
}
