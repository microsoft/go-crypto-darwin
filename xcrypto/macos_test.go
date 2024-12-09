// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package xcrypto_test

import (
	"strconv"
	"strings"
	"syscall"
)

// macOSVersion returns the OS version name/number.
func macOSVersion() (string, error) {
	version, err := syscall.Sysctl("kern.osproductversion")
	if err != nil {
		return "", err
	}
	return version, nil
}

func isMacOS14OrAbove() bool {
	version, err := macOSVersion()
	if err != nil {
		return false
	}
	parts := strings.Split(version, ".")
	if len(parts) < 1 {
		return false // Unable to parse version; assume not 14 or above.
	}

	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return false // Unable to parse version; assume not 14 or above.
	}

	return major >= 14
}
