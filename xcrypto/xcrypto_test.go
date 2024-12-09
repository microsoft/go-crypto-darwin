// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package xcrypto_test

import (
	"go/version"
	"runtime"
	"strings"
)

// sink is used to prevent the compiler from optimizing out the allocations.
var sink uint8

// compareCurrentVersion compares v with [runtime.Version].
// See [go/versions.Compare] for information about
// v format and comparison rules.
func compareCurrentVersion(v string) int {
	ver := strings.TrimPrefix(runtime.Version(), "devel ")
	return version.Compare(ver, v)
}
