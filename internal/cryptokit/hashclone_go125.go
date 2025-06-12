// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build go1.25 && darwin

package cryptokit

import (
	"hash"
)

type HashCloner = hash.Cloner
