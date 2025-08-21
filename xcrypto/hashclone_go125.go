// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build go1.25 && darwin

package xcrypto

import (
	"hash"
)

type HashCloner = hash.Cloner
