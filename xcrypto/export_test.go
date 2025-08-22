// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package xcrypto

import "errors"

var CurveToKeySizeInBytes = curveToKeySizeInBytes
var EncodeToUncompressedAnsiX963Key = encodeToUncompressedAnsiX963Key

// TODO fix errOpen
// var ErrOpen = errOpen
var ErrOpen = errors.New("cipher: message authentication failed")
var NormalizeBigInt = normalizeBigInt
