// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Package commoncrypto provides a Go interface to the CommonCrypto API
package commoncrypto

//go:generate go run ../../cmd/checkheader shims.h
//go:generate go run ../../cmd/mkcgo -out zcommoncrypto.go -package commoncrypto --noerrors shims.h
//go:generate go run ../../cmd/mkcgo -out zcommoncrypto.go -nocgo -package commoncrypto --noerrors shims.h
