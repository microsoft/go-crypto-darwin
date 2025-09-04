// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Package commoncrypto provides a Go interface to the CommonCrypto API
package commoncrypto

//go:generate go run ../../cmd/checkheader -shim shims.h
//go:generate go run ../../cmd/mkcgo -out zcommoncrypto.go -mode all -package commoncrypto shims.h
