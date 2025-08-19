// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Package security provides a Go interface to the Security framework
package security

//go:generate go run ../../cmd/checkheader -shim shims.h
//go:generate go run ../../cmd/mkcgo -out zsecurity.go -package security shims.h
