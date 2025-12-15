// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package xsyscall

//go:generate go run ../../cmd/mkcgo -out zdl.go -nocgo -mode dynamic -noerrors -package xsyscall -tags "darwin" dl.h
