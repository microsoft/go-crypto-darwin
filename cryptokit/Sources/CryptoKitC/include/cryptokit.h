// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// This header wraps shims.h for Swift @implementation @c validation.
// It strips mkcgo-specific __attribute__ annotations that clang doesn't understand.
//
// Nullability (nonnull) is declared inside shims.h itself using
// __clang__-guarded pragmas, so mkcgo never sees them.

#pragma once

// Strip mkcgo-specific __attribute__ annotations
#pragma push_macro("__attribute__")
#undef __attribute__
#define __attribute__(x)

#include "../../../../internal/cryptokit/shims.h"

#pragma pop_macro("__attribute__")
