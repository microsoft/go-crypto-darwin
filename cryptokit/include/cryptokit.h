// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// This header wraps shims.h for Swift @implementation @c validation.
// It fixes two issues:
// 1. mkcgo-specific __attribute__ annotations that clang doesn't understand
// 2. Type mappings: int64_t -> long (Swift Int instead of Int64)
//
// Nullability (nonnull) is declared inside shims.h itself using
// __clang__-guarded pragmas, so mkcgo never sees them.

#pragma once

// Strip mkcgo-specific __attribute__ annotations
#pragma push_macro("__attribute__")
#undef __attribute__
#define __attribute__(x)

// Pre-include stdint.h so its int64_t typedef is processed before our macro.
// The include guard then prevents shims.h from re-including it.
#include <stdint.h>

// Map int64_t to long so Swift sees Int instead of Int64
#define int64_t long

#include "../../internal/cryptokit/shims.h"

#undef int64_t
#pragma pop_macro("__attribute__")
