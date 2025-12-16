#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -e

BASE_URL="https://raw.githubusercontent.com/ebitengine/purego/main/internal/fakecgo"

# Skip list
files_to_skip=(
    "update.sh"
    "generate.go"
    "fakecgo.go"
)

# Files that don't need build tag modification
no_tag_modification=(
    "gen.go"
    "libcgo_darwin.go"
    "symbols_darwin.go"
)

# Update all files in the current directory, except those in the skip list
for file in *; do
    if [[ " ${files_to_skip[@]} " =~ " ${file} " ]]; then
        continue
    fi

    if [[ -f "$file" ]]; then
        echo "Updating $file..."
        curl -sSL "$BASE_URL/$file" -o "$file"
        # Modify build tags to only include darwin
        if [[ ! " ${no_tag_modification[@]} " =~ " ${file} " ]]; then
            sed -i '' 's#^//go:build.*#//go:build !cgo \&\& darwin#' "$file"
        fi
    fi
done

echo "Done."
