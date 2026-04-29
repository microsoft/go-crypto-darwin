# Building the Swift/CryptoKit Bindings

The CryptoKit bindings are pre-compiled Swift object files (`.syso`) checked into
the repository at `internal/cryptokit/`. Go links these files automatically during
the build, so most contributors never need to regenerate them.

## `.syso` files

The build produces two architecture-specific files:

- `internal/cryptokit/CryptoKit_arm64.syso` — Apple Silicon (arm64)
- `internal/cryptokit/CryptoKit_amd64.syso` — Intel (x86_64)

These are compiled from the Swift source in `cryptokit/Sources/CryptoKitSrc/` using
the bridging header at `cryptokit/Sources/CryptoKitC/include/cryptokit.h`.

## Reproducibility

The `.syso` files are **reproducible** as long as they are built with the exact same
Xcode version **and** build version (i.e., the complete output of `xcodebuild -version`
must match). The full `xcodebuild -version` output used for each build is recorded in
`internal/cryptokit/xcodebuild_version.txt`.

Before rebuilding, check that your local Xcode version matches the one used
upstream:

```sh
# Show the Xcode version the checked-in binaries were built with:
cat internal/cryptokit/xcodebuild_version.txt

# Show your local Xcode version:
xcodebuild -version
```

If the versions differ, the resulting `.syso` files will not match the ones in the
repository. The build script will print a warning when it detects a version
mismatch.

## Building locally

Run the build script from the repository root:

```sh
bash gen-swift-bindings.sh
```

The script will:

1. Remove any existing `.syso` files.
2. Check whether your Xcode version matches the previous build and warn if not.
3. Record your current Xcode version to `xcodebuild_version.txt`.
4. Compile the Swift source for both `arm64` and `x86_64` using `xcrun swiftc`.

## CI: reproducible build verification

The `verify-reproducible-build` CI workflow rebuilds the `.syso` files and checks
that they match the ones committed in the repository. This ensures that checked-in
binaries are always up to date and reproducible.

## Triggering a rebuild in a PR

To trigger the Swift binding build workflow on a pull request, add the
**`generate-bindings`** label to the PR. This runs the `build-swift` workflow,
which regenerates the `.syso` files and updates the PR if needed.

## Xcode version bumps in CI

Occasionally, the Xcode version is updated in the GitHub Actions runner images.
When this happens, the `verify-reproducible-build` check may fail on your PR even
if you haven't touched any Swift code — the CI-rebuilt `.syso` files no longer
match the checked-in ones because they were compiled with a different Xcode version.

If you encounter this, you can either:

- **Disregard the failing check** if your PR does not affect the Swift bindings.
- **Add the `generate-bindings` label** to your PR, which will automatically
  rebuild the `.syso` files with the new Xcode version and push the updated
  binaries to your branch.
