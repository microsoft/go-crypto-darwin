# Go macOS Crypto bindings for FIPS compliance

[![Go Reference](https://pkg.go.dev/badge/github.com/microsoft/go-crypto-darwin/xcrypto.svg)](https://pkg.go.dev/github.com/microsoft/go-crypto-darwin/xcrypto?GOOS=darwin)

The `xcrypto` package implements Go crypto primitives on macOS using [CommonCrypto](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/Common%20Crypto.3cc.html) and [CryptoKit](https://developer.apple.com/documentation/cryptokit). When configured correctly, CommonCrypto can be executed in FIPS mode, making the `xcrypto` package FIPS compliant.

The package is designed to be used as a drop-in replacement for the [boring](https://pkg.go.dev/crypto/internal/borings) package in order to facilitate integrating commoncrypto inside a forked Go toolchain.

Visit the [FIPS documentation in the microsoft/go repository](https://github.com/microsoft/go/tree/microsoft/main/eng/doc/fips) for more information about FIPS, enabling FIPS mode, and writing a FIPS compliant Go application.

## Disclaimer

A program directly or indirectly using this package in FIPS mode can claim it is using a FIPS-certified cryptographic module (CommonCrypto), but it can't claim the program as a whole is FIPS certified without passing the certification process, nor claim it is FIPS compliant without ensuring all crypto APIs and workflows are implemented in a FIPS-compliant manner.

## Contributing

This project welcomes contributions and suggestions. Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.opensource.microsoft.com.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft
trademarks or logos is subject to and must follow
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party's policies.
