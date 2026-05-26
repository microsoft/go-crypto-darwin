module github.com/microsoft/go-crypto-darwin/internal/cgotool/openssl

go 1.25

require github.com/microsoft/go-crypto-openssl v0.0.0-20260526093041-a7ca5d3c79e8 // indirect

tool (
	github.com/microsoft/go-crypto-openssl/cmd/checkheader
	github.com/microsoft/go-crypto-openssl/cmd/mkcgo
)
