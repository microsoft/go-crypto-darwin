module github.com/microsoft/go-crypto-darwin/internal/cgotool/openssl

go 1.26

require github.com/microsoft/go-crypto-openssl v0.5.1-0.20261023090206-948b9d36d97f // indirect

tool (
	github.com/microsoft/go-crypto-openssl/cmd/checkheader
	github.com/microsoft/go-crypto-openssl/cmd/mkcgo
)
