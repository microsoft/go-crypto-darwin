module github.com/microsoft/go-crypto-darwin/internal/cgotool/openssl

go 1.26

require github.com/microsoft/go-crypto-openssl v0.5.1-0.20261023091245-4ca482fc6e07 // indirect

tool (
	github.com/microsoft/go-crypto-openssl/cmd/checkheader
	github.com/microsoft/go-crypto-openssl/cmd/mkcgo
)
