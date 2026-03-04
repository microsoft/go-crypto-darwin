module github.com/microsoft/go-crypto-darwin/internal/cgotool/openssl

go 1.25

require github.com/golang-fips/openssl/v2 v2.0.4-0.20260304104649-dfdde545174a // indirect

tool (
	github.com/golang-fips/openssl/v2/cmd/checkheader
	github.com/golang-fips/openssl/v2/cmd/mkcgo
)
