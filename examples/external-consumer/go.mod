// 独立模块示例：外部宿主只能导入公开包，不能导入本仓库的 internal/ 包。
// replace 指向本地仓库，使示例与仓库代码保持同步；发布时应改为真实模块版本。
module example.com/evernightlogin-external-consumer

go 1.26.0

require github.com/kagurazakayashi/EvernightLogin v0.0.0

require (
	github.com/fxamacker/cbor/v2 v2.9.4 // indirect
	github.com/go-viper/mapstructure/v2 v2.5.0 // indirect
	github.com/go-webauthn/webauthn v0.18.2 // indirect
	github.com/go-webauthn/x v0.3.1 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.1 // indirect
	github.com/google/go-tpm v0.9.8 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/philhofer/fwd v1.2.0 // indirect
	github.com/tinylib/msgp v1.6.4 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	go.yaml.in/yaml/v3 v3.0.6 // indirect
	golang.org/x/crypto v0.58.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
	golang.org/x/text v0.44.0 // indirect
	rsc.io/qr v0.2.0 // indirect
	software.sslmate.com/src/go-pkcs12 v0.7.4 // indirect
)

replace github.com/kagurazakayashi/EvernightLogin => ../..
