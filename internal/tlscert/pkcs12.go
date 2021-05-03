package tlscert

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"time"

	pkcs12 "software.sslmate.com/src/go-pkcs12"

	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
)

// loadPFXIdentity 从 PKCS#12/PFX 文件加载单个证书身份。PFX 文件包含私钥，因此
// 必须通过受保护文件检查；密码来自配置的受保护来源，错误信息不包含密码或文件
// 内容。密码错误与文件损坏对外使用同一说明，避免区分猜测结果。
func loadPFXIdentity(source Source, now time.Time) (loadedIdentity, error) {
	if err := secrets.CheckProtectedFile(source.PFXFile); err != nil {
		return loadedIdentity{}, fmt.Errorf("PFX/P12 文件权限不安全: %w", err)
	}
	data, err := readLimitedFile(source.PFXFile, maxPFXFileBytes)
	if err != nil {
		return loadedIdentity{}, fmt.Errorf("无法读取 PFX/P12 文件: %v", err)
	}
	privateKey, leaf, caCertificates, err := pkcs12.DecodeChain(data, string(source.PFXPassword))
	if err != nil {
		return loadedIdentity{}, fmt.Errorf("PFX/P12 解析失败（密码错误或文件损坏）")
	}
	if leaf == nil {
		return loadedIdentity{}, fmt.Errorf("PFX/P12 不包含叶证书")
	}
	signer, ok := privateKey.(crypto.Signer)
	if !ok {
		return loadedIdentity{}, fmt.Errorf("PFX/P12 私钥类型不支持服务器 TLS")
	}
	chain := make([]*x509.Certificate, 0, len(caCertificates))
	chain = append(chain, caCertificates...)
	return buildIdentity(leaf, chain, signer, now)
}
