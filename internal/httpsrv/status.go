package httpsrv

import (
	"github.com/kagurazakayashi/EvernightLogin/config"
	"github.com/kagurazakayashi/EvernightLogin/httpapi"
	"github.com/kagurazakayashi/EvernightLogin/internal/tlscert"
)

// publicTLSStatus 把 internal/tlscert 的状态脱敏投影为公开 httpapi.TLSStatus。
// 只复制公开证书信息（DNS 名称、有效期、指纹、序列号、自签名标记与显式身份
// 映射），不包含私钥、密码或内部路径。
func publicTLSStatus(status tlscert.Status) httpapi.TLSStatus {
	result := httpapi.TLSStatus{
		LoadedAt:         status.LoadedAt,
		EarliestNotAfter: status.EarliestNotAfter,
		Expired:          status.Expired,
		ExpiringSoon:     status.ExpiringSoon,
		ReloadFailures:   status.ReloadFailures,
		LastReloadAt:     status.LastReloadAt,
		LastReloadFailed: status.LastReloadFailed,
	}
	result.Certificates = make([]httpapi.TLSCertificateStatus, len(status.Certificates))
	for index, certificate := range status.Certificates {
		result.Certificates[index] = httpapi.TLSCertificateStatus{
			Domains:           append([]string(nil), certificate.Domains...),
			NotBefore:         certificate.NotBefore,
			NotAfter:          certificate.NotAfter,
			FingerprintSHA256: certificate.FingerprintSHA256,
			SerialNumber:      certificate.SerialNumber,
			SelfSigned:        certificate.SelfSigned,
		}
	}
	result.ClientAuth = httpapi.TLSClientAuthStatus{
		Mode:         config.TLSClientAuthMode(status.ClientAuth.Mode),
		TrustAnchors: make([]httpapi.TLSClientTrustAnchor, len(status.ClientAuth.TrustAnchors)),
		Identities:   make([]config.TLSClientIdentity, len(status.ClientAuth.Identities)),
	}
	if result.ClientAuth.Mode == "" {
		result.ClientAuth.Mode = config.TLSClientAuthDisabled
	}
	for index, anchor := range status.ClientAuth.TrustAnchors {
		result.ClientAuth.TrustAnchors[index] = httpapi.TLSClientTrustAnchor{
			Subject:           anchor.Subject,
			FingerprintSHA256: anchor.FingerprintSHA256,
			NotBefore:         anchor.NotBefore,
			NotAfter:          anchor.NotAfter,
			SelfSigned:        anchor.SelfSigned,
		}
	}
	for index, identity := range status.ClientAuth.Identities {
		result.ClientAuth.Identities[index] = config.TLSClientIdentity{
			DNSName: identity.DNSName,
			Service: identity.Service,
		}
	}
	return result
}
