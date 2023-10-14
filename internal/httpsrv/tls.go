package httpsrv

import (
	"fmt"
	"log/slog"
	"net/url"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/config"
	"github.com/kagurazakayashi/EvernightLogin/internal/tlscert"
	"github.com/kagurazakayashi/EvernightLogin/netpolicy"
)

// newTLSManager 从有效配置构造 TLS 证书管理器。到期告警天数 0 表示使用默认值。
// PFX 密码来自配置秘密，只在内存中传给加载器，不写入日志或错误。客户端证书
// 认证所需的信任 CA 与身份映射一并传入；客户端信任配置在进程生命周期内不变。
func newTLSManager(cfg config.Config, logger *slog.Logger) (*tlscert.Manager, error) {
	warningDays := cfg.Server.TLSExpiryWarningDays
	if warningDays == 0 {
		warningDays = config.DefaultServerTLSExpiryWarningDays
	}
	clientAuth := tlscert.ClientAuthOptions{
		Mode:       tlscert.ClientAuthDisabled,
		CAFiles:    append([]string(nil), cfg.Server.TLSClientCAFiles...),
		Identities: make([]tlscert.ClientIdentity, 0, len(cfg.Server.TLSClientIdentities)),
	}
	switch config.NormalizeTLSClientAuthMode(cfg.Server.TLSClientAuthMode) {
	case config.TLSClientAuthRequired:
		clientAuth.Mode = tlscert.ClientAuthRequired
	case config.TLSClientAuthOptional:
		clientAuth.Mode = tlscert.ClientAuthOptional
	}
	for _, identity := range cfg.Server.TLSClientIdentities {
		clientAuth.Identities = append(clientAuth.Identities, tlscert.ClientIdentity{
			DNSName: identity.DNSName,
			Service: identity.Service,
		})
	}
	return tlscert.New(tlscert.Options{
		Source: tlscert.Source{
			CertFiles:   append([]string(nil), cfg.Server.TLSCertFiles...),
			KeyFiles:    append([]string(nil), cfg.Server.TLSKeyFiles...),
			CAFile:      cfg.Server.TLSCAFile,
			PFXFile:     cfg.Server.TLSPFXFile,
			PFXPassword: cfg.Secrets.TLSPFXPassword.Value(),
		},
		ClientAuth:    clientAuth,
		ExpiryWarning: time.Duration(warningDays) * 24 * time.Hour,
		Logger:        logger,
	})
}

// checkTLSCertificateCoverage 把显式公开地址与允许 Host 中的主机名同证书 DNS
// 名称交叉检查：某个配置主机没有被任何证书覆盖时，即使 Host 校验通过，客户端
// 也会因证书不匹配而握手失败，因此启动阶段就拒绝。IP 地址不在此检查范围（由
// 证书 IP SAN 与客户端校验负责）。
func checkTLSCertificateCoverage(manager *tlscert.Manager, cfg config.ServerConfig) error {
	return checkTLSCertificateCoverageStatus(manager.Status(), cfg)
}

// checkTLSCertificateCoverageStatus 用给定的候选状态执行同一套主机覆盖检查；
// 启动与重载共用它，避免“启动被拒但重载放行”的规则不一致。
func checkTLSCertificateCoverageStatus(status tlscert.Status, cfg config.ServerConfig) error {
	hosts := make([]string, 0, 1+len(cfg.AllowedHosts))
	if cfg.PublicBaseURL != "" {
		if parsed, err := url.Parse(cfg.PublicBaseURL); err == nil {
			if host := parsed.Hostname(); host != "" {
				hosts = append(hosts, host)
			}
		}
	}
	for _, raw := range cfg.AllowedHosts {
		parsed, err := netpolicy.ParseRequestHost(raw)
		if err != nil || parsed.IsIP() {
			continue
		}
		hosts = append(hosts, parsed.Host())
	}
	if len(hosts) == 0 {
		return nil
	}
	for _, host := range hosts {
		covered := false
		for _, certificate := range status.Certificates {
			if certificate.CoversDomain(host) {
				covered = true
				break
			}
		}
		if !covered {
			return fmt.Errorf("证书未覆盖主机 %q", host)
		}
	}
	return nil
}
