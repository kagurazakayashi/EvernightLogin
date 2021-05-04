package tlscert

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/netpolicy"
)

const (
	// MaxClientCAFiles 是客户端信任 CA 文件数量上限。
	MaxClientCAFiles = 8
	// MaxClientIdentities 是客户端证书身份映射条目数量上限。
	MaxClientIdentities = 32
	// MaxClientServiceIdentityBytes 是可信服务身份名称长度上限。
	MaxClientServiceIdentityBytes = 64
	// maxClientCAFileBytes 是单个客户端信任 CA 文件大小上限（公共材料，可较大）。
	maxClientCAFileBytes = 4 << 20
)

// ClientAuthMode 是客户端证书认证模式。
//
// 三种模式语义：
//   - disabled：不请求客户端证书，也不建立客户端身份；默认值。
//   - required：必须出示能链到显式配置的客户端信任 CA 的证书，并且证书身份必须
//     在显式映射表中；否则握手失败。
//   - optional：允许不出示证书（匿名连接），但一旦客户端出示证书，它必须通过
//     信任链、用途、有效期与显式身份映射校验；出示无效证书不会降级为匿名。
type ClientAuthMode string

const (
	// ClientAuthDisabled 表示关闭客户端证书认证（默认值）。
	ClientAuthDisabled ClientAuthMode = "disabled"
	// ClientAuthRequired 表示必须验证客户端证书。
	ClientAuthRequired ClientAuthMode = "required"
	// ClientAuthOptional 表示可选客户端证书，但出示的证书必须有效且已映射。
	ClientAuthOptional ClientAuthMode = "optional"
)

// Valid 报告模式是否已定义。空字符串按 disabled 解释（零值安全默认）。
func (m ClientAuthMode) Valid() bool {
	switch m {
	case "", ClientAuthDisabled, ClientAuthRequired, ClientAuthOptional:
		return true
	default:
		return false
	}
}

// Enabled 报告是否需要请求并验证客户端证书。
func (m ClientAuthMode) Enabled() bool {
	return m == ClientAuthRequired || m == ClientAuthOptional
}

// normalizeClientAuthMode 把空字符串归一为 disabled；其他值原样返回。
func normalizeClientAuthMode(mode ClientAuthMode) ClientAuthMode {
	if mode == "" {
		return ClientAuthDisabled
	}
	return mode
}

// ClientIdentity 是一条客户端证书身份到可信服务身份的显式映射。
//
// DNSName 是客户端叶证书必须包含的 DNS SAN（精确匹配，配置解析时规范化）；
// Service 是映射到的可信服务身份名称。仅有受信任 CA 签发的证书不等于获准接入：
// 证书必须命中本映射表才能建立连接。映射本身不授予 root 或任何业务权限，服务层
// 授权仍必须独立判断。
type ClientIdentity struct {
	DNSName string
	Service string
}

// ClientAuthOptions 是客户端证书双向认证的加载参数。
type ClientAuthOptions struct {
	// Mode 是认证模式；空字符串按 disabled 处理。
	Mode ClientAuthMode
	// CAFiles 是客户端信任 CA 的 PEM 文件列表；与服务器证书链完全分开。
	CAFiles []string
	// Identities 是显式身份映射；未命中的客户端证书一律拒绝。
	Identities []ClientIdentity
}

// ClientTrustAnchor 是单个客户端信任 CA 的脱敏状态。只包含公共证书信息。
type ClientTrustAnchor struct {
	// Subject 是证书主题的可读文本（截断到合理长度）。
	Subject string
	// FingerprintSHA256 是证书 DER 的 SHA-256 指纹（小写十六进制）。
	FingerprintSHA256 string
	// NotBefore/NotAfter 是信任 CA 的有效期边界（UTC）。
	NotBefore time.Time
	NotAfter  time.Time
	// SelfSigned 表示证书主题与签发者相同。
	SelfSigned bool
}

// ClientAuthStatus 是客户端证书认证的只读状态，用于配置诊断与脱敏证书状态报告。
type ClientAuthStatus struct {
	// Mode 是归一化后的客户端证书认证模式。
	Mode ClientAuthMode
	// TrustAnchors 是已加载的客户端信任 CA 公共信息。
	TrustAnchors []ClientTrustAnchor
	// Identities 是已生效的显式身份映射。
	Identities []ClientIdentity
}

// 客户端证书认证的固定失败原因。握手错误只使用不含具体证书、身份或配置的通用
// 文本，避免把映射表或证书细节回显给对端或写入日志。
var (
	errClientCertificateRequired     = errors.New("该连接要求客户端证书")
	errClientCertificateUnauthorized = errors.New("客户端证书身份未获授权")
)

// clientTrust 是加载完成且不可变的客户端信任配置：信任 CA 池、身份映射与诊断
// 状态。进程生命周期内不重载；信任更新需要重启。
type clientTrust struct {
	mode         ClientAuthMode
	pool         *x509.CertPool
	serviceByDNS map[string]string
	identities   []ClientIdentity
	anchors      []ClientTrustAnchor
}

// loadClientTrust 读取并校验客户端信任 CA 与身份映射。它不读取服务器私钥，也不
// 修改任何共享状态；任何一项校验失败都返回错误，不建立部分可用的信任配置。
//
// serverCertificates 是同一进程已加载的服务器证书身份；客户端信任 CA 与服务器
// 证书链必须分开，同一张证书不能同时充当两者（见 validateClientCAAnchors）。
func loadClientTrust(options ClientAuthOptions, now time.Time, serverCertificates []tls.Certificate) (*clientTrust, error) {
	mode := normalizeClientAuthMode(options.Mode)
	if !mode.Valid() {
		return nil, fmt.Errorf("客户端证书认证模式无效")
	}
	if !mode.Enabled() {
		if len(options.CAFiles) > 0 || len(options.Identities) > 0 {
			return nil, fmt.Errorf("未启用客户端证书认证时不能配置客户端信任 CA 或身份映射")
		}
		return nil, nil
	}
	if len(options.CAFiles) == 0 {
		return nil, fmt.Errorf("启用客户端证书认证时必须配置客户端信任 CA")
	}
	if len(options.CAFiles) > MaxClientCAFiles {
		return nil, fmt.Errorf("客户端信任 CA 文件不能超过 %d 个", MaxClientCAFiles)
	}
	if len(options.Identities) == 0 {
		return nil, fmt.Errorf("启用客户端证书认证时必须配置显式身份映射")
	}
	if len(options.Identities) > MaxClientIdentities {
		return nil, fmt.Errorf("客户端证书身份映射不能超过 %d 条", MaxClientIdentities)
	}

	trust := &clientTrust{
		mode:         mode,
		pool:         x509.NewCertPool(),
		serviceByDNS: make(map[string]string, len(options.Identities)),
		identities:   make([]ClientIdentity, 0, len(options.Identities)),
	}
	seenPairs := make(map[string]struct{}, len(options.Identities))
	for index, raw := range options.Identities {
		identity, err := normalizeClientIdentity(raw)
		if err != nil {
			return nil, fmt.Errorf("第 %d 条客户端证书身份映射无效: %w", index+1, err)
		}
		pairKey := identity.DNSName + "\x00" + identity.Service
		if _, duplicated := seenPairs[pairKey]; duplicated {
			return nil, fmt.Errorf("第 %d 条客户端证书身份映射重复", index+1)
		}
		seenPairs[pairKey] = struct{}{}
		if existing, duplicated := trust.serviceByDNS[identity.DNSName]; duplicated && existing != identity.Service {
			return nil, fmt.Errorf("客户端证书 DNS 名称被映射到多个可信服务身份")
		}
		trust.serviceByDNS[identity.DNSName] = identity.Service
		trust.identities = append(trust.identities, identity)
	}

	seenAnchors := make(map[string]struct{})
	for index, file := range options.CAFiles {
		certificates, err := loadCertificatesFromFile(file, maxClientCAFileBytes)
		if err != nil {
			return nil, fmt.Errorf("第 %d 个客户端信任 CA 文件无效: %w", index+1, err)
		}
		if len(certificates) == 0 {
			return nil, fmt.Errorf("第 %d 个客户端信任 CA 文件不包含证书", index+1)
		}
		for _, certificate := range certificates {
			if err := validateClientCACertificate(certificate, now); err != nil {
				return nil, err
			}
			key := string(certificate.Raw)
			if _, duplicated := seenAnchors[key]; duplicated {
				return nil, fmt.Errorf("客户端信任 CA 包含重复证书")
			}
			seenAnchors[key] = struct{}{}
			trust.pool.AddCert(certificate)
			trust.anchors = append(trust.anchors, clientTrustAnchorOf(certificate))
		}
	}

	// 客户端信任 CA 与服务器证书链必须分开：两者是不同信任方向，复用同一张
	// 证书会让“服务器身份”和“客户端信任根”混在一个配置对象里，难以审计。
	if err := validateClientCAAnchors(trust.anchors, serverCertificates); err != nil {
		return nil, err
	}
	return trust, nil
}

// normalizeClientIdentity 规范化并校验一条身份映射：DNS 名称必须是合法主机名
// （不接受 IP、通配符或端口），服务身份必须是稳定的小写标识符。
func normalizeClientIdentity(identity ClientIdentity) (ClientIdentity, error) {
	parsed, err := netpolicy.ParseRequestHost(strings.TrimSpace(identity.DNSName))
	if err != nil {
		return ClientIdentity{}, fmt.Errorf("客户端证书 DNS 名称不合法")
	}
	if parsed.IsIP() || parsed.Port() != 0 {
		return ClientIdentity{}, fmt.Errorf("客户端证书身份必须使用 DNS 主机名")
	}
	service := strings.TrimSpace(identity.Service)
	if problem := validateClientServiceName(service); problem != "" {
		return ClientIdentity{}, errors.New(problem)
	}
	return ClientIdentity{DNSName: parsed.Host(), Service: service}, nil
}

// validateClientServiceName 校验可信服务身份名称：1～64 字节 ASCII 小写标识符，
// 只允许 a-z、0-9、点、下划线与连字符，且首尾必须是字母或数字。禁止大写与空白，
// 避免不同系统对同一身份做出不同的大小写解释。
func validateClientServiceName(name string) string {
	if name == "" {
		return "可信服务身份名称不能为空"
	}
	if len(name) > MaxClientServiceIdentityBytes {
		return fmt.Sprintf("可信服务身份名称不能超过 %d 字节", MaxClientServiceIdentityBytes)
	}
	for index := 0; index < len(name); index++ {
		character := name[index]
		switch {
		case character >= 'a' && character <= 'z':
		case character >= '0' && character <= '9':
		case character == '.', character == '_', character == '-':
		default:
			return "可信服务身份名称只能包含小写 ASCII 字母、数字、点、下划线与连字符"
		}
	}
	first := name[0]
	last := name[len(name)-1]
	isAlphaNumeric := func(character byte) bool {
		return (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9')
	}
	if !isAlphaNumeric(first) || !isAlphaNumeric(last) {
		return "可信服务身份名称必须以字母或数字开头和结尾"
	}
	return ""
}

// clientTrustAnchorOf 把 CA 证书转为脱敏诊断信息；主题文本截断到 512 字节，避免
// 异常证书把超长主题写入诊断与日志。
func clientTrustAnchorOf(certificate *x509.Certificate) ClientTrustAnchor {
	sum := sha256.Sum256(certificate.Raw)
	subject := certificate.Subject.String()
	if len(subject) > 512 {
		subject = subject[:512] + "..."
	}
	return ClientTrustAnchor{
		Subject:           subject,
		FingerprintSHA256: hex.EncodeToString(sum[:]),
		NotBefore:         certificate.NotBefore.UTC(),
		NotAfter:          certificate.NotAfter.UTC(),
		SelfSigned:        certificate.RawSubject != nil && string(certificate.RawSubject) == string(certificate.RawIssuer),
	}
}

// validateClientCAAnchors 校验客户端信任 CA 与服务器证书链不重叠。参数只用于
// 比较 DER，不保存引用。
func validateClientCAAnchors(anchors []ClientTrustAnchor, serverCertificates []tls.Certificate) error {
	if len(anchors) == 0 || len(serverCertificates) == 0 {
		return nil
	}
	clientAnchors := make(map[string]struct{}, len(anchors))
	for _, anchor := range anchors {
		clientAnchors[anchor.FingerprintSHA256] = struct{}{}
	}
	for _, certificate := range serverCertificates {
		for _, der := range certificate.Certificate {
			sum := sha256.Sum256(der)
			if _, overlapped := clientAnchors[hex.EncodeToString(sum[:])]; overlapped {
				return fmt.Errorf("客户端信任 CA 不能与服务器证书链共用同一张证书")
			}
		}
	}
	return nil
}

// validateClientCACertificate 校验单个客户端信任 CA 证书的 CA 属性、用途与有效期。
// loadCertificatesFromFile 已经完成 PEM 解析；这里只做证书语义检查。信任锚的
// 有效期在每次握手时还会由 crypto/x509 再次检查，提前失败可以让错误配置在启动
// 阶段暴露，而不是等到客户端连不上。
func validateClientCACertificate(certificate *x509.Certificate, now time.Time) error {
	if !certificate.BasicConstraintsValid || !certificate.IsCA {
		return fmt.Errorf("客户端信任 CA 必须带有 CA 基本约束")
	}
	if certificate.KeyUsage != 0 && certificate.KeyUsage&x509.KeyUsageCertSign == 0 {
		return fmt.Errorf("客户端信任 CA 的密钥用途必须包含证书签发")
	}
	if len(certificate.ExtKeyUsage) > 0 {
		allowed := false
		for _, usage := range certificate.ExtKeyUsage {
			if usage == x509.ExtKeyUsageClientAuth || usage == x509.ExtKeyUsageAny {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("客户端信任 CA 的扩展用途不包含客户端认证")
		}
	}
	if now.Before(certificate.NotBefore) {
		return fmt.Errorf("客户端信任 CA 尚未生效")
	}
	if now.After(certificate.NotAfter) {
		return fmt.Errorf("客户端信任 CA 已过期")
	}
	return nil
}

// applyClientAuth 把客户端证书认证配置写入 tls.Config。
//
// 使用 VerifyConnection 而不是 VerifyPeerCertificate：Go 不会在会话恢复时调用
// VerifyPeerCertificate，但会调用 VerifyConnection，且恢复的 ConnectionState 仍
// 携带最初验证过的客户端证书链。这样会话恢复连接也必须命中当前身份映射，不会
// 因恢复而绕过映射检查。模式只使用 Required/VerifyIfGiven；绝不使用
// RequestClientCert/RequireAnyClientCert 这类不验证证书的模式，保证“出示无效
// 证书后降级”不可能发生。
func applyClientAuth(config *tls.Config, trust *clientTrust) {
	if config == nil || trust == nil {
		return
	}
	switch trust.mode {
	case ClientAuthRequired:
		config.ClientAuth = tls.RequireAndVerifyClientCert
	case ClientAuthOptional:
		config.ClientAuth = tls.VerifyClientCertIfGiven
	default:
		return
	}
	config.ClientCAs = trust.pool
	config.VerifyConnection = trust.verifyConnection
}

// verifyConnection 在标准证书链、有效期与客户端认证用途校验通过后执行显式身份
// 映射检查。required 模式下缺少客户端证书按失败处理（正常握手流程会更早失败，
// 这里保留防御性判断）；optional 模式下没有证书表示匿名连接，允许继续。
func (t *clientTrust) verifyConnection(state tls.ConnectionState) error {
	if len(state.PeerCertificates) == 0 {
		if t.mode == ClientAuthRequired {
			return errClientCertificateRequired
		}
		return nil
	}
	if _, ok := t.identityFor(state.PeerCertificates[0]); !ok {
		return errClientCertificateUnauthorized
	}
	return nil
}

// identityFor 从客户端叶证书的全部 DNS SAN 中匹配显式身份映射，返回可信服务
// 身份。没有任何命中、或命中多个不同服务身份（映射有歧义）时返回 false，按
// fail-closed 拒绝；同一服务身份的多个 DNS 名称可以同时出现在证书上。
func (t *clientTrust) identityFor(certificate *x509.Certificate) (string, bool) {
	if t == nil || certificate == nil || len(t.serviceByDNS) == 0 {
		return "", false
	}
	matchedService := ""
	matched := false
	for _, raw := range certificate.DNSNames {
		name := normalizeClientDNSName(raw)
		if name == "" {
			continue
		}
		service, ok := t.serviceByDNS[name]
		if !ok {
			continue
		}
		if matched && service != matchedService {
			// 证书同时命中多个不同服务身份：无法确定唯一可信身份，拒绝。
			return "", false
		}
		matched = true
		matchedService = service
	}
	if !matched {
		return "", false
	}
	return matchedService, true
}

// normalizeClientDNSName 规范化证书 DNS SAN：去空白、小写、去掉一个结尾根域点。
// 非法或空值返回空字符串，不参与匹配。
func normalizeClientDNSName(raw string) string {
	name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), "."))
	if name == "" || len(name) > 253 {
		return ""
	}
	for index := 0; index < len(name); index++ {
		character := name[index]
		if character <= 0x20 || character >= 0x7f {
			return ""
		}
	}
	return name
}

// status 返回客户端证书认证的只读状态副本。
func (t *clientTrust) status() ClientAuthStatus {
	if t == nil {
		return ClientAuthStatus{Mode: ClientAuthDisabled}
	}
	status := ClientAuthStatus{
		Mode:         t.mode,
		TrustAnchors: append([]ClientTrustAnchor(nil), t.anchors...),
		Identities:   append([]ClientIdentity(nil), t.identities...),
	}
	return status
}
