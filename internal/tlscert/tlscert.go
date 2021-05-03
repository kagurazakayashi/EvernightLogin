// Package tlscert 实现服务器 TLS 单向认证所需的证书材料加载、严格校验、按 SNI
// 选择证书与安全重载。
//
// 设计约束：
//   - 加载前完成全部校验（文件格式、私钥与证书匹配、证书链组织与签发关系、
//     有效期、服务器认证用途、DNS 名称），任何一项失败都不建立 TLS 配置。
//   - 支持 PEM 证书链 + 私钥、可选附加 CA/中间证书，以及 PKCS#12/PFX 导入；
//     PFX 密码只能由受保护来源提供，不在本包解析配置。
//   - SNI 只按证书实际覆盖的 DNS 名称选择证书；同名冲突、未知名称都会失败，
//     不做“回退到任意证书”的隐式选择。没有 SNI 时使用配置顺序的第一张证书，
//     这是显式记录的安全策略。
//   - 重载先在独立快照上完成全部加载与校验，成功后才原子替换；失败保留旧快照
//     并告警，绝不出现半更新的 TLS 配置。
//   - 协议与密码套件使用 Go 标准库当前安全默认：TLS 1.2 为最低版本，不设置
//     自定义 CipherSuites/CurvePreferences，不自行组合算法。
//
// 本包不负责配置解析、文件权限策略之外的主机密钥保护实现、证书签发、WebAuthn
// （RP ID）或客户端证书认证（步骤 17）；它也不发送到期通知，只提供到期状态。
package tlscert

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/netpolicy"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
)

const (
	// DefaultExpiryWarning 是默认的证书到期提前告警窗口（30 天）。
	DefaultExpiryWarning = 30 * 24 * time.Hour
	// MaxCertificates 是同时配置的证书身份（PEM 证书/私钥对）数量上限。
	MaxCertificates = 8
	// 证书材料文件大小上限：公共证书可较大，私钥与 PFX 单独限制。
	maxCertificateFileBytes = 2 << 20
	maxCAFileBytes          = 4 << 20
	maxPrivateKeyFileBytes  = 1 << 20
	maxPFXFileBytes         = 8 << 20
)

// Source 是 TLS 证书材料的显式来源。两种模式互斥：
//   - PEM 模式：CertFiles 与 KeyFiles 一一对应，CAFile 可选追加中间/根证书；
//   - PFX 模式：PFXFile 为 PKCS#12/PFX 文件，PFXPassword 为其密码。
type Source struct {
	CertFiles   []string
	KeyFiles    []string
	CAFile      string
	PFXFile     string
	PFXPassword []byte
}

// Options 是构造证书管理器的依赖。
type Options struct {
	Source Source
	// ExpiryWarning 是到期提前告警窗口；0 使用 DefaultExpiryWarning。
	ExpiryWarning time.Duration
	// Logger 记录加载与重载结果；nil 时丢弃。日志不写入证书内容或私钥/密码。
	Logger *slog.Logger
	// Now 是可注入时钟；nil 使用 time.Now。用于有效期与到期状态校验。
	Now func() time.Time
}

// CertificateInfo 是单张服务器叶证书的脱敏状态。
type CertificateInfo struct {
	// Domains 是证书实际覆盖的规范化 DNS 名称（支持 *.example.com 通配）。
	Domains []string
	// NotBefore/NotAfter 是证书有效期边界（UTC）。
	NotBefore time.Time
	NotAfter  time.Time
	// FingerprintSHA256 是叶证书 DER 的 SHA-256 指纹（小写十六进制）。
	FingerprintSHA256 string
	// SerialNumber 是叶证书序列号（十六进制，可能是大整数）。
	SerialNumber string
	// SelfSigned 表示叶证书是自签名证书；不表示客户端自动信任它。
	SelfSigned bool
}

// Status 是证书管理器的只读状态快照，供诊断与未来调度/通知接入使用。
type Status struct {
	// LoadedAt 是当前生效快照的加载时间。
	LoadedAt time.Time
	// Certificates 是当前生效的各证书身份状态。
	Certificates []CertificateInfo
	// EarliestNotAfter 是最早到期的证书时间；没有证书时为零值。
	EarliestNotAfter time.Time
	// Expired 表示当前时间已晚于最早到期时间。
	Expired bool
	// ExpiringSoon 表示已进入告警窗口（EarliestNotAfter - ExpiryWarning）。
	ExpiringSoon bool
	// ReloadFailures 是最近一次成功重载之后连续失败的重载次数。
	ReloadFailures int
	// LastReloadAt 是最近一次重载尝试时间；零值表示从未重载。
	LastReloadAt time.Time
	// LastReloadFailed 表示最近一次重载是否失败。
	LastReloadFailed bool
}

// Manager 管理一组 TLS 证书身份与 SNI 选择规则，支持并发握手与安全重载。
type Manager struct {
	options    Options
	now        func() time.Time
	logger     *slog.Logger
	current    atomic.Pointer[snapshot]
	tlsConfig  *tls.Config
	reloadMu   sync.Mutex
	statusMu   sync.Mutex
	relFail    int
	lastReload time.Time
	lastFailed bool
}

// snapshot 是某一代已校验证书的不可变快照；重载时整体替换。
type snapshot struct {
	loadedAt     time.Time
	certificates []tls.Certificate
	infos        []CertificateInfo
	exactNames   map[string]int
	wildcards    map[string]int
	defaultIndex int
}

// New 校验来源并加载第一代证书，构造证书管理器。任何材料错误都返回错误，且
// 不返回部分可用的管理器，避免带着无效证书启动 TLS 服务。
func New(options Options) (*Manager, error) {
	normalized, err := normalizeOptions(options)
	if err != nil {
		return nil, err
	}
	current, err := loadSnapshot(normalized, normalized.Now())
	if err != nil {
		return nil, err
	}
	manager := &Manager{
		options:   normalized,
		now:       normalized.Now,
		logger:    normalized.Logger,
		tlsConfig: nil,
	}
	manager.current.Store(current)
	manager.tlsConfig = &tls.Config{
		// 只使用安全基线：TLS 1.2 起；CipherSuites/CurvePreferences 留空使用 Go
		// 标准库当前安全默认，不自行组合算法。
		MinVersion:     tls.VersionTLS12,
		GetCertificate: manager.getCertificate,
	}
	return manager, nil
}

// normalizeOptions 填充默认值并校验来源形状（不读取文件）。
func normalizeOptions(options Options) (Options, error) {
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.ExpiryWarning == 0 {
		options.ExpiryWarning = DefaultExpiryWarning
	}
	if options.ExpiryWarning < 0 || options.ExpiryWarning > 365*24*time.Hour {
		return Options{}, fmt.Errorf("证书到期告警窗口必须在 0～365 天之间")
	}
	if options.Logger == nil {
		options.Logger = slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError + 1}))
	}
	source := options.Source
	pemMode := len(source.CertFiles) > 0 || len(source.KeyFiles) > 0 || source.CAFile != ""
	pfxMode := source.PFXFile != ""
	switch {
	case pemMode && pfxMode:
		return Options{}, fmt.Errorf("PEM 证书/私钥与 PFX/P12 不能同时配置")
	case !pemMode && !pfxMode:
		return Options{}, fmt.Errorf("未配置 TLS 证书材料")
	case pfxMode && len(source.PFXPassword) == 0:
		return Options{}, fmt.Errorf("PFX/P12 密码必须从受保护来源提供")
	case pemMode && len(source.CertFiles) != len(source.KeyFiles):
		return Options{}, fmt.Errorf("证书文件与私钥文件必须一一对应")
	case pemMode && len(source.CertFiles) == 0:
		return Options{}, fmt.Errorf("至少需要一个证书与私钥文件对")
	case pemMode && len(source.CertFiles) > MaxCertificates:
		return Options{}, fmt.Errorf("证书文件对不能超过 %d 个", MaxCertificates)
	}
	if pfxMode && source.CAFile != "" {
		return Options{}, fmt.Errorf("PFX/P12 模式不能同时使用附加 CA 文件")
	}
	checkPath := func(label, path string) error {
		if path == "" {
			return fmt.Errorf("%s路径不能为空", label)
		}
		if len(path) > 4096 {
			return fmt.Errorf("%s路径过长", label)
		}
		for _, character := range path {
			if character < 0x20 || character == 0x7f {
				return fmt.Errorf("%s路径包含控制字符", label)
			}
		}
		return nil
	}
	for index, file := range source.CertFiles {
		if err := checkPath("证书文件", file); err != nil {
			return Options{}, fmt.Errorf("第 %d 个证书文件无效: %w", index+1, err)
		}
	}
	for index, file := range source.KeyFiles {
		if err := checkPath("私钥文件", file); err != nil {
			return Options{}, fmt.Errorf("第 %d 个私钥文件无效: %w", index+1, err)
		}
	}
	if source.CAFile != "" {
		if err := checkPath("CA 文件", source.CAFile); err != nil {
			return Options{}, err
		}
	}
	if pfxMode {
		if err := checkPath("PFX/P12 文件", source.PFXFile); err != nil {
			return Options{}, err
		}
	}
	options.Source = source
	return options, nil
}

// TLSConfig 返回可交给 http.Server 的 TLS 配置。返回的配置只包含 SNI 选择函数
// 与安全最低版本；证书内容通过管理器快照读取，因此重载不需要替换 tls.Config。
func (m *Manager) TLSConfig() *tls.Config {
	if m == nil {
		return nil
	}
	return m.tlsConfig
}

// Status 返回当前生效证书的脱敏状态快照。返回值是副本，调用方修改不影响管理器。
func (m *Manager) Status() Status {
	if m == nil {
		return Status{}
	}
	return m.statusOf(m.current.Load())
}

// statusOf 由指定快照生成状态快照；重载校验使用候选快照，不读取仍生效的旧快照。
func (m *Manager) statusOf(current *snapshot) Status {
	m.statusMu.Lock()
	status := Status{
		ReloadFailures:   m.relFail,
		LastReloadAt:     m.lastReload,
		LastReloadFailed: m.lastFailed,
	}
	m.statusMu.Unlock()
	if current == nil {
		return status
	}
	now := m.now()
	status.LoadedAt = current.loadedAt
	status.Certificates = make([]CertificateInfo, len(current.infos))
	for index, info := range current.infos {
		cloned := info
		cloned.Domains = append([]string(nil), info.Domains...)
		status.Certificates[index] = cloned
	}
	if len(current.infos) > 0 {
		earliest := current.infos[0].NotAfter
		for _, info := range current.infos[1:] {
			if info.NotAfter.Before(earliest) {
				earliest = info.NotAfter
			}
		}
		status.EarliestNotAfter = earliest
		status.Expired = now.After(earliest)
		status.ExpiringSoon = !now.Before(earliest.Add(-m.options.ExpiryWarning))
	}
	return status
}

// Reload 重新读取并完整校验证书材料，成功后原子替换；失败保留旧快照、记录失败
// 次数并返回错误，调用方应告警但不能因此停止服务。ctx 取消时不替换快照。
func (m *Manager) Reload(ctx context.Context) error {
	return m.ReloadChecked(ctx, nil)
}

// ReloadChecked 与 Reload 相同，但在原子替换前调用 validate 校验候选证书状态。
// validate 返回错误（例如候选证书不覆盖已配置的公开主机）时保留旧证书、记录
// 失败次数并返回该错误，不会出现“重载成功但新证书无法服务原主机”的半更新。
func (m *Manager) ReloadChecked(ctx context.Context, validate func(Status) error) error {
	if m == nil {
		return errors.New("TLS 证书管理器为空")
	}
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	m.reloadMu.Lock()
	defer m.reloadMu.Unlock()
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	candidate, err := loadSnapshot(m.options, m.now())
	if err != nil {
		m.recordReloadFailure("tls_reload_failed")
		return err
	}
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	if validate != nil {
		if err := validate(m.statusOf(candidate)); err != nil {
			m.recordReloadFailure("tls_reload_rejected")
			return err
		}
	}
	m.current.Store(candidate)
	m.statusMu.Lock()
	m.relFail = 0
	m.lastReload = m.now()
	m.lastFailed = false
	m.statusMu.Unlock()
	m.logger.Info("TLS 证书已重载", "certificate_count", len(candidate.certificates))
	return nil
}

// recordReloadFailure 记录一次重载失败并写运行日志告警；不记录证书内容或密码。
func (m *Manager) recordReloadFailure(reasonCode string) {
	m.statusMu.Lock()
	m.relFail++
	m.lastReload = m.now()
	m.lastFailed = true
	failures := m.relFail
	m.statusMu.Unlock()
	m.logger.Warn("TLS 证书重载未生效，继续使用旧证书",
		"reason_code", reasonCode, "failure_count", failures)
}

// getCertificate 按 SNI 选择证书。未知 SNI 或没有可用快照时返回错误，让握手
// 失败，而不是回退到任意证书。
func (m *Manager) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	current := m.current.Load()
	if current == nil || len(current.certificates) == 0 {
		return nil, errors.New("TLS 证书尚未加载")
	}
	return current.selectCertificate(hello.ServerName)
}

// selectCertificate 从不可变快照中按 SNI 选择证书。
func (s *snapshot) selectCertificate(serverName string) (*tls.Certificate, error) {
	name := normalizeServerName(serverName)
	if name == "" {
		return &s.certificates[s.defaultIndex], nil
	}
	if index, ok := s.exactNames[name]; ok {
		return &s.certificates[index], nil
	}
	for suffix, index := range s.wildcards {
		if wildcardMatches(suffix, name) {
			return &s.certificates[index], nil
		}
	}
	return nil, fmt.Errorf("没有为服务器名配置 TLS 证书")
}

// normalizeServerName 规范化 SNI：小写、去掉一个结尾根域点、拒绝控制字符与
// 超长值。非法值按空值处理会退回默认证书，因此这里返回空字符串表示“使用默认”。
func normalizeServerName(raw string) string {
	name := strings.TrimSpace(raw)
	if name == "" || len(name) > 255 {
		return ""
	}
	for _, character := range name {
		if character <= 0x20 || character >= 0x7f {
			return ""
		}
	}
	name = strings.ToLower(name)
	name = strings.TrimSuffix(name, ".")
	return name
}

// wildcardMatches 按 RFC 6125 的简单通配规则匹配：通配符只覆盖最左一级标签，
// 不匹配裸域名的其余部分，也不覆盖多级子域。
func wildcardMatches(suffix, name string) bool {
	// suffix 形如 ".example.com"。
	if !strings.HasSuffix(name, suffix) {
		return false
	}
	prefix := name[:len(name)-len(suffix)]
	return prefix != "" && !strings.Contains(prefix, ".")
}

// loadSnapshot 读取并校验全部证书材料，构造不可变快照。它不修改任何共享状态，
// 可以在重载时安全地与正在进行的握手并行执行。
func loadSnapshot(options Options, now time.Time) (*snapshot, error) {
	source := options.Source
	result := &snapshot{
		loadedAt:   now,
		exactNames: make(map[string]int),
		wildcards:  make(map[string]int),
	}
	var identities []loadedIdentity
	if source.PFXFile != "" {
		identity, err := loadPFXIdentity(source, now)
		if err != nil {
			return nil, err
		}
		identities = append(identities, identity)
	} else {
		var additional []*x509.Certificate
		if source.CAFile != "" {
			parsed, err := loadCertificatesFromFile(source.CAFile, maxCAFileBytes)
			if err != nil {
				return nil, fmt.Errorf("附加 CA 文件无效: %w", err)
			}
			additional = parsed
		}
		for index := range source.CertFiles {
			identity, err := loadPEMIdentity(source.CertFiles[index], source.KeyFiles[index], additional, now)
			if err != nil {
				return nil, fmt.Errorf("第 %d 个证书身份无效: %w", index+1, err)
			}
			identities = append(identities, identity)
		}
	}
	for index, identity := range identities {
		for _, domain := range identity.info.Domains {
			if strings.HasPrefix(domain, "*.") {
				suffix := domain[1:]
				if existing, duplicated := result.wildcards[suffix]; duplicated && existing != index {
					return nil, fmt.Errorf("通配符证书名称在多个证书身份中重复")
				}
				result.wildcards[suffix] = index
				continue
			}
			if existing, duplicated := result.exactNames[domain]; duplicated && existing != index {
				return nil, fmt.Errorf("证书 DNS 名称在多个证书身份中重复")
			}
			result.exactNames[domain] = index
		}
		result.certificates = append(result.certificates, identity.certificate)
		result.infos = append(result.infos, identity.info)
	}
	return result, nil
}

// loadedIdentity 是单个证书身份（一张叶证书及其私钥与链）的加载结果。
type loadedIdentity struct {
	certificate tls.Certificate
	info        CertificateInfo
}

// loadPEMIdentity 加载一对 PEM 证书/私钥并追加附加 CA 证书。私钥文件必须通过
// 受保护文件检查，避免私钥以宽权限暴露给其他用户。
func loadPEMIdentity(certFile, keyFile string, additional []*x509.Certificate, now time.Time) (loadedIdentity, error) {
	if err := secrets.CheckProtectedFile(keyFile); err != nil {
		return loadedIdentity{}, fmt.Errorf("私钥文件权限不安全: %w", err)
	}
	certificates, err := loadCertificatesFromFile(certFile, maxCertificateFileBytes)
	if err != nil {
		return loadedIdentity{}, fmt.Errorf("证书文件无效: %w", err)
	}
	if len(certificates) == 0 {
		return loadedIdentity{}, fmt.Errorf("证书文件不包含证书")
	}
	signer, err := loadPrivateKeyFile(keyFile)
	if err != nil {
		return loadedIdentity{}, err
	}
	chain := append(append([]*x509.Certificate(nil), certificates[1:]...), additional...)
	return buildIdentity(certificates[0], chain, signer, now)
}

// loadPrivateKeyFile 读取并解析 PEM 私钥。文件只允许包含一个私钥块，拒绝其他
// PEM 块，避免把混合材料误当私钥。
func loadPrivateKeyFile(path string) (crypto.Signer, error) {
	data, err := readLimitedFile(path, maxPrivateKeyFileBytes)
	if err != nil {
		return nil, fmt.Errorf("无法读取私钥文件: %v", err)
	}
	rest := data
	var signer crypto.Signer
	blocks := 0
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		switch block.Type {
		case "PRIVATE KEY":
			key, parseErr := x509.ParsePKCS8PrivateKey(block.Bytes)
			if parseErr != nil {
				return nil, fmt.Errorf("PKCS#8 私钥解析失败")
			}
			parsed, ok := key.(crypto.Signer)
			if !ok {
				return nil, fmt.Errorf("私钥类型不支持服务器 TLS")
			}
			signer = parsed
		case "RSA PRIVATE KEY":
			key, parseErr := x509.ParsePKCS1PrivateKey(block.Bytes)
			if parseErr != nil {
				return nil, fmt.Errorf("RSA 私钥解析失败")
			}
			signer = key
		case "EC PRIVATE KEY":
			key, parseErr := x509.ParseECPrivateKey(block.Bytes)
			if parseErr != nil {
				return nil, fmt.Errorf("EC 私钥解析失败")
			}
			signer = key
		default:
			return nil, fmt.Errorf("私钥文件包含不支持的 PEM 块类型")
		}
		blocks++
		if blocks > 1 {
			return nil, fmt.Errorf("私钥文件只能包含一个私钥")
		}
	}
	if signer == nil {
		return nil, fmt.Errorf("私钥文件不包含受支持的私钥")
	}
	if leftover := strings.TrimSpace(string(rest)); leftover != "" {
		return nil, fmt.Errorf("私钥文件包含多余内容")
	}
	return signer, nil
}

// loadCertificatesFromFile 读取只含 CERTIFICATE PEM 块的文件。文件可以包含多张
// 证书（叶证书在前、中间证书依次在后）；其他 PEM 块或杂项文本一律拒绝。
func loadCertificatesFromFile(path string, limit int64) ([]*x509.Certificate, error) {
	data, err := readLimitedFile(path, limit)
	if err != nil {
		return nil, err
	}
	var certificates []*x509.Certificate
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("证书文件包含不支持的 PEM 块类型")
		}
		certificate, parseErr := x509.ParseCertificate(block.Bytes)
		if parseErr != nil {
			return nil, fmt.Errorf("证书解析失败")
		}
		certificates = append(certificates, certificate)
	}
	if leftover := strings.TrimSpace(string(rest)); leftover != "" {
		return nil, fmt.Errorf("证书文件包含多余内容")
	}
	return certificates, nil
}

// readLimitedFile 读取普通文件并执行大小上限；错误信息不包含文件内容。
func readLimitedFile(path string, limit int64) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("无法访问文件")
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("必须是普通文件")
	}
	if info.Size() > limit {
		return nil, fmt.Errorf("文件超过 %d 字节上限", limit)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("无法打开文件")
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, fmt.Errorf("读取文件失败")
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("文件超过 %d 字节上限", limit)
	}
	return data, nil
}

// buildIdentity 校验叶证书、证书链与私钥，构造 tls.Certificate 与脱敏状态。
func buildIdentity(leaf *x509.Certificate, chain []*x509.Certificate, signer crypto.Signer, now time.Time) (loadedIdentity, error) {
	if signer == nil {
		return loadedIdentity{}, fmt.Errorf("私钥为空")
	}
	leafPublic, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil {
		return loadedIdentity{}, fmt.Errorf("证书公钥不受支持")
	}
	keyPublic, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return loadedIdentity{}, fmt.Errorf("私钥公钥不受支持")
	}
	if !bytes.Equal(leafPublic, keyPublic) {
		return loadedIdentity{}, fmt.Errorf("私钥与叶证书不匹配")
	}
	if err := validateServerCertificate(leaf, now); err != nil {
		return loadedIdentity{}, err
	}
	all := append([]*x509.Certificate{leaf}, chain...)
	if err := validateChain(all, now); err != nil {
		return loadedIdentity{}, err
	}
	domains, err := certificateDomains(leaf)
	if err != nil {
		return loadedIdentity{}, err
	}
	der := append([][]byte(nil), all[0].Raw)
	for _, certificate := range all[1:] {
		der = append(der, certificate.Raw)
	}
	sum := sha256.Sum256(leaf.Raw)
	return loadedIdentity{
		certificate: tls.Certificate{
			Certificate: der,
			PrivateKey:  signer,
			Leaf:        leaf,
		},
		info: CertificateInfo{
			Domains:           domains,
			NotBefore:         leaf.NotBefore.UTC(),
			NotAfter:          leaf.NotAfter.UTC(),
			FingerprintSHA256: hex.EncodeToString(sum[:]),
			SerialNumber:      leaf.SerialNumber.Text(16),
			SelfSigned:        bytes.Equal(leaf.RawSubject, leaf.RawIssuer),
		},
	}, nil
}

// validateServerCertificate 校验叶证书本身的服务器认证用途与有效期。
func validateServerCertificate(leaf *x509.Certificate, now time.Time) error {
	if now.Before(leaf.NotBefore) {
		return fmt.Errorf("叶证书尚未生效")
	}
	if now.After(leaf.NotAfter) {
		return fmt.Errorf("叶证书已过期")
	}
	const serverKeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	if leaf.KeyUsage != 0 && leaf.KeyUsage&serverKeyUsage == 0 {
		return fmt.Errorf("叶证书用途不包含服务器认证所需的密钥用途")
	}
	if len(leaf.ExtKeyUsage) > 0 {
		allowed := false
		for _, usage := range leaf.ExtKeyUsage {
			if usage == x509.ExtKeyUsageServerAuth || usage == x509.ExtKeyUsageAny {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("叶证书扩展用途不包含服务器认证")
		}
	} else if len(leaf.UnknownExtKeyUsage) > 0 {
		return fmt.Errorf("叶证书扩展用途无法识别，拒绝作为服务器证书")
	}
	return nil
}

// validateChain 校验证书链组织：叶证书在前，签发者依次在后；每个证书必须由
// 下一张证书签发，中间证书必须是 CA；链尾可以是自签根证书，也可以停在缺少根
// 证书的中间证书（客户端需自行信任根）。所有证书必须处于有效期内且不重复。
func validateChain(all []*x509.Certificate, now time.Time) error {
	seen := make(map[string]struct{}, len(all))
	for index, certificate := range all {
		if index > 0 && now.Before(certificate.NotBefore) {
			return fmt.Errorf("证书链第 %d 张尚未生效", index+1)
		}
		if index > 0 && now.After(certificate.NotAfter) {
			return fmt.Errorf("证书链第 %d 张已过期", index+1)
		}
		key := string(certificate.Raw)
		if _, duplicated := seen[key]; duplicated {
			return fmt.Errorf("证书链包含重复证书")
		}
		seen[key] = struct{}{}
	}
	for index := 0; index+1 < len(all); index++ {
		if err := all[index].CheckSignatureFrom(all[index+1]); err != nil {
			return fmt.Errorf("证书链第 %d 张与第 %d 张的签发关系无效", index+1, index+2)
		}
	}
	last := all[len(all)-1]
	if bytes.Equal(last.RawSubject, last.RawIssuer) {
		// 自签名链尾：直接校验自签名，避免要求链尾必须带 CA 约束（自签服务器
		// 证书的常见形态）。
		if err := last.CheckSignature(last.SignatureAlgorithm, last.RawTBSCertificate, last.Signature); err != nil {
			return fmt.Errorf("自签名证书的签名无效")
		}
	}
	return nil
}

// certificateDomains 返回叶证书 SAN 中的规范化 DNS 名称；不支持只含 CN 的旧证书。
func certificateDomains(leaf *x509.Certificate) ([]string, error) {
	if len(leaf.DNSNames) == 0 {
		return nil, fmt.Errorf("证书缺少 DNS 名称（SAN），不能用于 HTTPS 域名")
	}
	domains := make([]string, 0, len(leaf.DNSNames))
	seen := make(map[string]struct{}, len(leaf.DNSNames))
	for _, raw := range leaf.DNSNames {
		domain, err := normalizeCertificateDomain(raw)
		if err != nil {
			return nil, err
		}
		if _, duplicated := seen[domain]; duplicated {
			continue
		}
		seen[domain] = struct{}{}
		domains = append(domains, domain)
	}
	if len(domains) == 0 {
		return nil, fmt.Errorf("证书没有可用的 DNS 名称")
	}
	return domains, nil
}

// normalizeCertificateDomain 校验并规范化证书 DNS 名称。支持精确主机名与左起
// 单级通配符（*.example.com）；拒绝 IP、端口、通配符裸域名与其他通配形式。
func normalizeCertificateDomain(raw string) (string, error) {
	name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), "."))
	if name == "" || len(name) > 253 {
		return "", fmt.Errorf("证书 DNS 名称长度不合法")
	}
	if strings.HasPrefix(name, "*.") {
		suffix := name[2:]
		if suffix == "" || strings.Contains(suffix, "*") || !strings.Contains(suffix, ".") {
			return "", fmt.Errorf("证书通配符名称不合法")
		}
		if _, err := netpolicy.ParseRequestHost(suffix); err != nil {
			return "", fmt.Errorf("证书通配符名称不合法")
		}
		return "*." + suffix, nil
	}
	if strings.Contains(name, "*") {
		return "", fmt.Errorf("证书 DNS 名称包含不支持的通配符")
	}
	host, err := netpolicy.ParseRequestHost(name)
	if err != nil {
		return "", fmt.Errorf("证书 DNS 名称不合法")
	}
	if host.IsIP() || host.Port() != 0 {
		return "", fmt.Errorf("证书 DNS 名称必须是主机名")
	}
	return host.Host(), nil
}

// CoversDomain 报告证书信息是否覆盖指定的规范化主机名（通配符按单级匹配）。
// 它用于启动时把公开地址与允许 Host 同证书 DNS 名称交叉检查。
func (info CertificateInfo) CoversDomain(host string) bool {
	name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if name == "" {
		return false
	}
	for _, domain := range info.Domains {
		if strings.HasPrefix(domain, "*.") {
			if wildcardMatches(domain[1:], name) {
				return true
			}
			continue
		}
		if domain == name {
			return true
		}
	}
	return false
}
