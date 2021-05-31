package login

import (
	"slices"
	"strconv"
	"strings"
)

// Diagnostic 返回已经脱敏的有效配置文本，用于启动日志、CLI 诊断或人工排查。
//
// 输出按 Fields 的稳定顺序逐行列出字段路径、有效值和重载分类。秘密字段只
// 显示 [REDACTED]（已设置）或 [UNSET]（未设置），任何时候都不包含秘密内容。
// 与秘密来源相关的环境变量名或文件路径也不出现在诊断里。
func (c Config) Diagnostic() string {
	var b strings.Builder
	for _, field := range configFields {
		b.WriteString(field.Field)
		b.WriteString(" = ")
		b.WriteString(c.fieldValueString(field.Field))
		b.WriteString(" (")
		b.WriteString(string(field.Class))
		b.WriteString(")\n")
	}
	return b.String()
}

// fieldValueString 返回单个字段的可打印值；秘密字段由 Secret.String 脱敏。
func (c Config) fieldValueString(field string) string {
	switch field {
	case "server.listen_addr":
		return strconv.Quote(c.Server.ListenAddr)
	case "server.extra_listen_addrs":
		return formatStringList(c.Server.ExtraListenAddrs)
	case "server.public_base_url":
		return strconv.Quote(c.Server.PublicBaseURL)
	case "server.path_prefix":
		return strconv.Quote(c.Server.PathPrefix)
	case "server.allowed_hosts":
		return formatStringList(c.Server.AllowedHosts)
	case "server.trusted_proxies":
		return formatStringList(c.Server.TrustedProxies)
	case "server.tls_terminating_proxy":
		return strconv.FormatBool(c.Server.TLSProxyMode)
	case "server.tls_cert_files":
		return formatStringList(c.Server.TLSCertFiles)
	case "server.tls_key_files":
		return formatStringList(c.Server.TLSKeyFiles)
	case "server.tls_ca_file":
		return strconv.Quote(c.Server.TLSCAFile)
	case "server.tls_pfx_file":
		return strconv.Quote(c.Server.TLSPFXFile)
	case "server.tls_expiry_warning_days":
		return strconv.Itoa(c.Server.TLSExpiryWarningDays)
	case "server.tls_client_auth":
		return strconv.Quote(string(normalizeTLSClientAuthMode(c.Server.TLSClientAuthMode)))
	case "server.tls_client_ca_files":
		return formatStringList(c.Server.TLSClientCAFiles)
	case "server.tls_client_identities":
		return formatTLSClientIdentities(c.Server.TLSClientIdentities)
	case "server.shutdown_timeout_seconds":
		return strconv.Itoa(c.Server.ShutdownTimeoutSeconds)
	case "logging.level":
		return strconv.Quote(string(c.Logging.Level))
	case "logging.format":
		return strconv.Quote(string(c.Logging.Format))
	case "database.driver":
		return strconv.Quote(string(c.Database.Driver))
	case "database.path":
		return strconv.Quote(c.Database.Path)
	case "database.wal":
		return strconv.FormatBool(c.Database.WAL)
	case "database.busy_timeout_ms":
		return strconv.Itoa(c.Database.BusyTimeoutMS)
	case "registration.enabled":
		return strconv.FormatBool(c.Registration.Enabled)
	case "registration.require_review":
		return strconv.FormatBool(c.Registration.RequireReview)
	case "registration.require_email_verification":
		return strconv.FormatBool(c.Registration.RequireEmailVerification)
	case "registration.default_role_ids":
		return formatStringList(c.Registration.DefaultRoleIDs)
	case "secrets.master_key":
		return c.Secrets.MasterKey.String()
	case "secrets.tls_pfx_password":
		return c.Secrets.TLSPFXPassword.String()
	default:
		return "[UNKNOWN]"
	}
}

// formatStringList 把字符串列表格式化为诊断文本；空列表显示 []。
func formatStringList(values []string) string {
	var b strings.Builder
	b.WriteString("[")
	for index, value := range values {
		if index > 0 {
			b.WriteString(", ")
		}
		b.WriteString(strconv.Quote(value))
	}
	b.WriteString("]")
	return b.String()
}

// formatTLSClientIdentities 把客户端证书身份映射格式化为诊断文本。只输出公开的
// DNS 名称与服务身份，不含任何证书或私钥内容。
func formatTLSClientIdentities(values []TLSClientIdentity) string {
	var b strings.Builder
	b.WriteString("[")
	for index, identity := range values {
		if index > 0 {
			b.WriteString(", ")
		}
		b.WriteString("{")
		b.WriteString(strconv.Quote(identity.DNSName))
		b.WriteString(" -> ")
		b.WriteString(strconv.Quote(identity.Service))
		b.WriteString("}")
	}
	b.WriteString("]")
	return b.String()
}

// ReloadDiff 描述两份有效配置之间的差异，并按重载分类拆开。
type ReloadDiff struct {
	// HotFields 是可在不重启进程的情况下生效的变更字段。
	HotFields []string
	// RestartFields 是必须重启进程才能生效的变更字段。
	RestartFields []string
}

// Empty 报告两份配置没有差异。
func (d ReloadDiff) Empty() bool {
	return len(d.HotFields) == 0 && len(d.RestartFields) == 0
}

// Fields 返回全部变更字段，顺序与 Fields 元数据一致。
func (d ReloadDiff) Fields() []string {
	fields := make([]string, 0, len(d.RestartFields)+len(d.HotFields))
	fields = append(fields, d.RestartFields...)
	fields = append(fields, d.HotFields...)
	return fields
}

// DiffReload 比较两份有效配置，区分可热更新项与必须重启项。本步只提供判断
// 依据，不实现配置后台或自动重载。
func DiffReload(previous, next Config) ReloadDiff {
	var diff ReloadDiff
	record := func(field string, changed bool) {
		if !changed {
			return
		}
		info, ok := LookupField(field)
		if !ok {
			return
		}
		if info.Class == ReloadHotReloadable {
			diff.HotFields = append(diff.HotFields, field)
			return
		}
		diff.RestartFields = append(diff.RestartFields, field)
	}

	record("server.listen_addr", previous.Server.ListenAddr != next.Server.ListenAddr)
	record("server.extra_listen_addrs", !slices.Equal(previous.Server.ExtraListenAddrs, next.Server.ExtraListenAddrs))
	record("server.public_base_url", previous.Server.PublicBaseURL != next.Server.PublicBaseURL)
	record("server.path_prefix", previous.Server.PathPrefix != next.Server.PathPrefix)
	record("server.allowed_hosts", !slices.Equal(previous.Server.AllowedHosts, next.Server.AllowedHosts))
	record("server.trusted_proxies", !slices.Equal(previous.Server.TrustedProxies, next.Server.TrustedProxies))
	record("server.tls_terminating_proxy", previous.Server.TLSProxyMode != next.Server.TLSProxyMode)
	record("server.tls_cert_files", !slices.Equal(previous.Server.TLSCertFiles, next.Server.TLSCertFiles))
	record("server.tls_key_files", !slices.Equal(previous.Server.TLSKeyFiles, next.Server.TLSKeyFiles))
	record("server.tls_ca_file", previous.Server.TLSCAFile != next.Server.TLSCAFile)
	record("server.tls_pfx_file", previous.Server.TLSPFXFile != next.Server.TLSPFXFile)
	record("server.tls_expiry_warning_days",
		previous.Server.TLSExpiryWarningDays != next.Server.TLSExpiryWarningDays)
	record("server.tls_client_auth",
		normalizeTLSClientAuthMode(previous.Server.TLSClientAuthMode) !=
			normalizeTLSClientAuthMode(next.Server.TLSClientAuthMode))
	record("server.tls_client_ca_files", !slices.Equal(previous.Server.TLSClientCAFiles, next.Server.TLSClientCAFiles))
	record("server.tls_client_identities",
		!slices.Equal(previous.Server.TLSClientIdentities, next.Server.TLSClientIdentities))
	record("server.shutdown_timeout_seconds",
		previous.Server.ShutdownTimeoutSeconds != next.Server.ShutdownTimeoutSeconds)
	record("logging.level", previous.Logging.Level != next.Logging.Level)
	record("logging.format", previous.Logging.Format != next.Logging.Format)
	record("database.driver", previous.Database.Driver != next.Database.Driver)
	record("database.path", previous.Database.Path != next.Database.Path)
	record("database.wal", previous.Database.WAL != next.Database.WAL)
	record("database.busy_timeout_ms", previous.Database.BusyTimeoutMS != next.Database.BusyTimeoutMS)
	record("secrets.master_key", !secretsEqual(previous.Secrets.MasterKey, next.Secrets.MasterKey))
	record("secrets.tls_pfx_password",
		!secretsEqual(previous.Secrets.TLSPFXPassword, next.Secrets.TLSPFXPassword))

	return diff
}
