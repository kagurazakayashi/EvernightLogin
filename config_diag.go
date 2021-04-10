package login

import (
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
	case "server.public_base_url":
		return strconv.Quote(c.Server.PublicBaseURL)
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
	case "secrets.master_key":
		return c.Secrets.MasterKey.String()
	default:
		return "[UNKNOWN]"
	}
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
	record("server.public_base_url", previous.Server.PublicBaseURL != next.Server.PublicBaseURL)
	record("server.shutdown_timeout_seconds",
		previous.Server.ShutdownTimeoutSeconds != next.Server.ShutdownTimeoutSeconds)
	record("logging.level", previous.Logging.Level != next.Logging.Level)
	record("logging.format", previous.Logging.Format != next.Logging.Format)
	record("database.driver", previous.Database.Driver != next.Database.Driver)
	record("database.path", previous.Database.Path != next.Database.Path)
	record("database.wal", previous.Database.WAL != next.Database.WAL)
	record("database.busy_timeout_ms", previous.Database.BusyTimeoutMS != next.Database.BusyTimeoutMS)
	record("secrets.master_key", !secretsEqual(previous.Secrets.MasterKey, next.Secrets.MasterKey))

	return diff
}
