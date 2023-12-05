// Copyright (c) KagurazakaYashi(KagurazakaMiyabi)
// EvernightLogin is licensed under Mulan PSL v2.

// Package settings 实现步骤 232 的受控 YAML 配置核心：字段白名单/权限分级、秘密遮盖、
// 文件摘要版本冲突、原子写入、写后严格加载、审计失败回滚、磁盘值 vs 当前有效值 vs
// 待宿主重载/待重启。HTTP/Go/CLI 共用本实现，公开门面只做身份与错误码映射。
//
// 安全边界：
//   - 不创建“内存覆盖一切”的配置后门；没有可写 YAML 路径时不可写；
//   - 秘密字段不可通过本服务写入；读取只输出固定脱敏标记，不泄露 env/file 来源；
//   - root/受信字段由调用方通过 allowRoot 控制；本包不猜测身份；
//   - 审计写入失败时恢复旧文件（fail-closed），不留未审计变更；
//   - 本服务不热重载运行时：热更新字段也报告“需宿主重新加载”，不虚报已生效。
package settings

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/config"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"go.yaml.in/yaml/v3"
)

// AuditRecorder 是关键变更审计写入契约；nil 时写操作 fail-closed。
type AuditRecorder interface {
	Record(ctx context.Context, event audit.Event) error
}

// Options 是核心服务构造参数。
type Options struct {
	// ConfigPath 是可写 YAML 配置文件绝对/相对路径；为空表示内联配置不可写。
	ConfigPath string
	// Effective 返回当前进程有效配置；必填。
	Effective func() config.Config
	// Audit 写设置变更审计；nil 时写操作拒绝。
	Audit AuditRecorder
	// Now 可注入时钟；nil 使用 time.Now。
	Now func() time.Time
}

// Service 是线程安全的配置核心服务；不启动协程、不打开数据库。
type Service struct {
	opts    Options
	mu      sync.Mutex
	writeMu sync.Mutex
	last    Status
}

// New 校验依赖并构造服务。
func New(options Options) (*Service, error) {
	if options.Effective == nil {
		return nil, fmt.Errorf("%w: 缺少有效配置提供者", ErrOptionsInvalid)
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	return &Service{opts: options}, nil
}

// 稳定错误码；与根包错误码注册表复用同一字面值。
const (
	CodeReqInvalid       = "REQ_INVALID"
	CodeAccessDenied     = "ACCESS_DENIED"
	CodeConfigInvalid    = "CONFIG_INVALID"
	CodeConflict         = "CONFLICT"
	CodeAuditWriteFailed = "AUDIT_WRITE_FAILED"
	CodeInternalError    = "INTERNAL_ERROR"
)

// 领域错误哨兵。
var (
	ErrOptionsInvalid = errors.New("配置管理服务选项无效")
)

// Error 是核心稳定错误（公开门面按 Code 映射为 AppError；不含秘密值）。
type Error struct {
	Code    string
	Message string
	Field   string
	Line    int
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	if e.Field != "" {
		return e.Code + ": " + e.Message + "（字段 " + e.Field + "）"
	}
	return e.Code + ": " + e.Message
}

// CodeOf 返回核心错误码；nil 返回空。
func CodeOf(err error) string {
	var coreErr *Error
	if errors.As(err, &coreErr) {
		return coreErr.Code
	}
	if err == nil {
		return ""
	}
	return CodeInternalError
}

// Field 是单个配置字段视图。
type Field struct {
	Field          string
	Value          string
	DiskValue      string
	Class          string
	Secret         bool
	RootOnly       bool
	Writable       bool
	PendingRestart bool
}

// View 是字段整体视图。
type View struct {
	Configured       bool
	Version          string
	EffectiveVersion string
	Fields           []Field
	HotReloadable    []string
	RestartRequired  []string
	Note             string
}

// Validation 是校验结果。
type Validation struct {
	Valid           bool
	Errors          []ValidationError
	ChangedFields   []string
	RootOnlyFields  []string
	Writable        bool
	RestartRequired []string
}

// ValidationError 是单字段错误。
type ValidationError struct {
	Field  string
	Code   string
	Detail string
}

// UpdateInput 是一次配置写入请求。
type UpdateInput struct {
	ExpectedVersion string
	Changes         map[string]string
	Reason          string
	Actor           audit.Actor
	RequestID       string
	// AllowRoot 表示调用者已通过 root/受信判定，可修改 root-only 配置字段。
	AllowRoot bool
}

// UpdateResult 是写入结果。
type UpdateResult struct {
	Version          string
	PreviousVersion  string
	ChangedFields    []string
	HotFields        []string
	RestartFields    []string
	AppliedNow       bool
	HostReloadNeeded bool
	Note             string
}

// Status 是配置状态。
type Status struct {
	Configured       bool
	Version          string
	EffectiveVersion string
	Writable         bool
	PendingHot       []string
	PendingRestart   []string
	HostReloadNeeded bool
	LastErrorCode    string
	LastErrorAt      time.Time
	LastWriteVersion string
}

// fieldAccess 是字段访问级别。
type fieldAccess int

const (
	accessUser fieldAccess = iota
	accessRoot
)

// FieldPolicy 返回字段访问级别。安全策略类字段一律 root/受信；普通 settings.manage
// 只保留纯展示/日志/关闭超时等非安全运行设置。未知字段默认 root（fail-closed），
// 与下方字段表和新字段演进策略一致：新增安全相关字段不需要先改授权表才能安全。
func FieldPolicy(field string) fieldAccess {
	switch field {
	case "logging.level", "logging.format", "server.shutdown_timeout_seconds":
		return accessUser
	}
	switch {
	case strings.HasPrefix(field, "server."):
		// 监听地址/公开 URL/路径前缀/Host/可信代理/TLS/关闭超时以外，server 节
		// 都属于安全边界；关闭超时已在上方显式放行。
		return accessRoot
	case strings.HasPrefix(field, "secrets."),
		strings.HasPrefix(field, "database."),
		strings.HasPrefix(field, "registration."),
		strings.HasPrefix(field, "passkey."),
		strings.HasPrefix(field, "app_qr_login."),
		strings.HasPrefix(field, "protocol."),
		strings.HasPrefix(field, "mail."):
		return accessRoot
	default:
		return accessRoot
	}
}

// RootOnly 报告字段是否仅 root/受信可写。
func RootOnly(field string) bool { return FieldPolicy(field) == accessRoot }

// fieldKind 是字段可写值类型。
type fieldKind int

const (
	kindString fieldKind = iota
	kindBool
	kindInt
	kindList
	kindObjectList
	kindSecret
)

var fieldKinds = map[string]fieldKind{
	"server.listen_addr": kindString, "server.extra_listen_addrs": kindList,
	"server.public_base_url": kindString, "server.path_prefix": kindString,
	"server.allowed_hosts": kindList, "server.trusted_proxies": kindList,
	"server.tls_terminating_proxy": kindBool, "server.tls_cert_files": kindList,
	"server.tls_key_files": kindList, "server.tls_ca_file": kindString,
	"server.tls_pfx_file": kindString, "server.tls_expiry_warning_days": kindInt,
	"server.tls_client_auth": kindString, "server.tls_client_ca_files": kindList,
	"server.tls_client_identities":    kindObjectList,
	"server.shutdown_timeout_seconds": kindInt,
	"logging.level":                   kindString, "logging.format": kindString,
	"database.driver": kindString, "database.path": kindString,
	"database.wal": kindBool, "database.busy_timeout_ms": kindInt,
	"registration.enabled": kindBool, "registration.require_review": kindBool,
	"registration.require_email_verification": kindBool,
	"registration.default_role_ids":           kindList,
	"passkey.enabled":                         kindBool, "passkey.rp_id": kindString,
	"passkey.rp_display_name": kindString, "passkey.allowed_origins": kindList,
	"passkey.user_verification": kindString,
	"app_qr_login.enabled":      kindBool, "app_qr_login.allowed_client_ids": kindList,
	"app_qr_login.request_ttl_seconds":    kindInt,
	"app_qr_login.claim_interval_seconds": kindInt,
	"protocol.device_code_enabled":        kindBool,
	"secrets.master_key":                  kindSecret, "secrets.tls_pfx_password": kindSecret,
	"mail.enabled": kindBool, "mail.smtp.addr": kindString,
	"mail.smtp.host": kindString, "mail.smtp.tls_mode": kindString,
	"mail.smtp.trusted_roots": kindList, "mail.smtp.username": kindString,
	"mail.smtp.password": kindSecret, "mail.smtp.timeout_seconds": kindInt,
	"mail.smtp.allow_plaintext_local": kindBool,
	"mail.from.address":               kindString, "mail.from.name": kindString,
	"mail.app_name": kindString, "mail.delivery.max_attempts": kindInt,
	"mail.delivery.timeout_seconds": kindInt,
}

// configPath 返回可写绝对路径；内联配置不可写。
func (s *Service) configPath() (string, error) {
	raw := strings.TrimSpace(s.opts.ConfigPath)
	if raw == "" {
		return "", &Error{Code: CodeConfigInvalid,
			Message: "当前运行时使用内联配置，未配置可写的 YAML 文件"}
	}
	absolute, err := filepath.Abs(raw)
	if err != nil {
		return "", &Error{Code: CodeConfigInvalid, Message: "配置文件路径无效"}
	}
	info, err := os.Lstat(absolute)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return "", &Error{Code: CodeConfigInvalid, Message: "配置文件不存在或不是普通文件"}
	}
	return absolute, nil
}

// readVersion 读取文件字节与 SHA-256 版本。
func readVersion(path string) ([]byte, string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(data)
	return data, hex.EncodeToString(sum[:]), nil
}

// effectiveFingerprint 生成有效配置稳定摘要（秘密只参与固定脱敏标记）。
func effectiveFingerprint(cfg config.Config) string {
	values := cfg.FieldValues()
	parts := make([]string, 0, len(values))
	for _, item := range values {
		value := item.Value
		if item.Secret {
			value = "[SECRET]"
		}
		parts = append(parts, item.Field+"="+value)
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\n")))
	return hex.EncodeToString(sum[:])
}

// pendingFields 比较当前有效与磁盘配置的待重载/待重启字段。
func pendingFields(effective, disk config.Config) (hot, restart []string) {
	diff := config.DiffReload(effective, disk)
	return append([]string(nil), diff.HotFields...), append([]string(nil), diff.RestartFields...)
}

func secretDisplay(value string) string {
	if value == "" || value == "[UNSET]" {
		return "[UNSET]"
	}
	return "[REDACTED]"
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

// Fields 返回字段视图；allowRoot 表示调用者已通过 root/受信判定。
func (s *Service) Fields(ctx context.Context, allowRoot bool) (View, error) {
	if err := ctx.Err(); err != nil {
		return View{}, err
	}
	path, err := s.configPath()
	if err != nil {
		return View{}, err
	}
	raw, diskVersion, err := readVersion(path)
	if err != nil {
		return View{}, &Error{Code: CodeConfigInvalid, Message: "读取配置版本失败"}
	}
	diskConfig, err := config.Load(config.LoadOptions{YAML: raw})
	if err != nil {
		return View{}, configError("读取磁盘配置失败", err)
	}
	hot, restart := pendingFields(s.opts.Effective(), diskConfig)
	diskValues := make(map[string]string)
	for _, item := range diskConfig.FieldValues() {
		value := item.Value
		if item.Secret {
			value = secretDisplay(value)
		}
		diskValues[item.Field] = value
	}
	view := View{Configured: true, Version: diskVersion,
		EffectiveVersion: effectiveFingerprint(s.opts.Effective()),
		HotReloadable:    hot, RestartRequired: restart,
		Note: "热更新字段需要宿主重新加载配置；重启字段需要重启进程；本运行时不会自动热重载。"}
	values := s.opts.Effective().FieldValues()
	view.Fields = make([]Field, 0, len(values))
	for _, item := range values {
		rootOnly := RootOnly(item.Field)
		writable := !item.Secret && fieldKinds[item.Field] != kindObjectList &&
			(!rootOnly || allowRoot)
		value := item.Value
		if item.Secret {
			value = secretDisplay(value)
		}
		view.Fields = append(view.Fields, Field{Field: item.Field, Value: value,
			DiskValue: diskValues[item.Field], Class: string(item.Class),
			Secret: item.Secret, RootOnly: rootOnly, Writable: writable,
			PendingRestart: contains(restart, item.Field) || contains(hot, item.Field)})
	}
	return view, nil
}

func configError(message string, err error) error {
	var configErrors config.ConfigErrors
	if errors.As(err, &configErrors) && len(configErrors) > 0 {
		first := configErrors[0]
		return &Error{Code: CodeConfigInvalid, Message: message,
			Field: first.Field, Line: first.Line}
	}
	return &Error{Code: CodeConfigInvalid, Message: message}
}

// validateChanges 校验字段/权限/类型与整体加载，返回规范化 YAML 与字段。
func (s *Service) validateChanges(path string, changes map[string]string,
	allowRoot bool) ([]byte, []string, error) {
	if len(changes) == 0 {
		return nil, nil, &Error{Code: CodeReqInvalid, Message: "没有要修改的配置字段"}
	}
	keys := make([]string, 0, len(changes))
	for field := range changes {
		keys = append(keys, field)
	}
	sort.Strings(keys)
	for _, field := range keys {
		if _, ok := config.LookupField(field); !ok {
			return nil, nil, &Error{Code: CodeReqInvalid, Message: "未知配置字段",
				Field: field}
		}
	}
	document, err := loadYAMLDocument(path)
	if err != nil {
		return nil, nil, &Error{Code: CodeConfigInvalid, Message: "配置文件结构无法解析"}
	}
	for _, field := range keys {
		kind := fieldKinds[field]
		switch kind {
		case kindSecret:
			return nil, nil, &Error{Code: CodeConfigInvalid,
				Message: "秘密字段只能通过受控本地入口修改", Field: field}
		case kindObjectList:
			return nil, nil, &Error{Code: CodeConfigInvalid,
				Message: "对象列表字段需要手工编辑配置文件", Field: field}
		}
		if RootOnly(field) && !allowRoot {
			return nil, nil, &Error{Code: CodeAccessDenied,
				Message: "该字段属于受信/root 设置，普通设置权限不能修改", Field: field}
		}
		node, problem := valueNode(kind, changes[field])
		if problem != "" {
			return nil, nil, &Error{Code: CodeReqInvalid, Message: problem, Field: field}
		}
		if err := setYAMLField(document, field, node); err != nil {
			return nil, nil, &Error{Code: CodeConfigInvalid,
				Message: "配置文件字段写入失败", Field: field}
		}
	}
	encoded, err := marshalYAML(document)
	if err != nil {
		return nil, nil, &Error{Code: CodeConfigInvalid, Message: "配置文件序列化失败"}
	}
	if _, err := config.Load(config.LoadOptions{YAML: encoded}); err != nil {
		return nil, nil, configError("配置校验失败", err)
	}
	return encoded, keys, nil
}

// Validate 只校验不写入。
func (s *Service) Validate(ctx context.Context, changes map[string]string,
	allowRoot bool) (Validation, error) {
	if err := ctx.Err(); err != nil {
		return Validation{}, err
	}
	path, err := s.configPath()
	if err != nil {
		return Validation{}, err
	}
	_, fields, err := s.validateChanges(path, changes, allowRoot)
	if err != nil {
		code := CodeOf(err)
		if code == CodeConfigInvalid || code == CodeReqInvalid {
			return Validation{Valid: false, Errors: []ValidationError{{Code: code,
				Detail: err.Error()}}}, nil
		}
		return Validation{}, err
	}
	result := Validation{Valid: true, ChangedFields: fields, Writable: true}
	for _, field := range fields {
		info, _ := config.LookupField(field)
		if info.Class == config.ReloadRestartRequired {
			result.RestartRequired = append(result.RestartRequired, field)
		}
	}
	return result, nil
}

// Update 原子写入配置；失败保留旧文件。
func (s *Service) Update(ctx context.Context, input UpdateInput) (UpdateResult, error) {
	if err := ctx.Err(); err != nil {
		return UpdateResult{}, err
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	path, err := s.configPath()
	if err != nil {
		return UpdateResult{}, err
	}
	oldData, oldVersion, err := readVersion(path)
	if err != nil {
		return UpdateResult{}, &Error{Code: CodeConfigInvalid, Message: "读取配置版本失败"}
	}
	expected := strings.TrimSpace(input.ExpectedVersion)
	if expected == "" || expected != oldVersion {
		return UpdateResult{}, &Error{Code: CodeConflict,
			Message: "配置已被其他操作修改，请重新读取"}
	}
	encoded, fields, err := s.validateChanges(path, input.Changes, input.AllowRoot)
	if err != nil {
		return UpdateResult{}, err
	}
	if err := writeFileAtomic(path, encoded); err != nil {
		return UpdateResult{}, &Error{Code: CodeConfigInvalid,
			Message: "配置写入失败，已保留原配置"}
	}
	_, newVersion, err := readVersion(path)
	if err != nil {
		_ = writeFileAtomic(path, oldData)
		return UpdateResult{}, &Error{Code: CodeConfigInvalid,
			Message: "配置写入后校验失败，已回滚"}
	}
	if _, err := config.Load(config.LoadOptions{YAML: encoded}); err != nil {
		_ = writeFileAtomic(path, oldData)
		return UpdateResult{}, configError("配置写入后校验失败，已回滚", err)
	}
	if err := s.recordAudit(ctx, input, fields); err != nil {
		_ = writeFileAtomic(path, oldData)
		return UpdateResult{}, &Error{Code: CodeAuditWriteFailed,
			Message: "设置审计不可用，已回滚配置"}
	}
	hot := make([]string, 0, len(fields))
	restart := make([]string, 0, len(fields))
	for _, field := range fields {
		info, _ := config.LookupField(field)
		if info.Class == config.ReloadHotReloadable {
			hot = append(hot, field)
		} else {
			restart = append(restart, field)
		}
	}
	s.mu.Lock()
	s.last.LastErrorCode = ""
	s.last.LastWriteVersion = newVersion
	s.mu.Unlock()
	if _, verifyVersion, err := readVersion(path); err != nil || verifyVersion != newVersion {
		_ = writeFileAtomic(path, oldData)
		return UpdateResult{}, &Error{Code: CodeConflict,
			Message: "配置在写入后被并发修改"}
	}
	return UpdateResult{Version: newVersion, PreviousVersion: oldVersion,
		ChangedFields: fields, HotFields: hot, RestartFields: restart,
		AppliedNow: false, HostReloadNeeded: true,
		Note: "配置已原子写入磁盘；热更新字段需宿主重新加载，重启字段需重启进程后才生效。"}, nil
}

func (s *Service) recordAudit(ctx context.Context, input UpdateInput, fields []string) error {
	if s.opts.Audit == nil {
		return &Error{Code: CodeAuditWriteFailed, Message: "审计服务未装配"}
	}
	changes := make([]audit.FieldChange, 0, len(fields))
	for _, field := range fields {
		changes = append(changes, audit.FieldChange{Field: "config." + field})
	}
	return s.opts.Audit.Record(ctx, audit.Event{Actor: input.Actor,
		Action: "settings.config.update", Target: audit.Target{Type: "config", ID: "yaml"},
		Outcome: audit.OutcomeSuccess, RequestID: input.RequestID, Changes: changes})
}

// Status 返回磁盘/有效版本、待重载字段与最近错误。
func (s *Service) Status(ctx context.Context) (Status, error) {
	if err := ctx.Err(); err != nil {
		return Status{}, err
	}
	s.mu.Lock()
	status := Status{LastErrorCode: s.last.LastErrorCode,
		LastErrorAt: s.last.LastErrorAt, LastWriteVersion: s.last.LastWriteVersion}
	s.mu.Unlock()
	path, err := s.configPath()
	if err != nil {
		return status, nil
	}
	if _, version, err := readVersion(path); err == nil {
		status.Configured = true
		status.Version = version
		status.Writable = true
	} else {
		return status, nil
	}
	status.EffectiveVersion = effectiveFingerprint(s.opts.Effective())
	raw, _, _ := readVersion(path)
	diskConfig, err := config.Load(config.LoadOptions{YAML: raw})
	if err != nil {
		s.markError(CodeConfigInvalid)
		return status, nil
	}
	hot, restart := pendingFields(s.opts.Effective(), diskConfig)
	status.PendingHot = hot
	status.PendingRestart = restart
	status.HostReloadNeeded = len(hot) > 0 || len(restart) > 0
	return status, nil
}

func (s *Service) markError(code string) {
	s.mu.Lock()
	s.last.LastErrorCode = code
	s.last.LastErrorAt = s.opts.Now()
	s.mu.Unlock()
}

// ---------- YAML 原子写入辅助 ----------

func loadYAMLDocument(path string) (*yaml.Node, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var document yaml.Node
	if err := yaml.Unmarshal(data, &document); err != nil {
		return nil, err
	}
	if document.Kind == 0 {
		document = yaml.Node{Kind: yaml.DocumentNode,
			Content: []*yaml.Node{{Kind: yaml.MappingNode}}}
	}
	if document.Kind != yaml.DocumentNode || len(document.Content) == 0 {
		return nil, errors.New("配置文档根必须是映射")
	}
	return &document, nil
}

func setYAMLField(document *yaml.Node, field string, value *yaml.Node) error {
	parts := strings.Split(field, ".")
	mapping := document.Content[0]
	if mapping.Kind != yaml.MappingNode {
		return errors.New("配置文档根必须是映射")
	}
	for _, part := range parts[:len(parts)-1] {
		child := mappingChild(mapping, part)
		if child == nil {
			child = &yaml.Node{Kind: yaml.MappingNode}
			appendMapping(mapping, part, child)
		}
		if child.Kind != yaml.MappingNode {
			return fmt.Errorf("配置节 %q 不是映射", part)
		}
		mapping = child
	}
	key := parts[len(parts)-1]
	for index := 0; index+1 < len(mapping.Content); index += 2 {
		if mapping.Content[index].Value == key {
			mapping.Content[index+1] = value
			return nil
		}
	}
	appendMapping(mapping, key, value)
	return nil
}

func appendMapping(mapping *yaml.Node, key string, value *yaml.Node) {
	mapping.Content = append(mapping.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, value)
}

func mappingChild(mapping *yaml.Node, key string) *yaml.Node {
	for index := 0; index+1 < len(mapping.Content); index += 2 {
		if mapping.Content[index].Value == key {
			return mapping.Content[index+1]
		}
	}
	return nil
}

func valueNode(kind fieldKind, raw string) (*yaml.Node, string) {
	value := strings.TrimSpace(raw)
	switch kind {
	case kindString:
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value}, ""
	case kindBool:
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			return nil, "布尔字段值无效（只接受 true/false）"
		}
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool",
			Value: strconv.FormatBool(parsed)}, ""
	case kindInt:
		parsed, err := strconv.Atoi(value)
		if err != nil {
			return nil, "整数字段值无效"
		}
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int",
			Value: strconv.Itoa(parsed)}, ""
	case kindList:
		items, problem := parseList(value)
		if problem != "" {
			return nil, problem
		}
		sequence := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		for _, item := range items {
			sequence.Content = append(sequence.Content,
				&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: item})
		}
		return sequence, ""
	default:
		return nil, "该字段类型不支持通过公开设置接口修改"
	}
}

func parseList(raw string) ([]string, string) {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "[]" {
		return nil, ""
	}
	if strings.HasPrefix(raw, "[") {
		var values []string
		if err := json.Unmarshal([]byte(raw), &values); err != nil {
			return nil, "列表字段值必须是 JSON 字符串数组"
		}
		return values, ""
	}
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r'
	})
	values := make([]string, 0, len(fields))
	for _, item := range fields {
		item = strings.TrimSpace(item)
		if item != "" {
			values = append(values, item)
		}
	}
	return values, ""
}

func marshalYAML(document *yaml.Node) ([]byte, error) { return yaml.Marshal(document) }

func writeFileAtomic(path string, data []byte) error {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".login-config-*.tmp")
	if err != nil {
		return err
	}
	name := temporary.Name()
	cleanup := func() {
		_ = temporary.Close()
		_ = os.Remove(name)
	}
	if err := temporary.Chmod(0o600); err != nil {
		cleanup()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		cleanup()
		return err
	}
	if err := temporary.Sync(); err != nil {
		cleanup()
		return err
	}
	if err := temporary.Close(); err != nil {
		_ = os.Remove(name)
		return err
	}
	if err := os.Rename(name, path); err != nil {
		_ = os.Remove(name)
		return err
	}
	return nil
}
