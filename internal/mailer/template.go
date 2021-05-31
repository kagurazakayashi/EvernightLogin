package mailer

import (
	"fmt"
	"net/url"
	"strings"
	"text/template"
)

// Kind 是邮件模板用途。验证、找回与事件告知必须使用不同模板，避免把验证/重置
// 入口混入普通告知邮件。
type Kind string

const (
	// KindVerification 是邮箱验证（验证码/验证入口）模板。
	KindVerification Kind = "verification"
	// KindPasswordReset 是密码找回模板。
	KindPasswordReset Kind = "password_reset"
	// KindSecurityNotice 是敏感操作事后告知模板。
	KindSecurityNotice Kind = "security_notice"
)

// Valid 报告模板用途是否受支持。
func (k Kind) Valid() bool {
	switch k {
	case KindVerification, KindPasswordReset, KindSecurityNotice:
		return true
	}
	return false
}

// VerificationData 是邮箱验证模板数据。Code 或 VerifyURL 至少有一个非空：
// Code 用于低熵验证码，VerifyURL 用于一次性验证入口链接。两者都只应出现在这封
// 邮件中，不得写入日志或普通存储。
type VerificationData struct {
	DisplayName string
	Code        string
	VerifyURL   string
	ExpiresIn   string
	AppName     string
}

// PasswordResetData 是密码找回模板数据。ResetURL 是单次、限时入口。
type PasswordResetData struct {
	DisplayName string
	ResetURL    string
	ExpiresIn   string
	AppName     string
}

// SecurityNoticeData 是敏感操作告知模板数据。不含密码、秘密或令牌。
type SecurityNoticeData struct {
	DisplayName string
	Event       string
	OccurredAt  string
	ClientInfo  string
	AppName     string
	SupportURL  string
}

// RenderRequest 是一次模板渲染请求；按 Kind 只读取对应数据。
type RenderRequest struct {
	Kind          Kind
	Verification  *VerificationData
	PasswordReset *PasswordResetData
	Notice        *SecurityNoticeData
}

// Content 是渲染后的主题与纯文本正文。
type Content struct {
	Subject  string
	TextBody string
}

// Template 是某用途的主题与正文模板（Go text/template 语法）。
type Template struct {
	Subject string
	Body    string
}

// builtinTemplates 是内置默认模板：验证、找回、事件告知分别独立。
var builtinTemplates = map[Kind]Template{
	KindVerification: {
		Subject: "{{.AppName}} 邮箱验证",
		Body: "你好 {{.DisplayName}}：\n\n" +
			"{{if .VerifyURL}}请打开以下一次性验证入口完成 {{.AppName}} 邮箱验证：\n\n{{.VerifyURL}}\n\n" +
			"验证入口 {{.ExpiresIn}} 内有效，仅可使用一次。请勿转发给他人。\n\n" +
			"{{else}}你的 {{.AppName}} 邮箱验证码是：\n\n{{.Code}}\n\n" +
			"验证码 {{.ExpiresIn}} 内有效，仅可使用一次。不要把验证码告诉任何人。\n\n{{end}}" +
			"如果这不是你的操作，请忽略本邮件并检查账户安全。\n",
	},
	KindPasswordReset: {
		Subject: "{{.AppName}} 密码找回",
		Body: "你好 {{.DisplayName}}：\n\n" +
			"我们收到了 {{.AppName}} 的密码找回请求。请在 {{.ExpiresIn}} 内打开以下一次性链接：\n\n" +
			"{{.ResetURL}}\n\n" +
			"链接仅可使用一次；如非本人操作，请忽略本邮件并尽快修改密码。\n",
	},
	KindSecurityNotice: {
		Subject: "{{.AppName}} 安全提醒：{{.Event}}",
		Body: "你好 {{.DisplayName}}：\n\n" +
			"你的 {{.AppName}} 账户发生了一次安全操作：\n\n" +
			"事件：{{.Event}}\n时间：{{.OccurredAt}}\n来源：{{.ClientInfo}}\n\n" +
			"如果这不是你的操作，请立即修改密码并联系管理员。\n" +
			"支持入口：{{.SupportURL}}\n\n" +
			"本邮件不会包含你的密码、验证码或令牌。\n",
	},
}

// TemplateSet 是已编译并校验的模板集合。
type TemplateSet struct {
	templates map[Kind]compiledTemplate
}

type compiledTemplate struct {
	subject *template.Template
	body    *template.Template
}

// DefaultTemplateSet 返回内置模板集合。
func DefaultTemplateSet() (*TemplateSet, error) {
	return NewTemplateSet(builtinTemplates)
}

// NewTemplateSet 编译并校验一组模板；缺少任一用途或模板为空时返回错误。
func NewTemplateSet(templates map[Kind]Template) (*TemplateSet, error) {
	set := &TemplateSet{templates: make(map[Kind]compiledTemplate, len(templates))}
	for _, kind := range []Kind{KindVerification, KindPasswordReset, KindSecurityNotice} {
		tmpl, ok := templates[kind]
		if !ok {
			return nil, fmt.Errorf("%w: 缺少 %s 模板", ErrTemplateInvalid, kind)
		}
		if strings.TrimSpace(tmpl.Subject) == "" || strings.TrimSpace(tmpl.Body) == "" {
			return nil, fmt.Errorf("%w: %s 模板主题或正文为空", ErrTemplateInvalid, kind)
		}
		subject, err := template.New(string(kind) + ".subject").Option("missingkey=error").Parse(tmpl.Subject)
		if err != nil {
			return nil, fmt.Errorf("%w: %s 主题模板: %v", ErrTemplateInvalid, kind, err)
		}
		body, err := template.New(string(kind) + ".body").Option("missingkey=error").Parse(tmpl.Body)
		if err != nil {
			return nil, fmt.Errorf("%w: %s 正文模板: %v", ErrTemplateInvalid, kind, err)
		}
		set.templates[kind] = compiledTemplate{subject: subject, body: body}
	}
	return set, nil
}

// Render 渲染指定用途的邮件内容，并做头部/正文安全校验。
//
// 数据字段在渲染前校验：可见内联文本不得包含 CR/LF 或其他控制字符（防止头部
// 注入与伪造行），链接只接受 http/https。渲染结果再次通过 SanitizeHeaderValue
// 检查，确保即使模板被替换也不会把换行带进主题。
func (s *TemplateSet) Render(request RenderRequest) (Content, error) {
	if s == nil {
		return Content{}, fmt.Errorf("%w: 模板集合为空", ErrTemplateInvalid)
	}
	if !request.Kind.Valid() {
		return Content{}, fmt.Errorf("%w: 不支持的模板用途 %q", ErrTemplateInvalid, request.Kind)
	}
	compiled, ok := s.templates[request.Kind]
	if !ok {
		return Content{}, fmt.Errorf("%w: 缺少 %s 模板", ErrTemplateInvalid, request.Kind)
	}
	data, err := templateData(request)
	if err != nil {
		return Content{}, err
	}
	var subject, body strings.Builder
	if err := compiled.subject.Execute(&subject, data); err != nil {
		return Content{}, fmt.Errorf("%w: 主题渲染失败: %v", ErrTemplateInvalid, err)
	}
	if err := compiled.body.Execute(&body, data); err != nil {
		return Content{}, fmt.Errorf("%w: 正文渲染失败: %v", ErrTemplateInvalid, err)
	}
	subjectText, err := SanitizeHeaderValue("Subject", subject.String())
	if err != nil {
		return Content{}, fmt.Errorf("%w: 渲染后的主题不安全: %v", ErrTemplateInvalid, err)
	}
	if strings.TrimSpace(subjectText) == "" {
		return Content{}, fmt.Errorf("%w: 渲染后的主题为空", ErrTemplateInvalid)
	}
	if len(subjectText) > MaxSubjectRunes {
		return Content{}, fmt.Errorf("%w: 渲染后的主题过长", ErrTemplateInvalid)
	}
	bodyText := body.String()
	if strings.TrimSpace(bodyText) == "" {
		return Content{}, fmt.Errorf("%w: 渲染后的正文为空", ErrTemplateInvalid)
	}
	if len(bodyText) > MaxBodyBytes {
		return Content{}, fmt.Errorf("%w: 渲染后的正文超过 %d 字节", ErrTemplateInvalid, MaxBodyBytes)
	}
	return Content{Subject: subjectText, TextBody: bodyText}, nil
}

// templateData 校验并返回对应用途的模板数据。
func templateData(request RenderRequest) (any, error) {
	switch request.Kind {
	case KindVerification:
		data := request.Verification
		if data == nil {
			return nil, fmt.Errorf("%w: 缺少验证模板数据", ErrTemplateInvalid)
		}
		if err := checkInline("DisplayName", data.DisplayName, 100); err != nil {
			return nil, err
		}
		if err := checkInline("Code", data.Code, 64); err != nil {
			return nil, err
		}
		switch {
		case strings.TrimSpace(data.VerifyURL) != "":
			if err := checkURL("VerifyURL", data.VerifyURL); err != nil {
				return nil, err
			}
		case strings.TrimSpace(data.Code) == "":
			return nil, fmt.Errorf("%w: 验证码与验证入口不能同时为空", ErrTemplateInvalid)
		}
		if err := checkInline("ExpiresIn", data.ExpiresIn, 64); err != nil {
			return nil, err
		}
		if err := checkInline("AppName", data.AppName, 100); err != nil {
			return nil, err
		}
		return data, nil
	case KindPasswordReset:
		data := request.PasswordReset
		if data == nil {
			return nil, fmt.Errorf("%w: 缺少找回模板数据", ErrTemplateInvalid)
		}
		if err := checkInline("DisplayName", data.DisplayName, 100); err != nil {
			return nil, err
		}
		if err := checkURL("ResetURL", data.ResetURL); err != nil {
			return nil, err
		}
		if err := checkInline("ExpiresIn", data.ExpiresIn, 64); err != nil {
			return nil, err
		}
		if err := checkInline("AppName", data.AppName, 100); err != nil {
			return nil, err
		}
		return data, nil
	case KindSecurityNotice:
		data := request.Notice
		if data == nil {
			return nil, fmt.Errorf("%w: 缺少告知模板数据", ErrTemplateInvalid)
		}
		fields := []struct {
			name  string
			value string
			max   int
		}{
			{"DisplayName", data.DisplayName, 100},
			{"Event", data.Event, 100},
			{"OccurredAt", data.OccurredAt, 64},
			{"ClientInfo", data.ClientInfo, 200},
			{"AppName", data.AppName, 100},
		}
		for _, field := range fields {
			if err := checkInline(field.name, field.value, field.max); err != nil {
				return nil, err
			}
		}
		if strings.TrimSpace(data.Event) == "" {
			return nil, fmt.Errorf("%w: 事件名称为空", ErrTemplateInvalid)
		}
		if err := checkURL("SupportURL", data.SupportURL); err != nil {
			return nil, err
		}
		return data, nil
	default:
		return nil, fmt.Errorf("%w: 不支持的模板用途 %q", ErrTemplateInvalid, request.Kind)
	}
}

// checkInline 校验内联文本字段：不含 CR/LF 与控制字符，且不超过长度上限。
func checkInline(name, value string, max int) error {
	if len(value) > max {
		return fmt.Errorf("%w: 字段 %s 超过 %d 字节", ErrTemplateInvalid, name, max)
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%w: 字段 %s 包含控制字符", ErrTemplateInvalid, name)
		}
	}
	return nil
}

// checkURL 校验媒体入口链接：仅 http/https、无控制字符、无凭证信息。http 仅便于
// 本地测试；生产部署应只生成 https 链接（本函数不代替部署侧的强制策略）。
func checkURL(name, raw string) error {
	if strings.TrimSpace(raw) == "" {
		return fmt.Errorf("%w: 字段 %s 不能为空", ErrTemplateInvalid, name)
	}
	if len(raw) > 2048 {
		return fmt.Errorf("%w: 字段 %s 超过 2048 字节", ErrTemplateInvalid, name)
	}
	for _, r := range raw {
		if r <= 0x20 || r == 0x7f || r == 0x00 {
			return fmt.Errorf("%w: 字段 %s 包含空白或控制字符", ErrTemplateInvalid, name)
		}
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%w: 字段 %s 不是合法 URL: %v", ErrTemplateInvalid, name, err)
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return fmt.Errorf("%w: 字段 %s 只允许 http/https", ErrTemplateInvalid, name)
	}
	if parsed.Host == "" {
		return fmt.Errorf("%w: 字段 %s 缺少主机名", ErrTemplateInvalid, name)
	}
	if parsed.User != nil {
		return fmt.Errorf("%w: 字段 %s 不得包含用户名/口令", ErrTemplateInvalid, name)
	}
	return nil
}
