// Package passkeypolicy 定义 Passkey 依赖方（RP）配置的公共纯策略：用户验证（UV）
// 枚举与 RP ID / 允许来源校验规则。
//
// 本包只做纯字符串/URL 校验，不依赖本模块的 internal 包，供公开的 config 包、宿主
// 与内部 Passkey 服务共同使用（单一实现，避免配置校验与实际服务出现两套口径）。
// 它不访问网络、不读取文件、不建立挑战，也不代表 Passkey 功能已启用。
package passkeypolicy

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/go-webauthn/webauthn/protocol"
)

// ErrOptionsInvalid 是 Passkey RP 配置无效的稳定哨兵；错误文本不含秘密。
var ErrOptionsInvalid = errors.New("Passkey 服务选项无效")

// UserVerification 是登录/注册挑战要求的用户验证（UV）策略。
type UserVerification string

const (
	// UserVerificationRequired 要求认证器完成用户验证（生物识别/PIN）；默认值。
	UserVerificationRequired UserVerification = "required"
	// UserVerificationPreferred 优先 UV 但不强制（较弱，宿主显式选择）。
	UserVerificationPreferred UserVerification = "preferred"
	// UserVerificationDiscouraged 不要求 UV（仅用于极弱场景，通常不应使用）。
	UserVerificationDiscouraged UserVerification = "discouraged"
)

// Valid 报告 UV 策略是否已定义。
func (v UserVerification) Valid() bool {
	switch v {
	case UserVerificationRequired, UserVerificationPreferred, UserVerificationDiscouraged:
		return true
	default:
		return false
	}
}

// ValidateRPConfig 校验 RP ID 与允许来源（公开配置校验与内部 Passkey 服务共用）。
//
// 规则：RP ID 必须是可注册域名字符串（库的 ValidateRPID，拒绝 IP 与协议/路径）；
// 至少一个来源；来源必须是绝对 URL、无凭证/查询/片段、路径为空或 /；scheme
// 必须是 https，或主机恰为 localhost 的 http（浏览器对 localhost 的安全上下文
// 例外）；来源主机必须等于 RP ID 或是其子域，避免同一 RP ID 接受无关站点。
func ValidateRPConfig(rpID string, origins []string) error {
	if strings.TrimSpace(rpID) == "" {
		return fmt.Errorf("%w: RP ID 为空", ErrOptionsInvalid)
	}
	if rpID != strings.TrimSpace(rpID) || strings.ContainsAny(rpID, "/: @?#") {
		return fmt.Errorf("%w: RP ID 必须是裸域名字符串，不能包含协议/端口/路径", ErrOptionsInvalid)
	}
	if err := protocol.ValidateRPID(rpID); err != nil {
		return fmt.Errorf("%w: RP ID 不是合法域名: %v", ErrOptionsInvalid, err)
	}
	if len(origins) == 0 {
		return fmt.Errorf("%w: 至少需要一个允许来源", ErrOptionsInvalid)
	}
	for index, raw := range origins {
		if strings.TrimSpace(raw) == "" || raw != strings.TrimSpace(raw) {
			return fmt.Errorf("%w: 第 %d 个允许来源为空或含空白", ErrOptionsInvalid, index+1)
		}
		parsed, err := url.Parse(raw)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			return fmt.Errorf("%w: 第 %d 个允许来源不是绝对 URL", ErrOptionsInvalid, index+1)
		}
		if parsed.User != nil {
			return fmt.Errorf("%w: 允许来源不能包含用户信息", ErrOptionsInvalid)
		}
		if parsed.RawQuery != "" || parsed.Fragment != "" {
			return fmt.Errorf("%w: 允许来源不能包含查询或片段", ErrOptionsInvalid)
		}
		if parsed.Path != "" && parsed.Path != "/" {
			return fmt.Errorf("%w: 允许来源不能包含路径", ErrOptionsInvalid)
		}
		host := strings.ToLower(parsed.Hostname())
		switch {
		case parsed.Scheme == "https":
		case parsed.Scheme == "http" && host == "localhost":
			// 本地开发例外：浏览器把 localhost 视作安全上下文。
		default:
			return fmt.Errorf("%w: 允许来源必须使用 https（本地开发只允许 http://localhost）", ErrOptionsInvalid)
		}
		if host != rpID && !strings.HasSuffix(host, "."+rpID) {
			return fmt.Errorf("%w: 允许来源主机必须是 RP ID 或其子域", ErrOptionsInvalid)
		}
	}
	return nil
}
