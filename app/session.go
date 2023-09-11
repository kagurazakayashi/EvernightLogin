package app

// 会话校验公开门面（嵌入宿主用）。
//
// 目标：让宿主能在自己的业务 API 上验证 Evernight 会话，而不需要导入 internal/
// 或伪造 HTTP 请求。Validate 只接受完整会话；ValidateCSRF 校验与会话绑定的 CSRF
// 令牌，来源校验仍由宿主 HTTP 防护层负责。

import (
	"context"
	"strings"

	"github.com/kagurazakayashi/EvernightLogin/internal/session"
)

// Validate 校验会话秘密并返回脱敏快照。空闲/绝对过期、撤销、账户禁用、安全版本
// 变化、应用成员失效都会失败；不会延长会话。
func (f *sessionFacade) Validate(ctx context.Context, sessionSecret []byte) (SessionInfo, error) {
	r := f.r
	record, err := r.requireSession(ctx, sessionSecret, true)
	if err != nil {
		return SessionInfo{}, err
	}
	info := SessionInfo{
		UserID:               record.UserID,
		SessionID:            record.ID,
		AppID:                record.AppID,
		ExpiresAt:            record.AbsoluteExpiresAt,
		IdleExpiresAt:        record.IdleExpiresAt,
		CreatedAt:            record.CreatedAt,
		SecurityVersion:      record.SecurityVersion,
		StrongAuthVerifiedAt: record.StrongAuthVerifiedAt,
	}
	for _, method := range record.AuthMethods {
		info.AuthMethods = append(info.AuthMethods, string(method))
	}
	return info, nil
}

// ValidateCSRF 校验与会话绑定的 CSRF 令牌。会话秘密必须由可信边界取得；不要把
// 会话秘密或 CSRF 令牌写入 URL、日志或 localStorage。
func (f *sessionFacade) ValidateCSRF(ctx context.Context, sessionSecret []byte, token string) error {
	services := f.r.coreServices()
	if services == nil {
		return configError("服务未装配")
	}
	if len(sessionSecret) == 0 {
		return configError("会话秘密为空")
	}
	if strings.TrimSpace(token) == "" {
		return configError("CSRF 令牌为空")
	}
	if err := services.Sessions.ValidateCSRFTokenForSecret(ctx, string(sessionSecret), token); err != nil {
		return mapDomainError("会话 CSRF 校验未通过", string(session.CodeOf(err)))
	}
	return nil
}
