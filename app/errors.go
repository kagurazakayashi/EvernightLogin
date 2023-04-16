package app

import (
	"errors"
	"strings"

	"github.com/kagurazakayashi/EvernightLogin"
)

// configError 返回稳定的 CONFIG_INVALID AppError。
func configError(message string) error {
	return login.NewAppError(login.CodeConfigInvalid, message)
}

// wrapInternal 把内部错误包装为不泄露内部细节的公开错误；保留原始错误供调试
// 时需要时由宿主通过 errors.Is/As 判断（不写日志内容）。
func wrapInternal(message string, err error) error {
	if err == nil {
		return login.NewAppError(login.CodeInternalError, message)
	}
	if appErr, ok := err.(*login.AppError); ok {
		return appErr
	}
	return login.NewAppError(login.CodeInternalError, message)
}

// mapAuthError 把认证错误映射为公开稳定错误；不返回账户存在性细节。
func mapAuthError(err error) error {
	if err == nil {
		return nil
	}
	message := "登录失败"
	lower := strings.ToLower(err.Error())
	if strings.Contains(lower, "disabled") || strings.Contains(lower, "禁用") {
		return login.NewAppError(login.CodeUserDisabled, "账户当前不可使用")
	}
	return login.NewAppError(login.CodeAuthFailed, message)
}

// mapServiceError 是通用内部错误映射；只返回稳定公开码与直白说明。
func mapServiceError(err error) error {
	if err == nil {
		return nil
	}
	if appErr, ok := err.(*login.AppError); ok {
		return appErr
	}
	return login.NewAppError(login.CodeInternalError, "操作未完成")
}

var _ = errors.Is
