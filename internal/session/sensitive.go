package session

import "github.com/kagurazakayashi/EvernightLogin/internal/reauth"

// SensitiveRunner 是敏感操作收敛入口（生产实现 *reauth.Service）。nil 时管理访问
// 仍由既有 CanAccessManagement 强认证闸门 fail-closed；接线后额外经敏感策略判定，
// 策略要求强认证而 MFA 未实现时继续拒绝，不放宽。
type SensitiveRunner = reauth.OperationRunner
