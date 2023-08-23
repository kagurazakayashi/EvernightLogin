// Package securitycenter 提供安全中心相关的生产适配器：把“账户是否被强制要求
// 强认证（MFA）”与“是否还存在其他强因素”投影到 MFA/TOTP/Passkey 领域的策略契约。
//
// 背景（步骤 194）：各领域服务都定义了“最后可用/最后强制因素不可移除”的保护，
// 但保护只有在宿主注入真实的强制策略与其他强因素来源时才生效。本包把这些适配器
// 集中到一处，供 internal/serverapp 装配时复用，避免三处各写一份策略导致语义漂移。
//
// 安全不变量：
//   - 策略来源读取失败一律返回错误（各领域服务据此 fail-closed），绝不把错误解释成
//     “未强制”而放行移除最后一个因素。
//   - “其他强因素”查询只回答存在性，不返回因素细节；未启用/未接线视为“没有其他
//     强因素”（结构上 nil），此时若账户被强制 MFA，移除最后一个因素仍会被领域服务
//     拒绝，而不是本包放行。
package securitycenter

import (
	"context"
	"errors"
	"fmt"
	"reflect"
)

// ErrOptionsInvalid 表示适配器依赖无效。
var ErrOptionsInvalid = errors.New("安全中心适配器选项无效")

// StrongAuthRequirement 是“账户是否被强制要求强认证”的可信来源；生产实现为
// internal/authn 的 SQLite Store（root 恒为 true；直接/经角色被要求强认证的账户
// 也为 true）。
type StrongAuthRequirement interface {
	StrongAuthRequired(ctx context.Context, userID string) (bool, error)
}

// MFAPolicy 把 StrongAuthRequirement 投影为 mfa.Policy / totp.Policy /
// passkey.MFAPolicy 需要的 MFARequired 契约。
type MFAPolicy struct {
	source StrongAuthRequirement
}

// NewMFAPolicy 构造强制 MFA 策略适配器；来源缺失时拒绝构造（fail-closed）。
func NewMFAPolicy(source StrongAuthRequirement) (*MFAPolicy, error) {
	if isNil(source) {
		return nil, fmt.Errorf("%w: 强认证要求来源为空", ErrOptionsInvalid)
	}
	return &MFAPolicy{source: source}, nil
}

// MFARequired 报告账户是否被强制要求强认证。读取失败返回错误而不是 false：
// 领域服务必须把错误按策略不可用拒绝，不能据此放行移除最后一个因素。
func (p *MFAPolicy) MFARequired(ctx context.Context, userID string) (bool, error) {
	if p == nil || isNil(p.source) {
		return false, fmt.Errorf("%w: 强认证要求来源未接线", ErrOptionsInvalid)
	}
	required, err := p.source.StrongAuthRequired(ctx, userID)
	if err != nil {
		return false, fmt.Errorf("%w: 读取强认证要求失败", ErrOptionsInvalid)
	}
	return required, nil
}

// TOTPPresence 是“账户是否有活动 TOTP”的只读来源；生产实现为 *internal/totp.Service。
type TOTPPresence interface {
	HasActive(ctx context.Context, userID string) (bool, error)
}

// PasskeyPresence 是“账户是否有活动 Passkey 第二因素”的只读来源；生产实现为
// *internal/passkey.Service。
type PasskeyPresence interface {
	HasSecondFactor(ctx context.Context, userID string) (bool, error)
}

// TOTPOtherStrongFactor 实现 passkey.OtherStrongFactors：删除最后一个 Passkey 第二
// 因素时判断是否还有活动 TOTP 作为其他强因素。totp 为 nil（未启用）时如实返回
// “没有其他强因素”。
type TOTPOtherStrongFactor struct {
	totp TOTPPresence
}

// NewTOTPOtherStrongFactor 构造适配器；nil 表示未启用 TOTP，按“没有其他强因素”
// 处理（不是测试替身，也不会因此放宽删除保护）。
//
// 返回**指针**：适配器需要在装配阶段后接线（Passkey 服务先于 TOTP 服务构造），
// 若以值类型/值接收者装箱进接口，后续 SetTOTP 只会改到接口内的副本，生产服务
// 永远看不到真实 TOTP（步骤 194 审计 F1）。指针接收者保证 SetTOTP 对接口内同一
// 实例生效。
func NewTOTPOtherStrongFactor(totp TOTPPresence) *TOTPOtherStrongFactor {
	return &TOTPOtherStrongFactor{totp: totp}
}

// SetTOTP 供装配时解决构造循环（Passkey 服务需要“其他强因素”来源，而 TOTP 服务
// 在同一阶段稍后构造）。只允许在发布使用前设置一次；nil 保持“没有其他强因素”。
func (a *TOTPOtherStrongFactor) SetTOTP(totp TOTPPresence) {
	if a == nil {
		return
	}
	a.totp = totp
}

// HasOtherStrongFactor 实现 passkey.OtherStrongFactors。指针接收者保证装配阶段
// SetTOTP 后同一实例可见（值接收者会被接口装箱复制，导致永远读不到 TOTP）。
func (a *TOTPOtherStrongFactor) HasOtherStrongFactor(ctx context.Context,
	userID string) (bool, error) {
	if a == nil || isNil(a.totp) {
		return false, nil
	}
	active, err := a.totp.HasActive(ctx, userID)
	if err != nil {
		return false, fmt.Errorf("%w: 查询 TOTP 状态失败", ErrOptionsInvalid)
	}
	return active, nil
}

// PasskeyOtherStrongFactor 实现 totp.OtherFactors：删除 TOTP 时判断是否还有活动
// Passkey 作为其他强因素。passkeys 为 nil（Passkey 关闭）时如实返回“没有其他强
// 因素”。
type PasskeyOtherStrongFactor struct {
	passkeys PasskeyPresence
}

// NewPasskeyOtherStrongFactor 构造适配器；nil 表示 Passkey 未启用。
func NewPasskeyOtherStrongFactor(passkeys PasskeyPresence) PasskeyOtherStrongFactor {
	return PasskeyOtherStrongFactor{passkeys: passkeys}
}

// HasOtherStrongFactor 实现 totp.OtherFactors。
func (a PasskeyOtherStrongFactor) HasOtherStrongFactor(ctx context.Context,
	userID string) (bool, error) {
	if isNil(a.passkeys) {
		return false, nil
	}
	active, err := a.passkeys.HasSecondFactor(ctx, userID)
	if err != nil {
		return false, fmt.Errorf("%w: 查询 Passkey 状态失败", ErrOptionsInvalid)
	}
	return active, nil
}

// isNil 识别 nil 与 typed-nil 依赖。
func isNil(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
