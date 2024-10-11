package oauthclient

// 步骤 290（本地维护控制台）：OAuth 客户端凭证本地维护窄方法。
//
// 普通 RegisterClient/RotateClientSecret/RevokeClientSecret 要求真实管理会话授权 +
// 敏感策略近期强认证；本地维护控制台以 OS 访问权限执行救援/维护，不要求应用会话
// 或再次认证，但：
//   - 显式 LocalMaintenanceCaller（不可 JSON 反序列化、仅本机 login-setup 装配）；
//   - 复用同一登记/轮换/撤销实现与关键审计，秘密只在返回中一次性出现；
//   - 不绕过客户端类型/密钥/证书配置校验、不读取既有秘密明文；
//   - 适用客户端 ID = 应用 ID（既有模型；应用 ID 创建后不变）。

import (
	"context"
	"fmt"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/app"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
)

// LocalMaintenanceCaller 是仅供本机维护控制台使用的显式本地身份。
type LocalMaintenanceCaller struct {
	operatorID string
}

// NewLocalMaintenanceCaller 构造本地维护身份；只应由 cmd/login-setup（经
// internal/setupconsole）调用，不代表 Evernight 账户/HTTP 身份。
func NewLocalMaintenanceCaller(operatorID string) (LocalMaintenanceCaller, error) {
	actor := audit.Actor{Type: audit.ActorLocalAdmin, ID: operatorID}
	if err := actor.Validate(); err != nil {
		return LocalMaintenanceCaller{}, fmt.Errorf("%w: 本地维护操作者标识无效", ErrInvalidRequest)
	}
	return LocalMaintenanceCaller{operatorID: operatorID}, nil
}

// OperatorID 返回审计用本地操作者标识。
func (c LocalMaintenanceCaller) OperatorID() string { return c.operatorID }

// LocalMaintenanceClientSecret 是客户端密钥元数据（不含明文/摘要）。
type LocalMaintenanceClientSecret struct {
	ID        string
	Prefix    string
	CreatedAt time.Time
	ExpiresAt time.Time
	RetireAt  time.Time
	Revoked   bool
}

// LocalMaintenanceClientState 是客户端配置只读状态。
type LocalMaintenanceClientState struct {
	Registered   bool
	ClientType   ClientType
	AuthMethods  []AuthMethod
	GrantTypes   []GrantType
	RedirectURIs []string
	Secrets      []LocalMaintenanceClientSecret
}

// LocalMaintenanceClientState 读取指定应用（=客户端 ID）的 OAuth 客户端状态。
func (s *Service) LocalMaintenanceClientState(ctx context.Context,
	caller LocalMaintenanceCaller, applicationID string) (LocalMaintenanceClientState, error) {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return LocalMaintenanceClientState{}, err
	}
	if caller.operatorID == "" {
		return LocalMaintenanceClientState{}, ErrAccessDenied
	}
	if !app.ValidApplicationID(applicationID) {
		return LocalMaintenanceClientState{}, fmt.Errorf("%w: 客户端 ID 无效", ErrInvalidRequest)
	}
	record, found, err := s.opts.Store.GetClient(ctx, applicationID)
	if err != nil {
		return LocalMaintenanceClientState{}, mapStoreError(err)
	}
	if !found {
		return LocalMaintenanceClientState{}, nil
	}
	state := LocalMaintenanceClientState{Registered: true,
		ClientType: record.Client.ClientType, AuthMethods: record.Client.AuthMethods,
		GrantTypes: record.Client.GrantTypes, RedirectURIs: record.Client.RedirectURIs}
	secrets, err := s.opts.Store.ListSecrets(ctx, applicationID)
	if err != nil {
		return LocalMaintenanceClientState{}, mapStoreError(err)
	}
	for _, secret := range secrets {
		state.Secrets = append(state.Secrets, LocalMaintenanceClientSecret{
			ID: secret.ID, Prefix: secret.Prefix, CreatedAt: secret.CreatedAt,
			ExpiresAt: secret.ExpiresAt, RetireAt: secret.RetireAt,
			Revoked: !secret.RevokedAt.IsZero()})
	}
	return state, nil
}

func (s *Service) localMaintenanceCaller(caller LocalMaintenanceCaller) (Caller, error) {
	if caller.operatorID == "" {
		return Caller{}, ErrAccessDenied
	}
	return LocalAdminCaller(caller.operatorID)
}

// LocalMaintenanceRegisterClient 登记客户端安全设置并返回一次性秘密（保密客户端）。
func (s *Service) LocalMaintenanceRegisterClient(ctx context.Context,
	caller LocalMaintenanceCaller, request RegisterRequest) (RegisterResult, error) {
	internalCaller, err := s.localMaintenanceCaller(caller)
	if err != nil {
		return RegisterResult{}, err
	}
	return s.registerClientInternal(ctx, internalCaller, request, true)
}

// LocalMaintenanceRotateClientSecret 轮换客户端密钥并只返回一次新明文。
func (s *Service) LocalMaintenanceRotateClientSecret(ctx context.Context,
	caller LocalMaintenanceCaller, clientID, requestID string) (RevealedClientSecret, error) {
	internalCaller, err := s.localMaintenanceCaller(caller)
	if err != nil {
		return RevealedClientSecret{}, err
	}
	return s.rotateClientSecretInternal(ctx, internalCaller,
		RotateSecretRequest{ClientID: clientID, RequestID: requestID}, true)
}

// LocalMaintenanceRevokeClientSecret 撤销指定客户端密钥。
func (s *Service) LocalMaintenanceRevokeClientSecret(ctx context.Context,
	caller LocalMaintenanceCaller, clientID, secretID, requestID string) error {
	internalCaller, err := s.localMaintenanceCaller(caller)
	if err != nil {
		return err
	}
	return s.revokeClientSecretInternal(ctx, internalCaller,
		RevokeSecretRequest{ClientID: clientID, SecretID: secretID,
			RequestID: requestID}, true)
}
