// Copyright (c) KagurazakaYashi(KagurazakaMiyabi)
// EvernightLogin is licensed under Mulan PSL v2.

package app

// 会话管理公开接口与 OAuth 授权能力边界（步骤 226）。
//
// 本文件补齐宿主可调用的会话业务操作：查询（已有 SessionService.ListDevices 与
// AdminService.ListUserSessions）、本人指定设备退出/退出其他设备、管理员强制下线，
// 以及“会话有效 + 属于当前应用 + 具备所需权限”的联合校验（已有 SessionService.Authorize）。
// 身份只来自会话秘密或真实管理会话，不接受 userID 自称；所有操作复用 internal/session
// 的真实授权、强认证、审计与幂等语义，不复制第二套会话或协议实现。
//
// OAuth 授权能力边界（盘点结论，避免虚假声明）：
//   - 授权同意、设备码批准、令牌签发/刷新、UserInfo、introspection、协议撤销当前由
//     internal/oauthflow、internal/oidc 与标准 HTTP 协议端点实现（页面适配器与
//     /oauth2/ 端点），需要 protocol 装配；本步不机械导出内部协议处理器，也不新造
//     第二套协议入口。
//   - 令牌类型/issuer/audience 与调用应用身份、资源服务身份是不同概念：Access Token
//     的 audience 表示被授权调用的资源（不是 client_id 即可任意访问），id_token 的
//     audience 是 OAuth 客户端，issuer 是部署固定标识；client_id 只证明调用应用身份，
//     不能替代资源服务授权判断；离线验签成功也不证明未撤销/未过期/账户仍可用。
//   - introspection 与协议撤销的公开 Go 门面由后续步骤（227/228）在协议装配可用时
//     补齐；本步不提供“看起来可用”的占位实现，也不把 client_id 当任意资源授权。
//   - 会话有效 != 会话属于当前应用 != 具备所需权限：三者分别判断，业务/管理操作
//     必须用 Authorize 或领域服务重新判定，禁止只凭 Validate 放行。

import (
	"context"
	"errors"
	"strings"

	"github.com/kagurazakayashi/EvernightLogin/internal/session"
)

// RevokeDevice 让当前会话本人退出指定的其他设备。
//
// 安全语义：身份只来自会话秘密；目标不存在/不属于本人/已失效按幂等成功返回
// Revoked=false（不泄露他人会话存在性）；受限会话拒绝；实际撤销写审计，审计失败
// 拒绝并回滚。不能通过本方法探测其他用户是否在线。
func (f *sessionFacade) RevokeDevice(ctx context.Context,
	req SessionDeviceRevokeRequest) (SessionDeviceRevokeResult, error) {
	requestID, err := resolveRequestID(ctx, req.RequestID)
	if err != nil {
		return SessionDeviceRevokeResult{}, err
	}
	if len(req.SessionSecret) == 0 {
		return SessionDeviceRevokeResult{}, mapDomainError("缺少会话秘密", "ACCESS_DENIED", requestID)
	}
	services := f.r.coreServices()
	if services == nil || services.Sessions == nil {
		return SessionDeviceRevokeResult{}, configError("会话服务未装配", requestID)
	}
	revoked, err := services.Sessions.RevokeSession(ctx, string(req.SessionSecret),
		req.TargetSessionID)
	if err != nil {
		return SessionDeviceRevokeResult{}, mapDomainError("退出指定设备失败",
			string(session.CodeOf(err)), requestID)
	}
	return SessionDeviceRevokeResult{TargetSessionID: strings.TrimSpace(req.TargetSessionID),
		Revoked: revoked}, nil
}

// RevokeOtherDevices 退出本人其他全部会话（KeepCurrent=true 保留当前会话）。
//
// 返回实际撤销数量；受限会话拒绝；审计失败拒绝并回滚。该操作不会提升当前会话权限，
// 也不会影响其他用户或其他应用的独立会话。
func (f *sessionFacade) RevokeOtherDevices(ctx context.Context,
	req SessionRevokeOthersRequest) (SessionRevokeOthersResult, error) {
	requestID, err := resolveRequestID(ctx, req.RequestID)
	if err != nil {
		return SessionRevokeOthersResult{}, err
	}
	if len(req.SessionSecret) == 0 {
		return SessionRevokeOthersResult{}, mapDomainError("缺少会话秘密", "ACCESS_DENIED", requestID)
	}
	services := f.r.coreServices()
	if services == nil || services.Sessions == nil {
		return SessionRevokeOthersResult{}, configError("会话服务未装配", requestID)
	}
	revoked, err := services.Sessions.RevokeAllOwnSessions(ctx, string(req.SessionSecret),
		req.KeepCurrent)
	if err != nil {
		return SessionRevokeOthersResult{}, mapDomainError("退出其他会话失败",
			string(session.CodeOf(err)), requestID)
	}
	return SessionRevokeOthersResult{Revoked: revoked, KeptCurrent: req.KeepCurrent}, nil
}

// RevokeUserSessions 管理员按作用范围强制下线目标用户或指定会话。
//
// 安全边界：
//   - 只允许真实 AdminSession（管理员本人会话）；LocalAdmin 是宿主进程操作者，
//     没有真实管理会话，不能执行强制下线（返回 ACCESS_DENIED），避免本地旁路。
//   - 必须先完成真实敏感操作再次认证（session.revoke.other，密码，必要时强因素
//     动态码）；再由会话服务复核强认证会话状态、范围授权、root/受保护目标与目标
//     归属，目标越界或已失效按幂等 0 返回，不泄露存在性。
//   - Reason 必填入审计；失败审计/成功审计由会话服务同一事务语义处理。
func (f *adminFacade) RevokeUserSessions(ctx context.Context,
	req AdminRevokeSessionsRequest) (AdminRevokeSessionsResult, error) {
	call, err := f.begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminRevokeSessionsResult{}, err
	}
	services := f.r.coreServices()
	if services == nil || services.Sessions == nil {
		return AdminRevokeSessionsResult{}, call.configError("会话服务未装配")
	}
	if call.identity.local || len(call.identity.sessionSecret) == 0 {
		return AdminRevokeSessionsResult{}, mapDomainError(
			"强制下线只允许真实管理会话调用者，本机受信操作者没有管理会话",
			"ACCESS_DENIED", call.requestID)
	}
	scopeApplicationID := strings.TrimSpace(req.ScopeApplicationID)
	targetUserID := strings.TrimSpace(req.TargetUserID)
	targetSessionID := strings.TrimSpace(req.TargetSessionID)
	if (targetUserID == "") == (targetSessionID == "") {
		return AdminRevokeSessionsResult{}, mapDomainError(
			"必须且只能指定目标用户或目标会话之一", "REQ_INVALID", call.requestID)
	}
	reason := strings.TrimSpace(req.Reason)
	if reason == "" {
		return AdminRevokeSessionsResult{}, mapDomainError(
			"强制下线必须填写理由", "REQ_INVALID", call.requestID)
	}
	targetType, targetID := "user", targetUserID
	if targetSessionID != "" {
		targetType, targetID = "session", targetSessionID
	}
	approved, err := f.sensitiveContext(ctx, call.identity,
		session.OperationSessionRevokeOther, targetType, targetID,
		session.AdminRevokeParams(scopeApplicationID, targetUserID, targetSessionID),
		req.Password, req.TOTPCode, call.requestID)
	if err != nil {
		return AdminRevokeSessionsResult{}, err
	}
	result, err := services.Sessions.AdminRevoke(approved,
		string(call.identity.sessionSecret), session.AdminRevokeRequest{
			ScopeAppID: scopeApplicationID, TargetUserID: targetUserID,
			TargetSessionID: targetSessionID, RequestID: call.requestID, Reason: reason})
	if err != nil {
		if errors.Is(err, session.ErrStrongAuthRequired) {
			return AdminRevokeSessionsResult{}, mapDomainError("强制下线需要真实管理强认证",
				"REAUTH_REQUIRED", call.requestID)
		}
		return AdminRevokeSessionsResult{}, call.domainError("强制下线失败",
			string(session.CodeOf(err)))
	}
	return AdminRevokeSessionsResult{ScopeApplicationID: scopeApplicationID,
		TargetUserID: targetUserID, TargetSessionID: targetSessionID,
		Revoked: result.Revoked}, nil
}
