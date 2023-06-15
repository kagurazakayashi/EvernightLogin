package serverapp

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	login "github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/adminapi"
)

// buildAdminWriteRoutesExtra 补齐步骤 156 的删除/更新/成员/组合/RBAC 与客服写路由；
// 与 buildAdminWriteRoutes 相同，复用页面适配器授权/事务/审计。
func buildAdminWriteRoutesExtra(managed *ManagedServices, pages *Pages, gate *SecurityGate) []adminapi.DomainRoute {
	if managed == nil || pages == nil || pages.Admin == nil {
		return nil
	}
	routes := make([]adminapi.DomainRoute, 0, 20)
	add := func(method, pattern string,
		handler func(ctx context.Context, caller account.Caller, request *http.Request) (any, error)) {
		routes = append(routes, adminapi.DomainRoute{Method: method, Pattern: pattern, Handler: handler})
	}

	add(http.MethodPost, "users/{user_id}/delete-preview", func(ctx context.Context,
		caller account.Caller, request *http.Request) (any, error) {
		if _, err := adminWriteBody(request); err != nil {
			return nil, err
		}
		preview, err := pages.Admin.PreviewDeletion(ctx, caller.Actor().ID, adminLastPathPartPrevious(request))
		if err != nil {
			return nil, adminUIError(err)
		}
		return map[string]any{"user_id": preview.UserID, "username": preview.Username,
			"is_root": preview.IsRoot, "app_memberships": preview.AppMemberships,
			"user_roles": preview.UserRoles, "group_memberships": preview.GroupMemberships,
			"one_time_credentials": preview.OneTimeCredentials,
			"owned_applications":   preview.OwnedApplications, "row_version": preview.RowVersion}, nil
	})
	add(http.MethodPost, "users/{user_id}/delete", func(ctx context.Context,
		caller account.Caller, request *http.Request) (any, error) {
		body, err := adminWriteBody(request)
		if err != nil {
			return nil, err
		}
		preview, err := pages.Admin.CompleteDeletion(ctx, caller.Actor().ID,
			adminLastPathPart(request), adminInt64(body, "expected_row_version"),
			adminRequestID(body, request))
		if err != nil {
			return nil, adminUIError(err)
		}
		return map[string]any{"user_id": preview.UserID, "deleted": true}, nil
	})

	add(http.MethodPut, "groups/{group_id}", func(ctx context.Context,
		caller account.Caller, request *http.Request) (any, error) {
		body, err := adminWriteBody(request)
		if err != nil {
			return nil, err
		}
		view, err := pages.Admin.UpdateGroup(ctx, caller.Actor().ID, adminLastPathPart(request),
			adminString(body, "name"), adminString(body, "description"), adminRequestID(body, request))
		if err != nil {
			return nil, adminUIError(err)
		}
		return map[string]any{"id": view.ID, "name": view.Name, "description": view.Description}, nil
	})
	add(http.MethodDelete, "groups/{group_id}", func(ctx context.Context,
		caller account.Caller, request *http.Request) (any, error) {
		body, err := adminWriteBody(request)
		if err != nil {
			return nil, err
		}
		if err := pages.Admin.DeleteGroup(ctx, caller.Actor().ID, adminLastPathPart(request),
			adminRequestID(body, request)); err != nil {
			return nil, adminUIError(err)
		}
		return map[string]any{"deleted": true}, nil
	})
	add(http.MethodPost, "groups/{group_id}/members", func(ctx context.Context,
		caller account.Caller, request *http.Request) (any, error) {
		body, err := adminWriteBody(request)
		if err != nil {
			return nil, err
		}
		var userIDs []string
		_ = json.Unmarshal(body["user_ids"], &userIDs)
		groupID := adminLastPathPartPrevious(request)
		var result login.UIAdminMemberResult
		if adminString(body, "action") == "remove" {
			result, err = pages.Admin.RemoveMembers(ctx, caller.Actor().ID, groupID, userIDs,
				adminRequestID(body, request))
		} else {
			result, err = pages.Admin.AddMembers(ctx, caller.Actor().ID, groupID, userIDs,
				adminRequestID(body, request))
		}
		if err != nil {
			return nil, adminUIError(err)
		}
		return map[string]any{"added": result.Added, "removed": result.Removed,
			"skipped": result.Skipped}, nil
	})

	add(http.MethodPut, "roles/{role_id}", func(ctx context.Context,
		caller account.Caller, request *http.Request) (any, error) {
		if pages.RBAC == nil {
			return nil, &adminapi.DomainError{Code: "INTERNAL_ERROR", Message: "RBAC 适配器未装配"}
		}
		body, err := adminWriteBody(request)
		if err != nil {
			return nil, err
		}
		view, err := pages.RBAC.UpdateRole(ctx, caller.Actor().ID, adminLastPathPart(request),
			login.UIRBACTextChange{Name: adminString(body, "name"),
				Description: adminString(body, "description"), Limits: adminString(body, "limits")},
			adminRequestID(body, request))
		if err != nil {
			return nil, adminUIError(err)
		}
		return map[string]any{"id": view.ID, "name": view.Name, "enabled": view.Enabled}, nil
	})
	add(http.MethodPost, "roles/{role_id}/state", func(ctx context.Context,
		caller account.Caller, request *http.Request) (any, error) {
		if pages.RBAC == nil {
			return nil, &adminapi.DomainError{Code: "INTERNAL_ERROR", Message: "RBAC 适配器未装配"}
		}
		body, err := adminWriteBody(request)
		if err != nil {
			return nil, err
		}
		view, changed, err := pages.RBAC.SetRoleState(ctx, caller.Actor().ID,
			adminLastPathPartPrevious(request), adminBool(body, "enable"), adminRequestID(body, request))
		if err != nil {
			return nil, adminUIError(err)
		}
		return map[string]any{"id": view.ID, "enabled": view.Enabled, "changed": changed}, nil
	})
	add(http.MethodPut, "roles/{role_id}/permissions", func(ctx context.Context,
		caller account.Caller, request *http.Request) (any, error) {
		if pages.RBAC == nil {
			return nil, &adminapi.DomainError{Code: "INTERNAL_ERROR", Message: "RBAC 适配器未装配"}
		}
		body, err := adminWriteBody(request)
		if err != nil {
			return nil, err
		}
		result, err := pages.RBAC.ComposeRolePermission(ctx, caller.Actor().ID,
			adminLastPathPartPrevious(request), adminString(body, "permission_id"),
			adminBool(body, "add"), adminRequestID(body, request))
		if err != nil {
			return nil, adminUIError(err)
		}
		return map[string]any{"action": result.Action, "added": len(result.Added),
			"removed": len(result.Removed), "affected_users": result.AffectedUsers,
			"affected_groups": result.AffectedGroups}, nil
	})
	add(http.MethodPut, "permissions/{permission_id}", func(ctx context.Context,
		caller account.Caller, request *http.Request) (any, error) {
		if pages.RBAC == nil {
			return nil, &adminapi.DomainError{Code: "INTERNAL_ERROR", Message: "RBAC 适配器未装配"}
		}
		body, err := adminWriteBody(request)
		if err != nil {
			return nil, err
		}
		view, err := pages.RBAC.UpdatePermission(ctx, caller.Actor().ID, adminLastPathPart(request),
			login.UIRBACTextChange{Name: adminString(body, "name"),
				Description: adminString(body, "description"), Limits: adminString(body, "limits")},
			adminRequestID(body, request))
		if err != nil {
			return nil, adminUIError(err)
		}
		return map[string]any{"id": view.PermissionID, "key": view.Key, "name": view.Name}, nil
	})
	add(http.MethodPost, "permissions/{permission_id}/state", func(ctx context.Context,
		caller account.Caller, request *http.Request) (any, error) {
		if pages.RBAC == nil {
			return nil, &adminapi.DomainError{Code: "INTERNAL_ERROR", Message: "RBAC 适配器未装配"}
		}
		body, err := adminWriteBody(request)
		if err != nil {
			return nil, err
		}
		view, changed, err := pages.RBAC.SetPermissionState(ctx, caller.Actor().ID,
			adminLastPathPartPrevious(request), adminBool(body, "enable"), adminRequestID(body, request))
		if err != nil {
			return nil, adminUIError(err)
		}
		return map[string]any{"id": view.PermissionID, "key": view.Key,
			"enabled": view.Enabled, "changed": changed}, nil
	})

	add(http.MethodPost, "applications", func(ctx context.Context,
		caller account.Caller, request *http.Request) (any, error) {
		if pages.Apps == nil {
			return nil, &adminapi.DomainError{Code: "INTERNAL_ERROR", Message: "应用适配器未装配"}
		}
		body, err := adminWriteBody(request)
		if err != nil {
			return nil, err
		}
		view, err := pages.Apps.CreateApplication(ctx, caller.Actor().ID, login.UIApplicationCreate{
			Name: adminString(body, "name"), Description: adminString(body, "description"),
			IconRef: adminString(body, "icon_ref"), Homepage: adminString(body, "homepage"),
			OwnerUserID: adminString(body, "owner_user_id"), ContactInfo: adminString(body, "contact_info"),
			ClientType: adminString(body, "client_type")}, adminRequestID(body, request))
		if err != nil {
			return nil, adminUIError(err)
		}
		return map[string]any{"id": view.ID, "name": view.Name, "status": view.Status,
			"row_version": view.RowVersion}, nil
	})
	add(http.MethodPost, "applications/{application_id}/members", func(ctx context.Context,
		caller account.Caller, request *http.Request) (any, error) {
		if pages.Apps == nil {
			return nil, &adminapi.DomainError{Code: "INTERNAL_ERROR", Message: "应用适配器未装配"}
		}
		body, err := adminWriteBody(request)
		if err != nil {
			return nil, err
		}
		appID := adminLastPathPartPrevious(request)
		if adminString(body, "action") == "remove" {
			if err := pages.Apps.RemoveMember(ctx, caller.Actor().ID, appID,
				adminString(body, "user_id"), adminInt64(body, "expected_row_version"),
				adminRequestID(body, request)); err != nil {
				return nil, adminUIError(err)
			}
			return map[string]any{"removed": true}, nil
		}
		view, err := pages.Apps.AddMember(ctx, caller.Actor().ID, appID,
			adminString(body, "user_id"), login.UIAppMemberProfile{
				DisplayName: adminString(body, "display_name"), Title: adminString(body, "title"),
				Note: adminString(body, "note")}, adminRequestID(body, request))
		if err != nil {
			return nil, adminUIError(err)
		}
		return map[string]any{"user_id": view.UserID, "status": view.Status}, nil
	})
	add(http.MethodPost, "applications/{application_id}/members/state", func(ctx context.Context,
		caller account.Caller, request *http.Request) (any, error) {
		if pages.Apps == nil {
			return nil, &adminapi.DomainError{Code: "INTERNAL_ERROR", Message: "应用适配器未装配"}
		}
		body, err := adminWriteBody(request)
		if err != nil {
			return nil, err
		}
		view, changed, err := pages.Apps.SetMemberState(ctx, caller.Actor().ID,
			adminLastPathPartPrevious(request), adminString(body, "user_id"), adminBool(body, "enable"),
			adminInt64(body, "expected_row_version"), adminRequestID(body, request))
		if err != nil {
			return nil, adminUIError(err)
		}
		return map[string]any{"user_id": view.UserID, "status": view.Status, "changed": changed}, nil
	})
	add(http.MethodGet, "applications/{application_id}/managed-policy", func(ctx context.Context,
		caller account.Caller, request *http.Request) (any, error) {
		if pages.Apps == nil {
			return nil, &adminapi.DomainError{Code: "INTERNAL_ERROR", Message: "应用适配器未装配"}
		}
		view, err := pages.Apps.GetManagedPolicy(ctx, caller.Actor().ID, adminLastPathPartPrevious(request))
		if err != nil {
			return nil, adminUIError(err)
		}
		return map[string]any{"state": view.State, "application_id": view.ApplicationID,
			"row_version": view.RowVersion, "can_write": view.CanWrite,
			"allowed": view.Allowed, "limits": view.Limits}, nil
	})

	if pages.Support != nil {
		add(http.MethodPost, "support/cases/{case_id}/reassign", func(ctx context.Context,
			caller account.Caller, request *http.Request) (any, error) {
			body, err := adminWriteBody(request)
			if err != nil {
				return nil, err
			}
			view, err := pages.Support.ReassignCase(ctx, caller.Actor().ID,
				adminLastPathPartPrevious(request), adminString(body, "new_assignee_user_id"),
				adminRequestID(body, request))
			if err != nil {
				return nil, adminUIError(err)
			}
			return map[string]any{"id": view.ID, "assignee_user_id": view.AssigneeUserID}, nil
		})
		add(http.MethodPost, "support/cases/{case_id}/transition", func(ctx context.Context,
			caller account.Caller, request *http.Request) (any, error) {
			body, err := adminWriteBody(request)
			if err != nil {
				return nil, err
			}
			view, err := pages.Support.TransitionCase(ctx, caller.Actor().ID,
				adminLastPathPartPrevious(request), adminString(body, "to_status"),
				adminString(body, "note"), adminRequestID(body, request))
			if err != nil {
				return nil, adminUIError(err)
			}
			return map[string]any{"id": view.ID, "status": view.Status}, nil
		})
		add(http.MethodPost, "support/recovery/{request_id}/reject", func(ctx context.Context,
			caller account.Caller, request *http.Request) (any, error) {
			body, err := adminWriteBody(request)
			if err != nil {
				return nil, err
			}
			if err := pages.Support.RejectRecovery(ctx, caller.Actor().ID,
				adminLastPathPartPrevious(request), adminString(body, "reason"),
				adminRequestID(body, request)); err != nil {
				return nil, adminUIError(err)
			}
			return map[string]any{"rejected": true}, nil
		})
		add(http.MethodPost, "support/recovery/{request_id}/cancel", func(ctx context.Context,
			caller account.Caller, request *http.Request) (any, error) {
			body, err := adminWriteBody(request)
			if err != nil {
				return nil, err
			}
			if err := pages.Support.CancelRecovery(ctx, caller.Actor().ID,
				adminLastPathPartPrevious(request), adminString(body, "reason"),
				adminRequestID(body, request)); err != nil {
				return nil, adminUIError(err)
			}
			return map[string]any{"cancelled": true}, nil
		})
	}

	add(http.MethodPut, "applications/{application_id}/managed-policy", func(ctx context.Context,
		caller account.Caller, request *http.Request) (any, error) {
		if pages.Apps == nil || gate == nil || managed.ManagedPolicyApprovals == nil {
			return nil, &adminapi.DomainError{Code: "INTERNAL_ERROR", Message: "托管策略写通道未装配"}
		}
		body, err := adminWriteBody(request)
		if err != nil {
			return nil, err
		}
		appID := adminLastPathPartPrevious(request)
		change := login.UIAppPolicyChange{
			Allowed:        adminStringList(body, "allowed"),
			ServiceAllowed: adminStringList(body, "service_allowed"),
			Limits: login.UIAppPolicyLimits{MaxLimit: int(adminInt64(body, "max_limit")),
				MaxOffset: int(adminInt64(body, "max_offset")), MaxBatch: int(adminInt64(body, "max_batch"))},
		}
		_ = json.Unmarshal(body["objects"], &change.Objects)
		_ = json.Unmarshal(body["fields"], &change.Fields)
		expected := adminInt64(body, "expected_row_version")
		digest := change.Digest()
		requestID := adminRequestID(body, request)
		binding := login.UIAppPolicyActionBinding{ApplicationID: appID,
			ExpectedRowVersion: expected, PolicyDigest: digest, RequestID: requestID}
		if err := gate.ManagedPolicyReauth(ctx, caller.Actor().ID, binding); err != nil {
			return nil, &adminapi.DomainError{Code: "REAUTH_REQUIRED", Message: "策略写需要近期强认证", Cause: err}
		}
		if err := managed.ManagedPolicyApprovals.Register(caller.Actor().ID, binding); err != nil {
			return nil, adminUIError(err)
		}
		view, err := pages.Apps.SetManagedPolicy(ctx, caller.Actor().ID, appID, change,
			expected, requestID, digest)
		if err != nil {
			return nil, adminUIError(err)
		}
		return map[string]any{"state": view.State, "application_id": view.ApplicationID,
			"row_version": view.RowVersion}, nil
	})
	add(http.MethodPost, "applications/{application_id}/oauth-settings", func(ctx context.Context,
		caller account.Caller, request *http.Request) (any, error) {
		if pages.Apps == nil {
			return nil, &adminapi.DomainError{Code: "INTERNAL_ERROR", Message: "应用适配器未装配"}
		}
		body, err := adminWriteBody(request)
		if err != nil {
			return nil, err
		}
		appID := adminLastPathPartPrevious(request)
		if adminString(body, "action") == "register" {
			result, err := pages.Apps.RegisterClient(ctx, caller.Actor().ID, appID, login.UIOAuthRegister{
				GrantTypes:             adminStringList(body, "grant_types"),
				RedirectURIs:           adminStringList(body, "redirect_uris"),
				PostLogoutRedirectURIs: adminList(body, "post_logout_redirect_uris"),
				Scopes:                 adminStringList(body, "scopes"), Audiences: adminStringList(body, "audiences"),
				AuthMethods: adminStringList(body, "auth_methods"), RequirePKCE: adminBool(body, "require_pkce"),
				CertificatePEM: adminString(body, "certificate_pem")}, adminRequestID(body, request))
			if err != nil {
				return nil, adminUIError(err)
			}
			return map[string]any{"client_id": result.Settings.ClientID, "has_secret": result.Secret != nil}, nil
		}
		settings, err := pages.Apps.UpdateClientSettings(ctx, caller.Actor().ID, appID,
			login.UIOAuthChange{GrantTypes: adminStringList(body, "grant_types"),
				RedirectURIs:           adminStringList(body, "redirect_uris"),
				PostLogoutRedirectURIs: adminList(body, "post_logout_redirect_uris"),
				Scopes:                 adminStringList(body, "scopes"), Audiences: adminStringList(body, "audiences"),
				RequirePKCE: adminBool(body, "require_pkce")},
			adminInt64(body, "expected_row_version"), adminRequestID(body, request))
		if err != nil {
			return nil, adminUIError(err)
		}
		return map[string]any{"client_id": settings.ClientID}, nil
	})
	add(http.MethodPost, "applications/{application_id}/secrets/rotate", func(ctx context.Context,
		caller account.Caller, request *http.Request) (any, error) {
		if pages.Apps == nil {
			return nil, &adminapi.DomainError{Code: "INTERNAL_ERROR", Message: "应用适配器未装配"}
		}
		body, err := adminWriteBody(request)
		if err != nil {
			return nil, err
		}
		secret, err := pages.Apps.RotateSecret(ctx, caller.Actor().ID,
			adminLastPathPartPrevious(request), adminRequestID(body, request))
		if err != nil {
			return nil, adminUIError(err)
		}
		return map[string]any{"secret_id": secret.Info.ID,
			"secret": secret.Secret, "shown_once": true}, nil
	})
	add(http.MethodPost, "applications/{application_id}/secrets/{secret_id}/revoke", func(ctx context.Context,
		caller account.Caller, request *http.Request) (any, error) {
		if pages.Apps == nil {
			return nil, &adminapi.DomainError{Code: "INTERNAL_ERROR", Message: "应用适配器未装配"}
		}
		body, err := adminWriteBody(request)
		if err != nil {
			return nil, err
		}
		parts := strings.Split(strings.Trim(request.URL.Path, "/"), "/")
		appID, secretID := "", ""
		if len(parts) >= 3 {
			appID, secretID = parts[len(parts)-3], parts[len(parts)-2]
		}
		if err := pages.Apps.RevokeSecret(ctx, caller.Actor().ID, appID, secretID,
			adminRequestID(body, request)); err != nil {
			return nil, adminUIError(err)
		}
		return map[string]any{"revoked": true}, nil
	})
	add(http.MethodPost, "applications/{application_id}/certificates", func(ctx context.Context,
		caller account.Caller, request *http.Request) (any, error) {
		if pages.Apps == nil {
			return nil, &adminapi.DomainError{Code: "INTERNAL_ERROR", Message: "应用适配器未装配"}
		}
		body, err := adminWriteBody(request)
		if err != nil {
			return nil, err
		}
		cert, err := pages.Apps.RegisterCertificate(ctx, caller.Actor().ID,
			adminLastPathPartPrevious(request), adminString(body, "certificate_pem"),
			adminRequestID(body, request))
		if err != nil {
			return nil, adminUIError(err)
		}
		return map[string]any{"id": cert.ID, "fingerprint": cert.FingerprintSHA256}, nil
	})
	add(http.MethodPost, "applications/{application_id}/certificates/{certificate_id}/revoke", func(ctx context.Context,
		caller account.Caller, request *http.Request) (any, error) {
		if pages.Apps == nil {
			return nil, &adminapi.DomainError{Code: "INTERNAL_ERROR", Message: "应用适配器未装配"}
		}
		body, err := adminWriteBody(request)
		if err != nil {
			return nil, err
		}
		parts := strings.Split(strings.Trim(request.URL.Path, "/"), "/")
		appID, certID := "", ""
		if len(parts) >= 3 {
			appID, certID = parts[len(parts)-3], parts[len(parts)-2]
		}
		if err := pages.Apps.RevokeCertificate(ctx, caller.Actor().ID, appID, certID,
			adminRequestID(body, request)); err != nil {
			return nil, adminUIError(err)
		}
		return map[string]any{"revoked": true}, nil
	})
	return routes
}

var _ = strings.TrimSpace
