// Package main 的外部模块公开面覆盖检查（步骤 236）。
//
// 本文件只导入公开 login/app 包，用编译期引用证明 236 登记的公开 Go 类型/服务
// accessor 均可由外部宿主使用，不依赖 internal 包。
package main

import (
	"reflect"

	"github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/app"
)

// 服务接口的编译期引用。
var _ = reflect.TypeOf((*app.SessionService)(nil)).Elem()
var _ = reflect.TypeOf((*app.AdminService)(nil)).Elem()
var _ = reflect.TypeOf((*app.BackupArtifactService)(nil)).Elem()
var _ = reflect.TypeOf((*app.BackupJobService)(nil)).Elem()
var _ = reflect.TypeOf((*app.BackupPlanService)(nil)).Elem()
var _ = reflect.TypeOf((*app.BackupRecoveryService)(nil)).Elem()
var _ = reflect.TypeOf((*app.BackupService)(nil)).Elem()
var _ = reflect.TypeOf((*app.SupportAdminService)(nil)).Elem()
var _ = reflect.TypeOf((*app.ManualRecoveryAdminService)(nil)).Elem()
var _ = reflect.TypeOf((*app.ProtocolService)(nil)).Elem()
var _ = reflect.TypeOf((*app.ProtocolRevocationService)(nil)).Elem()
var _ = reflect.TypeOf((*app.DiagnosticsService)(nil)).Elem()
var _ = reflect.TypeOf((*app.SettingsService)(nil)).Elem()
var _ = reflect.TypeOf((*app.InvitationAdminService)(nil)).Elem()
var _ = reflect.TypeOf((*app.PasswordChangeService)(nil)).Elem()
var _ = reflect.TypeOf((*app.UserBatchService)(nil)).Elem()
var _ = reflect.TypeOf((*app.UserLifecycleService)(nil)).Elem()

// 公开请求/结果/视图类型的编译期引用（236 未覆盖面收口）。
var publicSurfaceTypes = []reflect.Type{
	reflect.TypeOf(app.SessionDeviceRequest{}),
	reflect.TypeOf(app.SessionDevice{}),
	reflect.TypeOf(app.SessionDeviceList{}),
	reflect.TypeOf(app.AdminListUserSessionsRequest{}),
	reflect.TypeOf(app.AdminSessionView{}),
	reflect.TypeOf(app.AdminUserSessionList{}),
	reflect.TypeOf(app.SessionDeviceRevokeRequest{}),
	reflect.TypeOf(app.SessionDeviceRevokeResult{}),
	reflect.TypeOf(app.SessionRevokeOthersRequest{}),
	reflect.TypeOf(app.SessionRevokeOthersResult{}),
	reflect.TypeOf(app.AdminRevokeSessionsRequest{}),
	reflect.TypeOf(app.AdminRevokeSessionsResult{}),
	reflect.TypeOf(app.BackupArtifact{}),
	reflect.TypeOf(app.BackupArtifactRequest{}),
	reflect.TypeOf(app.BackupCheck{}),
	reflect.TypeOf(app.BackupCheckReport{}),
	reflect.TypeOf(app.BackupExport{}),
	reflect.TypeOf(app.BackupImpact{}),
	reflect.TypeOf(app.BackupJob{}),
	reflect.TypeOf(app.BackupJobCancelRequest{}),
	reflect.TypeOf(app.BackupJobCancelResult{}),
	reflect.TypeOf(app.BackupJobRef{}),
	reflect.TypeOf(app.BackupJobRequest{}),
	reflect.TypeOf(app.BackupJobTriggerRequest{}),
	reflect.TypeOf(app.BackupMaintenanceRequest{}),
	reflect.TypeOf(app.BackupPendingRestore{}),
	reflect.TypeOf(app.BackupPlan{}),
	reflect.TypeOf(app.BackupPlanRequest{}),
	reflect.TypeOf(app.BackupPlanStateRequest{}),
	reflect.TypeOf(app.BackupRecoveryConfigRequest{}),
	reflect.TypeOf(app.BackupRecoveryInitializeRequest{}),
	reflect.TypeOf(app.BackupRecoveryLoadRequest{}),
	reflect.TypeOf(app.BackupRecoveryRestoreRequest{}),
	reflect.TypeOf(app.BackupRecoverySource{}),
	reflect.TypeOf(app.BackupRecoveryStatus{}),
	reflect.TypeOf(app.BackupRecoveryStatusRequest{}),
	reflect.TypeOf(app.BackupRehearsal{}),
	reflect.TypeOf(app.BackupRestoreResult{}),
	reflect.TypeOf(app.BackupSourceSummary{}),
	reflect.TypeOf(app.Runtime{}),
	reflect.TypeOf(app.SupportCase{}),
	reflect.TypeOf(app.SupportCaseEvent{}),
	reflect.TypeOf(app.SupportCasePage{}),
	reflect.TypeOf(app.SupportCaseRequest{}),
	reflect.TypeOf(app.SupportCreateCaseRequest{}),
	reflect.TypeOf(app.SupportEventPage{}),
	reflect.TypeOf(app.SupportListCasesRequest{}),
	reflect.TypeOf(app.SupportLookupTargetRequest{}),
	reflect.TypeOf(app.SupportReassignCaseRequest{}),
	reflect.TypeOf(app.SupportSendResetRequest{}),
	reflect.TypeOf(app.SupportSendResult{}),
	reflect.TypeOf(app.SupportTarget{}),
	reflect.TypeOf(app.SupportTransitionCaseRequest{}),
	reflect.TypeOf(app.ManualRecoveryApproval{}),
	reflect.TypeOf(app.ManualRecoveryCancelRequest{}),
	reflect.TypeOf(app.ManualRecoveryCreateRequest{}),
	reflect.TypeOf(app.ManualRecoveryDecisionRequest{}),
	reflect.TypeOf(app.ManualRecoveryExecuteRequest{}),
	reflect.TypeOf(app.ManualRecoveryExecutionRecord{}),
	reflect.TypeOf(app.ManualRecoveryExecutionResult{}),
	reflect.TypeOf(app.ManualRecoveryListItem{}),
	reflect.TypeOf(app.ManualRecoveryListPage{}),
	reflect.TypeOf(app.ManualRecoveryListRequest{}),
	reflect.TypeOf(app.ManualRecoveryPolicy{}),
	reflect.TypeOf(app.ManualRecoveryRequest{}),
	reflect.TypeOf(app.ManualRecoveryRequestRef{}),
	reflect.TypeOf(app.ProtocolIntrospectRequest{}),
	reflect.TypeOf(app.ProtocolTokenInspection{}),
	reflect.TypeOf(app.ProtocolRevokeTokenRequest{}),
	reflect.TypeOf(app.ProtocolRevokeResult{}),
	reflect.TypeOf(app.ProtocolRevokeAuthorizationRequest{}),
	reflect.TypeOf(app.ProtocolLogoutRequest{}),
	reflect.TypeOf(app.DiagnosticsConfigSummary{}),
	reflect.TypeOf(app.DiagnosticsErrorEntry{}),
	reflect.TypeOf(app.DiagnosticsErrorList{}),
	reflect.TypeOf(app.DiagnosticsErrorsRequest{}),
	reflect.TypeOf(app.DiagnosticsExport{}),
	reflect.TypeOf(app.DiagnosticsQueueCount{}),
	reflect.TypeOf(app.DiagnosticsQueueStatus{}),
	reflect.TypeOf(app.DiagnosticsReloadField{}),
	reflect.TypeOf(app.DiagnosticsReport{}),
	reflect.TypeOf(app.DiagnosticsRequest{}),
	reflect.TypeOf(app.DiagnosticsStorageHealth{}),
	reflect.TypeOf(app.DiagnosticsVersion{}),
	reflect.TypeOf(app.SettingField{}),
	reflect.TypeOf(app.SettingValidationError{}),
	reflect.TypeOf(app.SettingsFieldsRequest{}),
	reflect.TypeOf(app.SettingsRestoreSensitiveRequest{}),
	reflect.TypeOf(app.SettingsRestoreSensitiveResult{}),
	reflect.TypeOf(app.SettingsStatus{}),
	reflect.TypeOf(app.SettingsStatusRequest{}),
	reflect.TypeOf(app.SettingsUpdateRequest{}),
	reflect.TypeOf(app.SettingsUpdateResult{}),
	reflect.TypeOf(app.SettingsValidateRequest{}),
	reflect.TypeOf(app.SettingsValidation{}),
	reflect.TypeOf(app.SettingsView{}),
	reflect.TypeOf(app.AdminCancelInvitationRequest{}),
	reflect.TypeOf(app.AdminCreateInvitationRequest{}),
	reflect.TypeOf(app.AdminDeletionPreview{}),
	reflect.TypeOf(app.AdminDeletionResult{}),
	reflect.TypeOf(app.AdminInvitation{}),
	reflect.TypeOf(app.AdminInvitationCancelResult{}),
	reflect.TypeOf(app.AdminInvitationCreateResult{}),
	reflect.TypeOf(app.AdminInvitationList{}),
	reflect.TypeOf(app.AdminInvitationRequest{}),
	reflect.TypeOf(app.AdminInvitationRole{}),
	reflect.TypeOf(app.AdminListInvitationsRequest{}),
	reflect.TypeOf(app.AdminListRegistrationsRequest{}),
	reflect.TypeOf(app.AdminRegistration{}),
	reflect.TypeOf(app.AdminRegistrationDecisionRequest{}),
	reflect.TypeOf(app.AdminRegistrationDecisionResult{}),
	reflect.TypeOf(app.AdminRegistrationList{}),
	reflect.TypeOf(app.AdminRegistrationRequest{}),
	reflect.TypeOf(app.AdminUserBatchCancelRequest{}),
	reflect.TypeOf(app.AdminUserBatchExportRequest{}),
	reflect.TypeOf(app.AdminUserBatchImportRequest{}),
	reflect.TypeOf(app.AdminUserBatchJob{}),
	reflect.TypeOf(app.AdminUserBatchJobList{}),
	reflect.TypeOf(app.AdminUserBatchJobRequest{}),
	reflect.TypeOf(app.AdminUserBatchJobStart{}),
	reflect.TypeOf(app.AdminUserBatchListJobsRequest{}),
	reflect.TypeOf(app.AdminUserBatchParseError{}),
	reflect.TypeOf(app.AdminUserBatchPrecheckRequest{}),
	reflect.TypeOf(app.AdminUserBatchPrecheckResult{}),
	reflect.TypeOf(app.AdminUserBatchRow{}),
	reflect.TypeOf(app.AdminUserBatchRowList{}),
	reflect.TypeOf(app.AdminUserBatchRowsRequest{}),
	reflect.TypeOf(app.AdminUserState{}),
	reflect.TypeOf(app.AdminUserStateChange{}),
	reflect.TypeOf(app.AdminUserStateRequest{}),
	reflect.TypeOf(app.ChangeOwnPasswordRequest{}),
	reflect.TypeOf(app.PasswordChangeResult{}),
	reflect.TypeOf(app.AdminUserValidity{}),
	reflect.TypeOf(app.AdminUserValidityRequest{}),
	reflect.TypeOf(app.AdminUserValidityChange{}),
}

// Runtime 域 accessor 的编译期引用。
var (
	_ = (*app.Runtime).Diagnostics
	_ = (*app.Runtime).Settings
	_ = (*app.Runtime).Backup
	_ = (*app.Runtime).Support
	_ = (*app.Runtime).ManualRecovery
	_ = (*app.Runtime).Protocol
	_ = (*app.Runtime).ProtocolRevocation
	_ = (*app.Runtime).UserLifecycle
	_ = (*app.Runtime).Sessions
	_ = (*app.Runtime).Admin
)

// 框架入口的编译期引用：外部宿主可用于打开真实运行时。
var _ = app.Open
var _ = login.Default
var _ = login.NewRequestID
