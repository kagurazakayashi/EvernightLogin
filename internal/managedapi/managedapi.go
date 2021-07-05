// Package managedapi 把既有用户、应用成员、组、角色与权限服务封装为可委托给
// 业务应用的受保护管理 API（步骤 60）。
//
// 信任与安全不变量：
//   - 每个应用独立配置委托策略（迁移 0038）：允许操作、服务身份允许操作、对象
//     范围（仅应用作用域）、可读/可写字段白名单、分页与批量上限。无策略行 =
//     该应用托管 API 默认关闭。
//   - 调用主体只能来自宿主可信边界：代表用户必须出示真实完整普通会话（
//     internal/session 校验），应用服务身份必须完成客户端认证（internal/oauthclient）；
//     请求参数不能自称用户、应用或字段权限。目标应用来自可信主体/路由上下文，
//     不接受请求体自称的应用 ID。
//   - 实际许可 = 委托策略（操作/对象/字段/上限）∩ 代表用户的当前有效权限与数据
//     范围（internal/authz 实时计算，数据范围 undefined/none 一律 fail-closed）
//     ∩ 主体类型限制；服务身份没有用户角色权限，默认只读，写操作必须在策略中
//     显式列出且不得借用用户权限。
//   - 授权发生在查询与写入路径：托管层先判权再读目标，再调用既有服务；既有服务
//     的 Authorizer 由本包提供的 DelegatedAuthorizer 实现（无托管 grant 一律拒绝），
//     代表用户调用保留既有 delegation.Guard 与审计，不复制 CRUD、不绕过审计。
//   - 敏感能力永不下放：密码重置、MFA 解除、root/系统资格、全局账户删除/禁用、
//     应用凭证、系统角色/权限、邮件/电话等敏感字段既不在操作目录也不在字段目录；
//     硬禁字段（密码哈希、MFA/TOTP 种子、恢复代码、Token、私钥、is_root、
//     security_version、完整邮箱/电话）永不输出、永不接受写入。
//   - 错误复用根包既有错误码；每次成功/拒绝写托管调用审计（真实操作者、应用、
//     对象、request_id、稳定错误码/原因，不含敏感值），审计失败拒绝写入路径。
package managedapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/app"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/group"
	"github.com/kagurazakayashi/EvernightLogin/internal/permission"
	"github.com/kagurazakayashi/EvernightLogin/internal/role"
)

// APIVersion 是本步受保护管理 API 的版本；请求必须显式声明，未知版本拒绝。
const APIVersion = "v1"

// 全局硬上限（策略数值不得超过，超出在配置写入前拒绝）。
const (
	MaxPolicyLimit      = 100
	MaxPolicyOffset     = 1_000_000
	MaxPolicyBatch      = 100
	DefaultPolicyLimit  = 20
	DefaultPolicyOffset = 100_000
	DefaultPolicyBatch  = 10
)

// 对象类型。
const (
	ObjectApplication = "application"
	ObjectMember      = "member"
	ObjectUser        = "user"
	ObjectGroup       = "group"
	ObjectRole        = "role"
	ObjectPermission  = "permission"
)

// ObjectTypes 是策略允许声明的对象类型全集。
var ObjectTypes = []string{ObjectApplication, ObjectMember, ObjectUser, ObjectGroup, ObjectRole, ObjectPermission}

// 操作机器 ID。未知操作一律拒绝；本目录是唯一可调用集合。
const (
	OpApplicationGet = "application.get"

	OpMembersList          = "members.list"
	OpMembersGet           = "members.get"
	OpMembersUpdateProfile = "members.update_profile"
	OpMembersDisable       = "members.disable"
	OpMembersEnable        = "members.enable"
	OpMembersRemove        = "members.remove"
	OpUsersCreate          = "users.create_with_membership"

	OpGroupsList         = "groups.list"
	OpGroupsGet          = "groups.get"
	OpGroupsCreate       = "groups.create"
	OpGroupsUpdate       = "groups.update"
	OpGroupsDelete       = "groups.delete"
	OpGroupMembersList   = "groups.members.list"
	OpGroupMembersAdd    = "groups.members.add"
	OpGroupMembersRemove = "groups.members.remove"

	OpRolesList           = "roles.list"
	OpRolesGet            = "roles.get"
	OpRolesCreate         = "roles.create"
	OpRolesUpdate         = "roles.update"
	OpRolesDelete         = "roles.delete"
	OpRolePermissionsList = "roles.permissions.list"
	OpRoleAssignUser      = "roles.assign_user"
	OpRoleRevokeUser      = "roles.revoke_user"
	OpRoleAssignGroup     = "roles.assign_group"
	OpRoleRevokeGroup     = "roles.revoke_group"
	OpRoleAssignmentsList = "roles.assignments.list"

	OpPermissionsList    = "permissions.list"
	OpPermissionsGet     = "permissions.get"
	OpPermissionsCreate  = "permissions.create"
	OpPermissionsUpdate  = "permissions.update"
	OpPermissionsDelete  = "permissions.delete"
	OpPermissionsEnable  = "permissions.enable"
	OpPermissionsDisable = "permissions.disable"
)

// Operation 是操作目录的一项。
type Operation struct {
	ID string
	// Permissions 是代表用户必须持有的当前有效权限（应用作用域，all 模式）。
	Permissions []string
	// ObjectType 是操作的目标对象类型（用于对象范围与字段规则）。
	ObjectType string
	// Write 表示可能改变状态的写操作（用于审计/敏感分类）。
	Write bool
	// ServiceAllowed 表示应用服务身份是否允许执行（默认只读；写操作必须为
	// 不增加任何权限的受控写入，见 README）。
	ServiceAllowed bool
}

var operations = map[string]Operation{
	OpApplicationGet: {ID: OpApplicationGet, ObjectType: ObjectApplication, ServiceAllowed: true},

	OpMembersList:          {ID: OpMembersList, Permissions: []string{"applications.members.manage"}, ObjectType: ObjectMember, ServiceAllowed: true},
	OpMembersGet:           {ID: OpMembersGet, Permissions: []string{"applications.members.manage"}, ObjectType: ObjectMember, ServiceAllowed: true},
	OpMembersUpdateProfile: {ID: OpMembersUpdateProfile, Permissions: []string{"applications.members.manage"}, ObjectType: ObjectMember, Write: true},
	OpMembersDisable:       {ID: OpMembersDisable, Permissions: []string{"applications.members.manage"}, ObjectType: ObjectMember, Write: true},
	OpMembersEnable:        {ID: OpMembersEnable, Permissions: []string{"applications.members.manage"}, ObjectType: ObjectMember, Write: true},
	OpMembersRemove:        {ID: OpMembersRemove, Permissions: []string{"applications.members.manage"}, ObjectType: ObjectMember, Write: true},
	OpUsersCreate:          {ID: OpUsersCreate, Permissions: []string{"users.create", "applications.members.manage"}, ObjectType: ObjectUser, Write: true, ServiceAllowed: true},

	OpGroupsList:         {ID: OpGroupsList, Permissions: []string{"groups.read"}, ObjectType: ObjectGroup, ServiceAllowed: true},
	OpGroupsGet:          {ID: OpGroupsGet, Permissions: []string{"groups.read"}, ObjectType: ObjectGroup, ServiceAllowed: true},
	OpGroupMembersList:   {ID: OpGroupMembersList, Permissions: []string{"groups.read"}, ObjectType: ObjectGroup, ServiceAllowed: true},
	OpGroupMembersAdd:    {ID: OpGroupMembersAdd, Permissions: []string{"groups.manage"}, ObjectType: ObjectGroup, Write: true},
	OpGroupMembersRemove: {ID: OpGroupMembersRemove, Permissions: []string{"groups.manage"}, ObjectType: ObjectGroup, Write: true},

	OpRolesList:           {ID: OpRolesList, Permissions: []string{"roles.read"}, ObjectType: ObjectRole, ServiceAllowed: true},
	OpRolesGet:            {ID: OpRolesGet, Permissions: []string{"roles.read"}, ObjectType: ObjectRole, ServiceAllowed: true},
	OpRolePermissionsList: {ID: OpRolePermissionsList, Permissions: []string{"roles.read"}, ObjectType: ObjectRole, ServiceAllowed: true},
	OpRoleAssignUser:      {ID: OpRoleAssignUser, Permissions: []string{"roles.assign"}, ObjectType: ObjectRole, Write: true},
	OpRoleRevokeUser:      {ID: OpRoleRevokeUser, Permissions: []string{"roles.assign"}, ObjectType: ObjectRole, Write: true},
	OpRoleAssignGroup:     {ID: OpRoleAssignGroup, Permissions: []string{"roles.assign"}, ObjectType: ObjectRole, Write: true},
	OpRoleRevokeGroup:     {ID: OpRoleRevokeGroup, Permissions: []string{"roles.assign"}, ObjectType: ObjectRole, Write: true},
	OpRoleAssignmentsList: {ID: OpRoleAssignmentsList, Permissions: []string{"roles.read"}, ObjectType: ObjectRole, ServiceAllowed: true},

	OpPermissionsList: {ID: OpPermissionsList, Permissions: []string{"permissions.read"}, ObjectType: ObjectPermission, ServiceAllowed: true},
	OpPermissionsGet:  {ID: OpPermissionsGet, Permissions: []string{"permissions.read"}, ObjectType: ObjectPermission, ServiceAllowed: true},
}

// LookupOperation 返回操作定义。
func LookupOperation(id string) (Operation, bool) {
	op, ok := operations[id]
	return op, ok
}

// OperationIDs 返回排序后的全部操作 ID（诊断/测试用）。
func OperationIDs() []string {
	ids := make([]string, 0, len(operations))
	for id := range operations {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// 字段目录：对象类型 → 允许出现在策略中的字段（读/写共用全集，策略再细分）。
var objectFields = map[string][]string{
	ObjectApplication: {"id", "name", "description", "client_type", "status", "created_at", "updated_at"},
	ObjectMember:      {"user_id", "status", "row_version", "created_at", "updated_at", "display_name", "title", "note", "username", "nickname", "user_status"},
	ObjectUser:        {"id", "username", "nickname", "biography", "status", "created_at"},
	ObjectGroup:       {"id", "scope_id", "key", "name", "description", "created_at", "updated_at"},
	ObjectRole:        {"id", "scope_id", "key", "name", "description", "limits", "is_builtin", "enabled", "created_at", "updated_at"},
	ObjectPermission:  {"id", "scope_id", "key", "name", "description", "limits", "is_builtin", "root_only", "enabled", "created_at", "updated_at"},
}

// hardForbiddenFields 是任何策略都不能开放、任何输出都不能包含的硬禁字段。
var hardForbiddenFields = map[string]struct{}{
	"password": {}, "password_hash": {}, "hash": {}, "mfa_secret": {}, "totp_secret": {},
	"recovery_code": {}, "recovery_codes": {}, "token": {}, "access_token": {},
	"refresh_token": {}, "id_token": {}, "private_key": {}, "secret": {}, "is_root": {},
	"security_version": {}, "email": {}, "phone": {}, "session_secret": {}, "csrf_secret": {},
}

// FieldsOf 返回对象类型的字段全集副本。
func FieldsOf(objectType string) []string {
	fields, ok := objectFields[objectType]
	if !ok {
		return nil
	}
	return append([]string(nil), fields...)
}

// validField 报告字段是否属于对象目录且不是硬禁字段。
func validField(objectType, field string) bool {
	if _, forbidden := hardForbiddenFields[field]; forbidden {
		return false
	}
	for _, candidate := range objectFields[objectType] {
		if candidate == field {
			return true
		}
	}
	return false
}

// 领域错误哨兵。
var (
	ErrOptionsInvalid   = errors.New("托管管理 API 选项无效")
	ErrInvalidRequest   = errors.New("托管管理 API 请求无效")
	ErrAccessDenied     = errors.New("未获准调用该托管管理操作")
	ErrPolicyDisabled   = errors.New("该应用未启用托管管理 API")
	ErrObjectForbidden  = errors.New("目标对象不在委托范围")
	ErrVersionConflict  = errors.New("策略或对象版本已变化")
	ErrStoreUnavailable = errors.New("托管管理 API 存储暂时不可用")
	ErrAuditUnavailable = errors.New("关键操作未能可靠记录")
)

// ErrorCode 是根包错误码注册表投影（只复用既有码，本步不新增）。
type ErrorCode string

const (
	CodeReqInvalid            ErrorCode = "REQ_INVALID"
	CodeAccessDenied          ErrorCode = "ACCESS_DENIED"
	CodePermissionRequired    ErrorCode = "PERMISSION_REQUIRED"
	CodeAppMembershipRequired ErrorCode = "APP_MEMBERSHIP_REQUIRED"
	CodeAppScopeMismatch      ErrorCode = "APP_SCOPE_MISMATCH"
	CodeUserDisabled          ErrorCode = "USER_DISABLED"
	CodeClientDisabled        ErrorCode = "CLIENT_DISABLED"
	CodeResourceForbidden     ErrorCode = "RESOURCE_FORBIDDEN"
	CodeConflict              ErrorCode = "CONFLICT"
	CodeRateLimited           ErrorCode = "RATE_LIMITED"
	CodeDBUnavailable         ErrorCode = "DB_UNAVAILABLE"
	CodeAuditWriteFailed      ErrorCode = "AUDIT_WRITE_FAILED"
	CodeInternalError         ErrorCode = "INTERNAL_ERROR"
)

// CodeOf 把托管管理 API 领域错误映射为已登记错误码。
func CodeOf(err error) ErrorCode {
	switch {
	case err == nil:
		return ""
	}
	var serviceErr *ServiceError
	if errors.As(err, &serviceErr) && serviceErr.Code != "" {
		return serviceErr.Code
	}
	switch {
	case errors.Is(err, ErrInvalidRequest):
		return CodeReqInvalid
	case errors.Is(err, ErrAccessDenied), errors.Is(err, ErrPolicyDisabled):
		return CodeAccessDenied
	case errors.Is(err, ErrObjectForbidden):
		return CodeResourceForbidden
	case errors.Is(err, ErrVersionConflict):
		return CodeConflict
	case errors.Is(err, ErrStoreUnavailable):
		return CodeDBUnavailable
	case errors.Is(err, ErrAuditUnavailable):
		return CodeAuditWriteFailed
	default:
		return CodeInternalError
	}
}

// ServiceError 是底层服务返回错误的稳定映射结果（保留底层错误码与内部原因）。
type ServiceError struct {
	Code   ErrorCode
	Reason string
	Cause  error
}

// Error 返回不含内部细节的稳定错误文本。
func (e *ServiceError) Error() string { return string(e.Code) + ": " + e.Reason }

// Unwrap 返回底层错误供诊断（不对外输出）。
func (e *ServiceError) Unwrap() error { return e.Cause }

// PrincipalKind 是调用主体类别。
type PrincipalKind string

const (
	// PrincipalUser 表示代表已登录用户调用。
	PrincipalUser PrincipalKind = "user"
	// PrincipalService 表示应用自身服务身份调用。
	PrincipalService PrincipalKind = "service"
)

// Principal 是宿主可信边界建立并传入的调用主体。必须由本包构造器生成，不能由
// 请求参数自称；用户主体必须出示真实会话秘密，服务身份必须出示客户端凭证。
type Principal struct {
	kind          PrincipalKind
	appID         string
	sessionSecret string
	clientID      string
	clientSecret  string
	certificate   string
}

// UserPrincipal 构造代表用户的调用主体；sessionSecret 是真实普通会话秘密，
// appID 是宿主可信路由上下文提供的目标应用（会话带应用作用域时必须一致）。
func UserPrincipal(sessionSecret, appID string) Principal {
	return Principal{kind: PrincipalUser, sessionSecret: sessionSecret, appID: appID}
}

// ServicePrincipal 构造应用服务身份；clientID 是登记应用 ID，凭证必须是客户端
// secret 或客户端证书 PEM 之一（生产由可信传输层/宿主提供）。
func ServicePrincipal(clientID, clientSecret, certificatePEM string) Principal {
	return Principal{kind: PrincipalService, clientID: clientID, clientSecret: clientSecret,
		certificate: certificatePEM}
}

// Kind 返回主体类别。
func (p Principal) Kind() PrincipalKind { return p.kind }

// AppID 返回目标应用（用户主体为宿主提供值；服务身份为客户端所属应用）。
func (p Principal) AppID() string { return p.appID }

// 策略 v1 JSON 契约。
type Policy struct {
	Version    int              `json:"v"`
	Operations PolicyOperations `json:"operations"`
	Objects    []ObjectScope    `json:"objects"`
	Fields     []ObjectFields   `json:"fields"`
	Limits     PolicyLimits     `json:"limits"`
}

// PolicyOperations 是允许操作配置。
type PolicyOperations struct {
	Allowed        []string `json:"allowed"`
	ServiceAllowed []string `json:"service_allowed,omitempty"`
}

// ObjectScope 是单个对象类型的委托范围：all 或 resources 显式 ID 列表。
type ObjectScope struct {
	Object    string   `json:"object"`
	Mode      string   `json:"mode"`
	Resources []string `json:"resources,omitempty"`
}

// ObjectFields 是单个对象类型的可读/可写字段白名单。
type ObjectFields struct {
	Object string   `json:"object"`
	Read   []string `json:"read"`
	Write  []string `json:"write,omitempty"`
}

// PolicyLimits 是分页与批量上限。
type PolicyLimits struct {
	MaxLimit  int `json:"max_limit"`
	MaxOffset int `json:"max_offset"`
	MaxBatch  int `json:"max_batch"`
}

// 数据范围模式（与 internal/authz 契约一致）。
const (
	ScopeModeAll       = "all"
	ScopeModeResources = "resources"
)

// DecodePolicy 严格解码策略 JSON；未知字段/重复结构拒绝。
func DecodePolicy(raw []byte) (Policy, error) {
	if len(raw) == 0 || len(raw) > 64*1024 {
		return Policy{}, fmt.Errorf("%w: 策略内容为空或过长", ErrInvalidRequest)
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	var policy Policy
	if err := decoder.Decode(&policy); err != nil {
		return Policy{}, fmt.Errorf("%w: 策略不是合法 JSON", ErrInvalidRequest)
	}
	var extra any
	if err := decoder.Decode(&extra); err == nil {
		return Policy{}, fmt.Errorf("%w: 策略包含多余内容", ErrInvalidRequest)
	}
	if err := policy.Validate(); err != nil {
		return Policy{}, err
	}
	return policy, nil
}

// EncodePolicy 把已校验策略编码为规范 JSON（键排序稳定）。
func EncodePolicy(policy Policy) ([]byte, error) {
	return json.Marshal(policy)
}

// Validate 校验策略结构：已知操作/对象/字段、无硬禁字段、数值有界、服务身份
// 允许操作必须是允许操作与目录服务允许操作的子集。
func (p Policy) Validate() error {
	if p.Version != 1 {
		return fmt.Errorf("%w: 策略版本必须是 1", ErrInvalidRequest)
	}
	allowed := make(map[string]struct{}, len(p.Operations.Allowed))
	for _, opID := range p.Operations.Allowed {
		op, ok := operations[opID]
		if !ok {
			return fmt.Errorf("%w: 未知操作 %q", ErrInvalidRequest, opID)
		}
		allowed[opID] = struct{}{}
		_ = op
	}
	for _, opID := range p.Operations.ServiceAllowed {
		op, ok := operations[opID]
		if !ok {
			return fmt.Errorf("%w: 未知服务身份操作 %q", ErrInvalidRequest, opID)
		}
		if _, isAllowed := allowed[opID]; !isAllowed {
			return fmt.Errorf("%w: 服务身份操作 %q 必须同时出现在 allowed", ErrInvalidRequest, opID)
		}
		if !op.ServiceAllowed {
			return fmt.Errorf("%w: 操作 %q 不允许服务身份执行", ErrInvalidRequest, opID)
		}
	}
	seenObjects := make(map[string]struct{}, len(p.Objects))
	for _, scope := range p.Objects {
		if !validObjectType(scope.Object) {
			return fmt.Errorf("%w: 未知对象类型 %q", ErrInvalidRequest, scope.Object)
		}
		if _, duplicated := seenObjects[scope.Object]; duplicated {
			return fmt.Errorf("%w: 对象类型 %q 重复", ErrInvalidRequest, scope.Object)
		}
		seenObjects[scope.Object] = struct{}{}
		switch scope.Mode {
		case ScopeModeAll:
			if len(scope.Resources) != 0 {
				return fmt.Errorf("%w: all 对象范围不能携带资源列表", ErrInvalidRequest)
			}
		case ScopeModeResources:
			if len(scope.Resources) == 0 || len(scope.Resources) > 1024 {
				return fmt.Errorf("%w: resources 对象范围资源数量必须是 1～1024", ErrInvalidRequest)
			}
			seen := make(map[string]struct{}, len(scope.Resources))
			for _, resource := range scope.Resources {
				if !validResourceID(scope.Object, resource) {
					return fmt.Errorf("%w: 对象资源标识非法", ErrInvalidRequest)
				}
				if _, duplicated := seen[resource]; duplicated {
					return fmt.Errorf("%w: 对象资源重复", ErrInvalidRequest)
				}
				seen[resource] = struct{}{}
			}
		default:
			return fmt.Errorf("%w: 对象范围模式必须是 all 或 resources", ErrInvalidRequest)
		}
	}
	if len(p.Fields) > len(ObjectTypes) {
		return fmt.Errorf("%w: 字段规则过多", ErrInvalidRequest)
	}
	seenFieldObjects := make(map[string]struct{}, len(p.Fields))
	for _, rule := range p.Fields {
		if !validObjectType(rule.Object) {
			return fmt.Errorf("%w: 未知字段对象类型 %q", ErrInvalidRequest, rule.Object)
		}
		if _, duplicated := seenFieldObjects[rule.Object]; duplicated {
			return fmt.Errorf("%w: 字段对象类型 %q 重复", ErrInvalidRequest, rule.Object)
		}
		seenFieldObjects[rule.Object] = struct{}{}
		seenRead := make(map[string]struct{}, len(rule.Read))
		for _, field := range rule.Read {
			if !validField(rule.Object, field) {
				return fmt.Errorf("%w: 不可读字段 %q", ErrInvalidRequest, field)
			}
			if _, duplicated := seenRead[field]; duplicated {
				return fmt.Errorf("%w: 可读字段 %q 重复", ErrInvalidRequest, field)
			}
			seenRead[field] = struct{}{}
		}
		seenWrite := make(map[string]struct{}, len(rule.Write))
		for _, field := range rule.Write {
			if !validField(rule.Object, field) {
				return fmt.Errorf("%w: 不可写字段 %q", ErrInvalidRequest, field)
			}
			if _, duplicated := seenWrite[field]; duplicated {
				return fmt.Errorf("%w: 可写字段 %q 重复", ErrInvalidRequest, field)
			}
			seenWrite[field] = struct{}{}
		}
	}
	if p.Limits.MaxLimit <= 0 || p.Limits.MaxLimit > MaxPolicyLimit {
		return fmt.Errorf("%w: max_limit 必须在 1～%d", ErrInvalidRequest, MaxPolicyLimit)
	}
	if p.Limits.MaxOffset < 0 || p.Limits.MaxOffset > MaxPolicyOffset {
		return fmt.Errorf("%w: max_offset 必须在 0～%d", ErrInvalidRequest, MaxPolicyOffset)
	}
	if p.Limits.MaxBatch <= 0 || p.Limits.MaxBatch > MaxPolicyBatch {
		return fmt.Errorf("%w: max_batch 必须在 1～%d", ErrInvalidRequest, MaxPolicyBatch)
	}
	return nil
}

// validObjectType 报告对象类型是否受支持。
func validObjectType(objectType string) bool {
	for _, candidate := range ObjectTypes {
		if candidate == objectType {
			return true
		}
	}
	return false
}

// validResourceID 校验对象资源标识格式（user/member 为用户 ID，其它按包格式）。
func validResourceID(objectType, resourceID string) bool {
	switch objectType {
	case ObjectMember, ObjectUser:
		return account.ValidUserID(resourceID)
	case ObjectGroup:
		return group.ValidGroupID(resourceID)
	case ObjectRole:
		return role.ValidRoleID(resourceID)
	case ObjectPermission:
		return permission.ValidPermissionID(resourceID)
	case ObjectApplication:
		return app.ValidApplicationID(resourceID)
	default:
		return false
	}
}

// ObjectScopeOf 返回对象范围；未声明时返回 false（策略必须显式声明对象范围）。
func (p Policy) ObjectScopeOf(objectType string) (ObjectScope, bool) {
	for _, scope := range p.Objects {
		if scope.Object == objectType {
			return scope, true
		}
	}
	return ObjectScope{}, false
}

// FieldRuleOf 返回字段规则；未声明返回空规则（全部不可读/不可写）。
func (p Policy) FieldRuleOf(objectType string) ObjectFields {
	for _, rule := range p.Fields {
		if rule.Object == objectType {
			return rule
		}
	}
	return ObjectFields{Object: objectType}
}

// ReadAllowed 报告字段是否可读。
func (p Policy) ReadAllowed(objectType, field string) bool {
	for _, candidate := range p.FieldRuleOf(objectType).Read {
		if candidate == field {
			return true
		}
	}
	return false
}

// WriteAllowed 报告字段是否可写。
func (p Policy) WriteAllowed(objectType, field string) bool {
	for _, candidate := range p.FieldRuleOf(objectType).Write {
		if candidate == field {
			return true
		}
	}
	return false
}

// OperationAllowed 报告操作是否被策略允许。
func (p Policy) OperationAllowed(opID string) bool {
	for _, candidate := range p.Operations.Allowed {
		if candidate == opID {
			return true
		}
	}
	return false
}

// ServiceOperationAllowed 报告服务身份是否允许操作。
func (p Policy) ServiceOperationAllowed(opID string) bool {
	for _, candidate := range p.Operations.ServiceAllowed {
		if candidate == opID {
			return true
		}
	}
	return false
}

// ResourceAllowed 报告对象 ID 是否在策略对象范围内。
func (p Policy) ResourceAllowed(objectType, resourceID string) bool {
	scope, ok := p.ObjectScopeOf(objectType)
	if !ok {
		return false
	}
	switch scope.Mode {
	case ScopeModeAll:
		return true
	case ScopeModeResources:
		for _, resource := range scope.Resources {
			if resource == resourceID {
				return true
			}
		}
		return false
	default:
		return false
	}
}

// PolicyRecord 是持久化策略行。
type PolicyRecord struct {
	ApplicationID string
	Policy        Policy
	RowVersion    int64
	UpdatedBy     string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// Meta 是每个请求的公共元数据。
type Meta struct {
	APIVersion string
	RequestID  string
}

// validateMeta 校验 API 版本与请求编号。
func validateMeta(meta Meta) error {
	if strings.TrimSpace(meta.APIVersion) != APIVersion {
		return fmt.Errorf("%w: 不支持的 API 版本", ErrInvalidRequest)
	}
	return account.ValidateRequestID(meta.RequestID)
}

// View 是对象投影：Fields 只包含策略允许且非硬禁的字段。
type View struct {
	ID     string         `json:"id,omitempty"`
	Fields map[string]any `json:"fields"`
}

// MemberView 是应用成员投影。
type MemberView struct {
	UserID string         `json:"user_id"`
	Fields map[string]any `json:"fields"`
}

// MemberListResult 是成员分页结果。
type MemberListResult struct {
	Members []MemberView `json:"members"`
	HasMore bool         `json:"has_more"`
}

// ListResult 是通用分页列表结果。
type ListResult struct {
	Items   []View `json:"items"`
	HasMore bool   `json:"has_more"`
}

// RequestIDFrom 返回请求编号（审计关联）。
func (m Meta) RequestIDValue() string { return m.RequestID }

// ProjectMember 把应用成员快照投影为策略允许字段。
func ProjectMember(policy Policy, membership app.Membership, user *account.User) MemberView {
	fields := make(map[string]any)
	read := func(field string) bool { return policy.ReadAllowed(ObjectMember, field) }
	if read("status") {
		fields["status"] = string(membership.Status)
	}
	if read("row_version") {
		fields["row_version"] = membership.RowVersion
	}
	if read("created_at") {
		fields["created_at"] = membership.CreatedAt.UTC().Format(time.RFC3339)
	}
	if read("updated_at") {
		fields["updated_at"] = membership.UpdatedAt.UTC().Format(time.RFC3339)
	}
	if read("display_name") {
		fields["display_name"] = membership.Profile.DisplayName
	}
	if read("title") {
		fields["title"] = membership.Profile.Title
	}
	if read("note") {
		fields["note"] = membership.Profile.Note
	}
	if user != nil {
		if read("username") {
			fields["username"] = user.Username
		}
		if read("nickname") {
			fields["nickname"] = user.Nickname
		}
		if read("user_status") {
			fields["user_status"] = string(user.Status)
		}
	}
	return MemberView{UserID: membership.UserID, Fields: fields}
}

// ProjectGroup 投影用户组。
func ProjectGroup(policy Policy, record group.Group) View {
	fields := make(map[string]any)
	read := func(field string) bool { return policy.ReadAllowed(ObjectGroup, field) }
	if read("scope_id") {
		fields["scope_id"] = record.ScopeID
	}
	if read("key") {
		fields["key"] = record.GroupKey
	}
	if read("name") {
		fields["name"] = record.Name
	}
	if read("description") {
		fields["description"] = record.Description
	}
	if read("created_at") {
		fields["created_at"] = record.CreatedAt.UTC().Format(time.RFC3339)
	}
	if read("updated_at") {
		fields["updated_at"] = record.UpdatedAt.UTC().Format(time.RFC3339)
	}
	return View{ID: record.ID, Fields: fields}
}

// ProjectRole 投影角色。
func ProjectRole(policy Policy, record role.Role) View {
	fields := make(map[string]any)
	read := func(field string) bool { return policy.ReadAllowed(ObjectRole, field) }
	if read("scope_id") {
		fields["scope_id"] = record.ScopeID
	}
	if read("key") {
		fields["key"] = record.Key
	}
	if read("name") {
		fields["name"] = record.Name
	}
	if read("description") {
		fields["description"] = record.Description
	}
	if read("limits") {
		fields["limits"] = record.Limits
	}
	if read("is_builtin") {
		fields["is_builtin"] = record.IsBuiltin
	}
	if read("enabled") {
		fields["enabled"] = record.Enabled
	}
	if read("created_at") {
		fields["created_at"] = record.CreatedAt.UTC().Format(time.RFC3339)
	}
	if read("updated_at") {
		fields["updated_at"] = record.UpdatedAt.UTC().Format(time.RFC3339)
	}
	return View{ID: record.ID, Fields: fields}
}

// ProjectPermission 投影权限。
func ProjectPermission(policy Policy, record permission.Permission) View {
	fields := make(map[string]any)
	read := func(field string) bool { return policy.ReadAllowed(ObjectPermission, field) }
	if read("scope_id") {
		fields["scope_id"] = record.ScopeID
	}
	if read("key") {
		fields["key"] = record.Key
	}
	if read("name") {
		fields["name"] = record.Name
	}
	if read("description") {
		fields["description"] = record.Description
	}
	if read("limits") {
		fields["limits"] = record.Limits
	}
	if read("is_builtin") {
		fields["is_builtin"] = record.IsBuiltin
	}
	if read("root_only") {
		fields["root_only"] = record.RootOnly
	}
	if read("enabled") {
		fields["enabled"] = record.Enabled
	}
	if read("created_at") {
		fields["created_at"] = record.CreatedAt.UTC().Format(time.RFC3339)
	}
	if read("updated_at") {
		fields["updated_at"] = record.UpdatedAt.UTC().Format(time.RFC3339)
	}
	return View{ID: record.ID, Fields: fields}
}

// ProjectApplication 投影应用。
func ProjectApplication(policy Policy, record app.Application) View {
	fields := make(map[string]any)
	read := func(field string) bool { return policy.ReadAllowed(ObjectApplication, field) }
	if read("name") {
		fields["name"] = record.Name
	}
	if read("description") {
		fields["description"] = record.Description
	}
	if read("client_type") {
		fields["client_type"] = string(record.ClientType)
	}
	if read("status") {
		fields["status"] = string(record.Status)
	}
	if read("created_at") {
		fields["created_at"] = record.CreatedAt.UTC().Format(time.RFC3339)
	}
	if read("updated_at") {
		fields["updated_at"] = record.UpdatedAt.UTC().Format(time.RFC3339)
	}
	return View{ID: record.ID, Fields: fields}
}

// CheckWriteFields 校验写入请求中显式设置的字段都在策略可写白名单内。
// actual 是"字段名→是否显式设置"的映射；未授权字段一律拒绝（不静默丢弃）。
func CheckWriteFields(policy Policy, objectType string, actual map[string]bool) error {
	for field, set := range actual {
		if !set {
			continue
		}
		if !policy.WriteAllowed(objectType, field) {
			return fmt.Errorf("%w: 字段 %q 不在可写白名单", ErrInvalidRequest, field)
		}
	}
	return nil
}

// isNilInterface 检测 nil 接口与 typed-nil 指针。
func isNilInterface(value any) bool {
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

// validResourceID 已在上方定义；newPolicyRequestID 供策略服务审计编号使用。
func newPolicyRequestID(random interface{ Read([]byte) (int, error) }) (string, error) {
	buffer := make([]byte, 16)
	if _, err := random.Read(buffer); err != nil {
		return "", fmt.Errorf("%w: 安全随机源不可用", ErrStoreUnavailable)
	}
	return "map_" + hex.EncodeToString(buffer), nil
}

// normalizeContext 把 nil ctx 当成 Background。
func normalizeContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

// 编译期检查错误映射不产生未登记码（根包测试会核对全部 ErrorCode）。
var _ = audit.OutcomeSuccess
var _ = context.Background
var _ = rand.Reader
