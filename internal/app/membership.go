package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

const (
	// MaxMemberDisplayNameRunes 是应用内显示名的字符上限；为空表示沿用全局资料。
	MaxMemberDisplayNameRunes = 64
	// MaxMemberTitleRunes 是应用内职位/头衔的字符上限。
	MaxMemberTitleRunes = 64
	// MaxMemberNoteRunes 是应用内备注的字符上限。
	MaxMemberNoteRunes = 500
	// memberProfileVersion 是应用内成员资料的 JSON 结构版本。
	memberProfileVersion = 1
	// maxMemberProfileJSONBytes 限制数据库中被读取的资料 JSON 体积，避免异常数据
	// 放大内存与日志开销。
	maxMemberProfileJSONBytes = 8192
)

// MembershipStatus 是应用内成员状态，与 app_memberships.status 的 CHECK 约束一致。
// 它只影响指定应用，不改变全局账户状态，也不影响同一用户在其他应用中的成员关系。
type MembershipStatus string

const (
	// MembershipActive 表示成员可在该应用内获得业务访问资格（仍需权限判断）。
	MembershipActive MembershipStatus = "active"
	// MembershipDisabled 表示该应用的成员关系被停用；全局账户与其他应用不受影响。
	MembershipDisabled MembershipStatus = "disabled"
)

// Valid 报告成员状态是否已定义。
func (s MembershipStatus) Valid() bool {
	return s == MembershipActive || s == MembershipDisabled
}

// MemberSortField 是应用成员列表允许的排序字段白名单。
type MemberSortField string

const (
	MemberSortCreatedAt MemberSortField = "created_at"
	MemberSortUpdatedAt MemberSortField = "updated_at"
	MemberSortUserID    MemberSortField = "user_id"
)

// Valid 报告成员列表排序字段是否在白名单内。
func (s MemberSortField) Valid() bool {
	switch s {
	case MemberSortCreatedAt, MemberSortUpdatedAt, MemberSortUserID:
		return true
	default:
		return false
	}
}

// MemberProfile 是应用专属成员资料白名单。它只保存指定应用内的展示信息，不会写回
// 全局账户资料；为空字段表示沿用全局资料或留空。
type MemberProfile struct {
	// DisplayName 是该应用内的显示名，可以为空。
	DisplayName string
	// Title 是该应用内的职位/头衔，可以为空。
	Title string
	// Note 是该应用内的备注，可以为空，允许换行。
	Note string
}

// Membership 是一条应用成员关系快照与应用专属资料。
//
// ApplicationID 与 UserID 组成唯一键；Status 是应用内状态；Profile 只属于该应用。
// RowVersion 用于乐观并发控制。
type Membership struct {
	ApplicationID string
	UserID        string
	Status        MembershipStatus
	Profile       MemberProfile
	RowVersion    int64
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// AddMemberRequest 是受控加入应用的请求。它只接受稳定用户 ID 与应用专属资料，
// 不接受用户名、邮箱、全局资料字段或自称的管理身份：知道用户名/邮箱不能用于
// 任意认领账户，只有通过 Authorizer 的受控调用者才能建立成员关系。
type AddMemberRequest struct {
	ApplicationID string
	UserID        string
	Profile       MemberProfile
}

// MemberProfileRequest 是更新应用专属资料的请求；只更新本应用的 profile_json。
type MemberProfileRequest struct {
	ApplicationID      string
	UserID             string
	Profile            MemberProfile
	ExpectedRowVersion int64
}

// MemberStatusRequest 是应用内成员启停请求。
type MemberStatusRequest struct {
	ApplicationID      string
	UserID             string
	ExpectedRowVersion int64
}

// RemoveMemberRequest 是移除应用成员的请求。移除只删除本应用成员关系，不删除全局
// 账户，也不影响其他应用。ExpectedRowVersion 防止删除已经变化的成员关系。
type RemoveMemberRequest struct {
	ApplicationID      string
	UserID             string
	ExpectedRowVersion int64
}

// MemberStatusResult 是应用内成员启停结果。Changed=false 表示已处于目标状态
// （幂等成功）。
type MemberStatusResult struct {
	Membership Membership
	Changed    bool
}

// MemberListRequest 是应用成员列表请求；Status 为空表示不过滤。
type MemberListRequest struct {
	ApplicationID string
	Limit         int
	Offset        int
	Status        MembershipStatus
	Sort          MemberSortField
	Descending    bool
}

// MemberListResult 是应用成员列表结果。
type MemberListResult struct {
	Members []Membership
	HasMore bool
}

// MemberListQuery 是已校验的成员列表查询参数。
type MemberListQuery struct {
	ApplicationID string
	Limit         int
	Offset        int
	Status        MembershipStatus
	Sort          MemberSortField
	Descending    bool
}

// MemberProfileUpdate 是已通过校验的条件资料更新；仓储只更新 profile_json 与
// row_version，不触碰全局用户资料或其他应用。
type MemberProfileUpdate struct {
	ApplicationID      string
	UserID             string
	ExpectedRowVersion int64
	Profile            MemberProfile
	Now                time.Time
}

// MemberStatusChange 是已通过状态机校验的应用内成员启停更新。
type MemberStatusChange struct {
	ApplicationID      string
	UserID             string
	ExpectedRowVersion int64
	ExpectedStatus     MembershipStatus
	NewStatus          MembershipStatus
	Now                time.Time
}

// MemberRemove 是已通过校验的条件移除请求。
type MemberRemove struct {
	ApplicationID      string
	UserID             string
	ExpectedRowVersion int64
}

// 应用成员领域错误哨兵；调用方用 errors.Is 判断，并用 CodeOf 映射已登记错误码。
var (
	// ErrMemberNotFound 表示成员关系不存在（应用存在但用户未加入）。
	ErrMemberNotFound = errors.New("应用成员关系不存在")
	// ErrMemberExists 表示用户已经是该应用成员；重复加入返回 CONFLICT。
	ErrMemberExists = errors.New("用户已经是该应用成员")
	// ErrApplicationInactive 表示应用已停用，不能新增/启用成员或写入应用资料。
	ErrApplicationInactive = errors.New("应用当前已停用")
	// ErrUserNotEligible 表示目标全局账户不存在或不是 active 状态。
	ErrUserNotEligible = errors.New("目标账户当前不可加入应用")
	// ErrTargetUserNotFound 表示目标全局账户不存在。
	ErrTargetUserNotFound = errors.New("目标账户不存在")
)

// memberProfileDocument 是 profile_json 的规范结构；读取时拒绝未知字段与未知版本。
type memberProfileDocument struct {
	Version     int    `json:"v"`
	DisplayName string `json:"display_name,omitempty"`
	Title       string `json:"title,omitempty"`
	Note        string `json:"note,omitempty"`
}

// normalizeMemberProfile 规范化并校验应用专属资料白名单字段：NFKC、去首尾空白、
// 拒绝控制/格式字符；显示名与职位为单行，备注允许多行。它不接受全局资料字段。
func normalizeMemberProfile(profile MemberProfile) (MemberProfile, error) {
	displayName, err := normalizeText(profile.DisplayName, MaxMemberDisplayNameRunes, true)
	if err != nil {
		return MemberProfile{}, err
	}
	title, err := normalizeText(profile.Title, MaxMemberTitleRunes, true)
	if err != nil {
		return MemberProfile{}, err
	}
	note, err := normalizeText(profile.Note, MaxMemberNoteRunes, false)
	if err != nil {
		return MemberProfile{}, err
	}
	return MemberProfile{DisplayName: displayName, Title: title, Note: note}, nil
}

// EncodeMemberProfile 把已校验的应用专属资料编码为规范 JSON。仓储使用该函数
// 写入 profile_json；空资料也写入显式版本号，拒绝无版本的历史猜测格式。
func EncodeMemberProfile(profile MemberProfile) (string, error) {
	normalized, err := normalizeMemberProfile(profile)
	if err != nil {
		return "", err
	}
	document := memberProfileDocument{
		Version:     memberProfileVersion,
		DisplayName: normalized.DisplayName,
		Title:       normalized.Title,
		Note:        normalized.Note,
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		return "", fmt.Errorf("%w: 应用成员资料编码失败", ErrInvalidRequest)
	}
	return string(encoded), nil
}

// DecodeMemberProfile 解析 profile_json 为应用专属资料。它只接受当前版本、只含
// 白名单字段的规范 JSON；未知版本、未知字段、超长内容、非法字符或未规范化的值
// 都按存储不一致拒绝（fail-closed），不猜测或静默丢弃字段。
func DecodeMemberProfile(raw string) (MemberProfile, error) {
	if len(raw) == 0 || len(raw) > maxMemberProfileJSONBytes {
		return MemberProfile{}, fmt.Errorf("%w: 应用成员资料长度不合法", ErrStoreUnavailable)
	}
	decoder := json.NewDecoder(bytes.NewReader([]byte(raw)))
	decoder.DisallowUnknownFields()
	var document memberProfileDocument
	if err := decoder.Decode(&document); err != nil {
		return MemberProfile{}, fmt.Errorf("%w: 应用成员资料不是合法 JSON", ErrStoreUnavailable)
	}
	if err := ensureJSONEnd(decoder); err != nil {
		return MemberProfile{}, err
	}
	if document.Version != memberProfileVersion {
		return MemberProfile{}, fmt.Errorf("%w: 应用成员资料版本不受支持", ErrStoreUnavailable)
	}
	profile := MemberProfile{
		DisplayName: document.DisplayName,
		Title:       document.Title,
		Note:        document.Note,
	}
	normalized, err := normalizeMemberProfile(profile)
	if err != nil {
		return MemberProfile{}, fmt.Errorf("%w: 应用成员资料包含非法字段值", ErrStoreUnavailable)
	}
	if normalized != profile {
		return MemberProfile{}, fmt.Errorf("%w: 应用成员资料不是规范形式", ErrStoreUnavailable)
	}
	return profile, nil
}

// ensureJSONEnd 确认 JSON 文档没有尾随内容。
func ensureJSONEnd(decoder *json.Decoder) error {
	var extra any
	err := decoder.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return fmt.Errorf("%w: 应用成员资料包含多余内容", ErrStoreUnavailable)
	}
	return fmt.Errorf("%w: 应用成员资料包含多余内容", ErrStoreUnavailable)
}
