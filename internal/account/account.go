// Package account 实现普通账户的创建、按稳定 ID 查询与分页检索，以及用户名
// 规范化和资料字段白名单。
//
// 本包是内部领域包，不直接暴露 HTTP 端点：调用方只能通过显式传入的可信
// Caller 与 Authorizer 调用服务。授权模块尚未实现，因此本包只提供受限的本地
// 初始化授权器（LocalBootstrapAuthorizer）；生产 HTTP/远程调用默认没有可用
// 授权器，必须由后续服务层接入真实授权后才能开放。
//
// 安全不变量：
//   - 用户 ID 由服务生成、创建后不可变；用户名显示值与规范化值分开保存，唯一性
//     只由规范化值决定（NFKC 兼容规范化 + Unicode 大小写折叠）。
//   - 创建请求只接受资料白名单字段，没有 is_root、status、security_version、
//     已验证标记等字段；这些值由服务固定或数据库默认值决定。
//   - 创建、读取与列表查询都使用可信操作者写安全审计；创建与成功审计在同一事务
//     提交，审计失败时拒绝创建并回滚，不允许“成功但无记录”。
//   - 查询只允许有限分页与白名单排序/过滤，不接受任意 SQL 列或无上限列表。
package account

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"reflect"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
)

const (
	// MinUsernameRunes/MaxUsernameRunes 是用户名显示值的字符数范围（按 Unicode
	// 码点计数，规范化后计算）。
	MinUsernameRunes = 3
	MaxUsernameRunes = 32
	// MaxNicknameRunes 是昵称的字符数上限；昵称可以为空。
	MaxNicknameRunes = 64
	// MaxBiographyRunes 是简介的字符数上限；简介可以为空。
	MaxBiographyRunes = 1000
	// MaxLanguageBytes 是语言标签长度上限（BCP 47 子集）。
	MaxLanguageBytes = 35
	// MaxTimezoneBytes 是 IANA 时区名的长度上限。
	MaxTimezoneBytes = 64
	// DefaultLanguage/DefaultTimezone 是创建用户时的资料默认值。
	DefaultLanguage = "zh-CN"
	DefaultTimezone = "Asia/Shanghai"
	// DefaultListLimit/MaxListLimit 是列表查询的默认与最大每页数量。
	DefaultListLimit = 20
	MaxListLimit     = 100
	// MaxListOffset 限制列表偏移量，避免深分页放大数据库开销。
	MaxListOffset = 1_000_000
	// userIDPrefix/userIDRandomBytes 定义稳定用户 ID 的格式：usr_ + 128 位随机数。
	userIDPrefix      = "usr_"
	userIDRandomBytes = 16
)

// Status 是账户全局状态，与 users 表 CHECK 约束一致。
type Status string

const (
	// StatusPending 表示待验证（保留给未来自助注册流程）。
	StatusPending Status = "pending"
	// StatusActive 表示正常可用。本地初始化创建的账户使用该状态。
	StatusActive Status = "active"
	// StatusDisabled 表示全局禁用。
	StatusDisabled Status = "disabled"
	// StatusPendingDelete 表示已标记待删除，尚未完成删除流程。
	StatusPendingDelete Status = "pending_delete"
)

// Valid 报告状态是否为已定义值。
func (s Status) Valid() bool {
	switch s {
	case StatusPending, StatusActive, StatusDisabled, StatusPendingDelete:
		return true
	default:
		return false
	}
}

// SortField 是列表查询允许的排序字段白名单。
type SortField string

const (
	// SortCreatedAt 按创建时间排序（默认）。
	SortCreatedAt SortField = "created_at"
	// SortUpdatedAt 按更新时间排序。
	SortUpdatedAt SortField = "updated_at"
	// SortUsername 按规范化用户名排序。
	SortUsername SortField = "username"
	// SortID 按用户 ID 排序。
	SortID SortField = "id"
)

// Valid 报告排序字段是否在白名单内。
func (s SortField) Valid() bool {
	switch s {
	case SortCreatedAt, SortUpdatedAt, SortUsername, SortID:
		return true
	default:
		return false
	}
}

// User 是账户的只读快照。Username 是显示值（保留大小写、已做 NFKC 兼容
// 规范化），UsernameNormalized 是唯一性判定用的规范化值（大小写折叠）。
// 结构体不包含 is_root、security_version 等敏感管理字段，避免普通查询接口
// 顺带泄露系统管理资格。
type User struct {
	ID                 string
	Username           string
	UsernameNormalized string
	Nickname           string
	Biography          string
	Language           string
	Timezone           string
	Status             Status
	RowVersion         int64
	// SecurityVersion 是会话/令牌失效版本。禁用与删除请求会递增它；启用不会
	// 递减。未来会话/令牌模块必须拒绝版本低于当前值的凭证（本步未实现这些
	// 模块，只提供数据和可靠审计事件作为失效契约）。
	SecurityVersion int64
	// ValidFrom/ValidUntil 是全局账户有效期的 UTC 半开区间 [from, until)；
	// nil 表示该端不限制，默认都为空（永久有效）。root 的有效期由领域服务在写入
	// 与可用性判断中忽略，不由普通期限管理锁死。
	ValidFrom  *time.Time
	ValidUntil *time.Time
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// AvailabilityReason 是账户当前可用性的计算原因。它不持久化：到期/未开始都由
// 有效期与可注入时钟即时计算，绝不自动改写 users.status。
type AvailabilityReason string

const (
	// AvailabilityOK 表示账户在有效期内且状态允许使用。
	AvailabilityOK AvailabilityReason = "available"
	// AvailabilityNotStarted 表示尚未到 valid_from（半开区间左端）。
	AvailabilityNotStarted AvailabilityReason = "not_yet_valid"
	// AvailabilityExpired 表示已到 valid_until（半开区间右端，[from, until)）。
	AvailabilityExpired AvailabilityReason = "expired"
	// AvailabilityStatusPending 表示账户仍待验证/审核。
	AvailabilityStatusPending AvailabilityReason = "pending"
	// AvailabilityStatusDisabled 表示手动禁用。
	AvailabilityStatusDisabled AvailabilityReason = "disabled"
	// AvailabilityStatusPendingDelete 表示已标记待删除。
	AvailabilityStatusPendingDelete AvailabilityReason = "pending_delete"
)

// AvailabilityAt 计算账户在 now 的可用性。
//
// 语义：有效区间为 UTC 半开区间 [ValidFrom, ValidUntil)，任一端 nil 表示不限制；
// 到期只是计算出的不可用原因，不改写 Status；手动禁用与到期分离。root 不受普通
// 期限管理约束：其有效期字段在可用性判断中被忽略，但仍受手动状态约束。
func (u User) AvailabilityAt(now time.Time, isRoot bool) (bool, AvailabilityReason) {
	switch u.Status {
	case StatusPending:
		return false, AvailabilityStatusPending
	case StatusDisabled:
		return false, AvailabilityStatusDisabled
	case StatusPendingDelete:
		return false, AvailabilityStatusPendingDelete
	case StatusActive:
	default:
		return false, AvailabilityStatusDisabled
	}
	if isRoot {
		return true, AvailabilityOK
	}
	now = now.UTC()
	if u.ValidFrom != nil && now.Before(u.ValidFrom.UTC()) {
		return false, AvailabilityNotStarted
	}
	if u.ValidUntil != nil && !now.Before(u.ValidUntil.UTC()) {
		return false, AvailabilityExpired
	}
	return true, AvailabilityOK
}

// UserValidity 是账户有效期与当前可用性的只读快照。
type UserValidity struct {
	UserID     string
	Status     Status
	IsRoot     bool
	ValidFrom  *time.Time
	ValidUntil *time.Time
	RowVersion int64
	Available  bool
	Reason     AvailabilityReason
	CheckedAt  time.Time
}

// ValidityCommandRequest 是设置账户有效期的普通管理请求。ExpectedRowVersion 是
// 乐观并发校验；ValidFrom/ValidUntil 为 nil 表示清除该端（永久有效）。不允许设置
// root 的有效期。
type ValidityCommandRequest struct {
	UserID             string
	ValidFrom          *time.Time
	ValidUntil         *time.Time
	ExpectedRowVersion int64
}

// ValidityCommandResult 是有效期变更结果。
type ValidityCommandResult struct {
	User               User
	PreviousValidFrom  *time.Time
	PreviousValidUntil *time.Time
	Changed            bool
}

// ValidityEquals 报告两个可选时间是否都为空或表示同一毫秒时刻。
func ValidityEquals(left, right *time.Time) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.UTC().UnixMilli() == right.UTC().UnixMilli()
}

// CreateRequest 是创建用户的资料白名单。它刻意不包含 status、is_root、
// security_version、邮箱/电话验证状态等字段；这些值由服务或数据库决定。
type CreateRequest struct {
	Username  string
	Nickname  string
	Biography string
	Language  string
	Timezone  string
}

// UserSearchField 是 ListUsers 模糊搜索允许的字段白名单（字面子串匹配）。
//
// 默认只搜索用户名与昵称；邮箱/电话不默认纳入，它们需要独立的“字段可见”权限，
// 本轮没有该权限键，因此显式请求会被拒绝而不是静默忽略。用户名匹配使用存储的
// username_normalized（NFKC + 大小写折叠 + NFC），与唯一性/登录精确查询同一口径；
// 昵称匹配在 SQL 层按方言大小写规则（SQLite 仅能折叠 ASCII，中文等无大小写字段
// 不受影响）。模糊搜索不参与登录或唯一身份判定，GetUserByUsername 仍是精确查找。
type UserSearchField string

const (
	// UserSearchUsername 匹配用户名（规范化后的字面子串）。
	UserSearchUsername UserSearchField = "username"
	// UserSearchNickname 匹配昵称（字面子串，大小写按方言规则折叠）。
	UserSearchNickname UserSearchField = "nickname"
)

// Valid 报告搜索字段是否在白名单内。
func (f UserSearchField) Valid() bool {
	switch f {
	case UserSearchUsername, UserSearchNickname:
		return true
	default:
		return false
	}
}

// DefaultUserSearchFields 返回不指定字段时的默认搜索字段（用户名、昵称）。
func DefaultUserSearchFields() []UserSearchField {
	return []UserSearchField{UserSearchUsername, UserSearchNickname}
}

// ListRequest 是分页检索参数。零值 Limit 使用默认值 20，零值 Sort 使用
// SortCreatedAt；Status 为空表示不过滤状态。
//
// Search 为可选的字面子串搜索（空表示不过滤，保持原列表）；SearchFields 为空时
// 使用 DefaultUserSearchFields，非空时只能包含白名单字段，未知字段（含邮箱/电话）
// 返回 ErrInvalidRequest。搜索与 Status/Sort/Limit/Offset 在同一查询组合，先按
// 授权范围过滤（由服务层判定）再搜索与分页；本列表是 offset 分页，没有服务端
// 游标，因此搜索条件必须随每次请求重新提交，不存在“旧游标套用新搜索”的语义。
type ListRequest struct {
	Limit        int
	Offset       int
	Status       Status
	Sort         SortField
	Descending   bool
	Search       string
	SearchFields []UserSearchField
}

// ListResult 是分页检索结果。HasMore 表示按当前排序在 Offset+Limit 之后仍有
// 记录；本包不返回总条数，避免无界 COUNT 开销。
type ListResult struct {
	Users   []User
	HasMore bool
}

// 领域错误哨兵。调用方用 errors.Is 判断，并可用 CodeOf 映射到根包错误码。
var (
	// ErrOptionsInvalid 表示服务构造依赖不合法。
	ErrOptionsInvalid = errors.New("账户服务选项无效")
	// ErrInvalidRequest 表示用户名、资料字段、分页/排序或用户 ID 不合法。
	ErrInvalidRequest = errors.New("账户请求无效")
	// ErrUsernameTaken 表示规范化用户名已被占用。
	ErrUsernameTaken = errors.New("用户名已被占用")
	// ErrUserNotFound 表示按稳定 ID 找不到用户。
	ErrUserNotFound = errors.New("用户不存在")
	// ErrAccessDenied 表示可信调用身份未获准执行该操作。
	ErrAccessDenied = errors.New("未获准执行该操作")
	// ErrStoreUnavailable 表示账户存储暂时不可用。
	ErrStoreUnavailable = errors.New("账户存储暂时不可用")
	// ErrAuditUnavailable 表示安全审计未能可靠写入，操作被拒绝。
	ErrAuditUnavailable = errors.New("关键操作未能可靠记录")
	// ErrProtectedUser 表示目标账户受保护（root 等），普通管理流程不能禁用/删除。
	ErrProtectedUser = errors.New("受保护账户不能通过普通管理流程变更")
	// ErrInvalidTransition 表示当前状态不允许该操作（例如已待删除账户解禁）。
	ErrInvalidTransition = errors.New("当前账户状态不允许该操作")
	// ErrValidityInvalid 表示账户有效期输入无效（例如两段都设置但区间为空）。
	ErrValidityInvalid = errors.New("账户有效期无效")
	// ErrStateConflict 表示并发修改或行版本不匹配，调用方应重新读取后决定。
	ErrStateConflict = errors.New("账户状态已被其他操作修改")
)

// ErrorCode 是根包错误码注册表中的稳定字符串值。internal 包不能 import 根包，
// 因此这里只保存与注册表一致的字面值；根包测试会核对它们确实已登记。
type ErrorCode string

const (
	// CodeReqInvalid 对应已登记的 REQ_INVALID（请求内容不符合要求）。
	CodeReqInvalid ErrorCode = "REQ_INVALID"
	// CodeConflict 对应已登记的 CONFLICT（唯一值重复等数据冲突）。
	CodeConflict ErrorCode = "CONFLICT"
	// CodeAccessDenied 对应已登记的 ACCESS_DENIED。
	CodeAccessDenied ErrorCode = "ACCESS_DENIED"
	// CodeDBUnavailable 对应已登记的 DB_UNAVAILABLE。
	CodeDBUnavailable ErrorCode = "DB_UNAVAILABLE"
	// CodeAuditWriteFailed 对应已登记的 AUDIT_WRITE_FAILED。
	CodeAuditWriteFailed ErrorCode = "AUDIT_WRITE_FAILED"
	// CodeInternalError 对应已登记的 INTERNAL_ERROR。
	CodeInternalError ErrorCode = "INTERNAL_ERROR"
)

// CodeOf 把账户领域错误映射到已登记错误码。未知错误一律视为内部错误，避免把
// 原始错误文本或数据库细节暴露成新的对外码。
func CodeOf(err error) ErrorCode {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrInvalidRequest), errors.Is(err, ErrUserNotFound),
		errors.Is(err, ErrValidityInvalid):
		return CodeReqInvalid
	case errors.Is(err, ErrUsernameTaken):
		return CodeConflict
	case errors.Is(err, ErrAccessDenied), errors.Is(err, ErrProtectedUser):
		return CodeAccessDenied
	case errors.Is(err, ErrInvalidTransition), errors.Is(err, ErrStateConflict):
		return CodeConflict
	case errors.Is(err, ErrStoreUnavailable):
		return CodeDBUnavailable
	case errors.Is(err, ErrAuditUnavailable):
		return CodeAuditWriteFailed
	default:
		return CodeInternalError
	}
}

// NewUserID 生成稳定用户 ID：usr_ 加 128 位安全随机数的十六进制表示。创建后
// 不再改变；业务应用不得用用户名作为永久外键。
func NewUserID(random io.Reader) (string, error) {
	if random == nil {
		random = rand.Reader
	}
	buffer := make([]byte, userIDRandomBytes)
	if _, err := io.ReadFull(random, buffer); err != nil {
		return "", fmt.Errorf("无法生成用户 ID: %w", err)
	}
	return userIDPrefix + hex.EncodeToString(buffer), nil
}

// ValidUserID 报告用户 ID 是否符合本包生成的固定格式。查询前用它拒绝任意
// 字符串，避免把畸形输入带进 SQL 或错误信息。
func ValidUserID(id string) bool {
	if len(id) != len(userIDPrefix)+2*userIDRandomBytes || !strings.HasPrefix(id, userIDPrefix) {
		return false
	}
	_, err := hex.DecodeString(id[len(userIDPrefix):])
	return err == nil
}

// reservedUsernames 是不允许普通创建的规范化用户名集合（小写/大小写折叠后）。
// 该清单是稳定契约的一部分：新增保留名需要同步文档与测试，不能悄悄改变已发布
// 的保留规则。比较发生在 Unicode 大小写折叠之后，因此 fullwidth 变体也会命中。
var reservedUsernames = func() map[string]struct{} {
	values := []string{
		"root", "admin", "administrator", "superuser", "system", "support",
		"security", "moderator", "official", "login", "logout", "oauth",
		"oauth2", "openid", "api", "account", "accounts", "user", "users",
		"null", "undefined",
		"管理员", "客服", "系统", "官方", "登录", "支持",
	}
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		set[normalizeUsernameKey(value)] = struct{}{}
	}
	return set
}()

// ReservedUsernames 返回保留用户名的规范化副本，用于诊断与文档生成。返回值
// 已排序，调用方修改不影响内部规则。
func ReservedUsernames() []string {
	values := make([]string, 0, len(reservedUsernames))
	for value := range reservedUsernames {
		values = append(values, value)
	}
	sort.Strings(values)
	return values
}

// normalizeUsernameKey 对用于保留名比较/唯一性比较的文本执行 NFKC + 大小写
// 折叠 + NFC。它是用户名规范化的单一口径。
func normalizeUsernameKey(display string) string {
	compatibility := norm.NFKC.String(display)
	folded := cases.Fold().String(compatibility)
	return norm.NFC.String(folded)
}

// NormalizeUsername 校验并规范化用户名，保留名使用本包默认清单。
func NormalizeUsername(raw string) (display string, normalized string, err error) {
	return NormalizeUsernameWithReserved(raw, nil)
}

// NormalizeUsernameWithReserved 是 NormalizeUsername 的可配置保留名版本：
// reserved 为 nil 时沿用本包默认保留名；非 nil 时按给定规范化保留名集合校验
// （空切片表示显式不检查保留名，调用方必须确认这是受控配置）。
func NormalizeUsernameWithReserved(raw string, reserved []string) (display string, normalized string, err error) {
	reservedSet := reservedUsernames
	if reserved != nil {
		reservedSet = make(map[string]struct{}, len(reserved))
		for _, value := range reserved {
			reservedSet[normalizeUsernameKey(value)] = struct{}{}
		}
	}
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", "", fmt.Errorf("%w: 用户名不能为空", ErrInvalidRequest)
	}
	canonical := strings.TrimSpace(norm.NFKC.String(trimmed))
	if canonical == "" {
		return "", "", fmt.Errorf("%w: 用户名不能为空", ErrInvalidRequest)
	}
	runes := []rune(canonical)
	if len(runes) < MinUsernameRunes || len(runes) > MaxUsernameRunes {
		return "", "", fmt.Errorf("%w: 用户名长度必须在 %d～%d 个字符之间",
			ErrInvalidRequest, MinUsernameRunes, MaxUsernameRunes)
	}
	for index, character := range runes {
		switch {
		case unicode.IsLetter(character), unicode.IsDigit(character):
			continue
		case character == '.', character == '_', character == '-':
			if index == 0 || index == len(runes)-1 {
				return "", "", fmt.Errorf("%w: 用户名首尾必须是字母或数字", ErrInvalidRequest)
			}
			continue
		case unicode.IsSpace(character):
			return "", "", fmt.Errorf("%w: 用户名不能包含空白字符", ErrInvalidRequest)
		case unicode.IsControl(character), unicode.Is(unicode.Cf, character),
			unicode.Is(unicode.Zl, character), unicode.Is(unicode.Zp, character):
			return "", "", fmt.Errorf("%w: 用户名不能包含控制或格式字符", ErrInvalidRequest)
		default:
			return "", "", fmt.Errorf("%w: 用户名只能包含字母、数字与 . _ -", ErrInvalidRequest)
		}
	}
	normalized = normalizeUsernameKey(canonical)
	if _, reserved := reservedSet[normalized]; reserved {
		return "", "", fmt.Errorf("%w: 用户名为保留名称", ErrInvalidRequest)
	}
	return canonical, normalized, nil
}

// NormalizeNickname 校验并规范化昵称，规则与账户创建时的白名单一致。它供需要
// 创建受保护内置账户（例如 root 初始资料）的可信初始化流程复用同一口径，避免
// 复制第二套资料规则。空昵称合法。
func NormalizeNickname(raw string) (string, error) {
	return normalizeNickname(raw)
}

// NormalizeLanguage 校验并规范化 BCP 47 子集语言标签，空值使用默认语言。
func NormalizeLanguage(raw string) (string, error) {
	return normalizeLanguage(raw)
}

// NormalizeTimezone 校验并规范化 IANA 时区名，空值使用默认时区。
func NormalizeTimezone(raw string) (string, error) {
	return normalizeTimezone(raw)
}

// normalizeNickname 校验昵称：NFKC 规范化、去首尾空白、最多 MaxNicknameRunes
// 个码点；允许空格，不允许换行/控制/格式字符。空昵称合法。
func normalizeNickname(raw string) (string, error) {
	canonical := strings.TrimSpace(norm.NFKC.String(strings.TrimSpace(raw)))
	if canonical == "" {
		return "", nil
	}
	if !utf8.ValidString(canonical) {
		return "", fmt.Errorf("%w: 昵称不是合法 UTF-8", ErrInvalidRequest)
	}
	count := 0
	for _, character := range canonical {
		count++
		if unicode.IsControl(character) || unicode.Is(unicode.Cf, character) ||
			unicode.Is(unicode.Zl, character) || unicode.Is(unicode.Zp, character) {
			return "", fmt.Errorf("%w: 昵称不能包含控制或格式字符", ErrInvalidRequest)
		}
	}
	if count > MaxNicknameRunes {
		return "", fmt.Errorf("%w: 昵称不能超过 %d 个字符", ErrInvalidRequest, MaxNicknameRunes)
	}
	return canonical, nil
}

// normalizeBiography 校验简介：NFKC 规范化、去首尾空白、最多 MaxBiographyRunes
// 个码点；允许换行与制表符，拒绝其他控制/格式字符与 NUL。空简介合法。
func normalizeBiography(raw string) (string, error) {
	canonical := strings.TrimSpace(norm.NFKC.String(strings.TrimSpace(raw)))
	if canonical == "" {
		return "", nil
	}
	if !utf8.ValidString(canonical) {
		return "", fmt.Errorf("%w: 简介不是合法 UTF-8", ErrInvalidRequest)
	}
	count := 0
	for _, character := range canonical {
		count++
		if character == '\n' || character == '\t' {
			continue
		}
		if unicode.IsControl(character) || unicode.Is(unicode.Cf, character) ||
			unicode.Is(unicode.Zl, character) || unicode.Is(unicode.Zp, character) {
			return "", fmt.Errorf("%w: 简介包含不允许的控制字符", ErrInvalidRequest)
		}
	}
	if count > MaxBiographyRunes {
		return "", fmt.Errorf("%w: 简介不能超过 %d 个字符", ErrInvalidRequest, MaxBiographyRunes)
	}
	return canonical, nil
}

// normalizeLanguage 校验 BCP 47 子集语言标签；空值使用默认语言。
func normalizeLanguage(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return DefaultLanguage, nil
	}
	if len(value) > MaxLanguageBytes {
		return "", fmt.Errorf("%w: 语言标签过长", ErrInvalidRequest)
	}
	parts := strings.Split(value, "-")
	for index, part := range parts {
		if part == "" || len(part) > 8 {
			return "", fmt.Errorf("%w: 语言标签格式无效", ErrInvalidRequest)
		}
		if index == 0 && (len(part) < 2 || len(part) > 3) {
			return "", fmt.Errorf("%w: 语言标签格式无效", ErrInvalidRequest)
		}
		for _, character := range part {
			if !(character >= 'a' && character <= 'z') &&
				!(character >= 'A' && character <= 'Z') &&
				!(character >= '0' && character <= '9') {
				return "", fmt.Errorf("%w: 语言标签格式无效", ErrInvalidRequest)
			}
		}
	}
	return value, nil
}

// normalizeTimezone 校验 IANA 时区名；空值使用默认时区。它只校验名称可被
// time.LoadLocation 解析，不保存任意路径或本地化时区缩写。
func normalizeTimezone(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return DefaultTimezone, nil
	}
	if len(value) > MaxTimezoneBytes {
		return "", fmt.Errorf("%w: 时区名称过长", ErrInvalidRequest)
	}
	for _, character := range value {
		if character <= 0x20 || character == 0x7f || character == '\\' {
			return "", fmt.Errorf("%w: 时区名称无效", ErrInvalidRequest)
		}
	}
	if _, err := time.LoadLocation(value); err != nil {
		return "", fmt.Errorf("%w: 时区名称不是可识别的 IANA 时区", ErrInvalidRequest)
	}
	return value, nil
}

// ValidateRequestID 校验可选请求编号（ASCII 字母、数字与 . _ -，长度 1～64），
// 供服务写入审计事件。空字符串表示没有请求编号。
func ValidateRequestID(requestID string) error {
	if requestID == "" {
		return nil
	}
	if len(requestID) > 64 {
		return fmt.Errorf("%w: 请求编号过长", ErrInvalidRequest)
	}
	for index := 0; index < len(requestID); index++ {
		character := requestID[index]
		if (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') ||
			character == '.' || character == '_' || character == '-' {
			continue
		}
		return fmt.Errorf("%w: 请求编号包含非法字符", ErrInvalidRequest)
	}
	return nil
}

// Action 是可审计的账户操作动作。
type Action string

const (
	// ActionCreateUser 创建普通用户。
	ActionCreateUser Action = "user.create"
	// ActionGetUser 按稳定 ID 查询用户。
	ActionGetUser Action = "user.get"
	// ActionListUsers 分页检索用户。
	ActionListUsers Action = "user.list"
	// ActionDisableUser 全局禁用账户。
	ActionDisableUser Action = "user.disable"
	// ActionEnableUser 启用已禁用账户。
	ActionEnableUser Action = "user.enable"
	// ActionRequestDeletion 标记账户待删除（软删除状态）。
	ActionRequestDeletion Action = "user.delete.request"
	// ActionPreviewDeletion 查看删除影响范围。
	ActionPreviewDeletion Action = "user.delete.preview"
	// ActionCompleteDeletion 完成删除（硬删除账户与关联个人数据）。
	ActionCompleteDeletion Action = "user.delete.complete"
	// ActionGetValidity 读取账户有效期与当前可用性。
	ActionGetValidity Action = "user.validity.get"
	// ActionSetValidity 设置账户有效期（普通期限管理，不允许作用于 root）。
	ActionSetValidity Action = "user.validity.set"
)

// Valid 报告动作是否已定义。
func (a Action) Valid() bool {
	switch a {
	case ActionCreateUser, ActionGetUser, ActionListUsers,
		ActionDisableUser, ActionEnableUser, ActionRequestDeletion,
		ActionPreviewDeletion, ActionCompleteDeletion,
		ActionGetValidity, ActionSetValidity:
		return true
	default:
		return false
	}
}

// Caller 是通过可信边界建立的操作者上下文。字段不导出：调用方只能通过
// LocalBootstrapCaller/SystemCaller 构造，不能从请求参数直接伪造。
type Caller struct {
	actor     audit.Actor
	requestID string
}

// LocalBootstrapCaller 构造受限本地初始化操作者（audit.ActorLocalAdmin）。
// operatorID 必须是稳定的本地操作者标识，由宿主在可信环境提供。
func LocalBootstrapCaller(operatorID string) (Caller, error) {
	actor := audit.Actor{Type: audit.ActorLocalAdmin, ID: operatorID}
	if err := actor.Validate(); err != nil {
		return Caller{}, fmt.Errorf("%w: 本地操作者标识无效", ErrInvalidRequest)
	}
	return Caller{actor: actor}, nil
}

// SystemCaller 构造系统组件操作者（audit.ActorSystem），供未来后台流程使用。
// 它不会自动获得权限：Authorizer 必须显式允许该系统身份。
func SystemCaller(componentID string) (Caller, error) {
	actor := audit.Actor{Type: audit.ActorSystem, ID: componentID}
	if err := actor.Validate(); err != nil {
		return Caller{}, fmt.Errorf("%w: 系统操作者标识无效", ErrInvalidRequest)
	}
	return Caller{actor: actor}, nil
}

// UserCaller 构造已认证普通用户操作者（供受保护管理 API 的"代表用户"调用使用）。
// 它只代表用户身份，不代表系统资格；Authorizer 仍必须显式允许对应动作。
func UserCaller(userID string) (Caller, error) {
	if !ValidUserID(userID) {
		return Caller{}, fmt.Errorf("%w: 用户 ID 格式无效", ErrInvalidRequest)
	}
	actor := audit.Actor{Type: audit.ActorUser, ID: userID}
	if err := actor.Validate(); err != nil {
		return Caller{}, fmt.Errorf("%w: 用户操作者标识无效", ErrInvalidRequest)
	}
	return Caller{actor: actor}, nil
}

// WithRequestID 返回带请求编号的调用者副本，用于审计关联。非法编号返回
// ErrInvalidRequest，不会悄悄丢弃。
// Actor 返回底层审计身份副本（供需要记录/复核调用者身份的受信内部流程使用；
// 不导出字段，不能由请求参数伪造）。
func (c Caller) Actor() audit.Actor { return c.actor }

// RequestID 返回调用者绑定的请求编号（可能为空）。
func (c Caller) RequestID() string { return c.requestID }

func (c Caller) WithRequestID(requestID string) (Caller, error) {
	if err := ValidateRequestID(requestID); err != nil {
		return Caller{}, err
	}
	c.requestID = requestID
	return c, nil
}

// Authorizer 判定可信调用者是否可执行账户操作。实际授权模块未就绪前，生产
// 集成必须提供实现；本包只提供 LocalBootstrapAuthorizer 作为受限本地初始化
// 通道，不提供“默认放行”实现。
type Authorizer interface {
	Authorize(ctx context.Context, caller Caller, action Action) error
}

// LocalBootstrapAuthorizer 只允许显式配置的本地管理员执行账户初始化操作。
// 系统、普通用户与匿名身份一律拒绝；远程 HTTP 接入时不应使用它。
type LocalBootstrapAuthorizer struct {
	operators map[string]struct{}
}

// NewLocalBootstrapAuthorizer 构造受限本地授权器。operatorIDs 不能为空，每个
// 标识必须是审计包允许的可见 ASCII 稳定 ID。
func NewLocalBootstrapAuthorizer(operatorIDs []string) (*LocalBootstrapAuthorizer, error) {
	if len(operatorIDs) == 0 {
		return nil, fmt.Errorf("%w: 本地初始化操作者列表不能为空", ErrOptionsInvalid)
	}
	operators := make(map[string]struct{}, len(operatorIDs))
	for _, operatorID := range operatorIDs {
		actor := audit.Actor{Type: audit.ActorLocalAdmin, ID: operatorID}
		if err := actor.Validate(); err != nil {
			return nil, fmt.Errorf("%w: 本地初始化操作者标识无效", ErrOptionsInvalid)
		}
		operators[operatorID] = struct{}{}
	}
	return &LocalBootstrapAuthorizer{operators: operators}, nil
}

// Authorize 实现 Authorizer。只有本地管理员且动作已定义时放行。
func (a *LocalBootstrapAuthorizer) Authorize(_ context.Context, caller Caller, action Action) error {
	if a == nil || !action.Valid() {
		return ErrAccessDenied
	}
	if caller.actor.Type != audit.ActorLocalAdmin {
		return ErrAccessDenied
	}
	if _, allowed := a.operators[caller.actor.ID]; !allowed {
		return ErrAccessDenied
	}
	return nil
}

// UserCommand 是受控的全局账户状态命令。它不包含任意状态赋值：调用方只能
// 请求 disable/enable/request_deletion，由服务按状态机决定是否合法。
type UserCommand string

const (
	// CommandDisable 全局禁用账户（保留应用成员关系与其他数据，仅禁止账户使用）。
	CommandDisable UserCommand = "disable"
	// CommandEnable 重新启用已禁用账户；不会恢复旧会话，也不会降低安全版本。
	CommandEnable UserCommand = "enable"
	// CommandRequestDeletion 将账户标记为待删除，递增安全版本并使后续状态变更
	// 只能走向完成删除。
	CommandRequestDeletion UserCommand = "request_deletion"
)

// Valid 报告命令是否已定义。
func (c UserCommand) Valid() bool {
	return c == CommandDisable || c == CommandEnable || c == CommandRequestDeletion
}

// action 返回命令对应的审计动作。
func (c UserCommand) action() Action {
	switch c {
	case CommandDisable:
		return ActionDisableUser
	case CommandEnable:
		return ActionEnableUser
	case CommandRequestDeletion:
		return ActionRequestDeletion
	default:
		return ""
	}
}

// bumpsSecurityVersion 报告命令是否必须递增 security_version 以让未来会话/令牌
// 失效。启用不递增，避免“解禁即恢复旧凭证”的绕过。
func (c UserCommand) bumpsSecurityVersion() bool {
	return c == CommandDisable || c == CommandRequestDeletion
}

// StateCommandRequest 是状态变更请求。ExpectedRowVersion 必须是调用方读取到的
// 当前 row_version（>0），用于乐观并发；同一状态重复请求按幂等成功处理，不
// 要求版本匹配。
type StateCommandRequest struct {
	UserID             string
	ExpectedRowVersion int64
}

// StateChangeResult 是一次状态命令的结果。Changed=false 表示目标已处于请求状态
// （幂等成功）；此时不会修改 row_version/security_version。
type StateChangeResult struct {
	User           User
	PreviousStatus Status
	Changed        bool
}

// DeletionPreview 是完成删除前的影响范围快照。计数是读取时的快照，实际删除在
// 事务中再次执行；它用于让操作者在不可逆删除前确认影响。
type DeletionPreview struct {
	UserID             string
	Username           string
	Status             Status
	RowVersion         int64
	SecurityVersion    int64
	IsRoot             bool
	AppMemberships     int
	UserRoles          int
	GroupMemberships   int
	OneTimeCredentials int
	OwnedApplications  int
}

// DeletionResult 是完成删除的结果与删除前影响快照。
type DeletionResult struct {
	Preview   DeletionPreview
	DeletedAt time.Time
}

// transitionStatus 应用状态机。changed=false 表示幂等无操作；非法转换返回
// ErrInvalidTransition。
func transitionStatus(current Status, command UserCommand) (next Status, changed bool, err error) {
	if !command.Valid() {
		return current, false, fmt.Errorf("%w: 未知状态命令", ErrInvalidRequest)
	}
	switch command {
	case CommandDisable:
		switch current {
		case StatusPending, StatusActive:
			return StatusDisabled, true, nil
		case StatusDisabled:
			return StatusDisabled, false, nil
		default:
			return current, false, fmt.Errorf("%w: 待删除账户不能禁用", ErrInvalidTransition)
		}
	case CommandEnable:
		switch current {
		case StatusDisabled:
			return StatusActive, true, nil
		case StatusActive:
			return StatusActive, false, nil
		default:
			return current, false, fmt.Errorf("%w: 只有已禁用账户可以直接启用", ErrInvalidTransition)
		}
	case CommandRequestDeletion:
		switch current {
		case StatusPending, StatusActive, StatusDisabled:
			return StatusPendingDelete, true, nil
		case StatusPendingDelete:
			return StatusPendingDelete, false, nil
		default:
			return current, false, fmt.Errorf("%w: 当前状态不能请求删除", ErrInvalidTransition)
		}
	default:
		return current, false, fmt.Errorf("%w: 未知状态命令", ErrInvalidRequest)
	}
}

// isNilInterface 检测 nil 接口与 typed nil 指针，避免服务调用时 panic。
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
