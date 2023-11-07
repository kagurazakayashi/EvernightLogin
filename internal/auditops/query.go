package auditops

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
)

// SortOrder 是审计列表稳定排序。只支持“发生时间 + 事件 ID”的两种固定次序，
// 不接受任意字段排序。
type SortOrder string

const (
	// SortNewestFirst 是默认次序：发生时间倒序，事件 ID 倒序为并列决胜。
	SortNewestFirst SortOrder = "occurred_desc"
	// SortOldestFirst 是发生时间正序，事件 ID 正序为并列决胜。
	SortOldestFirst SortOrder = "occurred_asc"
)

// Valid 报告排序是否已定义。
func (o SortOrder) Valid() bool {
	return o == SortNewestFirst || o == SortOldestFirst
}

// Filter 是审计查询筛选条件。所有字段都是白名单精确匹配/时间区间，不提供自由
// SQL、全文日志搜索或原始正文查询；时间区间为 [From, To)（To 不含）。
type Filter struct {
	From time.Time
	To   time.Time
	// AppID 是应用快照 ID 精确筛选；SystemOnly 表示只看无应用快照的系统级事件。
	AppID      string
	SystemOnly bool
	// ActorType 为空表示不限；ActorID 精确匹配可信操作者稳定 ID。
	ActorType  audit.ActorKind
	ActorID    string
	Action     string
	Outcome    audit.Outcome
	ErrorCode  string
	RequestID  string
	TaskID     string
	TargetType string
	TargetID   string
}

// RetentionInfo 是保留期边界信息。Cutoff 之前的记录“已过保留期”，但可能尚未被
// 清理；查询到这类记录时调用方必须如实标注，不能谎称从未存在。
type RetentionInfo struct {
	Days       int
	Configured bool
	Version    int64
	Cutoff     time.Time
	UpdatedAt  time.Time
}

// ScopeInfo 是查询作用范围信息（system 或某个应用）。
type ScopeInfo struct {
	ID   string
	Kind string
}

// QueryRequest 是管理审计列表查询。ScopeID 决定作用范围，数据范围由服务端授权
// 结果决定；调用方不能通过参数扩大范围。
type QueryRequest struct {
	Caller  account.Caller
	ScopeID string
	Filter  Filter
	Order   SortOrder
	Limit   int
	Offset  int
	// Cursor 是服务端上一页返回的不透明稳定游标；非空时 Offset 必须为 0。
	// 游标绑定作用范围、筛选与排序，不匹配会被拒绝（REQ_INVALID）。
	Cursor string
}

// QueryResult 是审计列表结果。HasMore 由多取一条判定；不提供伪造的总条数。
type QueryResult struct {
	Events    []audit.Event
	HasMore   bool
	Limit     int
	Offset    int
	Order     SortOrder
	Scope     ScopeInfo
	Retention RetentionInfo
	// NextCursor 是下一页稳定游标；HasMore=false 时为空。
	NextCursor string
}

// OwnQueryRequest 是“我的安全活动”查询；操作者固定为调用者本人，不接受他人筛选。
type OwnQueryRequest struct {
	Caller account.Caller
	Filter Filter
	Order  SortOrder
	Limit  int
	Offset int
	Cursor string
}

// GetRequest 是审计详情查询。OccurredAtHint 可选：调用方从列表带来发生时，服务可
// 区分“从未存在”和“已过保留期”；没有时间提示时不擅自猜测。
type GetRequest struct {
	Caller         account.Caller
	ScopeID        string
	EventID        string
	OccurredAtHint time.Time
}

// EventDetail 是审计详情结果。
type EventDetail struct {
	Event     audit.Event
	Scope     ScopeInfo
	Retention RetentionInfo
	// Stale 表示该记录已过保留期但仍存在（尚未清理），页面必须如实标注。
	Stale bool
}

// queryScope 是服务层授权结果转换后的存储层范围约束。
type queryScope struct {
	kind          string
	scopeID       string
	allData       bool
	appIDs        []string
	includeSystem bool
}

// retentionInfo 读取当前保留策略；未设置时返回内置默认值（Configured=false），
// 不伪造设置时间。
func (s *Service) retentionInfo(ctx context.Context) (RetentionInfo, error) {
	record, found, err := s.opts.Store.GetRetention(ctx)
	if err != nil {
		return RetentionInfo{}, fmt.Errorf("%w: %w", ErrStoreUnavailable, err)
	}
	now := s.now()
	if !found {
		return RetentionInfo{
			Days:   s.retentionDays,
			Cutoff: now.Add(-time.Duration(s.retentionDays) * 24 * time.Hour),
		}, nil
	}
	if record.RetentionDays < 1 || record.RetentionDays > MaxRetentionDays {
		return RetentionInfo{}, fmt.Errorf("%w: 保留策略数据无效", ErrStoreUnavailable)
	}
	return RetentionInfo{
		Days:       record.RetentionDays,
		Configured: true,
		Version:    record.Version,
		Cutoff:     now.Add(-time.Duration(record.RetentionDays) * 24 * time.Hour),
		UpdatedAt:  record.UpdatedAt,
	}, nil
}

// Retention 返回保留策略与当前边界，供列表常驻说明与详情状态使用。
// 保留策略是运维信息而非秘密，已认证的普通用户也可读取（用于解释自身活动列表）。
func (s *Service) Retention(ctx context.Context, caller account.Caller) (RetentionInfo, error) {
	if err := caller.Actor().Validate(); err != nil {
		return RetentionInfo{}, ErrAccessDenied
	}
	return s.retentionInfo(ctx)
}

// QueryOwnActivity 查询调用者本人的安全活动。它不需要 audit.read：身份本身限定
// 只能看本人记录；匿名/系统/本地管理员身份不能使用该入口。
func (s *Service) QueryOwnActivity(ctx context.Context, request OwnQueryRequest) (QueryResult, error) {
	actor := request.Caller.Actor()
	if actor.Type != audit.ActorUser {
		return QueryResult{}, ErrAccessDenied
	}
	filter := request.Filter
	filter.ActorType = audit.ActorUser
	filter.ActorID = actor.ID
	return s.query(ctx, filter, SortNewestFirst, request.Order, request.Limit,
		request.Offset, request.Cursor, queryScope{kind: "system", scopeID: ScopeSystem,
			allData: true, includeSystem: true}, ScopeInfo{ID: ScopeSystem, Kind: "system"})
}

// Query 查询管理审计列表。调用者必须在 scopeID 作用范围内拥有 audit.read，且数据
// 范围在存储层生效；跨范围筛选直接拒绝而不是静默返回空列表。
func (s *Service) Query(ctx context.Context, request QueryRequest) (QueryResult, error) {
	scope, err := parseScope(request.ScopeID)
	if err != nil {
		return QueryResult{}, err
	}
	grant, err := s.authorizeScope(ctx, request.Caller, PermissionRead, scope.ID)
	if err != nil {
		return QueryResult{}, err
	}
	constraint, err := scopeConstraint(scope, grant)
	if err != nil {
		return QueryResult{}, err
	}
	return s.query(ctx, request.Filter, SortNewestFirst, request.Order, request.Limit,
		request.Offset, request.Cursor, constraint, scope)
}

// query 校验筛选/分页并从存储层读取一页。cursor 非空时使用 keyset 位置分页，
// offset 必须为 0；游标绑定 scope/filter/order，不匹配直接 REQ_INVALID。
func (s *Service) query(ctx context.Context, filter Filter, defaultOrder, order SortOrder,
	limit, offset int, cursor string, constraint queryScope,
	scope ScopeInfo) (QueryResult, error) {
	normalizedOrder, err := normalizeOrder(order, defaultOrder)
	if err != nil {
		return QueryResult{}, err
	}
	limit, offset, err = s.normalizePage(limit, offset)
	if err != nil {
		return QueryResult{}, err
	}
	if cursor != "" && offset != 0 {
		return QueryResult{}, fmt.Errorf("%w: 游标分页不能同时指定偏移", ErrInvalidRequest)
	}
	if err := s.validateFilter(filter, constraint); err != nil {
		return QueryResult{}, err
	}
	position, err := decodeCursor(cursor, scope, filter, normalizedOrder)
	if err != nil {
		return QueryResult{}, err
	}
	retention, err := s.retentionInfo(ctx)
	if err != nil {
		return QueryResult{}, err
	}
	page, err := s.opts.Store.QueryEvents(ctx, EventQuery{
		Filter: filter, AllData: constraint.allData, AppIDs: constraint.appIDs,
		IncludeSystem: constraint.includeSystem, Order: normalizedOrder,
		Limit: limit, Offset: offset,
		AfterOccurredAt: position.OccurredAt, AfterID: position.EventID,
	})
	if err != nil {
		return QueryResult{}, fmt.Errorf("%w: %w", ErrStoreUnavailable, err)
	}
	events := page.Events
	if events == nil {
		events = []audit.Event{}
	}
	result := QueryResult{Events: events, HasMore: page.HasMore, Limit: limit,
		Offset: offset, Order: normalizedOrder, Scope: scope, Retention: retention}
	if page.HasMore && len(events) > 0 {
		last := events[len(events)-1]
		nextCursor, cursorErr := encodeCursor(scope, filter, normalizedOrder,
			CursorPosition{OccurredAt: last.OccurredAt, EventID: last.ID})
		if cursorErr != nil {
			// 游标编码失败不能静默返回“无下一页”：按内部错误 fail-closed，避免
			// 调用方把部分结果当成完整结果。
			return QueryResult{}, fmt.Errorf("%w: 生成下一页游标失败", ErrStoreUnavailable)
		}
		result.NextCursor = nextCursor
	}
	return result, nil
}

// GetOwnEvent 读取调用者本人的单条安全活动；读取他人事件统一按不存在处理，
// 不泄露事件是否存在。
func (s *Service) GetOwnEvent(ctx context.Context, caller account.Caller,
	eventID string, occurredAtHint time.Time) (EventDetail, error) {
	actor := caller.Actor()
	if actor.Type != audit.ActorUser {
		return EventDetail{}, ErrAccessDenied
	}
	event, found, err := s.loadEvent(ctx, eventID)
	if err != nil {
		return EventDetail{}, err
	}
	if !found || event.Actor.Type != audit.ActorUser || event.Actor.ID != actor.ID {
		return EventDetail{}, s.missingError(ctx, occurredAtHint)
	}
	retention, err := s.retentionInfo(ctx)
	if err != nil {
		return EventDetail{}, err
	}
	return EventDetail{Event: event, Scope: ScopeInfo{ID: ScopeSystem, Kind: "system"},
		Retention: retention, Stale: !occurredAtHint.IsZero() &&
			occurredAtHint.Before(retention.Cutoff)}, nil
}

// GetEvent 读取管理审计详情。事件必须属于调用者获准的数据范围；跨范围事件按
// ACCESS_DENIED 拒绝，且不返回事件正文。不存在与已过保留期分开表达。
func (s *Service) GetEvent(ctx context.Context, request GetRequest) (EventDetail, error) {
	scope, err := parseScope(request.ScopeID)
	if err != nil {
		return EventDetail{}, err
	}
	grant, err := s.authorizeScope(ctx, request.Caller, PermissionRead, scope.ID)
	if err != nil {
		return EventDetail{}, err
	}
	constraint, err := scopeConstraint(scope, grant)
	if err != nil {
		return EventDetail{}, err
	}
	event, found, err := s.loadEvent(ctx, request.EventID)
	if err != nil {
		return EventDetail{}, err
	}
	if !found {
		return EventDetail{}, s.missingError(ctx, request.OccurredAtHint)
	}
	if !eventInScope(event, constraint) {
		return EventDetail{}, ErrAccessDenied
	}
	retention, err := s.retentionInfo(ctx)
	if err != nil {
		return EventDetail{}, err
	}
	return EventDetail{Event: event, Scope: scope, Retention: retention,
		Stale: event.OccurredAt.Before(retention.Cutoff)}, nil
}

// loadEvent 校验事件 ID 格式并从存储读取。
func (s *Service) loadEvent(ctx context.Context, eventID string) (audit.Event, bool, error) {
	if !validEventID(eventID) {
		return audit.Event{}, false, fmt.Errorf("%w: 事件 ID 格式无效", ErrInvalidRequest)
	}
	event, found, err := s.opts.Store.GetEvent(ctx, eventID)
	if err != nil {
		return audit.Event{}, false, fmt.Errorf("%w: %w", ErrStoreUnavailable, err)
	}
	return event, found, nil
}

// missingError 区分“已过保留期”和“从未存在”：只有调用方提供了发生时且该时间
// 早于保留边界时才返回保留期错误，其余情况统一不存在。
func (s *Service) missingError(ctx context.Context, occurredAtHint time.Time) error {
	if occurredAtHint.IsZero() {
		return ErrNotFound
	}
	retention, err := s.retentionInfo(ctx)
	if err != nil {
		return err
	}
	if occurredAtHint.Before(retention.Cutoff) {
		return ErrRetentionExpired
	}
	return ErrNotFound
}

// parseScope 解析作用范围："system" 或应用 ID；应用 ID 只做格式校验，应用是否
// 存在/启用由注入的 Authorizer 判定（内部授权引擎会检查状态）。
func parseScope(raw string) (ScopeInfo, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ScopeInfo{}, fmt.Errorf("%w: 作用范围不能为空", ErrInvalidRequest)
	}
	if trimmed == ScopeSystem {
		return ScopeInfo{ID: ScopeSystem, Kind: "system"}, nil
	}
	if err := validateToken("作用范围", trimmed, 64, true); err != nil {
		return ScopeInfo{}, err
	}
	return ScopeInfo{ID: trimmed, Kind: "app"}, nil
}

// normalizeScopeID 在授权前解析并返回规范化的作用范围 ID。
func normalizeScopeID(raw string) (string, error) {
	scope, err := parseScope(raw)
	if err != nil {
		return "", err
	}
	return scope.ID, nil
}

// scopeConstraint 把授权结果转换为存储层范围约束。数据范围为 undefined/none 或
// 资源集合为空时默认拒绝，不把“未声明”当成全部数据。
func scopeConstraint(scope ScopeInfo, grant ScopeGrant) (queryScope, error) {
	if !grant.Allowed {
		return queryScope{}, ErrAccessDenied
	}
	if scope.Kind == "app" {
		if !grant.AllData && !containsString(grant.ResourceIDs, scope.ID) {
			return queryScope{}, ErrAccessDenied
		}
		return queryScope{kind: "app", scopeID: scope.ID,
			appIDs: []string{scope.ID}}, nil
	}
	if grant.AllData {
		return queryScope{kind: "system", scopeID: ScopeSystem, allData: true,
			includeSystem: true}, nil
	}
	appIDs := make([]string, 0, len(grant.ResourceIDs))
	includeSystem := false
	for _, resource := range grant.ResourceIDs {
		if resource == ScopeSystem {
			includeSystem = true
			continue
		}
		if validateToken("数据范围资源", resource, 64, true) != nil {
			continue
		}
		appIDs = append(appIDs, resource)
	}
	if len(appIDs) == 0 && !includeSystem {
		return queryScope{}, ErrAccessDenied
	}
	return queryScope{kind: "system", scopeID: ScopeSystem, appIDs: appIDs,
		includeSystem: includeSystem}, nil
}

// eventInScope 判定单条事件是否在范围约束内（用于详情读取与导出逐条复核）。
func eventInScope(event audit.Event, constraint queryScope) bool {
	if event.AppID == "" {
		return constraint.includeSystem
	}
	if constraint.allData {
		return true
	}
	return containsString(constraint.appIDs, event.AppID)
}

// normalizeOrder 解析排序；空值使用默认次序，未知排序拒绝。
func normalizeOrder(order, defaultOrder SortOrder) (SortOrder, error) {
	if order == "" {
		order = defaultOrder
	}
	if !order.Valid() {
		return "", fmt.Errorf("%w: 排序只支持 %s 或 %s", ErrInvalidRequest,
			SortNewestFirst, SortOldestFirst)
	}
	return order, nil
}

// normalizePage 校验并填充分页参数。
func (s *Service) normalizePage(limit, offset int) (int, int, error) {
	if limit == 0 {
		limit = DefaultLimit
	}
	if limit < 1 || limit > MaxLimit {
		return 0, 0, fmt.Errorf("%w: 每页条数必须在 1～%d 之间", ErrInvalidRequest, MaxLimit)
	}
	if offset < 0 || offset > MaxOffset {
		return 0, 0, fmt.Errorf("%w: 分页偏移超出范围", ErrInvalidRequest)
	}
	return limit, offset, nil
}

// validateFilter 校验筛选条件并确认显式应用/系统范围不越权。
func (s *Service) validateFilter(filter Filter, constraint queryScope) error {
	now := s.now()
	if !filter.From.IsZero() && !filter.To.IsZero() {
		if !filter.From.Before(filter.To) {
			return fmt.Errorf("%w: 开始时间必须早于结束时间", ErrInvalidRequest)
		}
		if filter.To.Sub(filter.From) > time.Duration(MaxRetentionDays)*24*time.Hour {
			return fmt.Errorf("%w: 时间区间超过允许上限", ErrInvalidRequest)
		}
	}
	if !filter.To.IsZero() && filter.To.After(now.Add(time.Minute)) {
		return fmt.Errorf("%w: 结束时间不能在未来", ErrInvalidRequest)
	}
	if filter.SystemOnly && filter.AppID != "" {
		return fmt.Errorf("%w: 不能同时指定应用与系统范围", ErrInvalidRequest)
	}
	if filter.SystemOnly && !constraint.includeSystem {
		// 显式请求系统级事件但授权范围不含系统级数据：拒绝而不是静默空列表。
		return fmt.Errorf("%w: 不能查询当前作用范围以外的系统级事件", ErrAccessDenied)
	}
	if filter.AppID != "" {
		if err := validateToken("应用 ID", filter.AppID, 64, true); err != nil {
			return err
		}
		if constraint.kind == "app" && filter.AppID != constraint.scopeID {
			return fmt.Errorf("%w: 不能查询当前作用范围以外的应用", ErrAccessDenied)
		}
		if constraint.kind == "system" && !constraint.allData &&
			!containsString(constraint.appIDs, filter.AppID) {
			return fmt.Errorf("%w: 不能查询当前数据范围以外的应用", ErrAccessDenied)
		}
	}
	if filter.ActorType != "" && !filter.ActorType.Valid() {
		return fmt.Errorf("%w: 操作者类型未知", ErrInvalidRequest)
	}
	if filter.ActorID != "" {
		if filter.ActorType == "" {
			return fmt.Errorf("%w: 指定操作者 ID 时必须同时指定操作者类型", ErrInvalidRequest)
		}
		if err := validateVisibleASCII("操作者 ID", filter.ActorID, 128, true); err != nil {
			return err
		}
	}
	if filter.Action != "" {
		if err := validateToken("动作", filter.Action, 128, true); err != nil {
			return err
		}
	}
	if filter.Outcome != "" && !filter.Outcome.Valid() {
		return fmt.Errorf("%w: 结果类别未知", ErrInvalidRequest)
	}
	if filter.ErrorCode != "" {
		if err := validateErrorCode(filter.ErrorCode); err != nil {
			return err
		}
	}
	if filter.RequestID != "" {
		if err := validateCorrelationID("请求编号", filter.RequestID); err != nil {
			return err
		}
	}
	if filter.TaskID != "" {
		if err := validateCorrelationID("任务编号", filter.TaskID); err != nil {
			return err
		}
	}
	if filter.TargetType != "" {
		if err := validateToken("目标类型", filter.TargetType, 64, true); err != nil {
			return err
		}
	}
	if filter.TargetID != "" {
		if err := validateVisibleASCII("目标 ID", filter.TargetID, 128, true); err != nil {
			return err
		}
	}
	return nil
}

// validEventID 校验审计事件 ID：aud_ 加 32 位小写十六进制。
func validEventID(id string) bool {
	if len(id) != len("aud_")+32 || !strings.HasPrefix(id, "aud_") {
		return false
	}
	for index := len("aud_"); index < len(id); index++ {
		c := id[index]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// containsString 报告集合是否包含指定字符串。
func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

// validateToken 校验稳定标识：非空/可选、长度受限、ASCII 字母数字与 . _ -。
func validateToken(name, value string, max int, required bool) error {
	if value == "" {
		if required {
			return fmt.Errorf("%w: %s不能为空", ErrInvalidRequest, name)
		}
		return nil
	}
	if len(value) > max {
		return fmt.Errorf("%w: %s超过 %d 字节", ErrInvalidRequest, name, max)
	}
	for index := 0; index < len(value); index++ {
		c := value[index]
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '.' && c != '_' && c != '-' {
			return fmt.Errorf("%w: %s只能包含 ASCII 字母、数字和 . _ -", ErrInvalidRequest, name)
		}
	}
	return nil
}

// validateVisibleASCII 校验稳定/可识别标识：长度受限、只含可见 ASCII。
func validateVisibleASCII(name, value string, max int, required bool) error {
	if value == "" {
		if required {
			return fmt.Errorf("%w: %s不能为空", ErrInvalidRequest, name)
		}
		return nil
	}
	if len(value) > max {
		return fmt.Errorf("%w: %s超过 %d 字节", ErrInvalidRequest, name, max)
	}
	for index := 0; index < len(value); index++ {
		if value[index] < 0x21 || value[index] > 0x7e {
			return fmt.Errorf("%w: %s只能包含可见 ASCII 字符", ErrInvalidRequest, name)
		}
	}
	return nil
}

// validateErrorCode 校验对外错误码：大写字母开头，字母/数字/下划线，最多 64 字节。
func validateErrorCode(code string) error {
	if len(code) > 64 {
		return fmt.Errorf("%w: 错误码超过 64 字节", ErrInvalidRequest)
	}
	for index := 0; index < len(code); index++ {
		c := code[index]
		valid := c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_'
		if index == 0 && (c < 'A' || c > 'Z') {
			valid = false
		}
		if !valid {
			return fmt.Errorf("%w: 错误码只能包含大写字母、数字和下划线", ErrInvalidRequest)
		}
	}
	return nil
}

// validateCorrelationID 校验请求/任务编号：首字符字母数字，其余字母数字与 . _ -。
func validateCorrelationID(name, id string) error {
	if len(id) == 0 || len(id) > 64 {
		return fmt.Errorf("%w: %s长度无效", ErrInvalidRequest, name)
	}
	for index := 0; index < len(id); index++ {
		c := id[index]
		alnum := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
		if index == 0 {
			if !alnum {
				return fmt.Errorf("%w: %s首字符必须是 ASCII 字母或数字", ErrInvalidRequest, name)
			}
			continue
		}
		if !alnum && c != '.' && c != '_' && c != '-' {
			return fmt.Errorf("%w: %s只能包含 ASCII 字母、数字和 . _ -", ErrInvalidRequest, name)
		}
	}
	return nil
}
