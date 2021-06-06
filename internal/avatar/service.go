package avatar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"reflect"
	"strconv"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
)

const (
	// DefaultGCSafetyWindow 是孤儿文件清理的默认安全窗口：修改时间晚于“当前时间
	// 减去该窗口”的未引用文件不会被删除，避免误删刚写入但数据库引用尚未提交的
	// 新文件。
	DefaultGCSafetyWindow = 10 * time.Minute
	// MinGCSafetyWindow 是允许配置的 GC 安全窗口下限：即使高负载下单次“落盘 ->
	// 提交引用”在极端排队时超过数百毫秒，30 秒仍提供足够余量；更小的窗口会重新
	// 引入误删在途文件的风险，因此拒绝构造。
	MinGCSafetyWindow = 30 * time.Second
	// MaxGCSafetyWindow 是允许配置的 GC 安全窗口上限。
	MaxGCSafetyWindow = 24 * time.Hour
)

// Options 是头像服务依赖。
type Options struct {
	Store   Store
	Storage Storage
	Audit   AuditRecorder
	// Authorizer 判定跨用户读/写权限；nil 时使用“仅本人与受信 system/local_admin”
	// 的默认口径。跨用户展示头像必须由宿主注入实现并自行决定可见范围。
	// 默认口径只校验身份 ID，不检查账户状态（禁用/待审核用户若宿主仍传递 Caller
	// 仍可修改自己头像）；HTTP/装配阶段必须由宿主的会话/状态校验或注入的
	// Authorizer fail-closed 补齐，本包不把身份有效等同于账户可用。
	Authorizer Authorizer
	// GCSafetyWindow 是孤儿文件清理安全窗口；0 使用 DefaultGCSafetyWindow。
	// 允许范围 30 秒～24 小时；只清理修改时间早于 now-窗口 的未引用文件，保护正在
	// 写入但尚未提交引用的新文件。
	GCSafetyWindow time.Duration
	// Network 是网络头像抓取策略；零值为安全默认（仅 https、默认端口、10 秒）。
	Network NetworkPolicy
	// Resolver 仅供测试注入 DNS 解析器；nil 使用系统解析器。
	Resolver IPResolver
	Now      func() time.Time
	Logger   *slog.Logger
}

// Service 是头像领域服务。构造后不可变，不启动协程、不签发会话、不暴露 HTTP 路由。
type Service struct {
	opts     Options
	fetcher  *networkFetcher
	gcWindow time.Duration
}

// New 校验依赖并构造服务。缺少存储、审计或网络策略非法时拒绝构造。
func New(options Options) (*Service, error) {
	if isNil(options.Store) {
		return nil, fmt.Errorf("%w: 头像记录存储为空", ErrOptionsInvalid)
	}
	if isNil(options.Storage) {
		return nil, fmt.Errorf("%w: 头像文件存储为空", ErrOptionsInvalid)
	}
	if isNil(options.Audit) {
		return nil, fmt.Errorf("%w: 安全审计写入器为空", ErrOptionsInvalid)
	}
	policy, err := options.Network.resolve()
	if err != nil {
		return nil, err
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.Logger == nil {
		options.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	gcWindow := options.GCSafetyWindow
	if gcWindow == 0 {
		gcWindow = DefaultGCSafetyWindow
	}
	if gcWindow < MinGCSafetyWindow || gcWindow > MaxGCSafetyWindow {
		return nil, fmt.Errorf("%w: GC 安全窗口必须在 %s～%s 之间", ErrOptionsInvalid,
			MinGCSafetyWindow, MaxGCSafetyWindow)
	}
	return &Service{
		opts:     options,
		fetcher:  newNetworkFetcher(policy, options.Resolver),
		gcWindow: gcWindow,
	}, nil
}

// Upload 由本人（或受信 system/local_admin 代管）上传并替换头像。
//
// 顺序：先完成身份/目标/版本判定（避免无权限调用者消耗解码资源）-> 校验并重编码
// （不信任客户端扩展名）-> 写入受控目录 -> 审计事务内条件更新引用/替换记录 ->
// 事务成功后才清理旧文件。任一步失败都不会留下“引用已更新但文件缺失”或“文件已
// 写但引用未更新”的状态：数据库失败时补偿删除新文件，旧文件删除失败留给
// CollectGarbage。
func (s *Service) Upload(ctx context.Context, caller Caller, request UploadRequest) (Avatar, error) {
	ctx = normalizeContext(ctx)
	state, requestID, err := s.prepareWrite(ctx, caller, request.TargetUserID,
		request.ExpectedRowVersion, request.RequestID)
	if err != nil {
		return Avatar{}, err
	}
	processed, err := ProcessImage(request.Data, request.DeclaredMediaType)
	if err != nil {
		return Avatar{}, err
	}
	return s.storeProcessed(ctx, caller, state, requestID, SourceUpload, "", processed,
		request.ExpectedRowVersion)
}

// FetchFromURL 抓取网络头像并落库。抓取路径只允许公网 https 目标，大小、时限、
// 重定向与地址分类都受 Network 策略约束；调用者必须先通过目标与版本判定，避免
// 无权限请求驱使服务器抓取任意公网地址。抓取到的字节与上传走同一重编码流程。
func (s *Service) FetchFromURL(ctx context.Context, caller Caller, request FetchRequest) (Avatar, error) {
	ctx = normalizeContext(ctx)
	state, requestID, err := s.prepareWrite(ctx, caller, request.TargetUserID,
		request.ExpectedRowVersion, request.RequestID)
	if err != nil {
		return Avatar{}, err
	}
	data, declared, host, err := s.fetcher.fetch(ctx, request.URL)
	if err != nil {
		return Avatar{}, err
	}
	processed, err := ProcessImage(data, declared)
	if err != nil {
		return Avatar{}, err
	}
	return s.storeProcessed(ctx, caller, state, requestID, SourceNetwork, host, processed,
		request.ExpectedRowVersion)
}

// prepareWrite 在解码/抓取/写文件之前完成请求编号、目标授权与行版本判定。
func (s *Service) prepareWrite(ctx context.Context, caller Caller, targetUserID string,
	expectedRowVersion int64, requestID string) (UserState, string, error) {
	if err := account.ValidateRequestID(requestID); err != nil {
		return UserState{}, "", fmt.Errorf("%w: 请求编号无效", ErrInvalidRequest)
	}
	if caller.requestID != "" && requestID == "" {
		requestID = caller.requestID
	}
	if expectedRowVersion < 1 {
		return UserState{}, "", fmt.Errorf("%w: 资料版本无效", ErrInvalidRequest)
	}
	state, err := s.resolveTarget(ctx, caller, targetUserID, true)
	if err != nil {
		return UserState{}, "", err
	}
	if state.RowVersion != expectedRowVersion {
		return UserState{}, "", ErrVersionConflict
	}
	return state, requestID, nil
}

// storeProcessed 是上传与网络抓取的共同落库实现；state 由 prepareWrite 提供。
func (s *Service) storeProcessed(ctx context.Context, caller Caller, state UserState, requestID,
	sourceKind, sourceHost string, processed ProcessedImage, expectedRowVersion int64) (Avatar, error) {
	// 审计差异的“之前”值：同一行版本下的读取是一致的；任何并发写入都会递增
	// users.row_version，从而让事务内条件更新失败，不会出现差异与实际不一致。
	previous, hadPrevious, err := s.opts.Store.Current(ctx, state.UserID)
	if err != nil {
		return Avatar{}, ErrStoreUnavailable
	}
	storageKey, err := s.opts.Storage.Save(ctx, processed.Data, processed.Extension)
	if err != nil {
		return Avatar{}, err
	}
	avatarID, err := NewAvatarID()
	if err != nil {
		_ = s.opts.Storage.Remove(context.WithoutCancel(ctx), storageKey)
		return Avatar{}, err
	}
	now := s.now()
	record := AvatarRecord{
		ID:         avatarID,
		UserID:     state.UserID,
		StorageKey: storageKey,
		MediaType:  processed.MediaType,
		ByteSize:   int64(len(processed.Data)),
		Width:      processed.Width,
		Height:     processed.Height,
		SHA256:     processed.SHA256[:],
		SourceKind: sourceKind,
		CreatedAt:  now,
		UpdatedAt:  now,
		RowVersion: expectedRowVersion + 1,
	}
	action := "avatar.upload"
	failureReason := "avatar.upload_failed"
	if sourceKind == SourceNetwork {
		action = "avatar.fetch"
		failureReason = "avatar.fetch_failed"
	}
	changes := describeChanges(previous, hadPrevious, record)
	if sourceHost != "" {
		changes = append(changes, audit.FieldChange{Field: "source_host", After: sourceHost})
	}
	critical := audit.CriticalRequest{
		Event: audit.Event{
			Actor:     caller.actor,
			Action:    action,
			Target:    audit.Target{Type: "user", ID: state.UserID},
			RequestID: requestID,
			Changes:   changes,
		},
		FailureReasonCode: failureReason,
		FailureErrorCodeFor: func(err error) string {
			return string(CodeOf(mapCriticalError(err)))
		},
	}
	var removed AvatarRecord
	err = s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		old, ok, replaceErr := s.opts.Store.ReplaceTx(txCtx, tx, ReplaceRecord{
			UserID:             state.UserID,
			New:                record,
			ExpectedRowVersion: expectedRowVersion,
			Now:                now,
		})
		if replaceErr != nil {
			return replaceErr
		}
		if !ok {
			return ErrVersionConflict
		}
		removed = old
		return nil
	})
	if err != nil {
		// 补偿：数据库/审计失败时删除刚写入的新文件，旧引用保持不变。
		if removeErr := s.opts.Storage.Remove(context.WithoutCancel(ctx), storageKey); removeErr != nil {
			s.opts.Logger.Warn("头像新文件补偿删除失败，将由 CollectGarbage 清理", "error", removeErr)
		}
		return Avatar{}, mapCriticalError(err)
	}
	// 事务提交后再清理旧文件；删除失败不影响已成立的引用，留给 GC。
	s.removeFileBestEffort(ctx, removed.StorageKey)
	return avatarOf(record), nil
}

// Current 读取目标用户当前头像元数据；未设置时返回 found=false。
func (s *Service) Current(ctx context.Context, caller Caller, userID string) (Avatar, bool, error) {
	ctx = normalizeContext(ctx)
	record, found, err := s.currentRecord(ctx, caller, userID)
	if err != nil || !found {
		return Avatar{}, false, err
	}
	return avatarOf(record), true, nil
}

// Read 读取并校验当前头像内容：尺寸/字节数/摘要必须与记录一致，否则拒绝返回
// 可能被篡改或错位的内容。返回的数据只包含服务端重编码后的静态图片。
func (s *Service) Read(ctx context.Context, caller Caller, userID string) (Content, error) {
	ctx = normalizeContext(ctx)
	record, found, err := s.currentRecord(ctx, caller, userID)
	if err != nil {
		return Content{}, err
	}
	if !found {
		return Content{}, fmt.Errorf("%w: 当前没有头像", ErrInvalidRequest)
	}
	data, err := s.opts.Storage.Open(ctx, record.StorageKey)
	if err != nil {
		return Content{}, err
	}
	if int64(len(data)) != record.ByteSize {
		return Content{}, fmt.Errorf("%w: 头像文件大小与记录不一致", ErrStorageCorrupt)
	}
	sum := sha256.Sum256(data)
	if !bytes.Equal(sum[:], record.SHA256) {
		return Content{}, fmt.Errorf("%w: 头像文件摘要与记录不一致", ErrStorageCorrupt)
	}
	return Content{Avatar: avatarOf(record), Data: data}, nil
}

// Remove 清除当前头像；数据库引用先清除，文件删除失败留给 CollectGarbage。
func (s *Service) Remove(ctx context.Context, caller Caller, request RemoveRequest) error {
	ctx = normalizeContext(ctx)
	state, requestID, err := s.prepareWrite(ctx, caller, request.TargetUserID,
		request.ExpectedRowVersion, request.RequestID)
	if err != nil {
		return err
	}
	previous, found, err := s.opts.Store.Current(ctx, state.UserID)
	if err != nil {
		return ErrStoreUnavailable
	}
	if !found {
		return fmt.Errorf("%w: 当前没有头像", ErrInvalidRequest)
	}
	now := s.now()
	critical := audit.CriticalRequest{
		Event: audit.Event{
			Actor:     caller.actor,
			Action:    "avatar.remove",
			Target:    audit.Target{Type: "user", ID: state.UserID},
			RequestID: requestID,
			Changes: []audit.FieldChange{
				{Field: "avatar_id", Before: previous.ID, After: ""},
				{Field: "media_type", Before: previous.MediaType, After: ""},
			},
		},
		FailureReasonCode: "avatar.remove_failed",
		FailureErrorCodeFor: func(err error) string {
			return string(CodeOf(mapCriticalError(err)))
		},
	}
	var removed AvatarRecord
	err = s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		old, ok, removeErr := s.opts.Store.RemoveTx(txCtx, tx, state.UserID, request.ExpectedRowVersion, now)
		if removeErr != nil {
			return removeErr
		}
		if !ok {
			return ErrVersionConflict
		}
		removed = old
		return nil
	})
	if err != nil {
		return mapCriticalError(err)
	}
	s.removeFileBestEffort(ctx, removed.StorageKey)
	return nil
}

// CollectGarbage 清理受控目录内不再被任何头像记录引用、且修改时间早于安全窗口的
// 文件（旧文件删除失败与失败补偿的路径）。
//
// 安全窗口解决“上传已把新文件落盘、数据库引用事务尚未提交时 GC 恰好运行”的竞态：
// 未提交的新文件不会被当作孤儿删除；窗口过后仍未被引用才视为孤儿。它只删除符合
// 受控存储键格式的普通文件，不触碰其他文件、符号链接或目录内容。本方法假设同一
// 受控目录由单个服务实例管理；多实例同时写入时窗口仍能保护新文件，但更严格的
// 跨实例互斥留给后续步骤。
func (s *Service) CollectGarbage(ctx context.Context) (int, error) {
	ctx = normalizeContext(ctx)
	referenced, err := s.opts.Store.ListStorageKeys(ctx)
	if err != nil {
		return 0, ErrStoreUnavailable
	}
	keep := make(map[string]struct{}, len(referenced))
	for _, key := range referenced {
		keep[key] = struct{}{}
	}
	present, err := s.opts.Storage.ListFiles(ctx)
	if err != nil {
		return 0, err
	}
	now := s.now()
	removed := 0
	for _, file := range present {
		if _, ok := keep[file.Key]; ok {
			continue
		}
		if now.Sub(file.ModifiedAt) < s.gcWindow {
			// 可能是正在写入、引用尚未提交的新文件：本次跳过，留给窗口后的 GC。
			continue
		}
		if err := s.opts.Storage.Remove(ctx, file.Key); err != nil {
			return removed, err
		}
		removed++
	}
	return removed, nil
}

// currentRecord 读取并校验当前头像记录与用户引用的一致性。
func (s *Service) currentRecord(ctx context.Context, caller Caller, userID string) (AvatarRecord, bool, error) {
	ctx = normalizeContext(ctx)
	state, err := s.resolveTarget(ctx, caller, userID, false)
	if err != nil {
		return AvatarRecord{}, false, err
	}
	if state.AvatarRef == "" {
		return AvatarRecord{}, false, nil
	}
	record, found, err := s.opts.Store.GetAvatar(ctx, state.AvatarRef)
	if err != nil {
		return AvatarRecord{}, false, ErrStoreUnavailable
	}
	if !found || record.UserID != state.UserID {
		// 引用指向不存在的记录或他人记录属于数据不一致，fail-closed。
		return AvatarRecord{}, false, fmt.Errorf("%w: 头像引用与记录不一致", ErrStorageCorrupt)
	}
	return record, true, nil
}

// resolveTarget 解析并授权目标用户，返回带当前行版本的用户快照。
func (s *Service) resolveTarget(ctx context.Context, caller Caller, targetUserID string, write bool) (UserState, error) {
	if err := caller.actor.Validate(); err != nil {
		return UserState{}, ErrAccessDenied
	}
	if targetUserID == "" {
		if !caller.IsUser() {
			return UserState{}, fmt.Errorf("%w: 必须指定目标用户", ErrInvalidRequest)
		}
		targetUserID = caller.actor.ID
	}
	if !account.ValidUserID(targetUserID) {
		return UserState{}, fmt.Errorf("%w: 用户 ID 格式无效", ErrInvalidRequest)
	}
	// 先判权，避免向无权调用者泄露目标用户是否存在。
	if err := s.preAuthorize(ctx, caller, targetUserID, write); err != nil {
		return UserState{}, err
	}
	state, err := s.opts.Store.GetUserState(ctx, targetUserID)
	if err != nil {
		return UserState{}, ErrStoreUnavailable
	}
	if !state.Exists {
		return UserState{}, ErrUserNotFound
	}
	if err := s.authorize(ctx, caller, Target{UserID: targetUserID, IsRoot: state.IsRoot}, write); err != nil {
		return UserState{}, err
	}
	return state, nil
}

// preAuthorize 在读取目标前做保守判权。
func (s *Service) preAuthorize(ctx context.Context, caller Caller, targetUserID string, write bool) error {
	callerIsSelf := caller.IsUser() && caller.actor.ID == targetUserID
	if s.opts.Authorizer != nil {
		if callerIsSelf {
			return nil
		}
		if err := s.opts.Authorizer.AuthorizeAvatar(ctx, caller,
			Target{UserID: targetUserID}, write); err != nil {
			return ErrAccessDenied
		}
		return nil
	}
	switch caller.actor.Type {
	case audit.ActorUser:
		if caller.actor.ID != targetUserID {
			return ErrAccessDenied
		}
		return nil
	case audit.ActorSystem, audit.ActorLocalAdmin:
		return nil
	default:
		return ErrAccessDenied
	}
}

// authorize 使用注入 Authorizer 或默认口径判定权限。
func (s *Service) authorize(ctx context.Context, caller Caller, target Target, write bool) error {
	if s.opts.Authorizer != nil {
		if err := s.opts.Authorizer.AuthorizeAvatar(ctx, caller, target, write); err != nil {
			return ErrAccessDenied
		}
		return nil
	}
	switch caller.actor.Type {
	case audit.ActorUser:
		if caller.actor.ID != target.UserID {
			return ErrAccessDenied
		}
		return nil
	case audit.ActorSystem, audit.ActorLocalAdmin:
		return nil
	default:
		return ErrAccessDenied
	}
}

// removeFileBestEffort 在事务提交后清理旧文件，失败只记录日志（由 GC 兜底）。
func (s *Service) removeFileBestEffort(ctx context.Context, storageKey string) {
	if storageKey == "" {
		return
	}
	if err := s.opts.Storage.Remove(context.WithoutCancel(ctx), storageKey); err != nil {
		s.opts.Logger.Warn("旧头像文件删除失败，将由 CollectGarbage 清理", "error", err)
	}
}

func (s *Service) now() time.Time { return s.opts.Now().UTC().Truncate(time.Millisecond) }

// describeChanges 生成审计差异：只记录媒体类型/大小/尺寸/来源与头像 ID，
// 不记录存储键、本机路径或用户原始文件名。
func describeChanges(previous AvatarRecord, hadPrevious bool, next AvatarRecord) []audit.FieldChange {
	after := avatarChangeFields(next)
	if !hadPrevious {
		changes := make([]audit.FieldChange, 0, len(after))
		for _, change := range after {
			changes = append(changes, audit.FieldChange{Field: change.Field, After: change.After})
		}
		return changes
	}
	before := avatarChangeFields(previous)
	changes := make([]audit.FieldChange, 0, len(after))
	for index := range after {
		change := audit.FieldChange{Field: after[index].Field, After: after[index].After}
		if index < len(before) {
			change.Before = before[index].After
		}
		changes = append(changes, change)
	}
	return changes
}

// avatarChangeFields 返回固定顺序的头像字段描述。
func avatarChangeFields(record AvatarRecord) []audit.FieldChange {
	return []audit.FieldChange{
		{Field: "avatar_id", After: record.ID},
		{Field: "media_type", After: record.MediaType},
		{Field: "byte_size", After: strconv.FormatInt(record.ByteSize, 10)},
		{Field: "width", After: strconv.Itoa(record.Width)},
		{Field: "height", After: strconv.Itoa(record.Height)},
		{Field: "source_kind", After: record.SourceKind},
	}
}

// avatarOf 把持久化记录转换为对外快照（不包含存储键）。
func avatarOf(record AvatarRecord) Avatar {
	return Avatar{
		ID:         record.ID,
		UserID:     record.UserID,
		MediaType:  record.MediaType,
		SourceKind: record.SourceKind,
		ByteSize:   record.ByteSize,
		Width:      record.Width,
		Height:     record.Height,
		SHA256:     hex.EncodeToString(record.SHA256),
		RowVersion: record.RowVersion,
		CreatedAt:  record.CreatedAt,
		UpdatedAt:  record.UpdatedAt,
	}
}

// mapCriticalError 把审计事务错误映射为领域错误，不把内部错误伪装成成功。
func mapCriticalError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, audit.ErrAuditUnavailable):
		return fmt.Errorf("%w: %w", ErrAuditUnavailable, err)
	case errors.Is(err, audit.ErrInvalidEvent):
		return fmt.Errorf("%w: 审计事件无效", ErrOptionsInvalid)
	case errors.Is(err, ErrVersionConflict), errors.Is(err, ErrInvalidRequest),
		errors.Is(err, ErrAccessDenied), errors.Is(err, ErrUserNotFound),
		errors.Is(err, ErrOptionsInvalid):
		return err
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	case errors.Is(err, ErrStoreUnavailable), errors.Is(err, ErrStorageUnavailable):
		return err
	case errors.Is(err, ErrStorageCorrupt):
		return err
	default:
		return fmt.Errorf("%w: %w", ErrStoreUnavailable, err)
	}
}

func normalizeContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

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
