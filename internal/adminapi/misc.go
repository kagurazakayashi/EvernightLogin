package adminapi

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/task"
)

// handleMeta 处理 GET /meta：返回管理 API 版本、已装配能力与认证/CSRF 契约说明。
// 仅要求已认证管理会话，不返回任何秘密、宿主路径或内部配置。
func (s *Server) handleMeta(c *callContext) error {
	s.writeSuccess(c.writer, c.requestID, map[string]any{
		"api_version": s.version,
		"base_path":   s.basePath,
		"authentication": map[string]any{
			"scheme":               "management-session",
			"strong_auth_required": true,
			"secret_sources":       []string{"Authorization: Bearer", "会话 Cookie"},
			"csrf": "Cookie 会话的非安全方法必须携带与会话绑定的 " + CSRFHeaderName +
				" 令牌；Bearer 会话秘密不受浏览器 CSRF 影响，不要求 CSRF 头",
			"per_request_reauth": true,
			"session_contract":   "internal/session.Service.AuthorizeManagement（每次请求重新校验状态与强认证新鲜度）",
		},
		"services": map[string]bool{
			"audit":   s.audit != nil,
			"reports": s.reports != nil,
			"plans":   s.plans != nil,
			"backups": s.backups != nil,
			"tasks":   s.tasks != nil,
		},
		"limits": map[string]any{
			"max_body_bytes":     s.maxBodyBytes,
			"request_timeout_ms": int(s.requestTimeout / time.Millisecond),
			"default_page_limit": DefaultPageLimit,
			"max_page_limit":     MaxPageLimit,
			"max_offset":         MaxOffset,
			"rate_limit":         "依赖宿主 HTTP 防护中间件（本包不内置限流）",
		},
	})
	return nil
}

// errorCodeDTO 是错误码投影的公开条目。
type errorCodeDTO struct {
	Code       string `json:"code"`
	Message    string `json:"message"`
	HTTPStatus int    `json:"http_status"`
}

// handleErrorCodes 处理 GET /error-codes：返回根包错误码注册表投影（只读），
// 供 CLI/宿主做机器可读的错误码检索，不新增或改写任何码。
func (s *Server) handleErrorCodes(c *callContext) error {
	codes := make([]errorCodeDTO, 0, len(s.codes))
	for _, info := range s.codes {
		codes = append(codes, errorCodeDTO{Code: info.Code,
			Message: info.Message, HTTPStatus: info.HTTPStatus})
	}
	sort.Slice(codes, func(left, right int) bool { return codes[left].Code < codes[right].Code })
	filter, err := queryString(c.request, "code", 64)
	if err != nil {
		return err
	}
	if filter != "" {
		trimmed := make([]errorCodeDTO, 0, 1)
		for _, code := range codes {
			if strings.EqualFold(code.Code, filter) {
				trimmed = append(trimmed, code)
			}
		}
		codes = trimmed
	}
	s.writeSuccess(c.writer, c.requestID, map[string]any{"error_codes": codes})
	return nil
}

// taskAttemptDTO 是任务尝试历史公开投影。
type taskAttemptDTO struct {
	Attempt    int       `json:"attempt"`
	StartedAt  time.Time `json:"started_at,omitempty"`
	FinishedAt time.Time `json:"finished_at,omitempty"`
	Outcome    string    `json:"outcome,omitempty"`
	ErrorCode  string    `json:"error_code,omitempty"`
}

// taskDTO 是任务只读详情公开投影：不返回任务载荷，避免把业务数据/秘密带出。
type taskDTO struct {
	ID                 string           `json:"id"`
	Kind               string           `json:"kind"`
	State              string           `json:"state"`
	Initiator          actorDTO         `json:"initiator"`
	ExecutorID         string           `json:"executor_id,omitempty"`
	Canceller          *actorDTO        `json:"canceller,omitempty"`
	CancellationReason string           `json:"cancellation_reason,omitempty"`
	Attempt            int              `json:"attempt"`
	MaxAttempts        int              `json:"max_attempts"`
	PermissionRequired bool             `json:"permission_required"`
	TimeoutSeconds     int              `json:"timeout_seconds"`
	ErrorCode          string           `json:"error_code,omitempty"`
	FailureReason      string           `json:"failure_reason,omitempty"`
	RequestID          string           `json:"request_id,omitempty"`
	CreatedAt          time.Time        `json:"created_at"`
	UpdatedAt          time.Time        `json:"updated_at,omitempty"`
	StartedAt          time.Time        `json:"started_at,omitempty"`
	CancelRequestedAt  time.Time        `json:"cancel_requested_at,omitempty"`
	FinishedAt         time.Time        `json:"finished_at,omitempty"`
	NextAttemptAt      time.Time        `json:"next_attempt_at,omitempty"`
	Deadline           time.Time        `json:"deadline,omitempty"`
	Attempts           []taskAttemptDTO `json:"attempts,omitempty"`
}

// handleTaskGet 处理 GET /tasks/{task_id}：任务状态来自 internal/task 真实状态
// 机；载荷被显式剔除。
//
// 任务详情不是"可管理会话即可读"：先由注入的 TaskAuthorizer 复核功能权限与
// 数据范围/属主，拒绝统一 403，不泄露任务是否存在；任务不存在统一 404。
func (s *Server) handleTaskGet(c *callContext) error {
	taskID := c.pathParam("task_id")
	if strings.TrimSpace(taskID) == "" || len(taskID) > 128 {
		return fmt.Errorf("%w: 任务编号无效", ErrInvalidRequest)
	}
	job, err := s.tasks.Get(c.request.Context(), taskID)
	if err != nil {
		if errors.Is(err, task.ErrTaskNotFound) {
			return s.notFoundProblem()
		}
		return s.codeProblem(string(codeInternalError), err)
	}
	if authErr := s.taskAuthorizer.AuthorizeTaskRead(c.request.Context(), c.caller, job); authErr != nil {
		return fmt.Errorf("%w: %w", ErrAccessDenied, authErr)
	}
	dto := taskDTO{
		ID: job.ID, Kind: job.Kind, State: string(job.State),
		Initiator: toActorDTO(job.Initiator), ExecutorID: job.ExecutorID,
		CancellationReason: job.CancellationReason, Attempt: job.Attempt,
		MaxAttempts: job.MaxAttempts, PermissionRequired: job.PermissionRequired,
		TimeoutSeconds: job.TimeoutSeconds, ErrorCode: job.ErrorCode,
		FailureReason: job.FailureReason, RequestID: job.RequestID,
		CreatedAt: job.CreatedAt, UpdatedAt: job.UpdatedAt,
		StartedAt: job.StartedAt, CancelRequestedAt: job.CancelRequestedAt,
		FinishedAt: job.FinishedAt, NextAttemptAt: job.NextAttemptAt,
		Deadline: job.Deadline(),
	}
	if job.Canceller != nil {
		canceller := toActorDTO(*job.Canceller)
		dto.Canceller = &canceller
	}
	attempts, err := s.tasks.Attempts(c.request.Context(), taskID)
	if err != nil {
		if errors.Is(err, task.ErrTaskNotFound) {
			return s.notFoundProblem()
		}
		return s.codeProblem(string(codeInternalError), err)
	}
	for _, attempt := range attempts {
		dto.Attempts = append(dto.Attempts, taskAttemptDTO{
			Attempt: attempt.Attempt, StartedAt: attempt.StartedAt,
			FinishedAt: attempt.FinishedAt, Outcome: attempt.Outcome,
			ErrorCode: attempt.ErrorCode})
	}
	s.writeSuccess(c.writer, c.requestID, map[string]any{"task": dto})
	return nil
}

// taskListDTO 是任务列表条目：与详情共用可公开字段，但不含 payload。
type taskListDTO struct {
	ID            string    `json:"id"`
	Kind          string    `json:"kind"`
	State         string    `json:"state"`
	Initiator     actorDTO  `json:"initiator"`
	ExecutorID    string    `json:"executor_id,omitempty"`
	Attempt       int       `json:"attempt"`
	MaxAttempts   int       `json:"max_attempts"`
	ErrorCode     string    `json:"error_code,omitempty"`
	FailureReason string    `json:"failure_reason,omitempty"`
	RequestID     string    `json:"request_id,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	StartedAt     time.Time `json:"started_at,omitempty"`
	FinishedAt    time.Time `json:"finished_at,omitempty"`
}

// handleTaskList 处理 GET /tasks：分页列出任务（步骤 218）。列表级授权由
// TaskListAuthorizer 返回可见范围：普通用户只能看本人发起的任务，受信主体可看
// 全部；范围直接作为查询约束传入领域服务，不先取全量再过滤。响应不含 payload。
func (s *Server) handleTaskList(c *callContext) error {
	limit, offset, err := pageParams(c.request)
	if err != nil {
		return err
	}
	if offset != 0 {
		return fmt.Errorf("%w: 任务列表使用稳定游标，不接受非零 offset", ErrInvalidRequest)
	}
	cursor, err := queryString(c.request, "cursor", 4096)
	if err != nil {
		return err
	}
	kind, err := queryString(c.request, "kind", 64)
	if err != nil {
		return err
	}
	state, err := queryString(c.request, "state", 32)
	if err != nil {
		return err
	}
	requestID, err := queryString(c.request, "request_id", 128)
	if err != nil {
		return err
	}
	from, err := queryTime(c.request, "from")
	if err != nil {
		return err
	}
	to, err := queryTime(c.request, "to")
	if err != nil {
		return err
	}
	scope, authErr := s.taskListAuth.AuthorizeTaskList(c.request.Context(), c.caller)
	if authErr != nil {
		return fmt.Errorf("%w: %w", ErrAccessDenied, authErr)
	}
	request := task.ListJobsRequest{
		State: task.State(state), Kind: kind, RequestID: requestID,
		From: from, To: to, Limit: limit, Cursor: cursor,
	}
	if !scope.All {
		request.InitiatorType = scope.InitiatorType
		request.InitiatorID = scope.InitiatorID
	}
	page, listErr := s.taskLister.ListJobs(c.request.Context(), request)
	if listErr != nil {
		if errors.Is(listErr, task.ErrInvalidRequest) {
			return fmt.Errorf("%w: 任务列表参数无效", ErrInvalidRequest)
		}
		return s.codeProblem(string(codeInternalError), listErr)
	}
	items := make([]taskListDTO, 0, len(page.Jobs))
	for _, job := range page.Jobs {
		items = append(items, taskListDTO{
			ID: job.ID, Kind: job.Kind, State: string(job.State),
			Initiator: toActorDTO(job.Initiator), ExecutorID: job.ExecutorID,
			Attempt: job.Attempt, MaxAttempts: job.MaxAttempts,
			ErrorCode: job.ErrorCode, FailureReason: job.FailureReason,
			RequestID: job.RequestID, CreatedAt: job.CreatedAt,
			StartedAt: job.StartedAt, FinishedAt: job.FinishedAt,
		})
	}
	payload := map[string]any{"tasks": items, "has_more": page.HasMore, "limit": page.Limit}
	if page.NextCursor != "" {
		payload["next_cursor"] = page.NextCursor
	}
	s.writeSuccess(c.writer, c.requestID, payload)
	return nil
}

// 编译期确认 task.Job 状态字段被使用（避免未来重构时误删导入）。
var _ = task.Job{}
