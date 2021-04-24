package audit

import "errors"

// 本包错误只说明失败类别，不包含事件明文、秘密、差异值或数据库细节。调用方
// 对外映射时：ErrAuditUnavailable 对应错误码 AUDIT_WRITE_FAILED（503），
// ErrInvalidEvent/ErrOptionsInvalid 属于内部调用错误，ErrDuplicateEvent 表示
// 幂等重放。
var (
	// ErrInvalidEvent 表示审计事件字段不合法（身份、长度、字符集、差异超限等）。
	ErrInvalidEvent = errors.New("audit: 审计事件无效")
	// ErrAuditUnavailable 表示审计存储不可用或写入失败；关键管理变更必须拒绝，
	// 不能留下“业务成功但审计缺失”的结果。
	ErrAuditUnavailable = errors.New("audit: 审计写入不可用")
	// ErrDuplicateEvent 表示带 dedupe_key 的事件已存在；重试方可按幂等处理。
	ErrDuplicateEvent = errors.New("audit: 审计事件重复")
	// ErrOptionsInvalid 表示 Recorder 构造参数不合法。
	ErrOptionsInvalid = errors.New("audit: 服务选项无效")
	// ErrRandomSource 表示安全随机源不可用，无法生成事件 ID。
	ErrRandomSource = errors.New("audit: 安全随机源不可用")
)
