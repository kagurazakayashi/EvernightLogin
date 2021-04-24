package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// mustEventID 生成测试用事件 ID。
func mustEventID(t *testing.T) string {
	t.Helper()
	id, err := NewEventID()
	if err != nil {
		t.Fatalf("NewEventID 失败: %v", err)
	}
	return id
}

// validEvent 返回一条合法审计事件。
func validEvent(t *testing.T) Event {
	t.Helper()
	return Event{
		ID:         mustEventID(t),
		OccurredAt: time.Date(2026, 11, 15, 10, 0, 0, 0, time.UTC),
		Actor:      Actor{Type: ActorUser, ID: "user-1"},
		AppID:      "app_1",
		Action:     "users.disable",
		Target:     Target{Type: "user", ID: "user-2"},
		Outcome:    OutcomeSuccess,
		ErrorCode:  "PERMISSION_DENIED",
		ReasonCode: "scope_mismatch",
		RequestID:  "req_0123456789abcdef",
		TaskID:     "task_1",
		Changes: []FieldChange{
			{Field: "status", Before: "active", After: "disabled"},
		},
		DedupeKey: "users.disable/user-2/v1",
	}
}

// TestNormalizeEventValid 验证合法事件规范化与差异序列化。
func TestNormalizeEventValid(t *testing.T) {
	event := validEvent(t)
	normalized, err := NormalizeEvent(event)
	if err != nil {
		t.Fatalf("合法事件规范化失败: %v", err)
	}
	if normalized.ID != event.ID || normalized.Action != event.Action {
		t.Fatalf("规范化改动了非预期字段: %+v", normalized)
	}
	detail, err := DetailJSON(normalized.Changes)
	if err != nil {
		t.Fatalf("DetailJSON 失败: %v", err)
	}
	if !strings.Contains(detail, `"status"`) || !strings.Contains(detail, `"v":1`) {
		t.Fatalf("detail JSON = %s", detail)
	}
	emptyDetail, err := DetailJSON(nil)
	if err != nil || emptyDetail != `{"v":1}` {
		t.Fatalf("空差异 JSON = %q, %v", emptyDetail, err)
	}
}

// TestActorValidation 验证四类身份规则，匿名不得携带 ID，非匿名为稳定标识。
func TestActorValidation(t *testing.T) {
	valid := []Actor{
		{Type: ActorUser, ID: "user-1"},
		{Type: ActorSystem, ID: "scheduler"},
		{Type: ActorLocalAdmin, ID: "DOMAIN\\admin"},
		{Type: ActorAnonymous, ID: ""},
	}
	for _, actor := range valid {
		if err := actor.Validate(); err != nil {
			t.Fatalf("合法身份 %+v 被拒绝: %v", actor, err)
		}
	}
	invalid := []Actor{
		{Type: "root", ID: "root"},
		{Type: ActorUser, ID: ""},
		{Type: ActorSystem, ID: ""},
		{Type: ActorLocalAdmin, ID: ""},
		{Type: ActorAnonymous, ID: "pretend-root"},
		{Type: ActorUser, ID: "user\n1"},
		{Type: ActorUser, ID: strings.Repeat("u", MaxActorIDBytes+1)},
	}
	for _, actor := range invalid {
		if err := actor.Validate(); !errors.Is(err, ErrInvalidEvent) {
			t.Fatalf("非法身份 %+v 错误 = %v，期望 ErrInvalidEvent", actor, err)
		}
	}
}

// TestEventFieldValidation 验证字段格式、长度与范围限制，错误不回显字段值。
func TestEventFieldValidation(t *testing.T) {
	base := validEvent(t)
	mutations := []struct {
		name   string
		mutate func(*Event)
	}{
		{name: "事件 ID 为空", mutate: func(e *Event) { e.ID = "" }},
		{name: "事件 ID 前缀错误", mutate: func(e *Event) { e.ID = "evt_" + strings.Repeat("0", 32) }},
		{name: "事件 ID 非十六进制", mutate: func(e *Event) { e.ID = "aud_" + strings.Repeat("z", 32) }},
		{name: "发生时间为空", mutate: func(e *Event) { e.OccurredAt = time.Time{} }},
		{name: "动作缺失", mutate: func(e *Event) { e.Action = "" }},
		{name: "动作含空格", mutate: func(e *Event) { e.Action = "users disable" }},
		{name: "动作为空", mutate: func(e *Event) { e.Action = "" }},
		{name: "动作过长", mutate: func(e *Event) { e.Action = strings.Repeat("a", MaxActionBytes+1) }},
		{name: "应用快照非法字符", mutate: func(e *Event) { e.AppID = "app 1" }},
		{name: "目标类型为空", mutate: func(e *Event) { e.Target.Type = "" }},
		{name: "目标 ID 含换行", mutate: func(e *Event) { e.Target.ID = "user\n2" }},
		{name: "目标 ID 过长", mutate: func(e *Event) { e.Target.ID = strings.Repeat("t", MaxTargetIDBytes+1) }},
		{name: "结果未知", mutate: func(e *Event) { e.Outcome = "ok" }},
		{name: "错误码小写", mutate: func(e *Event) { e.ErrorCode = "permission_denied" }},
		{name: "错误码首字符数字", mutate: func(e *Event) { e.ErrorCode = "1BAD" }},
		{name: "错误码过长", mutate: func(e *Event) { e.ErrorCode = strings.Repeat("A", MaxErrorCodeBytes+1) }},
		{name: "原因码非法字符", mutate: func(e *Event) { e.ReasonCode = "reason code" }},
		{name: "请求编号首字符符号", mutate: func(e *Event) { e.RequestID = "_req" }},
		{name: "请求编号含空格", mutate: func(e *Event) { e.RequestID = "req 1" }},
		{name: "请求编号过长", mutate: func(e *Event) { e.RequestID = strings.Repeat("r", MaxRequestIDBytes+1) }},
		{name: "任务编号过长", mutate: func(e *Event) { e.TaskID = strings.Repeat("t", MaxTaskIDBytes+1) }},
		{name: "幂等键非法字符", mutate: func(e *Event) { e.DedupeKey = "dedupe key" }},
		{name: "幂等键过长", mutate: func(e *Event) { e.DedupeKey = strings.Repeat("d", MaxDedupeKeyBytes+1) }},
	}
	for _, testCase := range mutations {
		t.Run(testCase.name, func(t *testing.T) {
			event := base
			testCase.mutate(&event)
			if _, err := NormalizeEvent(event); !errors.Is(err, ErrInvalidEvent) {
				t.Fatalf("错误 = %v，期望 ErrInvalidEvent", err)
			}
		})
	}
}

// TestRedactChanges 验证敏感字段脱敏、普通字段保留、控制字符与超长值拒绝。
func TestRedactChanges(t *testing.T) {
	changes := []FieldChange{
		{Field: "status", Before: "active", After: "disabled"},
		{Field: "password", Before: "OldSecret123", After: "NewSecret456"},
		{Field: "api_key", Before: "sk-live-xxx", After: "sk-live-yyy"},
		{Field: "verification_code", Before: "12345678", After: "87654321"},
		{Field: "totp_seed", Before: "JBSWY3DPEHPK3PXP", After: "JBSWY3DPEHPK3PXQ"},
		{Field: "recovery_codes", Before: "aaaaaaaa", After: "bbbbbbbb"},
		{Field: "authorization_header", Before: "Bearer secret", After: ""},
	}
	normalized, err := RedactChanges(changes)
	if err != nil {
		t.Fatalf("RedactChanges 失败: %v", err)
	}
	detail, err := DetailJSON(normalized)
	if err != nil {
		t.Fatalf("DetailJSON 失败: %v", err)
	}
	var decoded struct {
		Version int           `json:"v"`
		Changes []FieldChange `json:"changes"`
	}
	if err := json.Unmarshal([]byte(detail), &decoded); err != nil {
		t.Fatalf("detail JSON 解析失败: %v", err)
	}
	if len(decoded.Changes) != len(changes) {
		t.Fatalf("差异字段数量 = %d", len(decoded.Changes))
	}
	for _, secret := range []string{"OldSecret123", "NewSecret456", "sk-live-xxx", "sk-live-yyy", "12345678", "87654321", "JBSWY3DPEHPK3PXP", "aaaaaaaa", "Bearer secret"} {
		if strings.Contains(detail, secret) {
			t.Fatalf("detail 泄露敏感值 %q: %s", secret, detail)
		}
	}
	if !strings.Contains(detail, "[REDACTED]") {
		t.Fatalf("detail 缺少脱敏标记: %s", detail)
	}
	if !strings.Contains(detail, `"before":"active"`) || !strings.Contains(detail, `"after":"disabled"`) {
		t.Fatalf("普通字段未原样保留: %s", detail)
	}

	invalidChanges := []struct {
		name   string
		change FieldChange
	}{
		{name: "字段名为空", change: FieldChange{Field: ""}},
		{name: "字段名非法字符", change: FieldChange{Field: "bad field"}},
		{name: "普通值含换行", change: FieldChange{Field: "note", Before: "a\nb"}},
		{name: "普通值含控制字符", change: FieldChange{Field: "note", After: "a\x00b"}},
		{name: "普通值过长", change: FieldChange{Field: "note", Before: strings.Repeat("x", MaxDiffValueBytes+1)}},
		{name: "普通值非法 UTF-8", change: FieldChange{Field: "note", Before: string([]byte{0xff, 0xfe})}},
		{name: "重复字段名", change: FieldChange{Field: "note"}},
	}
	for _, testCase := range invalidChanges {
		t.Run(testCase.name, func(t *testing.T) {
			candidate := []FieldChange{testCase.change}
			if testCase.name == "重复字段名" {
				candidate = append(candidate, FieldChange{Field: "note", Before: "x"})
			}
			if _, err := RedactChanges(candidate); !errors.Is(err, ErrInvalidEvent) {
				t.Fatalf("错误 = %v，期望 ErrInvalidEvent", err)
			}
		})
	}
}

// TestRedactChangesFieldLimit 验证字段数量上限与 detail JSON 大小上限。
func TestRedactChangesFieldLimit(t *testing.T) {
	tooMany := make([]FieldChange, MaxDiffFields+1)
	for i := range tooMany {
		tooMany[i] = FieldChange{Field: "field_" + string(rune('a'+i)), Before: "x"}
	}
	if _, err := RedactChanges(tooMany); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("超量字段错误 = %v", err)
	}
	large := make([]FieldChange, MaxDiffFields)
	for i := range large {
		large[i] = FieldChange{Field: "field_" + string(rune('a'+i)), Before: strings.Repeat("x", MaxDiffValueBytes), After: strings.Repeat("y", MaxDiffValueBytes)}
	}
	if _, err := DetailJSON(large); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("超大 detail 错误 = %v", err)
	}
}

// TestOutcomeAndKindValid 验证枚举值。
func TestOutcomeAndKindValid(t *testing.T) {
	for _, outcome := range []Outcome{OutcomeSuccess, OutcomeFailure, OutcomeDenied} {
		if !outcome.Valid() {
			t.Fatalf("%q 应为合法结果", outcome)
		}
	}
	for _, outcome := range []Outcome{"", "ok", "SUCCESS"} {
		if outcome.Valid() {
			t.Fatalf("%q 不应为合法结果", outcome)
		}
	}
	for _, actorType := range []ActorKind{ActorUser, ActorSystem, ActorLocalAdmin, ActorAnonymous} {
		if !actorType.Valid() {
			t.Fatalf("%q 应为合法操作者类型", actorType)
		}
	}
	for _, actorType := range []ActorKind{"", "root", "USER"} {
		if actorType.Valid() {
			t.Fatalf("%q 不应为合法操作者类型", actorType)
		}
	}
}

// TestNewEventIDFormatAndRandomFailure 验证事件 ID 格式与随机源失败。
func TestNewEventIDFormatAndRandomFailure(t *testing.T) {
	first := mustEventID(t)
	second := mustEventID(t)
	if first == second {
		t.Fatal("两次生成的事件 ID 相同")
	}
	if err := validateEventID(first); err != nil {
		t.Fatalf("生成的事件 ID 不合格式: %v", err)
	}
	failing := bytes.NewReader(nil)
	if _, err := newEventID(failing); !errors.Is(err, ErrRandomSource) {
		t.Fatalf("随机源失败错误 = %v，期望 ErrRandomSource", err)
	}
}
