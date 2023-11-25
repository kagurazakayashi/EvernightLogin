package managecli

// 步骤 233：本地脱敏运行时诊断/关联错误 CLI 测试。
//   - diag runtime 输出脱敏快照（版本/存储/队列/配置待重启），JSON 契约稳定；
//   - diag errors 按请求编号返回白名单错误事件；
//   - 非法 scope/request-id/limit 在参数阶段拒绝（退出码 2），不进入数据库查询。

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestStep233DiagRuntimeAndErrors(t *testing.T) {
	fixture := newDomainFixture(t)
	seedDiagnosticsCLIFixtures(t, fixture)
	configPath := fixture.configPath

	stdout, stderr, exit := runCLI(t, "diag", "runtime", "--config", configPath, "--json")
	if exit != ExitOK {
		t.Fatalf("diag runtime 退出码 = %d，stderr=%s", exit, stderr)
	}
	envelope := decodeEnvelope(t, stdout)
	data, ok := envelope["data"].(map[string]any)
	if !ok {
		t.Fatalf("diag runtime 缺少 data: %s", stdout)
	}
	if data["status"] == "" || data["version"] == nil || data["storage"] == nil ||
		data["queues"] == nil || data["config"] == nil {
		t.Fatalf("diag runtime 数据不完整: %v", data)
	}
	raw, _ := json.Marshal(data)
	for _, forbidden := range []string{"diag-cli-secret", "diag-cli@example.test",
		"usr_00000000000000000000000000000092"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("诊断输出泄露 %q: %s", forbidden, raw)
		}
	}

	stdout, stderr, exit = runCLI(t, "diag", "errors", "--request-id",
		"req_diag_cli_1", "--config", configPath, "--json")
	if exit != ExitOK {
		t.Fatalf("diag errors 退出码 = %d，stderr=%s", exit, stderr)
	}
	errorData := decodeEnvelope(t, stdout)["data"].(map[string]any)
	entries, ok := errorData["entries"].([]any)
	if !ok || len(entries) != 1 {
		t.Fatalf("关联错误条目异常: %v", errorData)
	}
	entry := entries[0].(map[string]any)
	if entry["error_code"] != "AUTH_FAILED" || entry["request_id"] != "req_diag_cli_1" {
		t.Fatalf("关联错误白名单字段异常: %v", entry)
	}
	if strings.Contains(stdout, "diag-cli-secret") || strings.Contains(stdout, "diag-cli@example.test") {
		t.Fatalf("关联错误输出泄露合成秘密")
	}

	// 非法参数：退出码 2，不执行数据库查询。
	for _, args := range [][]string{
		{"diag", "errors", "--config", configPath, "--json"},
		{"diag", "errors", "--request-id", "not a request id", "--config", configPath, "--json"},
		{"diag", "errors", "--request-id", "req_diag_cli_1", "--limit", "999",
			"--config", configPath, "--json"},
		{"diag", "runtime", "--scope", "not-an-app", "--config", configPath, "--json"},
	} {
		if _, _, exit := runCLI(t, args...); exit != ExitUsage {
			t.Fatalf("参数 %v 退出码 = %d，期望 %d", args, exit, ExitUsage)
		}
	}
}

// seedDiagnosticsCLIFixtures 写入任务/邮件/审计夹具（含合成秘密与个人资料）。
func seedDiagnosticsCLIFixtures(t *testing.T, fixture *domainFixture) {
	t.Helper()
	db := fixture.raw.DB()
	nowMS := time.Now().UTC().UnixMilli()
	exec := func(query string, args ...any) {
		if _, err := db.Exec(query, args...); err != nil {
			t.Fatalf("写入诊断夹具: %v", err)
		}
	}
	exec(`INSERT INTO jobs(id,kind,state,initiated_by_type,initiated_by_id,timeout_seconds,
created_at_ms,updated_at_ms) VALUES(?,?,?,?,?,?,?,?)`, "diag-cli-job", "mail.delivery",
		"queued", "system", "diag-test", 30, nowMS, nowMS)
	exec(`INSERT INTO mail_deliveries(id,idempotency_key,template_kind,recipient,
owner_type,owner_id,state,sealed_payload,created_at_ms,updated_at_ms)
VALUES(?,?,?,?,?,?,?,?,?,?)`, "diag-cli-mail", "diag-cli-idem", "verification",
		"diag-cli@example.test", "user", "usr_00000000000000000000000000000092",
		"queued", []byte("sealed-diag-cli-secret"), nowMS, nowMS)
	exec(`INSERT INTO audit_events(id,occurred_at_ms,actor_type,actor_id,action,
target_type,target_id,outcome,error_code,reason_code,request_id,detail_json)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`, "diag-cli-audit", nowMS, "user",
		"usr_00000000000000000000000000000092", "diag.error", "user", "target",
		"failure", "AUTH_FAILED", "bad_credentials", "req_diag_cli_1",
		`{"password":"diag-cli-secret"}`)
}
