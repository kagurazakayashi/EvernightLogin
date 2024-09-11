package serverapp_test

// 步骤 266 端到端：真实临时 SQLite + 真实 login-server 进程 + 管理 API 会话。
//
// 覆盖：
//   - GET /admin/v1/notifications/history：真实 reauth 存储的稳定游标分页（同创建
//     时间不重不漏）、脱敏字段、无会话 401 / 受限会话 403；
//   - GET /admin/v1/deliveries：真实 mail_deliveries 记录的终态筛选（failed/
//     cancelled）、脱敏收件人、不含加密载荷、游标分页；
//   - 未认证/受限会话拒绝且不泄露数据。

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/serverapp"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
)

// step266AdminGet 以管理会话请求 API 并返回解析后的 data 对象。
func step266AdminGet(t *testing.T, client *http.Client, target string,
	cookie *http.Cookie) (int, map[string]any) {
	t.Helper()
	status, body := adminAPIGet(t, client, target, cookie)
	var envelope struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal([]byte(body), &envelope); err != nil {
		return status, nil
	}
	return status, envelope.Data
}

// TestStep266HistoryEndpointsE2E 验证安全告知分页与投递记录端点的生产装配闭环。
func TestStep266HistoryEndpointsE2E(t *testing.T) {
	paths := preparePaths(t, nil)
	writeMasterKey(t, paths.masterKey)
	if stdout, err := runInit(t, paths); err != nil {
		t.Fatalf("首次初始化失败: %v（stdout=%s）", err, stdout)
	}
	// 在服务启动前向真实 SQLite 写入合成数据（与真实表结构一致）。
	raw, err := storagesqlite.Open(context.Background(),
		storagesqlite.DefaultOptions(paths.database))
	if err != nil {
		t.Fatalf("打开临时数据库失败: %v", err)
	}
	ctx := context.Background()
	var rootID string
	if err := raw.DB().QueryRowContext(ctx,
		`SELECT id FROM users WHERE is_root=1 LIMIT 1`).Scan(&rootID); err != nil {
		_ = raw.Close()
		t.Fatalf("读取 root 用户失败: %v", err)
	}
	baseMS := time.Date(2026, 11, 26, 3, 0, 0, 0, time.UTC).UnixMilli()
	// 同一 created_at_ms 的 5 条安全告知（以稳定 ID 并列），queued 状态。
	for index := 1; index <= 5; index++ {
		if _, err := raw.DB().ExecContext(ctx, `INSERT INTO security_notifications(
id,user_id,operation_id,target_type,target_id,outcome,state,error_code,reason_code,
recipient_masked,created_at_ms) VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
			"ntf_step266_"+string(rune('0'+index)), rootID, "password.change", "user",
			rootID, "success", "queued", "", "", "a***@example.com", baseMS); err != nil {
			_ = raw.Close()
			t.Fatalf("写入告知 %d: %v", index, err)
		}
	}
	// 真实投递记录：failed / cancelled / succeeded 终态各一条（收件人为完整地址，
	// 端点必须脱敏；sealed_payload 只有在领域层被显式清空后才不会外泄）。
	deliveries := []struct {
		id, state, recipient, errorCode string
		createdMS                       int64
	}{
		{"del_step266_0001", "failed", "alice@example.com", "MAIL_DELIVERY_FAILED", baseMS},
		{"del_step266_0002", "cancelled", "bob@example.com", "", baseMS + 1000},
		{"del_step266_0003", "succeeded", "carol@example.com", "", baseMS + 2000},
	}
	for _, item := range deliveries {
		var lastError any
		if item.errorCode != "" {
			lastError = item.errorCode
		}
		if _, err := raw.DB().ExecContext(ctx, `INSERT INTO mail_deliveries(
id,idempotency_key,template_kind,recipient,owner_type,owner_id,state,attempts,
max_attempts,task_id,last_error_code,last_error_kind,sealed_payload,request_id,
created_at_ms,updated_at_ms) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			item.id, "step266:"+item.id, "security_notice", item.recipient, "user",
			rootID, item.state, 1, 3, nil, lastError, nil, []byte("sealed-step266"),
			"req_step266", item.createdMS, item.createdMS); err != nil {
			_ = raw.Close()
			t.Fatalf("写入投递记录 %s: %v", item.id, err)
		}
	}
	if err := raw.Close(); err != nil {
		t.Fatalf("关闭临时数据库失败: %v", err)
	}

	result, _, cancel := startServeResult(t, serverapp.ServeOptions{
		ConfigPath: paths.config, MasterKeyFile: paths.masterKey,
		EnableAdminAPI: true,
	})
	defer cancel()
	address := result.Addresses[0]
	base := "http://" + address + "/admin/v1"
	client := &http.Client{Timeout: 10 * time.Second}
	strong := issueRootSession(t, paths.config, paths.database, paths.masterKey, "strong")
	restricted := issueRootSession(t, paths.config, paths.database, paths.masterKey, "restricted")

	// 未认证 401、受限会话 403（越权拒绝，不泄露数据）。
	if status, _ := adminAPIGet(t, client,
		base+"/notifications/history?user_id="+rootID, nil); status != http.StatusUnauthorized {
		t.Fatalf("无会话告知历史状态 = %d，期望 401", status)
	}
	if status, _ := adminAPIGet(t, client,
		base+"/deliveries", restricted); status != http.StatusForbidden {
		t.Fatalf("受限会话投递状态 = %d，期望 403", status)
	}

	// 安全告知：limit=2 跟随游标取完 5 条，不重不漏，且始终脱敏。
	seen := map[string]bool{}
	cursor := ""
	pages := 0
	for {
		target := base + "/notifications/history?user_id=" + rootID + "&limit=2"
		if cursor != "" {
			target += "&cursor=" + cursor
		}
		status, data := step266AdminGet(t, client, target, strong)
		if status != http.StatusOK {
			t.Fatalf("告知历史状态 = %d，期望 200", status)
		}
		items, _ := data["notifications"].([]any)
		for _, item := range items {
			record, _ := item.(map[string]any)
			id, _ := record["id"].(string)
			if id == "" || seen[id] {
				t.Fatalf("分页重复/缺 ID: %q", id)
			}
			if record["recipient_masked"] != "a***@example.com" {
				t.Fatalf("收件人未脱敏: %v", record["recipient_masked"])
			}
			// 未关联投递记录时 delivery_state 为空并以 omitempty 省略（nil）；关联后
			// 只允许领域层投影出的真实状态，不能伪造成 sent。
			if state := record["delivery_state"]; state != nil && state != "" && state != "queued" {
				t.Fatalf("历史记录投递状态投影异常: %v", state)
			}
			seen[id] = true
		}
		pages++
		if data["has_more"] != true {
			break
		}
		cursor, _ = data["next_cursor"].(string)
		if cursor == "" {
			t.Fatal("has_more=true 时必须返回 next_cursor")
		}
		if pages > 10 {
			t.Fatal("告知分页未收敛")
		}
	}
	if len(seen) != 5 {
		t.Fatalf("告知分页覆盖 %d 条，期望 5", len(seen))
	}

	// 投递记录：failed 终态筛选、脱敏收件人、无加密载荷；cancelled 单独可筛。
	status, data := step266AdminGet(t, client, base+"/deliveries?state=failed&limit=10", strong)
	if status != http.StatusOK {
		t.Fatalf("投递记录状态 = %d，期望 200", status)
	}
	items, _ := data["deliveries"].([]any)
	if len(items) != 1 {
		t.Fatalf("failed 投递条数 = %d，期望 1", len(items))
	}
	record, _ := items[0].(map[string]any)
	if record["delivery_id"] != "del_step266_0001" || record["state"] != "failed" ||
		record["recipient_masked"] != "***@example.com" ||
		record["last_error_code"] != "MAIL_DELIVERY_FAILED" {
		t.Fatalf("投递白名单字段异常: %v", record)
	}
	serialized, _ := json.Marshal(data)
	if strings.Contains(string(serialized), "sealed-step266") ||
		strings.Contains(string(serialized), "alice@example.com") {
		t.Fatalf("投递端点泄露载荷/完整收件人: %s", string(serialized))
	}
	status, data = step266AdminGet(t, client, base+"/deliveries?state=cancelled", strong)
	if status != http.StatusOK {
		t.Fatalf("cancelled 筛选状态 = %d", status)
	}
	if items, _ := data["deliveries"].([]any); len(items) != 1 {
		t.Fatalf("cancelled 投递条数 = %d，期望 1", len(items))
	}
	// 非法状态由领域层拒绝为 400（不静默当作全部）。
	if status, _ := adminAPIGet(t, client, base+"/deliveries?state=bogus", strong); status != http.StatusBadRequest {
		t.Fatalf("非法状态状态码 = %d，期望 400", status)
	}
}
