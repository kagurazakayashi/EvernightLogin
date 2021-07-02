package login

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// manualErrorRow 表示错误码手册表格中的一行，用于文档覆盖校验。
type manualErrorRow struct {
	Code     string
	Category string
	HTTP     int
	Message  string
}

func TestErrorCodeRegistryUnique(t *testing.T) {
	definitions := RegisteredErrorCodes()
	if len(definitions) != 48 {
		t.Fatalf("错误码数量 = %d，期望 48 个设计码", len(definitions))
	}
	seen := make(map[ErrorCode]bool, len(definitions))
	for _, definition := range definitions {
		if definition.Code == "" {
			t.Error("存在空错误码")
		}
		if seen[definition.Code] {
			t.Errorf("错误码重复：%s", definition.Code)
		}
		seen[definition.Code] = true
		if definition.Category == "" {
			t.Errorf("错误码 %s 缺少分类", definition.Code)
		}
		if definition.DefaultMessage == "" {
			t.Errorf("错误码 %s 缺少默认公开消息", definition.Code)
		}
		if definition.HTTPStatus != 0 &&
			(definition.HTTPStatus < 400 || definition.HTTPStatus > 599) {
			t.Errorf("错误码 %s 的 HTTP 状态不合理：%d", definition.Code, definition.HTTPStatus)
		}
		if !definition.Code.Valid() {
			t.Errorf("错误码 %s 无法通过 Valid()", definition.Code)
		}
	}
}

func TestLookupErrorCode(t *testing.T) {
	definition, ok := LookupErrorCode(CodePermissionRequired)
	if !ok {
		t.Fatal("已注册错误码查询失败")
	}
	if definition.Category != CategoryPermission {
		t.Errorf("分类 = %q，期望 %q", definition.Category, CategoryPermission)
	}
	if definition.HTTPStatus != 403 {
		t.Errorf("HTTP 状态 = %d，期望 403", definition.HTTPStatus)
	}
	if _, ok := LookupErrorCode(ErrorCode("NOT_REGISTERED")); ok {
		t.Error("未注册错误码不应查询成功")
	}
	if ErrorCode("NOT_REGISTERED").Valid() {
		t.Error("未注册错误码 Valid() 应为 false")
	}
}

func TestRegisteredErrorCodesReturnsCopy(t *testing.T) {
	first := RegisteredErrorCodes()
	first[0].DefaultMessage = "被修改"
	second := RegisteredErrorCodes()
	if second[0].DefaultMessage == "被修改" {
		t.Error("RegisteredErrorCodes 未返回副本")
	}
}

// TestErrorCodeDocumentationMatches 逐项比较代码注册表与错误码手册，防止新增
// 或修改错误码时只改代码不改文档，或改变已发布码的含义。手册不存在时跳过并
// 在 MEMORY 中记录该限制，避免在未携带产品文档的环境里误报。
func TestErrorCodeDocumentationMatches(t *testing.T) {
	path := filepath.Join("docs", "requirements", "login_错误码与排障手册.md")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			t.Skipf("错误码手册不存在，跳过文档覆盖校验：%v", err)
		}
		t.Fatalf("读取错误码手册失败：%v", err)
	}

	rows := parseManualErrorRows(t, string(data))
	if len(rows) != 48 {
		t.Fatalf("手册错误码数量 = %d，期望 48", len(rows))
	}

	definitions := RegisteredErrorCodes()
	if len(definitions) != len(rows) {
		t.Fatalf("注册表 %d 项，手册 %d 项", len(definitions), len(rows))
	}
	for index, row := range rows {
		definition := definitions[index]
		if string(definition.Code) != row.Code {
			t.Errorf("第 %d 项错误码：注册表 %s，手册 %s", index+1, definition.Code, row.Code)
		}
		if string(definition.Category) != row.Category {
			t.Errorf("错误码 %s 分类：注册表 %q，手册 %q", row.Code, definition.Category, row.Category)
		}
		if definition.HTTPStatus != row.HTTP {
			t.Errorf("错误码 %s HTTP：注册表 %d，手册 %d", row.Code, definition.HTTPStatus, row.HTTP)
		}
		if definition.DefaultMessage != row.Message {
			t.Errorf("错误码 %s 说明：注册表 %q，手册 %q", row.Code, definition.DefaultMessage, row.Message)
		}
	}
}

// parseManualErrorRows 解析错误码手册第 3 节的 Markdown 表格。只接受全大写
// 错误码，跳过表头与分隔行。
func parseManualErrorRows(t *testing.T, markdown string) []manualErrorRow {
	t.Helper()
	seen := make(map[string]bool)
	var rows []manualErrorRow
	for _, line := range strings.Split(markdown, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "| ") {
			continue
		}
		cells := strings.Split(strings.Trim(line, "|"), "|")
		for index := range cells {
			cells[index] = strings.TrimSpace(cells[index])
		}
		if len(cells) < 7 {
			continue
		}
		code := cells[0]
		if code == "" || strings.Trim(code, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_") != "" {
			continue
		}
		if strings.ContainsAny(code, "abcdefghijklmnopqrstuvwxyz") {
			continue
		}
		if seen[code] {
			t.Fatalf("手册错误码重复：%s", code)
		}
		seen[code] = true
		httpStatus := 0
		if cells[2] != "—" {
			value, err := strconv.Atoi(cells[2])
			if err != nil {
				t.Fatalf("错误码 %s 的 HTTP 列无法解析：%q", code, cells[2])
			}
			httpStatus = value
		}
		rows = append(rows, manualErrorRow{
			Code:     code,
			Category: cells[1],
			HTTP:     httpStatus,
			Message:  cells[3],
		})
	}
	return rows
}

// TestNoOAuthProtocolCodesRegistered 锁定边界：标准 OAuth/OIDC 错误使用协议
// 规定的小写字段值（如 invalid_grant、access_denied），由未来协议适配层按协议
// 字段映射，不注册为全大写统一业务码，也不被统一 JSON 强行覆盖。
func TestNoOAuthProtocolCodesRegistered(t *testing.T) {
	protocolCodes := map[string]bool{
		"invalid_grant":         true,
		"invalid_token":         true,
		"authorization_pending": true,
		"slow_down":             true,
		"invalid_client":        true,
		"unauthorized_client":   true,
		"access_denied":         true,
		"invalid_scope":         true,
	}
	for _, definition := range RegisteredErrorCodes() {
		code := string(definition.Code)
		if code != strings.ToUpper(code) {
			t.Errorf("错误码 %s 不是全大写稳定字符串", code)
		}
		if protocolCodes[code] {
			t.Errorf("标准 OAuth 协议错误 %s 不应注册为统一业务错误码", code)
		}
	}
}
