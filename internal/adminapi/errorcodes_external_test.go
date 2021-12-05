package adminapi_test

import (
	"context"
	"net/http"
	"testing"

	login "github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/adminapi"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
)

// externalSession 是外部测试包使用的最小管理会话边界实现。
type externalSession struct{}

func (externalSession) SessionSecretFromRequest(*http.Request) (string, bool) {
	return "secret", true
}

func (externalSession) AuthorizeManagement(context.Context, string) (session.Session, error) {
	return session.Session{UserID: "usr_00000000000000000000000000000001"}, nil
}

func (externalSession) ValidateCSRFToken(context.Context, *http.Request, string) error {
	return nil
}

// TestEmittedErrorCodesRegistered 对照根包错误码注册表，验证管理 API 会返回的
// 每个错误码都已登记且 HTTP 状态/默认消息一致（防止未登记码或状态漂移）。
// 该测试放在外部测试包，避免未来根包装配本包时出现测试导入环。
func TestEmittedErrorCodesRegistered(t *testing.T) {
	definitions := login.RegisteredErrorCodes()
	byCode := make(map[string]login.ErrorCodeDefinition, len(definitions))
	for _, definition := range definitions {
		byCode[string(definition.Code)] = definition
	}
	codes := adminapi.EmittedErrorCodes()
	if len(codes) == 0 {
		t.Fatal("管理 API 未声明任何错误码")
	}
	for _, code := range codes {
		definition, ok := byCode[code]
		if !ok {
			t.Fatalf("错误码 %s 未在根包注册表登记", code)
		}
		if definition.DefaultMessage == "" {
			t.Fatalf("错误码 %s 缺少默认公开消息", code)
		}
	}
	// 构造一次服务以取得投影后的 HTTP 状态，逐项与根包注册表比较。
	server, err := adminapi.New(adminapi.Options{
		Session:    externalSession{},
		ErrorCodes: projectCodes(definitions),
	})
	if err != nil {
		t.Fatalf("构造管理 API 失败: %v", err)
	}
	if server.BasePath() != adminapi.DefaultBasePath {
		t.Fatalf("默认前缀 = %q", server.BasePath())
	}
	for _, code := range codes {
		definition := byCode[code]
		status, ok := server.ErrorCodeStatus(code)
		if !ok {
			t.Fatalf("错误码 %s 未进入管理 API 投影", code)
		}
		if status != definition.HTTPStatus {
			t.Fatalf("错误码 %s HTTP 状态不一致：根包=%d 管理 API=%d",
				code, definition.HTTPStatus, status)
		}
	}
}

// projectCodes 把根包注册表投影为管理 API 的错误码投影。
func projectCodes(definitions []login.ErrorCodeDefinition) []adminapi.ErrorCodeInfo {
	codes := make([]adminapi.ErrorCodeInfo, 0, len(definitions))
	for _, definition := range definitions {
		codes = append(codes, adminapi.ErrorCodeInfo{Code: string(definition.Code),
			Message: definition.DefaultMessage, HTTPStatus: definition.HTTPStatus})
	}
	return codes
}
