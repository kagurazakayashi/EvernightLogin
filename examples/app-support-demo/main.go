// 应用受限客服 API 外部示例（步骤 154）。
//
// 本示例是独立 Go module，只使用标准库；不导入 EvernightLogin 的 internal 包，
// 不显示/读取密码、MFA、恢复代码或恢复链接。access token 应由真实 OAuth
// 授权码+PKCE 流程（客服用户登录、ClientID=应用、aud=urn:evernight:app-support）
// 取得后通过 -access-token 或环境变量传入；本程序只调用业务 API。
package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const apiVersion = "v1"

func main() {
	base := flag.String("base", "http://127.0.0.1:8080/api/app/v1/support", "应用客服 API 基址")
	accessToken := flag.String("access-token", "", "OAuth 用户委托 Access Token（或用 APPSUPPORT_ACCESS_TOKEN）")
	command := flag.String("command", "list", "list|create|get")
	caseID := flag.String("case-id", "", "get 用例 ID")
	targetUserID := flag.String("target-user-id", "", "create 目标用户 ID")
	reason := flag.String("reason", "", "create 原因（不可信自由文本）")
	flag.Parse()
	if *accessToken == "" {
		*accessToken = os.Getenv("APPSUPPORT_ACCESS_TOKEN")
	}
	if strings.TrimSpace(*accessToken) == "" {
		fail("必须提供 -access-token 或 APPSUPPORT_ACCESS_TOKEN（由 OAuth 授权码+PKCE 取得）")
	}
	client := &http.Client{Timeout: 15 * time.Second}
	switch strings.ToLower(strings.TrimSpace(*command)) {
	case "list":
		call(client, *base, *accessToken, http.MethodGet, "/cases", nil)
	case "get":
		if strings.TrimSpace(*caseID) == "" {
			fail("get 需要 -case-id")
		}
		call(client, *base, *accessToken, http.MethodGet, "/cases/"+*caseID, nil)
	case "create":
		if strings.TrimSpace(*targetUserID) == "" || strings.TrimSpace(*reason) == "" {
			fail("create 需要 -target-user-id 与 -reason")
		}
		body, _ := json.Marshal(map[string]string{"target_user_id": *targetUserID,
			"reason": *reason})
		call(client, *base, *accessToken, http.MethodPost, "/cases", body)
	default:
		fail("未知 -command")
	}
}

func call(client *http.Client, base, token, method, path string, body []byte) {
	request, err := http.NewRequest(method, strings.TrimRight(base, "/")+path,
		bytes.NewReader(body))
	if err != nil {
		fail(err.Error())
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("X-Evernight-API-Version", apiVersion)
	request.Header.Set("X-Request-Id", requestID())
	if len(body) > 0 {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := client.Do(request)
	if err != nil {
		fail(err.Error())
	}
	defer response.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		fail(err.Error())
	}
	fmt.Printf("HTTP %d\n%s\n", response.StatusCode, strings.TrimSpace(string(payload)))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		os.Exit(1)
	}
}

func requestID() string {
	buffer := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, buffer); err != nil {
		fail("无法生成请求编号")
	}
	return "req_" + hex.EncodeToString(buffer)
}

func fail(message string) {
	fmt.Fprintln(os.Stderr, "app-support-demo:", message)
	os.Exit(2)
}
