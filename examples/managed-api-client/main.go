// 业务应用托管管理 API 外部客户端示例（步骤 147）。
//
// 本示例只使用 Go 标准库与 HTTP 公开契约，不导入 EvernightLogin 的任何 internal
// 包，也不复用服务端实现。认证二选一：
//   - 用户普通会话：-session <会话 secret>（Authorization: Bearer）；
//   - 应用服务身份：-client-id <应用 ID> -client-secret <客户端密钥>（HTTP Basic）。
//
// 客户端证书认证可在支持 mTLS 的部署中由 TLS 客户端提供叶子证书；本示例不读取
// 私钥、不打印秘密、不自动重试写操作。每个写请求显式携带 Idempotency-Key。
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
	base := flag.String("base", "http://127.0.0.1:8080/api/managed/v1", "托管 API 基址")
	appID := flag.String("app", "", "应用 ID（必须与认证主体一致）")
	session := flag.String("session", "", "用户会话 secret（二选一）")
	clientID := flag.String("client-id", "", "应用客户端 ID（二选一）")
	clientSecret := flag.String("client-secret", "", "应用客户端 secret（二选一）")
	command := flag.String("command", "get-application", "get-application|list-members|get-member|create-user|update-member")
	userID := flag.String("user", "", "get-member/update-member 目标用户 ID")
	username := flag.String("username", "", "create-user 用户名")
	displayName := flag.String("display-name", "", "update-member 显示名")
	rowVersion := flag.Int64("row-version", 1, "update-member 行版本")
	flag.Parse()
	if strings.TrimSpace(*appID) == "" {
		fail("必须指定 -app")
	}
	client := &http.Client{Timeout: 15 * time.Second}
	switch strings.ToLower(strings.TrimSpace(*command)) {
	case "get-application":
		do(client, *base, *appID, *session, *clientID, *clientSecret,
			http.MethodGet, "/applications/"+*appID, nil, false)
	case "list-members":
		do(client, *base, *appID, *session, *clientID, *clientSecret,
			http.MethodGet, "/applications/"+*appID+"/members?limit=20&offset=0", nil, false)
	case "get-member":
		requireUser(*userID)
		do(client, *base, *appID, *session, *clientID, *clientSecret,
			http.MethodGet, "/applications/"+*appID+"/members/"+*userID, nil, false)
	case "create-user":
		if strings.TrimSpace(*username) == "" {
			fail("create-user 需要 -username")
		}
		payload, _ := json.Marshal(map[string]any{"username": *username})
		do(client, *base, *appID, *session, *clientID, *clientSecret,
			http.MethodPost, "/applications/"+*appID+"/users", payload, true)
	case "update-member":
		requireUser(*userID)
		payload, _ := json.Marshal(map[string]any{"expected_row_version": *rowVersion,
			"display_name": *displayName})
		do(client, *base, *appID, *session, *clientID, *clientSecret,
			http.MethodPatch, "/applications/"+*appID+"/members/"+*userID, payload, true)
	default:
		fail("未知 -command")
	}
}

func requireUser(userID string) {
	if strings.TrimSpace(userID) == "" {
		fail("该命令需要 -user")
	}
}

func do(client *http.Client, base, appID, session, clientID, clientSecret,
	method, path string, body []byte, write bool) {
	request, err := http.NewRequest(method, strings.TrimRight(base, "/")+path,
		bytes.NewReader(body))
	if err != nil {
		fail(err.Error())
	}
	request.Header.Set("X-Evernight-API-Version", apiVersion)
	request.Header.Set("X-Request-Id", requestID())
	request.Header.Set("Accept", "application/json")
	if len(body) > 0 {
		request.Header.Set("Content-Type", "application/json")
	}
	if strings.TrimSpace(session) != "" {
		request.Header.Set("Authorization", "Bearer "+session)
	} else if strings.TrimSpace(clientID) != "" {
		request.SetBasicAuth(clientID, clientSecret)
	}
	if write {
		request.Header.Set("Idempotency-Key", requestID())
	}
	response, err := client.Do(request)
	if err != nil {
		fail(err.Error())
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		fail(err.Error())
	}
	fmt.Printf("HTTP %d\n%s\n", response.StatusCode, strings.TrimSpace(string(data)))
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
	fmt.Fprintln(os.Stderr, "managed-api-client:", message)
	os.Exit(2)
}
