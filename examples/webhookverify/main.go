// Command webhookverify 演示业务应用如何验证应用安全事件 Webhook 的签名。
//
// 它是自包含示例（不导入本项目 internal 包），可复制 HMAC 验证逻辑到业务服务：
// 读取原始请求体字节 → 解析 X-Evernight-Signature（t=秒,v1=hex[,v1=hex]）→ 用自己
// 保存的签名密钥对 "<t>.<原始body>" 计算 HMAC-SHA256 并恒定时间比较 → 校验时间窗
// （默认 300 秒）→ 按 X-Evernight-Event-Id 去重后再处理事件（至少一次语义）。
//
// 用法：webhookverify <签名密钥base64url> <签名头> <时间戳头> <原始body文件>
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

const tolerance = 5 * time.Minute

func main() {
	if len(os.Args) != 5 {
		fmt.Fprintln(os.Stderr, "用法: webhookverify <secret-base64url> <signature-header> <timestamp-header> <body-file>")
		os.Exit(2)
	}
	secret, err := decodeSecret(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "签名密钥无效:", err)
		os.Exit(2)
	}
	body, err := os.ReadFile(os.Args[4])
	if err != nil {
		fmt.Fprintln(os.Stderr, "读取 body 失败:", err)
		os.Exit(2)
	}
	if err := Verify(secret, os.Args[2], os.Args[3], body, time.Now(), tolerance); err != nil {
		fmt.Fprintln(os.Stderr, "验签失败:", err)
		os.Exit(1)
	}
	fmt.Println("签名与时间戳验证通过（业务侧仍需按事件 ID 去重）")
}

// decodeSecret 解析 base64url 签名密钥（无填充）。
func decodeSecret(value string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimSpace(value))
}

// Verify 校验签名头：任一 v1 与 HMAC-SHA256(secret, t+"."+body) 恒定时间匹配，
// 且 "|now-t|" 不超过 tolerance。
func Verify(secret []byte, signatureHeader, timestampHeader string, body []byte,
	now time.Time, tolerance time.Duration) error {
	timestampValue := strings.TrimSpace(timestampHeader)
	if timestampValue == "" {
		// 兼容仅提供签名头时从中解析 t=。
		for _, part := range strings.Split(signatureHeader, ",") {
			if strings.HasPrefix(part, "t=") {
				timestampValue = strings.TrimPrefix(part, "t=")
			}
		}
	}
	timestamp, err := strconv.ParseInt(timestampValue, 10, 64)
	if err != nil || timestamp <= 0 {
		return fmt.Errorf("时间戳无效")
	}
	if tolerance <= 0 {
		tolerance = 5 * time.Minute
	}
	delta := now.Unix() - timestamp
	if delta < 0 {
		delta = -delta
	}
	if time.Duration(delta)*time.Second > tolerance {
		return fmt.Errorf("时间戳超出允许窗口")
	}
	expected := hmac.New(sha256.New, secret)
	_, _ = expected.Write([]byte(strconv.FormatInt(timestamp, 10)))
	_, _ = expected.Write([]byte("."))
	_, _ = expected.Write(body)
	expectedSum := expected.Sum(nil)
	for _, part := range strings.Split(signatureHeader, ",") {
		part = strings.TrimSpace(part)
		if !strings.HasPrefix(part, "v1=") {
			continue
		}
		decoded, err := hex.DecodeString(strings.TrimPrefix(part, "v1="))
		if err != nil {
			continue
		}
		if hmac.Equal(decoded, expectedSum) {
			return nil
		}
	}
	return fmt.Errorf("签名不匹配")
}
