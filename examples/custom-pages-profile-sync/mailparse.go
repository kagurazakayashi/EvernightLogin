package main

// mailparse.go 解析被本地捕获器接收的一次性验证/找回邮件，提取公开页面链接参数。
//
// 只做最小解析：邮件由 EvernightLogin 内置投递链生成（text/plain + base64 传输编码，
// 内置模板正文含完整 URL）。解析结果（uid/cid/token）只在内存中传给公开接口，
// 不写日志、不写入临时文件。

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// mailURLPattern 匹配邮件正文中的绝对 http(s) URL。
var mailURLPattern = regexp.MustCompile(`https?://[^\s<>"'）)】]+`)

// decodeCapturedMailText 把捕获的原始邮件解码为正文文本（支持 base64 传输编码）。
func decodeCapturedMailText(data []byte) (string, error) {
	separator := []byte("\r\n\r\n")
	index := bytes.Index(data, separator)
	if index < 0 {
		separator = []byte("\n\n")
		index = bytes.Index(data, separator)
	}
	if index < 0 {
		return "", errors.New("邮件缺少头部与正文分隔")
	}
	headers := strings.ToLower(string(data[:index]))
	body := data[index+len(separator):]
	if strings.Contains(headers, "content-transfer-encoding: base64") {
		trimmed := strings.Join(strings.Fields(string(body)), "")
		decoded, err := base64.StdEncoding.DecodeString(trimmed)
		if err != nil {
			return "", fmt.Errorf("解码邮件正文失败: %w", err)
		}
		return string(decoded), nil
	}
	return string(body), nil
}

// mailURLs 返回正文中所有绝对 URL。
func mailURLs(text string) []*url.URL {
	matches := mailURLPattern.FindAllString(text, -1)
	urls := make([]*url.URL, 0, len(matches))
	for _, match := range matches {
		parsed, err := url.Parse(strings.TrimRight(match, ".,;"))
		if err != nil || parsed.Host == "" {
			continue
		}
		urls = append(urls, parsed)
	}
	return urls
}

// verificationLink 从验证邮件正文提取一次性验证入口参数。
func verificationLink(text string) (userID, credentialID, token string, err error) {
	for _, parsed := range mailURLs(text) {
		if !strings.HasSuffix(parsed.Path, "/email/verify") {
			continue
		}
		query := parsed.Query()
		userID = query.Get("uid")
		credentialID = query.Get("cid")
		token = query.Get("token")
		if userID != "" && credentialID != "" && token != "" {
			return userID, credentialID, token, nil
		}
	}
	return "", "", "", errors.New("验证邮件中未找到完整的一次性验证入口")
}

// passwordResetLink 从找回邮件正文提取一次性重置链接。
func passwordResetLink(text string) (*url.URL, error) {
	for _, parsed := range mailURLs(text) {
		if !strings.HasSuffix(parsed.Path, "/login/reset-password") {
			continue
		}
		if parsed.Query().Get("token") == "" {
			continue
		}
		return parsed, nil
	}
	return nil, errors.New("找回邮件中未找到一次性重置链接")
}

// passwordResetToken 从找回邮件正文提取一次性重置令牌。
func passwordResetToken(text string) (string, error) {
	parsed, err := passwordResetLink(text)
	if err != nil {
		return "", err
	}
	return parsed.Query().Get("token"), nil
}
