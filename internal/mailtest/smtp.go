// Copyright (c) KagurazakaYashi(KagurazakaMiyabi)
// EvernightMail is licensed under Mulan PSL v2.

package mailtest

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"net/smtp"
	"os"
	"strings"
	"time"
)

// BuildMessage 构造一封合成 RFC5322 邮件；返回原始字节（与发送内容一致）。
func BuildMessage(from string, to []string, subject, body string) []byte {
	var buffer bytes.Buffer
	buffer.WriteString("From: " + from + "\r\n")
	buffer.WriteString("To: " + strings.Join(to, ", ") + "\r\n")
	buffer.WriteString("Subject: " + subject + "\r\n")
	buffer.WriteString("Date: " + time.Now().UTC().Format(time.RFC1123Z) + "\r\n")
	buffer.WriteString("Message-ID: <mailtest-" + randToken() + "@mailtest.local>\r\n")
	buffer.WriteString("MIME-Version: 1.0\r\n")
	buffer.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	buffer.WriteString("\r\n")
	buffer.WriteString(body)
	if !strings.HasSuffix(body, "\r\n") {
		buffer.WriteString("\r\n")
	}
	return buffer.Bytes()
}

// SendRaw 通过 SMTP（可选 STARTTLS）投递原始邮件到夹具。
func (i *Instance) SendRaw(from string, to []string, raw []byte) error {
	if len(to) == 0 {
		return fmt.Errorf("mailtest: 至少需要一个收件人")
	}
	conn, err := net.DialTimeout("tcp", i.SMTPAddr, 5*time.Second)
	if err != nil {
		return err
	}
	client, err := smtp.NewClient(conn, "localhost")
	if err != nil {
		_ = conn.Close()
		return err
	}
	defer func() { _ = client.Close() }()
	if i.options.TLS {
		caData, err := os.ReadFile(i.CAFile)
		if err != nil {
			return err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caData) {
			return fmt.Errorf("mailtest: 测试 CA 无法解析")
		}
		if err := client.StartTLS(&tls.Config{RootCAs: pool, ServerName: "localhost", MinVersion: tls.VersionTLS12}); err != nil {
			return err
		}
	}
	if err := client.Auth(smtp.PlainAuth("", i.UserLogin, i.UserPassword, "localhost")); err != nil {
		return fmt.Errorf("mailtest: SMTP AUTH 失败: %w", err)
	}
	if err := client.Mail(from); err != nil {
		return err
	}
	for _, recipient := range to {
		if err := client.Rcpt(recipient); err != nil {
			return err
		}
	}
	writer, err := client.Data()
	if err != nil {
		return err
	}
	if _, err := writer.Write(raw); err != nil {
		_ = writer.Close()
		return err
	}
	if err := writer.Close(); err != nil {
		return err
	}
	return client.Quit()
}

// randToken 生成短随机标记（仅测试 Message-ID）。
func randToken() string {
	buffer := make([]byte, 8)
	if _, err := rand.Read(buffer); err != nil {
		return "fallback"
	}
	return hex.EncodeToString(buffer)
}
