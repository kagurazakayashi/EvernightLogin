package main

// smtpsink.go 是示例自带的**本地邮件捕获器**（仅用于本示例自检/演示，不是产品能力）。
//
// 步骤 241 要求自检自动启动本地 Mail 走邮箱验证与找回。外部 Module 不能导入仓库的
// internal/mailtest（也不能依赖 EvernightMail 子模块二进制），因此这里用标准库实现
// 一个最小 SMTP 接收端：只监听 127.0.0.1 动态端口，接收明文（TLSMode=none +
// AllowPlaintextLocal）投递并保存原始报文，供自检解析一次性验证/找回链接。
//
// 边界：它不是 SMTP 服务器产品，不支持 AUTH/STARTTLS/中继/持久化；只接受本示例
// 进程内 EvernightLogin 邮件投递任务的连接，退出时关闭监听并等待连接结束。

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// capturedMail 是一封被捕获的原始邮件。
type capturedMail struct {
	From       string
	To         []string
	Data       []byte
	ReceivedAt time.Time
}

// smtpSink 是本地明文 SMTP 捕获器。
type smtpSink struct {
	listener net.Listener
	mu       sync.Mutex
	messages []capturedMail
	closed   bool
	conns    map[net.Conn]struct{}
	wg       sync.WaitGroup
}

// newSMTPSink 在 127.0.0.1 的动态端口启动捕获器。
func newSMTPSink() (*smtpSink, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("启动本地邮件捕获器失败: %w", err)
	}
	sink := &smtpSink{listener: listener, conns: make(map[net.Conn]struct{})}
	sink.wg.Add(1)
	go sink.acceptLoop()
	return sink, nil
}

// Addr 返回捕获器监听地址（配置给 mail.smtp.addr）。
func (s *smtpSink) Addr() string { return s.listener.Addr().String() }

// acceptLoop 接受并发连接。
func (s *smtpSink) acceptLoop() {
	defer s.wg.Done()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			_ = conn.Close()
			return
		}
		s.conns[conn] = struct{}{}
		s.mu.Unlock()
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleConnection(conn)
			s.mu.Lock()
			delete(s.conns, conn)
			s.mu.Unlock()
		}()
	}
}

// Close 停止监听并等待所有连接结束；已捕获邮件保留在内存中。
func (s *smtpSink) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	conns := make([]net.Conn, 0, len(s.conns))
	for conn := range s.conns {
		conns = append(conns, conn)
	}
	s.mu.Unlock()
	_ = s.listener.Close()
	for _, conn := range conns {
		_ = conn.Close()
	}
	s.wg.Wait()
	return nil
}

// WaitForMessage 等待第 index 封（从 0 开始）邮件到达；ctx 到期返回错误。
func (s *smtpSink) WaitForMessage(ctx context.Context, index int) (capturedMail, error) {
	for {
		s.mu.Lock()
		if len(s.messages) > index {
			message := s.messages[index]
			s.mu.Unlock()
			return message, nil
		}
		closed := s.closed
		s.mu.Unlock()
		if closed {
			return capturedMail{}, errors.New("本地邮件捕获器已关闭")
		}
		select {
		case <-ctx.Done():
			return capturedMail{}, fmt.Errorf("等待第 %d 封邮件超时: %w", index+1, ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// MessageCount 返回已捕获邮件数量。
func (s *smtpSink) MessageCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.messages)
}

// handleConnection 实现最小 ESMTP 会话（明文，无 AUTH/STARTTLS）。
func (s *smtpSink) handleConnection(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)
	reply := func(line string) bool {
		if _, err := writer.WriteString(line + "\r\n"); err != nil {
			return false
		}
		return writer.Flush() == nil
	}
	if !reply("220 localhost EvernightLogin example mail sink") {
		return
	}
	var from string
	var recipients []string
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		upper := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(upper, "EHLO"):
			// 只声明最基本的 EHLO；不声明 STARTTLS/AUTH，匹配 tls_mode=none 本地配置。
			reply("250-localhost")
			if !reply("250 HELP") {
				return
			}
		case strings.HasPrefix(upper, "HELO"):
			if !reply("250 localhost") {
				return
			}
		case strings.HasPrefix(upper, "MAIL FROM:"):
			from = extractSMTPAddress(line)
			if !reply("250 OK") {
				return
			}
		case strings.HasPrefix(upper, "RCPT TO:"):
			recipients = append(recipients, extractSMTPAddress(line))
			if !reply("250 OK") {
				return
			}
		case upper == "DATA":
			if !reply("354 End data with <CR><LF>.<CR><LF>") {
				return
			}
			data, readErr := readSMTPData(reader)
			if readErr != nil {
				return
			}
			s.record(capturedMail{From: from, To: append([]string(nil), recipients...),
				Data: data, ReceivedAt: time.Now()})
			if !reply("250 OK queued") {
				return
			}
			from = ""
			recipients = nil
		case upper == "RSET" || upper == "NOOP":
			if !reply("250 OK") {
				return
			}
		case upper == "QUIT":
			reply("221 Bye")
			return
		default:
			if !reply("250 OK") {
				return
			}
		}
	}
}

// extractSMTPAddress 从 "MAIL FROM:<a@b>" 形式的行中提取尖括号地址。
func extractSMTPAddress(line string) string {
	start := strings.Index(line, "<")
	end := strings.LastIndex(line, ">")
	if start >= 0 && end > start {
		return line[start+1 : end]
	}
	if index := strings.Index(line, ":"); index >= 0 {
		return strings.TrimSpace(line[index+1:])
	}
	return ""
}

// readSMTPData 读取 DATA 段直到单独一行 "."（处理 dot-stuffing）。
func readSMTPData(reader *bufio.Reader) ([]byte, error) {
	var builder strings.Builder
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return nil, err
		}
		trimmed := strings.TrimRight(line, "\r\n")
		if trimmed == "." {
			return []byte(builder.String()), nil
		}
		if strings.HasPrefix(trimmed, "..") {
			trimmed = trimmed[1:]
		}
		builder.WriteString(trimmed)
		builder.WriteString("\r\n")
	}
}

// record 保存一封捕获邮件。
func (s *smtpSink) record(message capturedMail) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.messages = append(s.messages, message)
}

// Snapshot 返回当前已捕获邮件副本（供演示模式本地信报页使用）。
func (s *smtpSink) Snapshot() []capturedMail {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]capturedMail, len(s.messages))
	for index, message := range s.messages {
		message.To = append([]string(nil), message.To...)
		message.Data = append([]byte(nil), message.Data...)
		out[index] = message
	}
	return out
}
