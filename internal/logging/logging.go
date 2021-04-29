// Package logging 构造 login 的结构化运行日志器。
//
// 它只负责把已验证的日志配置映射为 Go 标准库 log/slog 的处理器，不做审计、
// HTTP 访问日志或日志轮转。HTTP 访问日志在内部传输层按 W3C Extended 格式输出，
// 与运行日志和 SQLite 安全审计分开，不能互相替代。
package logging

import (
	"fmt"
	"io"
	"log/slog"
)

// New 按日志级别与格式创建 slog.Logger。level 接受 "debug"、"info"、"warn"、
// "error"（字符串来自 login.Config，已由配置校验保证合法）；format 接受
// "text"、"json"。output 为 nil 时丢弃全部日志，适合嵌入模式默认静默。
//
// 非法级别或格式返回错误而不是静默回退，避免配置与实际行为不一致。
func New(level, format string, output io.Writer) (*slog.Logger, error) {
	parsedLevel, err := ParseLevel(level)
	if err != nil {
		return nil, err
	}
	if output == nil {
		output = io.Discard
	}
	options := &slog.HandlerOptions{Level: parsedLevel}

	var handler slog.Handler
	switch format {
	case "text":
		handler = slog.NewTextHandler(output, options)
	case "json":
		handler = slog.NewJSONHandler(output, options)
	default:
		return nil, fmt.Errorf("不支持的日志格式（只支持 text 或 json）")
	}
	return slog.New(handler), nil
}

// ParseLevel 把配置字符串转换为 slog.Level。
func ParseLevel(level string) (slog.Level, error) {
	switch level {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("不支持的日志级别（只支持 debug、info、warn、error）")
	}
}
