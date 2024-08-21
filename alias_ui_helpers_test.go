package login_test

// 步骤 214：原 UI 测试随 UI 实现迁入 ui/ 包；根包测试仍需要一个静默日志器。
// 该文件只提供测试辅助，不进入生产构建。

import (
	"io"
	"log/slog"
)

// testDiscardLogger 返回丢弃输出的测试日志器。
func testDiscardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError + 1}))
}
