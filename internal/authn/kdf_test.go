package authn

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

// TestPasswordWorkSlotsBounded 直接验证 Argon2 工作槽位的有界性：单槽位占用时
// 第二个请求排队超时返回 errPasswordWorkBusy，释放后可再次获取，取消上下文
// 立即返回而不是继续排队。
func TestPasswordWorkSlotsBounded(t *testing.T) {
	service := &Service{
		kdfSlots:        make(chan struct{}, 1),
		kdfQueueTimeout: 20 * time.Millisecond,
	}
	ctx := context.Background()
	if err := service.acquirePasswordWork(ctx); err != nil {
		t.Fatalf("首个槽位获取失败: %v", err)
	}
	start := time.Now()
	err := service.acquirePasswordWork(ctx)
	if !errors.Is(err, errPasswordWorkBusy) {
		t.Fatalf("槽位占满时错误 = %v，期望 errPasswordWorkBusy", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("等待超时耗时 = %v，超出预期", elapsed)
	}
	service.releasePasswordWork()
	if err := service.acquirePasswordWork(ctx); err != nil {
		t.Fatalf("释放后获取槽位失败: %v", err)
	}
	service.releasePasswordWork()

	// 占用后使用已取消上下文应立即返回取消错误，而不是等满排队超时。
	if err := service.acquirePasswordWork(ctx); err != nil {
		t.Fatalf("重新获取槽位失败: %v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	start = time.Now()
	if err := service.acquirePasswordWork(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("已取消上下文错误 = %v，期望 context.Canceled", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("取消等待耗时 = %v，超出预期", elapsed)
	}
	service.releasePasswordWork()

	// nil 槽位（测试构造/未启用限制）默认放行且释放无害。
	unlimited := &Service{}
	if err := unlimited.acquirePasswordWork(ctx); err != nil {
		t.Fatalf("nil 槽位获取失败: %v", err)
	}
	unlimited.releasePasswordWork()
}

// TestAggregateClientAddress 验证来源地址归一：IPv4 保留完整地址，IPv6 聚合到
// /64 前缀，空/非法值进入固定共享键。
func TestAggregateClientAddress(t *testing.T) {
	cases := []struct {
		raw  string
		want string
	}{
		{"203.0.113.10", "ipv4:203.0.113.10"},
		{"::ffff:203.0.113.10", "ipv4:203.0.113.10"},
		{"2001:db8:1:2::1", "ipv6:20010db800010002"},
		{"2001:db8:1:2:ffff::99", "ipv6:20010db800010002"},
		{"2001:db8:1:3::1", "ipv6:20010db800010003"},
		{"", "unknown"},
		{"not-an-ip", "invalid"},
	}
	for _, test := range cases {
		if got := aggregateClientAddress(test.raw); got != test.want {
			t.Errorf("aggregateClientAddress(%q) = %q，期望 %q", test.raw, got, test.want)
		}
	}
	if aggregateClientAddress("2001:db8:1:2::1") == aggregateClientAddress("2001:db8:1:3::1") {
		t.Error("不同 IPv6 /64 前缀被错误合并")
	}
}

// TestContextFailureClassification 验证密码计算路径的上下文错误判定：取消与超时
// 必须被识别并原样传播，不能被当作业务限流或凭据损坏；其他错误不受影响。
func TestContextFailureClassification(t *testing.T) {
	if !contextFailure(context.Canceled) {
		t.Error("context.Canceled 未被识别为上下文错误")
	}
	if !contextFailure(context.DeadlineExceeded) {
		t.Error("context.DeadlineExceeded 未被识别为上下文错误")
	}
	if !contextFailure(fmt.Errorf("wrapped: %w", context.Canceled)) {
		t.Error("包装后的 context.Canceled 未被识别")
	}
	if contextFailure(errPasswordWorkBusy) || contextFailure(nil) {
		t.Error("非上下文错误被误判为上下文错误")
	}
}
