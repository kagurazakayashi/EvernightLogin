package token_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	. "github.com/kagurazakayashi/EvernightLogin/internal/token"
)

// ensuredAuditEnv 是可切换失败的成功审计包装（用于验证复用路径审计 fail-closed）。
type ensuredAuditEnv struct {
	inner AuditRecorder
	mu    sync.Mutex
	fail  bool
}

func (a *ensuredAuditEnv) setFail(value bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.fail = value
}

func (a *ensuredAuditEnv) Record(ctx context.Context, event audit.Event) error {
	a.mu.Lock()
	fail := a.fail
	a.mu.Unlock()
	if fail {
		return audit.ErrAuditUnavailable
	}
	return a.inner.Record(ctx, event)
}

func (a *ensuredAuditEnv) RecordFailure(ctx context.Context, event audit.Event) error {
	return a.inner.RecordFailure(ctx, event)
}

func (a *ensuredAuditEnv) ExecuteCritical(ctx context.Context, request audit.CriticalRequest,
	change audit.Change) error {
	return a.inner.ExecuteCritical(ctx, request, change)
}

// countAuditAction 统计指定审计动作条数（真实审计表）。
func countAuditAction(env *testEnv, action string) int64 {
	env.t.Helper()
	var count int64
	if err := env.raw.DB().QueryRowContext(env.ctx,
		`SELECT COUNT(*) FROM audit_events WHERE action=?`, action).Scan(&count); err != nil {
		env.t.Fatalf("查询审计失败: %v", err)
	}
	return count
}

// TestEnsureSigningKeyCreatesOnceAndReuses 验证首次创建一把 active 密钥、二次幂等
// 复用不新建，且创建/复用两条路径都有审计。
func TestEnsureSigningKeyCreatesOnceAndReuses(t *testing.T) {
	env := newTestEnv(t, nil)
	first, err := env.service.EnsureSigningKey(env.ctx)
	if err != nil {
		t.Fatalf("首次预引导失败: %v", err)
	}
	if first.Kid == "" {
		t.Fatal("首次预引导未返回 kid")
	}
	if created := countAuditAction(env, "token.key.created"); created != 1 {
		t.Fatalf("创建审计条数 = %d，期望 1", created)
	}
	second, err := env.service.EnsureSigningKey(env.ctx)
	if err != nil {
		t.Fatalf("二次预引导失败: %v", err)
	}
	if second.Kid != first.Kid {
		t.Fatalf("kid 变化：first=%s second=%s", first.Kid, second.Kid)
	}
	infos, err := env.service.KeyInfos(env.ctx)
	if err != nil || len(infos) != 1 {
		t.Fatalf("密钥数 = %d err=%v，期望仅 1 把", len(infos), err)
	}
	if ensured := countAuditAction(env, "token.key.ensured"); ensured != 1 {
		t.Fatalf("复用审计条数 = %d，期望 1", ensured)
	}
	if created := countAuditAction(env, "token.key.created"); created != 1 {
		t.Fatalf("复用不得新建密钥，创建审计条数 = %d", created)
	}
}

// TestEnsureSigningKeyConcurrentSingleActive 验证并发两路：仅产生一把 active 密钥，
// 两路都成功且复用路径有审计。
func TestEnsureSigningKeyConcurrentSingleActive(t *testing.T) {
	env := newTestEnv(t, nil)
	var wait sync.WaitGroup
	kids := make([]string, 2)
	errs := make([]error, 2)
	for index := 0; index < 2; index++ {
		wait.Add(1)
		go func(slot int) {
			defer wait.Done()
			info, err := env.service.EnsureSigningKey(env.ctx)
			kids[slot], errs[slot] = info.Kid, err
		}(index)
	}
	wait.Wait()
	for index, err := range errs {
		if err != nil {
			t.Fatalf("第 %d 路预引导失败: %v", index, err)
		}
	}
	if kids[0] == "" || kids[0] != kids[1] {
		t.Fatalf("并发两路 kid 不一致: %v", kids)
	}
	infos, err := env.service.KeyInfos(env.ctx)
	if err != nil || len(infos) != 1 {
		t.Fatalf("并发后密钥数 = %d err=%v，期望仅 1 把 active", len(infos), err)
	}
	if created := countAuditAction(env, "token.key.created"); created != 1 {
		t.Fatalf("并发创建审计条数 = %d，期望 1", created)
	}
	if ensured := countAuditAction(env, "token.key.ensured"); ensured < 1 {
		t.Fatalf("并发复用路径缺少审计（ensured=%d）", ensured)
	}
}

// TestEnsureSigningKeyReuseAuditFailureFailsClosed 验证复用路径审计不可用时
// fail-closed 返回审计错误（不静默成功）。
func TestEnsureSigningKeyReuseAuditFailureFailsClosed(t *testing.T) {
	wrapper := &ensuredAuditEnv{}
	env := newTestEnv(t, func(options *Options) {
		wrapper.inner = options.Audit
		options.Audit = wrapper
	})
	if _, err := env.service.EnsureSigningKey(env.ctx); err != nil {
		t.Fatalf("首次预引导失败: %v", err)
	}
	wrapper.setFail(true)
	if _, err := env.service.EnsureSigningKey(env.ctx); !errors.Is(err, ErrAuditUnavailable) {
		t.Fatalf("复用路径审计失败应返回 ErrAuditUnavailable，得到 %v", err)
	}
	wrapper.setFail(false)
	infos, _ := env.service.KeyInfos(env.ctx)
	if len(infos) != 1 {
		t.Fatalf("密钥数 = %d，期望仍为 1（审计失败不得新建/删除密钥）", len(infos))
	}
}
