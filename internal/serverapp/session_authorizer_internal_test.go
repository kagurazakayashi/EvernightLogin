package serverapp

import (
	"context"
	"errors"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
)

// fakeScopeAuthorizer 记录调用并返回预设错误。
type fakeScopeAuthorizer struct {
	called bool
	err    error
}

func (f *fakeScopeAuthorizer) AuthorizeSessionRevoke(context.Context, audit.Actor, string, string) error {
	f.called = true
	return f.err
}

// TestLazySessionScopeAuthorizerFailClosed 覆盖步骤 151 装配顺序：未注入前拒绝，
// 注入后原子生效；nil 注入清回拒绝。
func TestLazySessionScopeAuthorizerFailClosed(t *testing.T) {
	lazy := newLazySessionScopeAuthorizer()
	actor := audit.Actor{Type: audit.ActorUser, ID: "usr_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	if err := lazy.AuthorizeSessionRevoke(context.Background(), actor, "", actor.ID); !errors.Is(err, session.ErrAccessDenied) {
		t.Fatalf("未注入应 fail-closed，实际 %v", err)
	}
	fake := &fakeScopeAuthorizer{}
	lazy.Set(fake)
	if err := lazy.AuthorizeSessionRevoke(context.Background(), actor, "", actor.ID); err != nil || !fake.called {
		t.Fatalf("注入后应调用真实授权器: %v", err)
	}
	lazy.Set(nil)
	if err := lazy.AuthorizeSessionRevoke(context.Background(), actor, "", actor.ID); !errors.Is(err, session.ErrAccessDenied) {
		t.Fatalf("清除注入后应 fail-closed，实际 %v", err)
	}
}
