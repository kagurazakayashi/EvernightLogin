package group_test

import (
	"context"
	"errors"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/group"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
)

// denyingSensitiveRunner 模拟敏感策略拒绝的收敛入口。
type denyingSensitiveRunner struct{ calls int }

func (r *denyingSensitiveRunner) Authorize(ctx context.Context, caller reauth.Caller, request reauth.Request) (reauth.Result, error) {
	r.calls++
	return reauth.Result{}, reauth.ErrMFARequired
}

func (r *denyingSensitiveRunner) NotifyOutcome(ctx context.Context, result reauth.Result, outcome reauth.Outcome) error {
	return nil
}

// TestAddMembersRequiresSensitivePolicy 验证组成员变更接入敏感策略：策略拒绝时
// fail-closed 且不写入成员，既有委派 Guard 仍保留在事务内。
func TestAddMembersRequiresSensitivePolicy(t *testing.T) {
	runner := &denyingSensitiveRunner{}
	env := prepareEnv(t, func(options *group.Options) { options.Sensitive = runner })
	record := env.createGroup(group.ScopeSystem, "sensitive.members")
	const memberID = "usr_00000000000000000000000000000091"
	env.seedUser(memberID, "member", "active")
	if _, err := env.service.AddMembers(context.Background(), env.system,
		group.MemberBatchRequest{GroupID: record.ID, UserIDs: []string{memberID}}); !errors.Is(err, group.ErrAccessDenied) {
		t.Fatalf("策略拒绝后加成员错误 = %v，期望 ErrAccessDenied", err)
	}
	if runner.calls != 1 {
		t.Errorf("敏感策略调用数 = %d，期望 1", runner.calls)
	}
	if count := env.queryInt(`SELECT COUNT(*) FROM group_members WHERE group_id=?`, record.ID); count != 0 {
		t.Errorf("被拒绝后组成员数 = %d，期望 0", count)
	}
	if _, err := env.raw.ExecContext(context.Background(),
		`INSERT INTO group_members(group_id,user_id,created_at_ms) VALUES(?,?,?)`,
		record.ID, memberID, env.queryInt(`SELECT 1`)); err != nil {
		t.Fatalf("插入测试成员: %v", err)
	}
	if _, err := env.service.RemoveMembers(context.Background(), env.system,
		group.MemberBatchRequest{GroupID: record.ID, UserIDs: []string{memberID}}); !errors.Is(err, group.ErrAccessDenied) {
		t.Fatalf("策略拒绝后移除成员错误 = %v，期望 ErrAccessDenied", err)
	}
	if count := env.queryInt(`SELECT COUNT(*) FROM group_members WHERE group_id=?`, record.ID); count != 1 {
		t.Errorf("被拒绝后成员数 = %d，期望仍为 1", count)
	}
	if runner.calls < 2 {
		t.Errorf("敏感策略判定调用数 = %d，期望至少 2", runner.calls)
	}
}

// groupAllowRunner 记录调用并允许执行。
type groupAllowRunner struct {
	calls       int
	notifyCalls int
	last        reauth.Request
}

func (r *groupAllowRunner) Authorize(ctx context.Context, caller reauth.Caller, request reauth.Request) (reauth.Result, error) {
	r.calls++
	r.last = request
	return reauth.Result{OperationID: request.OperationID, TargetType: request.TargetType,
		TargetID: request.TargetID, UserID: caller.Actor().ID}, nil
}

func (r *groupAllowRunner) NotifyOutcome(ctx context.Context, result reauth.Result, outcome reauth.Outcome) error {
	r.notifyCalls++
	return nil
}

// TestAddMembersBindsMemberSetAndNotifies 验证批准绑定方向+成员集合摘要并在成功后告知。
func TestAddMembersBindsMemberSetAndNotifies(t *testing.T) {
	runner := &groupAllowRunner{}
	env := prepareEnv(t, func(options *group.Options) { options.Sensitive = runner })
	record := env.createGroup(group.ScopeSystem, "sensitive.digest")
	members := []string{"usr_00000000000000000000000000000081", "usr_00000000000000000000000000000082"}
	for index, memberID := range members {
		env.seedUser(memberID, "member"+string(rune('a'+index)), "active")
	}
	if _, err := env.service.AddMembers(context.Background(), env.system,
		group.MemberBatchRequest{GroupID: record.ID, UserIDs: members}); err != nil {
		t.Fatalf("接线成功加成员: %v", err)
	}
	if runner.last.Params["direction"] != "add" || runner.last.Params["members"] == "" {
		t.Errorf("成员集合/方向摘要缺失: %+v", runner.last.Params)
	}
	if runner.notifyCalls != 1 {
		t.Errorf("成功告知调用数 = %d，期望 1", runner.notifyCalls)
	}
}

// TestAddMembersFailsClosedWithoutRunner 验证未接线且未显式允许旧语义时拒绝。
func TestAddMembersFailsClosedWithoutRunner(t *testing.T) {
	env := prepareEnv(t, func(options *group.Options) { options.AllowLegacyWithoutSensitive = false })
	record := env.createGroup(group.ScopeSystem, "sensitive.closed")
	const memberID = "usr_00000000000000000000000000000083"
	env.seedUser(memberID, "member", "active")
	if _, err := env.service.AddMembers(context.Background(), env.system,
		group.MemberBatchRequest{GroupID: record.ID, UserIDs: []string{memberID}}); !errors.Is(err, group.ErrAccessDenied) {
		t.Fatalf("未接线时加成员错误 = %v，期望 ErrAccessDenied", err)
	}
	if count := env.queryInt(`SELECT COUNT(*) FROM group_members WHERE group_id=?`, record.ID); count != 0 {
		t.Errorf("fail-closed 后组成员数 = %d，期望 0", count)
	}
}
