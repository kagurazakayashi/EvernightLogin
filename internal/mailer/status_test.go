package mailer_test

import (
	"context"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/mailer"
)

// TestDeliveryReconcileAndStatus 覆盖：残留 sending 有界修复为永久失败、不重发；
// 状态计数与最近失败码可读。
func TestDeliveryReconcileAndStatus(t *testing.T) {
	env := newDeliveryEnv(t)
	ctx := context.Background()
	record := mailer.Record{
		ID: "mdl_" + "a" + "014", IdempotencyKey: "reconcile-key", Kind: mailer.KindPasswordReset,
		Recipient: "user@example.test", OwnerType: audit.ActorSystem, OwnerID: "system",
		State: mailer.DeliverySending, Attempts: 1, MaxAttempts: 3,
		SealedPayload: []byte("sealed"), CreatedAt: deliveryStart, UpdatedAt: deliveryStart,
	}
	if _, _, err := env.store.Create(ctx, record); err != nil {
		t.Fatalf("Create: %v", err)
	}
	repaired, err := env.service.Reconcile(ctx, 100)
	if err != nil || repaired != 1 {
		t.Fatalf("Reconcile = %d, %v; 期望 1,nil", repaired, err)
	}
	stored, err := env.store.Get(ctx, record.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if stored.State != mailer.DeliveryFailed || stored.LastErrorCode != mailer.CodeUnavailable {
		t.Fatalf("残留 sending 应标永久失败且不自动重发: %+v", stored)
	}
	status, err := env.service.Status(ctx)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !status.Known || status.Counts[mailer.DeliveryFailed] != 1 {
		t.Fatalf("状态计数不符: %+v", status)
	}
	if len(status.RecentErrorCodes) != 1 || status.RecentErrorCodes[0] != mailer.CodeUnavailable {
		t.Fatalf("最近失败码不符: %+v", status.RecentErrorCodes)
	}
	if env.sender.sent != nil {
		t.Fatal("Reconcile 不得自动重发")
	}
	_ = time.Now
}
