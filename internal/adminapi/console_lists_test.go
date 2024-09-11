package adminapi

// 步骤 266：安全告知历史与邮件投递记录端点的协议层测试。
// 覆盖：未装配时 404（不占位空列表）、权限拒绝映射 403、参数校验（user_id/offset/
// limit）、稳定游标透传、白名单字段序列化、非法游标映射 REQ_INVALID。

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
)

// fakeSecurityNotificationReader 返回固定分页结果，便于验证协议映射。
type fakeSecurityNotificationReader struct {
	page    SecurityNotificationList
	err     error
	seen    SecurityNotificationListQuery
	callers []account.Caller
}

func (f *fakeSecurityNotificationReader) ListSecurityNotifications(_ context.Context,
	caller account.Caller, query SecurityNotificationListQuery) (SecurityNotificationList, error) {
	f.seen = query
	f.callers = append(f.callers, caller)
	return f.page, f.err
}

// fakeMailDeliveryReader 返回固定分页结果。
type fakeMailDeliveryReader struct {
	page MailDeliveryList
	err  error
	seen MailDeliveryListQuery
}

func (f *fakeMailDeliveryReader) ListMailDeliveries(_ context.Context, _ account.Caller,
	query MailDeliveryListQuery) (MailDeliveryList, error) {
	f.seen = query
	return f.page, f.err
}

const historyTestUserID = "usr_00000000000000000000000000000002"

// newHistoryTestServer 构造只安装两个读取实现的测试服务器。
func newHistoryTestServer(t *testing.T, notifications SecurityNotificationReader,
	deliveries MailDeliveryReader) http.Handler {
	t.Helper()
	session := &stubSession{secret: "management-secret",
		userID: "usr_00000000000000000000000000000001"}
	server, err := New(Options{Session: session, ErrorCodes: testCodes(),
		SecurityNotifications: notifications, MailDeliveries: deliveries,
		Now: func() time.Time { return adminBaseTime }})
	if err != nil {
		t.Fatalf("构造管理 API 失败: %v", err)
	}
	return server
}

// TestNotificationHistoryEndpoint 验证安全告知历史的参数、游标与白名单投影。
func TestNotificationHistoryEndpoint(t *testing.T) {
	reader := &fakeSecurityNotificationReader{page: SecurityNotificationList{
		HasMore: true, NextCursor: "next-notification-cursor",
		Notifications: []SecurityNotificationView{{
			ID: "ntf_0001", UserID: historyTestUserID, OperationID: "password.change",
			TargetType: "user", TargetID: historyTestUserID, Outcome: "success",
			State: "queued", RecipientMasked: "a***@example.com",
			DeliveryID: "del_0001", DeliveryState: "queued",
			CreatedAt: time.Date(2026, 11, 26, 3, 0, 0, 0, time.UTC),
		}}}}
	handler := newHistoryTestServer(t, reader, nil)
	reply := callAPI(t, handler, http.MethodGet,
		"/admin/v1/notifications/history?user_id="+historyTestUserID+"&limit=5&cursor=abc",
		"", "Bearer management-secret", nil)
	if reply.status != http.StatusOK {
		t.Fatalf("状态 = %d，body=%s", reply.status, string(reply.body))
	}
	data, _ := reply.parsed["data"].(map[string]any)
	if data == nil || data["has_more"] != true ||
		data["next_cursor"] != "next-notification-cursor" {
		t.Fatalf("分页字段缺失: %s", string(reply.body))
	}
	items, _ := data["notifications"].([]any)
	if len(items) != 1 {
		t.Fatalf("告知条数 = %d，body=%s", len(items), string(reply.body))
	}
	item, _ := items[0].(map[string]any)
	if item["recipient_masked"] != "a***@example.com" ||
		item["delivery_state"] != "queued" || item["operation_id"] != "password.change" {
		t.Fatalf("白名单字段异常: %s", string(reply.body))
	}
	if reader.seen.UserID != historyTestUserID || reader.seen.Cursor != "abc" ||
		reader.seen.Limit != 5 {
		t.Fatalf("查询参数未透传: %+v", reader.seen)
	}
	// 参数校验：缺 user_id / 非法 user_id / 非零 offset / 越界 limit。
	for _, path := range []string{
		"/admin/v1/notifications/history",
		"/admin/v1/notifications/history?user_id=bad-id",
		"/admin/v1/notifications/history?user_id=" + historyTestUserID + "&offset=1",
		"/admin/v1/notifications/history?user_id=" + historyTestUserID + "&limit=1000",
	} {
		if invalid := callAPI(t, handler, http.MethodGet, path, "",
			"Bearer management-secret", nil); invalid.status != http.StatusBadRequest {
			t.Fatalf("%s 状态 = %d，期望 400", path, invalid.status)
		}
	}
}

// TestNotificationHistoryDenied 验证读取实现拒绝时映射为 403，不回显内部细节。
func TestNotificationHistoryDenied(t *testing.T) {
	reader := &fakeSecurityNotificationReader{err: ErrAccessDenied}
	handler := newHistoryTestServer(t, reader, nil)
	reply := callAPI(t, handler, http.MethodGet,
		"/admin/v1/notifications/history?user_id="+historyTestUserID, "", "Bearer management-secret", nil)
	if reply.status != http.StatusForbidden {
		t.Fatalf("状态 = %d，期望 403（body=%s）", reply.status, string(reply.body))
	}
}

// TestMailDeliveryEndpoint 验证投递记录端点：游标透传、终态筛选、白名单投影。
func TestMailDeliveryEndpoint(t *testing.T) {
	reader := &fakeMailDeliveryReader{page: MailDeliveryList{
		HasMore: true, NextCursor: "next-delivery-cursor",
		Deliveries: []MailDeliveryView{{
			DeliveryID: "del_0001", Kind: "security.notice", State: "failed",
			RecipientMasked: "***@example.com", OwnerType: "user",
			OwnerID: historyTestUserID, Attempts: 3, MaxAttempts: 3,
			LastErrorCode: "MAIL_DELIVERY_FAILED",
			CreatedAt:     time.Date(2026, 11, 26, 3, 0, 0, 0, time.UTC),
			UpdatedAt:     time.Date(2026, 11, 26, 3, 1, 0, 0, time.UTC),
		}}}}
	handler := newHistoryTestServer(t, nil, reader)
	reply := callAPI(t, handler, http.MethodGet,
		"/admin/v1/deliveries?state=failed&limit=10&cursor=opaque", "", "Bearer management-secret", nil)
	if reply.status != http.StatusOK {
		t.Fatalf("状态 = %d，body=%s", reply.status, string(reply.body))
	}
	data, _ := reply.parsed["data"].(map[string]any)
	items, _ := data["deliveries"].([]any)
	if len(items) != 1 || data["has_more"] != true {
		t.Fatalf("投递分页字段异常: %s", string(reply.body))
	}
	item, _ := items[0].(map[string]any)
	if item["state"] != "failed" || item["last_error_code"] != "MAIL_DELIVERY_FAILED" ||
		item["recipient_masked"] != "***@example.com" {
		t.Fatalf("白名单字段异常: %s", string(reply.body))
	}
	if reader.seen.State != "failed" || reader.seen.Cursor != "opaque" || reader.seen.Limit != 10 {
		t.Fatalf("查询参数未透传: %+v", reader.seen)
	}
}

// TestMailDeliveryEndpointInvalidCursor 验证领域层拒绝非法游标时映射为 REQ_INVALID。
func TestMailDeliveryEndpointInvalidCursor(t *testing.T) {
	reader := &fakeMailDeliveryReader{err: ErrInvalidRequest}
	handler := newHistoryTestServer(t, nil, reader)
	reply := callAPI(t, handler, http.MethodGet, "/admin/v1/deliveries?cursor=tampered", "",
		"Bearer management-secret", nil)
	if reply.status != http.StatusBadRequest {
		t.Fatalf("状态 = %d，期望 400（body=%s）", reply.status, string(reply.body))
	}
}

// TestHistoryEndpointsUnwired 验证未装配读取实现时端点不挂载（404，不占位空列表）。
func TestHistoryEndpointsUnwired(t *testing.T) {
	handler := newHistoryTestServer(t, nil, nil)
	for _, path := range []string{
		"/admin/v1/notifications/history?user_id=" + historyTestUserID,
		"/admin/v1/deliveries",
	} {
		if reply := callAPI(t, handler, http.MethodGet, path, "",
			"Bearer management-secret", nil); reply.status != http.StatusNotFound {
			t.Fatalf("%s 状态 = %d，期望 404", path, reply.status)
		}
	}
}
