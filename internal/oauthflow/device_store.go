package oauthflow

import "time"

// 设备授权请求状态。expired 不落库：由服务层按 ExpiresAt 惰性判断，避免为了
// “看起来有状态”而写入可能与真实时钟不一致的终态。
const (
	// DeviceStatusPending 表示等待用户在另一台设备确认。
	DeviceStatusPending = "pending"
	// DeviceStatusApproved 表示用户已批准，等待原设备领取令牌。
	DeviceStatusApproved = "approved"
	// DeviceStatusDenied 表示用户明确拒绝（轮询按标准 access_denied 返回）。
	DeviceStatusDenied = "denied"
	// DeviceStatusCancelled 表示发起设备主动取消（轮询按 access_denied 返回）。
	DeviceStatusCancelled = "cancelled"
	// DeviceStatusConsumed 表示设备已成功领取令牌；设备码不可再次兑换。
	DeviceStatusConsumed = "consumed"
)

// DeviceAuthorizationRecord 是一次设备授权申请的持久化记录。
//
// 安全边界：记录不包含 device_code/user_code 明文（只保存摘要），也不包含会话
// 秘密或任何令牌。UserID/SessionID/SecurityVersion 是用户批准时的真实会话快照，
// 领取令牌前必须重新核对用户、成员、客户端与安全版本仍与快照一致。
type DeviceAuthorizationRecord struct {
	ID string
	// DeviceCodeSHA256 是高熵设备码（32 字节随机）的无密钥 SHA-256 摘要：256 bit
	// 熵使离线枚举不可行。
	DeviceCodeSHA256 [32]byte
	// UserCodeDigest/UserCodeKeyID 是低熵人工短码（8 字符 base20 ≈ 34.6 bit）的
	// **带密钥 HMAC-SHA256 摘要**与所用密钥编号。低熵值不能用无密钥摘要保护，故
	// 使用宿主注入的 secrets.Keyring 派生 HMAC；key_id 随行保存以支持密钥轮换后
	// 的历史查找（旧密钥仍在密钥环中时仍可核对旧记录）。明文只在申请响应出现一次。
	UserCodeDigest  [32]byte
	UserCodeKeyID   string
	ClientID        string
	Scopes          []string
	Audiences       []string
	Status          string
	UserID          string
	SessionID       string
	SecurityVersion int64
	// IntervalSeconds/LastPolledAt 用于服务端强制轮询间隔（slow_down）。
	IntervalSeconds int
	LastPolledAt    time.Time
	RequestID       string
	CreatedAt       time.Time
	ExpiresAt       time.Time
	DecidedAt       time.Time
	CancelledAt     time.Time
	ConsumedAt      time.Time
}

// ExpiredAt 报告请求在 now 时刻是否已过期；过期判断不依赖落库状态。
func (r DeviceAuthorizationRecord) ExpiredAt(now time.Time) bool {
	return !r.ExpiresAt.IsZero() && !now.Before(r.ExpiresAt)
}

// PollAllowedAt 报告在 now 时刻是否已满足服务端强制的最小轮询间隔。
func (r DeviceAuthorizationRecord) PollAllowedAt(now time.Time) bool {
	if r.LastPolledAt.IsZero() {
		return true
	}
	interval := time.Duration(r.IntervalSeconds) * time.Second
	if interval <= 0 {
		interval = time.Second
	}
	return !now.Before(r.LastPolledAt.Add(interval))
}
