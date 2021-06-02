package profile

import (
	"context"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
)

// UpdateRecord 是事务内资料更新参数；只含白名单字段与条件版本。
type UpdateRecord struct {
	UserID    string
	Nickname  string
	Biography string
	Language  string
	Timezone  string
	Phone     string
	// PhoneChanged 表示本次更新改变了电话号码：同事务清空 phone_verified_at_ms，
	// 防止未来验证能力误用旧号码的验证状态。
	PhoneChanged       bool
	ExpectedRowVersion int64
	Now                time.Time
}

// UsernameUpdate 是事务内更名参数。
type UsernameUpdate struct {
	UserID             string
	Username           string
	UsernameNormalized string
	ExpectedRowVersion int64
	Now                time.Time
}

// Store 是资料领域持久化契约，由 internal/profile/sqlite 实现。
// 事务方法必须在调用方审计事务内执行；版本不匹配返回 changed=false（由服务映射
// CONFLICT），用户名唯一冲突返回 ErrUsernameTaken。
type Store interface {
	// GetProfile 读取用户全局资料；不存在返回 found=false。
	GetProfile(ctx context.Context, userID string) (UserProfile, bool, error)
	// GetProfileTx 在审计事务内读取用户全局资料。
	GetProfileTx(ctx context.Context, tx audit.Tx, userID string) (UserProfile, bool, error)
	// UpdateProfile 条件更新白名单资料；行版本不匹配返回 false。
	UpdateProfile(ctx context.Context, tx audit.Tx, record UpdateRecord) (bool, error)
	// UpdateUsername 条件更名并更新更名时间；行版本不匹配返回 false，唯一冲突
	// 返回 ErrUsernameTaken；稳定用户 ID 不变。
	UpdateUsername(ctx context.Context, tx audit.Tx, update UsernameUpdate) (bool, error)
}
