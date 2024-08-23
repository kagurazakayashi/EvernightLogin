package app

import (
	"context"
	"time"
)

// CreateUserRequest 是宿主受信创建用户请求。
type CreateUserRequest struct {
	Username  string
	Password  string
	Email     string
	Nickname  string
	Language  string
	Timezone  string
	RequestID string
}

// User 是脱敏用户视图。
type User struct {
	ID        string
	Username  string
	Nickname  string
	Email     string
	Status    string
	CreatedAt time.Time
}

// UserService 是宿主受信用户门面。
type UserService interface {
	Create(ctx context.Context, req CreateUserRequest) (User, error)
}
