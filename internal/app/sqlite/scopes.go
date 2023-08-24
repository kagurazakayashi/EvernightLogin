// Copyright (c) KagurazakaYashi(KagurazakaMiyabi)
// EvernightLogin is licensed under Mulan PSL v2.

package sqlite

// 本文件是 internal/app.ScopeCandidateLister 的 SQLite 实现：只枚举“候选应用范围”，
// 不做授权判定。授权仍由宿主权限引擎逐应用 Check（应用状态、成员关系、角色/权限启用
// 状态与 root_only 过滤都在引擎内完成），因此候选查询不会放宽任何权限。
//
// 只读取 user_roles/group_roles → roles → scopes 三张表；不读取应用资料内容，
// 不返回应用名称/状态，避免在候选阶段泄露范围外应用的任何业务数据。

import (
	"context"
	"fmt"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/app"
)

// listUserApplicationScopesSQL 返回用户拥有启用角色的应用 scope（含直接用户角色与
// 用户组角色），只保留 kind='application' 且 scope ID 与应用 ID 一致的行。
const listUserApplicationScopesSQL = `SELECT DISTINCT candidate.scope_id FROM (
  SELECT ur.scope_id AS scope_id FROM user_roles ur
  JOIN roles r ON r.id=ur.role_id AND r.scope_id=ur.scope_id
  WHERE ur.user_id=? AND r.enabled=1
  UNION
  SELECT gr.scope_id AS scope_id FROM group_members gm
  JOIN group_roles gr ON gr.group_id=gm.group_id
  JOIN roles r ON r.id=gr.role_id AND r.scope_id=gr.scope_id
  WHERE gm.user_id=? AND r.enabled=1
) candidate
JOIN scopes s ON s.id=candidate.scope_id AND s.kind='application' AND s.app_id=candidate.scope_id
ORDER BY candidate.scope_id
LIMIT ?`

// ListUserApplicationScopes 实现 app.ScopeCandidateLister。
//
// 语义与安全边界：
//   - 结果按 scope ID 升序去重，调用方可稳定分页/比较；
//   - 超过 app.MaxManageableApplicationScopes 时返回错误（fail-closed），不截断；
//   - 用户 ID 非法或存储不可用时返回错误，调用方必须按拒绝处理；
//   - 空结果表示“没有候选应用”，是否拒绝由调用方的权限判定决定。
func (s *Store) ListUserApplicationScopes(ctx context.Context, userID string) ([]string, error) {
	if s == nil || s.store == nil {
		return nil, fmt.Errorf("%w: 应用存储未初始化", app.ErrOptionsInvalid)
	}
	if !account.ValidUserID(userID) {
		return nil, fmt.Errorf("%w: 用户 ID 格式无效", app.ErrInvalidRequest)
	}
	rows, err := s.store.QueryContext(ctx, listUserApplicationScopesSQL, userID, userID,
		app.MaxManageableApplicationScopes+1)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", app.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	scopes := make([]string, 0, 8)
	for rows.Next() {
		var scopeID string
		if err := rows.Scan(&scopeID); err != nil {
			return nil, fmt.Errorf("%w: %w", app.ErrStoreUnavailable, err)
		}
		if scopeID == "" {
			return nil, fmt.Errorf("%w: 应用范围数据不完整", app.ErrStoreUnavailable)
		}
		scopes = append(scopes, scopeID)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%w: %w", app.ErrStoreUnavailable, err)
	}
	if len(scopes) > app.MaxManageableApplicationScopes {
		return nil, fmt.Errorf("%w: 应用管理范围超过上限 %d，拒绝枚举",
			app.ErrStoreUnavailable, app.MaxManageableApplicationScopes)
	}
	return scopes, nil
}

// 编译期确认可选能力实现（不强制 app.Store 接口变化，保持既有实现兼容）。
var _ app.ScopeCandidateLister = (*Store)(nil)
