package app

import (
	"context"
)

// AccessRequest 是“受信调用者已经确认用户身份”后的权限检查请求；所需权限由业务
// 服务端（受信宿主）选定，不能采用客户端自填值。
//
// 安全语义（步骤 251）：
//   - UserID 必须来自已校验的会话/令牌或宿主可信身份，绝不能来自客户端自填字段；
//   - Permission 必填：受信宿主选定本次操作需要的权限键。空权限不是“无需权限”，
//     会被拒绝；客户端不能靠传空权限自证已授权；
//   - AppID 为空表示系统范围，非空表示应用范围；跨应用同名权限与资源按范围隔离，
//     不能用一个应用的授权结论代替另一个应用；
//   - ResourceID 为空时只判定功能权限，不校验任何具体业务资源的归属；
//   - ResourceID 非空时按资源级语义判定：先判定功能权限，再复用领域授权内核的
//     数据范围判定（数据范围未声明/为 none/不包含该资源都拒绝），不会只返回功能
//     权限结论。资源类型与“资源是否属于该用户”的业务含义仍由宿主定义；
//   - Mode 为空按 all；资源级判定只接受单个权限键，all/any 对单权限判定等价。
type AccessRequest struct {
	UserID     string
	AppID      string
	Permission string
	// Mode 是功能权限组合模式："all"（默认）或 "any"。
	Mode string
	// ResourceID 是可选的业务资源标识。为空表示只判定功能权限；非空表示要求同时
	// 通过该资源的数据范围判定。
	ResourceID string
	RequestID  string
}

// AccessDecision 是权限检查结果；Reason/Code 为稳定公开值。
//
// 读取本结果时必须同时检查 ResourceChecked：Allowed=true 且 ResourceChecked=false
// 只证明功能权限通过，不证明任何具体业务资源已通过数据范围/归属检查，宿主仍须
// 自行校验资源归属。
type AccessDecision struct {
	Allowed   bool
	Code      string
	Reason    string
	RequestID string
	// Application 是本次判定的应用范围（请求 AppID 的回显）；系统范围为 ""。
	Application string
	// ResourceChecked 表示本次判定是否按资源级语义执行（请求提供了 ResourceID）。
	// 为 false 时 Allowed 只代表功能权限判定，不代表任何具体资源已校验。
	// 为 true 时 Allowed=false 可能由功能权限不足（例如 PERMISSION_REQUIRED）或
	// 数据范围不足（RESOURCE_FORBIDDEN）引起，由 Code/Reason 区分。
	ResourceChecked bool
	// ResourceID 是本次做数据范围判定的资源标识；未提供 ResourceID 时为 ""。
	ResourceID string
}

// AccessService 是联合权限检查门面。
//
// 功能权限判定与具体业务资源的数据范围判定分开，不能用一个代替另一个。
//
// 它只做授权判定、不校验会话；需要“会话有效 + 属于当前应用 + 所需权限（+ 可选
// 资源）”的联合判断时使用 SessionService.Authorize。会话是否有效、CSRF 是否通过
// 与是否有权限是三个不同判断，本门面不会因为缺少会话校验而扩大权限。
type AccessService interface {
	Check(ctx context.Context, req AccessRequest) (AccessDecision, error)
}
