// Package httpapi 定义 EvernightLogin 的公开 HTTP 契约：可信身份类型与解析器、
// HTTP Handler / 防护选项、独立监听服务选项与 TLS 状态视图。
//
// 职责边界：
//   - 本包只包含可被宿主直接使用的公开契约（类型、常量、默认值、纯校验），不
//     import 本模块的 internal 包或根包门面；内部传输引擎（internal/transport）、
//     Handler 组装（internal/httpassemble）与监听生命周期（internal/httpsrv）
//     依赖本包而不是反过来。
//   - 这里不创建监听、不创建协程、不打开数据库；NewHTTPHandler/NewServer 的
//     实际装配在 internal 实现包与根门面中完成。
//   - 安全默认值（请求体上限、超时/并发、限流、CSRF Cookie/头名、Cookie 策略）
//     以本包为单一来源；internal/transport 从本包派生，避免两套默认值漂移。
//
// 迁移说明（步骤 213）：本包类型与函数原位于模块根包的 http.go/http_protection.go/
// server.go 公开部分；根包通过类型/常量别名与薄函数包装保持既有公开 API 兼容。
package httpapi
