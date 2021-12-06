// Package loginte2e 是 OAuth2/OIDC/设备码/扫码协议端点与管理 JSON API 的
// 端到端测试实现库；命令行入口是 tools/loginte2e（薄 main 包装），本包同时供
// internal/serverapp、internal/protocolapi、internal/adminapi 的集成测试导入复用。
//
// # 用途
//
// 对一个**已经运行**的 login 服务做黑盒验收、回归与故障排查：
//
//   - discovery：核对 Discovery 声明的 issuer/端点/能力是否与真实挂载一致；
//   - jwks：拉取 JWKS，并用标准库 crypto 独立验证 ID Token 的签名与 iss/aud/exp/nonce；
//   - authcode：授权码 + PKCE S256 全流程（真实登录会话 + 最小同意页 CSRF）；
//   - token：code 兑换 / UserInfo / refresh 轮换与重放 / revoke / introspect；
//   - device：设备授权申请、pending 轮询、（可注入的）用户确认、领取令牌、取消；
//   - qr：扫码请求、状态轮询、确认端 prompt/decision、claim 与重放负例；
//   - adminapi：以管理会话秘密调用 /meta、/error-codes 与稳定的拒绝路径；
//   - all：按 discovery→jwks→authcode→token→device→qr→adminapi 顺序汇总。
//
// # 安全边界（重要）
//
//   - 工具只用于测试/验收，绝不能进入生产入口：本包不在根包、cmd/、internal/
//     生产代码中被导入（import_guard_test.go 静态守护）。
//   - 默认严格 TLS 校验，**不提供**跳过校验的开关；自签测试环境用 CAFile 信任
//     指定 CA。自定义 CA 只追加到系统信任之外，不关闭主机名/有效期校验。
//   - 会话秘密/管理会话秘密只从受保护文件读取（读取前调用
//     secrets.CheckProtectedFile），只放内存，不写入日志、报告或命令行；结果里的
//     令牌、授权码、设备码、短码、领取绑定、会话秘密一律不出现。
//   - 不真实外发邮件/Webhook：工具只调用协议端点与管理只读端点，不触碰通知测试
//     等会触发外部投递的写操作。
//   - 设备码/扫码的“用户确认”在协议包中**没有**传输层端点：扫码确认走
//     /oauth/qr/prompt + /oauth/qr/decision（会话秘密 Bearer，无浏览器环境凭据
//     时不需要 CSRF）；设备确认由宿主页面层实现，CLI 只有在显式给出
//     --device-confirm-url 时才用通用 HTML 表单驱动，库使用者可注入
//     DeviceConfirmFunc 直接调用真实领域服务。缺少确认能力时套件如实标记 skip，
//     绝不伪造成功。
//
// # 可复用 API
//
//	cfg := loginte2e.Config{Server: srv.URL, ClientID: clientID, RedirectURI: redirect}
//	client, err := loginte2e.New(cfg)
//	report, err := client.Run(ctx, loginte2e.SuiteDiscovery)
//
// 典型集成测试用法：用 httptest 启动真实 protocolapi.Handler（或 serverapp 装配
// 后的处理程序），把 httptest.URL 作为 Server；需要“已登录用户”时由测试直接用
// 真实会话服务签发会话并把会话秘密填入 Config.SessionSecret。
//
// # 已知限制
//
//   - 不模拟真实浏览器/真实手机 APP：机器驱动的标准 HTTP 客户端不等于浏览器或
//     官方 OAuth 客户端互操作验收；内置登录页交互式认证未实现（仅支持受保护
//     会话 Cookie/秘密文件）。
//   - 设备确认页、扫码确认页属于宿主页面层，本工具不保证其存在。
//   - 只覆盖公开协议契约与管理只读端点；写管理操作（需要 confirm/原因/敏感策略）
//     不做真实执行，避免测试工具产生业务副作用。
package loginte2e
