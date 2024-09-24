// Package protocolapi 的宿主集成契约、端点清单与已知限制。
//
// 本文件是给人看的集成说明；包级安全说明见 protocolapi.go 的包文档。本包只提供
// 传输层装配，不修改根包公开 API，也不修改 internal/serverapp（接线由后续集成
// 任务完成）。
//
// # 一、端点清单
//
// 固定路径（BasePath 非空时实际路径为 BasePath + 下列路径）：
//
//	方法    路径                                 说明
//	GET     /.well-known/openid-configuration    OIDC Discovery（只声明真实能力）
//	GET     /jwks                                JWT 签名公钥（ES256，公开可缓存）
//	GET     /oauth/authorize                     授权端点：会话 Cookie → 最小同意页
//	POST    /oauth/authorize                     同意/拒绝决定（会话 Cookie + CSRF）
//	POST    /oauth/token/authorize               宿主注入的一次性授权处理器（仅 TokenAuthorize 非空时挂载）
//	POST    /oauth/token                         令牌端点（authorization_code /
//	                                             refresh_token / client_credentials /
//	                                             urn:ietf:params:oauth:grant-type:device_code）
//	GET     /oauth/userinfo                      UserInfo（Authorization: Bearer）
//	POST    /oauth/userinfo                      UserInfo（同上，POST 兼容）
//	POST    /oauth/revoke                        令牌撤销（RFC 7009）
//	POST    /oauth/introspect                    令牌状态查询（RFC 7662，需显式启用）
//	POST    /oauth/device_authorization          设备授权申请（RFC 8628，需显式启用）
//	POST    /oauth/device/cancel                 设备授权取消（本包扩展，需显式启用）
//	POST    /oauth/qr/request                    扫码登录：创建请求（匿名）
//	POST    /oauth/qr/status                     扫码登录：原发起端轮询状态
//	POST    /oauth/qr/claim                      扫码登录：原发起端领取目标应用会话
//	POST    /oauth/qr/cancel                     扫码登录：原发起端取消
//	POST    /oauth/qr/regenerate                 扫码登录：重新生成二维码
//	GET     /oauth/qr/prompt                     扫码登录：确认端读取受控上下文（会话）
//	POST    /oauth/qr/decision                   扫码登录：确认端批准/拒绝（会话 + CSRF）
//
// 标准端点错误使用 RFC 6749/6750/7009/7662/8628 的 error/error_description 字段；
// 自定义扫码端点使用项目统一错误信封 {code,message,request_id}。所有响应都带
// X-Request-ID（合法传入值复用，否则服务端生成），令牌/同意页响应带 no-store。
//
// # 二、宿主集成步骤
//
// 1. 构造真实领域服务（顺序很重要：token → oidc → oauthflow；oidc 的在线撤销
// 检查依赖 oauthflow.Service，而 oauthflow 的 ID Token 签发依赖 oidc.Service，
// 生产装配应使用一个先注入、后回填的适配器解耦这个循环，测试环境 env_test.go
// 中的 revocationLinker 是同一做法的测试版本）：
//
//	tokens      = token.New(token.Options{Store, Audit, Sealer, Issuer, Clients,
//	                Authorizer, ...})                       // 签名密钥/JWKS
//	oauthclient = oauthclient.New(...)                       // 客户端登记与 secret/证书认证
//	oidc        = oidc.New(oidc.Options{Issuer, AuthorizationEndpoint: Issuer+protocolapi.PathAuthorize,
//	                TokenEndpoint: Issuer+protocolapi.PathToken,
//	                UserInfoEndpoint: Issuer+protocolapi.PathUserInfo,
//	                JWKSURI: Issuer+protocolapi.PathJWKS,
//	                Tokens, Users, RevocationChecker, SubjectSecret, ...})
//	oauthflow   = oauthflow.New(oauthflow.Options{..., OIDC: oidc, Tokens: tokens,
//	                ClientAuth: oauthclient, Sessions: session,
//	                DeviceVerificationURI: 部署后的设备确认页地址,
//	                DeviceUserCodeKeyring: 设备短码 HMAC 密钥环,
//	                InspectAuthorizer/InspectClientAuthorizer: 启用状态查询所需})
//	qrlogin     = qrlogin.New(qrlogin.Options{..., Enabled, AllowedClientIDs, Keyring})
//
// 关键约束：oidc.Options 的四个端点地址必须**逐字节等于** Issuer + 本包 Path*
// 常量；Issuer 的路径部分必须等于 Options.BasePath。不一致时 New 直接拒绝构造，
// 避免 Discovery 声明未挂载端点（fail-closed）。
//
// 2. 构造本包服务：
//
//	server, err := protocolapi.New(protocolapi.Options{
//	    OAuth: oauthflow, OIDC: oidc, Tokens: tokens, Sessions: session,
//	    ClientAuth: oauthclient, QRLogin: qrlogin,
//	    QRClientID: "app_...", QRScopes: []string{"profile"},
//	    EnableDeviceFlow: true,          // 仅当 oauthflow 配好 DeviceVerificationURI
//	    EnableIntrospection: true,       // 仅当 oauthflow 配好 InspectAuthorizer
//	    BasePath: cfg.Server.PathPrefix, // issuer 路径必须一致
//	    LoginPath: "/login",             // 可选：未登录时跳转宿主登录页
//	    Logger: logger, Now: time.Now,
//	})
//
// 3. 挂载。协议端点必须挂在既有业务 Handler 之外或作为其最具体的子路径，两种
// 推荐方式：
//
// 方式 A（不依赖框架，直接合成 mux）：
//
//	mux := http.NewServeMux()
//	if err := server.Mount(mux); err != nil { return err } // 冲突/空 mux 都返回错误
//	mux.Handle("/", 既有根 Handler)                        // 其余路径回落到业务 Handler
//	http.Server{Handler: outerMiddleware(mux)}.Serve(listener)
//
// 方式 B（宿主已用“前缀剥离 + 子处理器”组合，例如 internal/serverapp 的
// ComposeHandler 语义）：用 PathPrefixHandler 生成三个命名空间处理器，分别挂到
// BasePath+"/oauth"、BasePath+"/.well-known"、BasePath+"/jwks"：
//
//	oauthNS, _ := server.PathPrefixHandler(server.BasePath() + "/oauth")
//	wellKnownNS, _ := server.PathPrefixHandler(server.BasePath() + "/.well-known")
//	jwksNS, _ := server.PathPrefixHandler(server.BasePath() + "/jwks")
//	mounts := []HandlerMount{
//	    {Name: "protocol-oauth", Prefix: "/oauth", Handler: oauthNS},
//	    {Name: "protocol-well-known", Prefix: "/.well-known", Handler: wellKnownNS},
//	    {Name: "protocol-jwks", Prefix: "/jwks", Handler: jwksNS},
//	}
//	composed, err := ComposeHandler(base, cfg.Server.PathPrefix, mounts)
//
// PathPrefixHandler 把宿主剥离掉的前缀重新拼回路径再交给协议路由；传入非路由
// 前缀会返回错误，避免处理器被挂到永远不会命中的位置。
//
// Mount 会在注册前做冲突探测：宿主已用同一路径或更宽/方法限定模式占用了本包
// 路径时返回 ErrMountConflict，并且**不注册任何路由**（不会留下半挂载状态）。
// 也可以不 Mount，直接把 server.Handler() 挂到宿主自己的路由树上；上述方式共享
// 同一组路径常量与冲突语义。Paths() 返回实际挂载清单（含 BasePath）。
//
// 4. 宿主必须提供的前置防护（本包不实现）：
//   - TLS 终止与 HSTS；生产会话 Cookie 是 __Host- 前缀 + Secure，必须 HTTPS。
//   - 请求体上限/超时/连接与按 IP、账户、客户端的限流（本包只做单请求体上限）。
//   - 访问日志、真实客户端地址与 TLS 客户端证书的验证：本包只读取已经由信任
//     边界验证出的 r.TLS.VerifiedChains；绝不读 X-Forwarded-* 建立身份。
//   - Cookie 会话的 CSRF Origin/Referer 允许列表：internal/transport 的 CSRF 中间件
//     或等价实现。本包自身对**状态修改端点**（POST /oauth/authorize、
//     POST /oauth/qr/decision）已 fail-closed：Origin/Referer 至少一个存在且必须与
//     issuer 同源，两者都缺失直接 403；Cookie 会话还必须通过会话绑定 CSRF 令牌，
//     两类校验不可互相替代。宿主仍须配置 CSRF 中间件覆盖其他业务页面。
//   - 浏览器登录页/设备确认页/扫码 APP 页面属于宿主页面层（步骤 65 的页面与
//     internal/uiauthadapter 已实现），本包只提供协议端点；LoginPath 指向登录页。
//   - 反向代理上的路径前缀：BasePath 必须与 OIDC issuer 路径一致，代理不得改写
//     路径后再转发（否则 Discovery 地址与真实请求不一致）。
//   - CORS：/oauth/qr/* 的创建响应一次性返回领取绑定（claim_secret），宿主**不得**
//     为这些路径配置允许跨源的 CORS，也不得在共享缓存/日志中记录响应正文；本包
//     不设置任何 CORS 头。标准协议端点同样不应开放跨源凭据 CORS。
//
// 5. 与 internal/serverapp 的接线（后续集成任务，不在本包完成）：
//   - serverapp 目前只装配入口页所需的最小服务集合，尚未构造 oauthflow/oidc/
//     token/qrlogin；集成任务需要补充这批服务（复用 BuildServices 的存储/审计/
//     密钥环/base 依赖）并调用 protocolapi.New。
//   - 根包 transport Handler 只注册健康与 OpenAPI 路由并保留 /oauth2 前缀；本包
//     使用 /oauth 前缀，二者不冲突。集成应把协议路径放在最具体位置（见第 3 步），
//     或在 serverapp 构造监听前用外层 mux 组合。
//   - 设备码确认页（oauthflow.DeviceVerificationURI）与扫码确认页（宿主页面）
//     必须在同一部署中可用，否则不要设置 EnableDeviceFlow。
//
// # 三、安全检查与失败语义
//
//   - 身份只来自服务端会话（BrowserSessions）或客户端认证（secret/已验证 TLS
//     证书）；请求参数不能自称用户、应用或资源服务。
//   - 授权端点：无效 client_id/redirect_uri 不重定向（返回 JSON 错误）；其余协议
//     错误只在服务层验证过的已登记回调上以 error 参数重定向。缺 PKCE/plain PKCE
//     一律拒绝；授权码兑换由服务层原子消费，重放按 invalid_grant 拒绝。
//   - 同意页与扫码批准是显式决定：GET 只创建待确认请求，绝不自动批准；POST 必须
//     同一会话 + 会话绑定 CSRF 令牌 +（携带时）同源 Origin。
//   - 令牌端点：保密客户端必须通过 client_secret_basic/post 或已验证客户端证书；
//     一次请求只能使用一种认证方式；重复参数按 invalid_request 拒绝；错误响应
//     不回显内部错误文本。
//   - UserInfo 只接受 Authorization: Bearer；查询串/请求体中的令牌被拒绝，避免
//     令牌进入 URL 与访问日志；ID Token 不能冒充 Access Token。
//   - introspect 的 ResourceServerClientID 只来自本包对客户端的真实认证结果；
//     audience 由请求声明但披露裁剪与审计由注入 oauthflow 的授权器负责。
//   - 设备码：设备码/短码只在申请响应出现一次，短码只以 keyed HMAC 摘要存储；
//     轮询由服务端强制 interval/slow_down；拒绝/取消/过期/重放都有稳定协议错误。
//   - 扫码登录：二维码只含一次性 request_id；领取绑定只出现在创建/重新生成响应；
//     领取只对持有绑定的原发起端成功且只能成功一次；跨用户必须有该请求的领取
//     绑定，否则 410；确认端批准绑定用户+会话+安全版本快照，领取后签发的是
//     确认者本人的目标应用会话（不是发起者的长期 Token）。
//   - 审计由真实服务在关键事务中写入（授权码消费、令牌签发/撤销、设备码申请/
//     确认/领取、扫码创建/批准/领取、失败尝试）；关键审计不可用时服务返回失败，
//     本包把失败映射为 temporarily_unavailable，绝不把未审计的成功当成功。
//   - 运行日志只含端点、结果类别、request_id；令牌、授权码、设备码、短码、刷新
//     令牌、会话秘密、领取绑定、客户端密钥都不会写入日志或审计明细（有测试断言）。
//   - 最外层 router 是统一错误边界：未匹配路径返回 404 统一信封（带 X-Request-ID
//     头与 JSON request_id）；任何处理器 panic 都在此恢复，响应未写出时返回
//     INTERNAL_ERROR + 服务端 request_id 的统一 500，panic 值与栈不进入响应/日志；
//     已写出响应时只记录类别、不追加第二个响应。
//
// # 四、已知限制（如实列出，不声称已支持）
//
//   - 最小同意页是内置的窄功能 HTML（无主题/无脚本/无多语言切换）；生产如需完整
//     页面应使用宿主页面层，并保留同样的服务端会话/CSRF/决定语义。本包含简版页面
//     是为了让独立服务在没有前端构建链时也能完成真实授权闭环。
//   - 未实现 OIDC 会话管理/退出协议（end_session_endpoint、前后台登出）、动态客户端
//     注册、PAR（pushed authorization requests）、request/request_uri 对象、CIBA、
//     token exchange。Discovery 不声明这些能力。
//   - 未实现设备码/扫码登录的“用户确认页”端点：确认页由宿主页面层实现。宿主页面
//     **必须**保留：真实完整会话校验、会话绑定 CSRF 校验、Origin/Referer 同源校验、
//     批准前的敏感策略（近期认证）判定与服务层绑定快照；不得因为复用本包端点而
//     跳过其中任何一项。本包的测试为了让设备码/扫码流程闭环，是在测试内用真实
//     `internal/oauthflow`/`internal/qrlogin` 服务直接完成“确认”步骤（真实服务 +
//     真实 SQLite），这**不是**生产确认页已接线或已验收的证据；确认页接线属宿主
//     页面层任务，交付时必须如实标注。
//   - 扫码登录只签发目标应用会话 Cookie，不签发 OAuth Token；它不是“把扫码结果
//     换成任意应用 Token”的通道（与 qrlogin 服务的安全边界一致）。扫码确认端的
//     prompt 端点只读受控上下文，不返回秘密，也不构成批准。
//   - introspect/device 能力必须由宿主显式声明（EnableIntrospection/EnableDeviceFlow），
//     本包无法从服务对象探测其内部配置；声明不实会由服务返回 temporarily_unavailable，
//     测试覆盖了关闭时的发现文档与 404 行为，但宿主仍须按实际配置声明。
//   - 限流只有服务层内建的设备码/扫码限流；HTTP 维度的限流、请求体总量、连接数、
//     超时、访问日志轮转全部由宿主中间件负责，本包不重复实现。
//   - 本包不做跨实例协调：风控/限流/设备码轮询间隔依赖共享数据库状态；多实例部署
//     需要宿主保证存储一致性与时钟同步（相对时间/唯一约束由服务层使用）。
//   - 未做真实浏览器/标准 OAuth 客户端互操作验收（步骤 92 已记录该边界）：本包的
//     测试用 httptest + 真实 SQLite + 真实服务 + 第三方 JOSE 独立验签，属于进程内
//     协议验收，不等于官方认证或真实浏览器/手机 APP 互操作。
//   - 本包不修改根包公开 API、不修改 internal/serverapp、不新增第三方依赖。
package protocolapi
