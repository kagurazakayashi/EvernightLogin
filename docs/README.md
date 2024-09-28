# EvernightLogin 文档中心

本目录是产品文档的唯一入口。根 [README.md](../README.md) 是面向新用户的最短上手页
（权限速览、三种恢复路径与直接管理、列表搜索、可复制接入示例），需要判断能力、选择形态、
按场景操作或查接口契约时，从本索引进入。

## 1. 目录地图

| 目录 | 读它做什么 |
|---|---|
| [guide/](guide/README.md) | **产品使用主干**：能力状态、快速开始、两模式选择、登录/OAuth、应用与权限、角色与范围、配置、客服恢复、CLI、审计报告、备份恢复、错误码排障、内置 Web 管理台操作（[admin-console.md](guide/admin-console.md)） |
| [deployment/](deployment/README.md) | 独立部署：首次初始化、独立服务启动、TLS/反代、容器、服务托管、邮件子模块、协议/管理 API 接入、打包与构建入口 |
| [embedding/](embedding/README.md) | 作为 Go Module 嵌入：公开 API 稳定范围、生命周期与资源所有权、页面替换、嵌入示例与宿主调用边界 |
| [database/](database/数据库基线说明.md) | 存储模型、迁移设计、表字段索引与 SQLite/MySQL/PostgreSQL/SQL Server 适配说明 |
| [requirements/](requirements/) | 需求基线：功能列表（设计目标，不等于已实现）与历史错误码手册 |
| [acceptance/](acceptance/README.md) | 验收与交付核对记录、能力矩阵（机器可读）、短测试入口；**历史证据不改写** |
| [licenses/](licenses/THIRD_PARTY_NOTICES.md) | 第三方组件/字体/依赖的版权与许可声明 |

> [`docs/reference/`](reference/README.md)（人类与 AI 共用的接口参考：Go API / HTTP / CLI / 权限 /
> 错误码 / 配置 / 能力映射与 4 个机器可读 JSON）由 `scripts/reference` 从代码生成，`-check` 与
> `verify-docs` 逐字节校验；不要再手工维护第二套接口清单。接口问题可同时参考
> [guide/api-status.md](guide/api-status.md) 与 [embedding/host_integration.md](embedding/host_integration.md)。

## 2. 建议阅读路径

1. **先判断能不能用**：[guide/README.md](guide/README.md) 第 2 节能力总览 +
   [guide/deployment-modes.md](guide/deployment-modes.md)。
2. **嵌入自己的 Go 程序**：[embedding/README.md](embedding/README.md) →
   [embedding/host_integration.md](embedding/host_integration.md) →
   [guide/configuration.md](guide/configuration.md)；
   可运行示例：[../examples/embedded-minimal/](../examples/embedded-minimal/README.md)、
   [../examples/custom-pages-profile-sync/](../examples/custom-pages-profile-sync/README.md)、
   [../examples/external-consumer/](../examples/external-consumer/)。
3. **独立部署服务**：[deployment/first-run.md](deployment/first-run.md) →
   [deployment/standalone-service.md](deployment/standalone-service.md) →
   [deployment/reverse-proxy.md](deployment/reverse-proxy.md)。
4. **运维已部署实例**：[guide/configuration.md](guide/configuration.md)、
   [guide/root-cli.md](guide/root-cli.md)、[guide/backup-and-restore.md](guide/backup-and-restore.md)、
   [guide/troubleshooting.md](guide/troubleshooting.md)。
5. **出问题**：[guide/troubleshooting.md](guide/troubleshooting.md) 的错误码表与排障顺序，
   再按对应主题深入。

## 3. 文档约定

- 文档使用简体中文；命令优先给 Windows 写法，非 Windows 平台按说明替换路径分隔符与执行位。
- 命令示例标注前提与预期；预期结果描述本版本的真实行为，不承诺“绝对成功”。
- **平台与验证口径**：当前运行实测为 Windows 11 + SQLite；其他平台/数据库仅编译或静态检查，
  不能写成“已验证支持”。详见 [guide/README.md](guide/README.md) 第 6 节。
- **权威来源**：配置默认值与 `login.Default()`/配置文档一致；错误码以代码注册表与
  [guide/troubleshooting.md](guide/troubleshooting.md) 为准；权限键以
  [guide/applications-and-permissions.md](guide/applications-and-permissions.md) 为准；三者由
  `scripts/verify-docs` 静态核对。
- 开发协作材料（`.ai/`、步骤提示词、内部报告）不属于产品文档，不进入发布包。

## 4. 维护约定

- 新增/调整公开 Go API、HTTP 路由、CLI 参数、权限键、错误码或配置字段时，同步更新对应
  guide/embedding 文档与（步骤 245 之后的）`docs/reference/` 条目；不允许只改代码不写文档。
- 历史验收记录（`docs/acceptance/`）保留当时的时间、版本与结果，只修正不可达引用，不改写
  历史测试事实。
- 文档链接与代码计数由 `go run ./scripts/verify-docs` 与文档链接检查共同校验；提交前运行。

## 5. 相关入口

- 项目根说明与许可：[../README.md](../README.md)、[../LICENSE](../LICENSE)
- 可运行示例：[../examples/](../examples/)
- 一键自检（短测试统一入口）：[acceptance/shorttest.md](acceptance/shorttest.md)
- 能力矩阵（机器可读）：[acceptance/capability-matrix.json](acceptance/capability-matrix.json) /
  [acceptance/capability-matrix.md](acceptance/capability-matrix.md)
