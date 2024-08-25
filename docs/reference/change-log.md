# 公开接口变更记录

> 本文记录**公开契约**（公开 Go API、HTTP 路由/错误、CLI、权限键、配置字段）的兼容性变更。破坏性变更策略见 [../embedding/host_integration.md](../embedding/host_integration.md) 第 2 节。

完整历史变更记录仍保留在嵌入指南的“变更记录”小节；Phase B（245B，等 214/215/226–235 稳定）会把历史条目迁入本文件并停用旧小节，避免两处维护。在那之前以嵌入指南为准。

## 1. 记录规则

- 兼容性变更（新增可选字段/新方法/新错误码）与**破坏性变更**分开标注；破坏性变更必须给出迁移方式与替代接口。
- 错误码、权限键、HTTP 路由、CLI 命令与配置字段是稳定机器契约；新增属兼容，删除/改名/改变含义属破坏性变更。
- 数据迁移与公开契约变更分别记录；数据库迁移只向前、不清库，见 [../database/存储模型与迁移设计.md](../database/存储模型与迁移设计.md)。

## 2. 本轮记录（步骤 245A：接口参考首版）

- 新增人类与 AI 共用的 `docs/reference/`：由代码生成的 4 个机器 JSON（错误码/权限/HTTP 路由/CLI）与稳定领域 Markdown（错误码/权限/配置/HTTP/CLI/能力映射/Go API 框架/AI 入口）。
- `scripts/verify-docs` 接入 `-reference=auto|off|require`：`docs/reference` 存在时逐字节校验生成物；新增公开符号未登记映射、能力声明无法解析时 fail-closed。
- 新增 `examples/reference-snippets` 最小可编译示例，并被参考文档内嵌；文档内嵌代码与源码逐字一致由 `-check` 保证。
- 尚未包含**方法级** Go API 参考：Phase B 在 214/215 与 226–235 稳定后补齐，当前 [go-api.md](go-api.md) 提供生命周期/接口总览与稳定领域框架。

## 3. 相关文档

- 公开 API 稳定范围与破坏性变更策略：[../embedding/host_integration.md](../embedding/host_integration.md)
- 版本与验收记录：[../acceptance/README.md](../acceptance/README.md)
- 能力状态（是否已实现）：[../acceptance/capability-matrix.md](../acceptance/capability-matrix.md)
