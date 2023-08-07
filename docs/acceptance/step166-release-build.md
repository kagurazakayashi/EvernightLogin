# 最终发布验收记录（步骤 166）

- 执行者：小肥鱼；环境：Windows 11 amd64、Go 1.27.1、`CGO_ENABLED=0`、`GOMAXPROCS=2`。
- 基线：**干净基线**，源码树 **`b9c668f…`**（最终提交使用该树；发布产物由该树构建并 verify 183/0）；未含 dirty 工作树候选。
- 结论：**发布构建与包校验 PASS**：六目标全部构建成功，`verify-release.ps1` 完整运行 **183 checks / 0 failures**；LICENSE/署名/包内容/Windows 冒烟通过。此结论不表示全部产品需求已验收，未测项见第 5 节。

## 1. 六目标构建

- 目标：`windows/amd64`、`windows/arm64`、`linux/amd64`、`linux/arm64`、`darwin/amd64`、`darwin/arm64`，全部 `code=built`，无失败/空占位。
- 构建记录（`build-matrix.txt`）：`version=0.1.0-dev`、`worktree_dirty=no`、Go 1.27.1、CGO=0、GOMAXPROCS=2。
- 每个发布包含：`bin/login-server`、`bin/loginctl`、`bin/login-backup`、`VERSION.txt`、`BUILDINFO.txt`、`DEPENDENCIES.txt`、`README.txt`、`LICENSE`、`config/`、`deploy/`、`docs/deployment/`、`docs/licenses/`。

## 2. 发布包校验

`verify-release.ps1` 完整执行（含 Windows amd64 冒烟）：

- **Checks run: 183 / failures: 0 / VERIFY: PASS**。
- 覆盖：6 包 SHA-256、包内容/禁止路径、内层清单、私钥块扫描、逐包 LICENSE 与 MulanPSL2/无年份署名检查、Windows amd64 三二进制 version/help/无参数退出码、示例配置真实加载与秘密扫描。
- Windows 冒烟：`login-server`/`loginctl`/`login-backup` 版本与帮助正常；`login-server` 无参数返回 1 并给出诚实提示；示例配置加载通过。
- 包内容复核（windows/amd64）：**118 文件**；根 `LICENSE` 首部为 `EvernightLogin`、`Copyright (c) KagurazakaYashi(KagurazakaMiyabi)`（不附年份）；无 AI 文件、数据库、私钥块。

## 3. 产物与 SHA256SUMS

产物目录：`P:/go/tmp/release-166-final-clean/`（仓库外）；顶层 `SHA256SUMS.txt` 六行：

| 目标 | SHA-256 |
|---|---|
| windows/amd64 | `f7a42565a5d79489f7124d1c24941685cfdd79d627cdad514379cf07a59e181f` |
| windows/arm64 | `96aea0b7faf3718f4a09225125e2e8bb2e7effa375d49387ae343b73858c4a63` |
| linux/amd64 | `66f88ccb6fbfa827acd3b3c270ff651291aa16eb36aa4f47922d4458c686904d` |
| linux/arm64 | `f25f2293d47011178fdc61ec948e4878409e1c2136515d1210c364b77659ae77` |
| darwin/amd64 | `3d298ac953360fcf7729366baf6790ef5dac946b09e6ebf6c2200095db209969` |
| darwin/arm64 | `a98d441f9d8305294ddbfd3506141961cfa6cd582f8fda22bbe01b873c54f83e` |

校验方法：在产物目录执行 `verify-release.ps1 -ReleaseDir P:/go/tmp/release-166-final-clean -ExpectedVersion 0.1.0-dev`；或逐文件核对 `SHA256SUMS.txt`。

## 4. 许可与包内容

- 项目许可证：MulanPSL2（木兰宽松许可证第 2 版）标准正文；项目署名 `Copyright (c) KagurazakaYashi(KagurazakaMiyabi)`，不附年份。
- 6 个包均含根 `LICENSE`，逐包通过 MulanPSL2 与署名检查；第三方组件/字体许可在 `docs/licenses/THIRD_PARTY_NOTICES.md` 与 `docs/licenses/deps/`，保留原版权/年份。
- 发布包不包含 `.ai/`、开发交接、测试数据库、运行日志、测试密钥或私钥。

## 5. 未测/未覆盖

1. 仅 Windows amd64 做运行冒烟；linux/darwin/Windows arm64 目标只做交叉编译与包内容校验，未在对应 OS 运行（项目约定）。
2. 真实浏览器/读屏/硬件认证器、真实第三方 OAuth/OIDC 客户端、手机扫码未做完整互操作验收。
3. 159 的 TOTP 解除/最后因素保护 SKIP；160 的 OIDC UserInfo audience、loginte2e 直接连接、slow_down/expired；161 的 app-admin 应用范围页/管理员 revoke/logout；163 的报告五格式生成/下载等精确缺口保留。
4. `govulncheck`/`gosec`/`-race`、真实外部 SMTP/反向代理/mTLS、GB 级数据库/ENOSPC/跨机恢复未执行或未测。
5. 本记录只证明**构建/发布包/许可/Windows 冒烟**通过，不签发“全部需求 PASS”；完整需求状态见 `requirements-matrix-login.md`。
