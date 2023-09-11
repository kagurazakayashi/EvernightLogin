# 步骤 202 发布包验收（正式产物，文档/help 修正后重建）

- 状态：**PASS**（正式发布包已生成于干净 HEAD）
- 最终提交：EvernightLogin `3586a52a2d92afbefe962ddbb5e565df82302caa`「完成一键构建发布包与最终验收汇总」（amend 含 F1 introspection 文案/F2 配置字段 52 修正 + 202 脚本/文档）
- 子模块：EvernightMail `b9891ac569c7f5a0530ac74b73dfe8d5a9441b6e`；go-build-all `8764de6504db1ecd1ecc5c3d4dd6618b51699cf1`
- 产物目录：`dist/release/evernight-0.1.0-dev/`（`dist/` 已被 `.gitignore` 忽略，保留在磁盘供交付/审计校验）
- 生成环境：Windows 11 + Go 1.27.4；Windows PowerShell 5.1；`GOMAXPROCS=2`；版本 `0.1.0-dev`
- 重建原因：收尾审计发现 introspection help 文案与配置字段计数文档错误；中肥鱼助手仅修正文档/help 后由 Lead amend，本包为修正后重建。
- 说明：构建前工作树仅步骤提示词 untracked，构建期间临时移出仓库，构建后恢复；`build-summary` 记录 dirty=no。

## 1. 构建入口（PASS）

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\build.ps1 -Version 0.1.0-dev
```

- 退出码 **0**；`verify-build: manifests=32 ok, artifacts=24/24 ok, warnings=0 -> exit 0`。
- `build-summary.json` 关键字段：

| 字段 | 实测值 |
|---|---|
| format / exit_code / stage | 1 / 0 / completed |
| version / build_time | 0.1.0-dev / 2026-11-22T22:31:48Z |
| totals | expected=24, verified=24, failed=0 |
| verification.exit_code | 0（manifest_checks 32/32 OK） |
| modules | Login `3586a52a…` dirty=**false**；Mail `b9891ac…` dirty=**false** |
| submodule_gitlinks | mail=`b9891ac…`，tool=`8764de6…` |
| tool | commit=`8764de6…`，sha256=`571d986db8263bb2f6abab2eff5c3530e7018811e0ab751016bafd9fe2ea8cdd` |
| go | 1.27.4，CGO_ENABLED=0，GOTOOLCHAIN=local，GOWORK=off，GOFLAGS=-mod=readonly |
| warnings | []（无 dirty/gitlink 警告） |
| checklist | 24 项，全部 status=OK |
| invocations | login exit 0 / 31913ms；mail exit 0 / 8506ms |

`trimpath`/`buildvcs=false`/`ldflags=-s -w` 由构建命令、manifest 与 build-summary 记录并校验。

## 2. 打包与校验（PASS）

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\package-release.ps1 -Version 0.1.0-dev
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\verify-release.ps1 `
  -ReleaseDir .\dist\release\evernight-0.1.0-dev `
  -BuildSummary .\dist\build\build-summary.json -ExpectedVersion 0.1.0-dev
```

- package **exit 0**：12 zip + 顶层 `SHA256SUMS.txt`/`build-matrix.txt`/`release-summary.json`/`RELEASE-NOTES.md`。
- verify **exit 0**：顶层/包内 SHA256SUMS、文件集合、禁止项、许可/元数据、PE/ELF/Mach-O 类型与架构、
  size+sha 对照 build-summary、`build-matrix` 一致性、Windows/amd64 四命令短冒烟全部通过。
- 四命令冒烟补充证据：解压正式包后运行 `bin/login-server.exe --help`，输出包含修正后的新文案
  `已实现但默认关闭：设备码与扫码登录…、令牌状态查询（introspection，145/160 验收边界；mTLS/故障等未实测）`，
  exit 0；不再出现“introspection 未交付”。
- 包内容来源（真实路径）：Login 为 `bin/3 命令 + LICENSE + README.md + THIRD_PARTY_NOTICES.txt +
  docs/deployment/samples/*（9 个样例） + README-PACKAGE.txt/VERSION/BUILDINFO/DEPENDENCIES/SHA256SUMS`；
  Mail 为 `bin/evernightmail + LICENSE + README.md + evernightmail.example.yaml +
  docs/{README,config-reference,cli-reference,protocol-matrix,offline-security}.md + 元数据`。
- 12 zip 合计 **187,420,139 bytes（178.74 MiB）**；顶层 16 文件合计 **187,442,180 bytes**。

## 3. 12 个正式 zip（重建后，大小/SHA256）

| zip | size | sha256 |
|---|---:|---|
| evernight-login-0.1.0-dev-darwin-amd64.zip | 26403327 | 2277601360a0f02d1c9a6eafc2b91ea7c379e8a1982a0d2cb7b09e2ee68a0f14 |
| evernight-login-0.1.0-dev-darwin-arm64.zip | 24604282 | 5c3dcd29326a7bdd574468bd0ba0821a5f583712a009fd63f8229bce55ed3c01 |
| evernight-login-0.1.0-dev-linux-amd64.zip | 26255483 | f7593a62828878ea40e0bddf05d512a83d99ffdcaf43bc8fc3a850bc83f4a347 |
| evernight-login-0.1.0-dev-linux-arm64.zip | 23945867 | 70b44ff7aaad74296e3fb82f305a442fbcfb385e5f3b65d6f853c56aedfa466a |
| evernight-login-0.1.0-dev-windows-amd64.zip | 26477468 | c027e460380283b464ef913b3c26045b6ec98a02806b777f5704ceb182dac518 |
| evernight-login-0.1.0-dev-windows-arm64.zip | 23952765 | 033c2fe43177be5adaaa1540513045896137a800f2c56d41f8e665c4ba35e7c2 |
| evernightmail-0.1.0-dev-darwin-amd64.zip | 6261334 | 5047d9e51c770c89623082ecc2b3ffcc4815443437ac055a076de241ccc17446 |
| evernightmail-0.1.0-dev-darwin-arm64.zip | 5802707 | 5b13d6352701c9cf1baf289f6cf5edbbe48f03196670364b50d2e3bd111ec159 |
| evernightmail-0.1.0-dev-linux-amd64.zip | 6160819 | 083ed61be6b94b973073a10c6bfbd90375bbff90f939c09022c32e613c8a7523 |
| evernightmail-0.1.0-dev-linux-arm64.zip | 5591643 | c5f63e85e7b95d9fec79b1ebe5fe46083274f4cbea71179f6414a726410bd42d |
| evernightmail-0.1.0-dev-windows-amd64.zip | 6298839 | f23aeeeaf83f257dac5fb230cd18f3306021f4b0f1f155cc776a95462043bd92 |
| evernightmail-0.1.0-dev-windows-arm64.zip | 5665605 | 95b407671938273be8ee1bc6fb242415ce2c915e90fe5172ec666eca4f944c05 |

顶层 `SHA256SUMS.txt`（GNU 格式、LF、字节序排序、不含自身）：

```text
2277601360a0f02d1c9a6eafc2b91ea7c379e8a1982a0d2cb7b09e2ee68a0f14  evernight-login-0.1.0-dev-darwin-amd64.zip
5c3dcd29326a7bdd574468bd0ba0821a5f583712a009fd63f8229bce55ed3c01  evernight-login-0.1.0-dev-darwin-arm64.zip
f7593a62828878ea40e0bddf05d512a83d99ffdcaf43bc8fc3a850bc83f4a347  evernight-login-0.1.0-dev-linux-amd64.zip
70b44ff7aaad74296e3fb82f305a442fbcfb385e5f3b65d6f853c56aedfa466a  evernight-login-0.1.0-dev-linux-arm64.zip
c027e460380283b464ef913b3c26045b6ec98a02806b777f5704ceb182dac518  evernight-login-0.1.0-dev-windows-amd64.zip
033c2fe43177be5adaaa1540513045896137a800f2c56d41f8e665c4ba35e7c2  evernight-login-0.1.0-dev-windows-arm64.zip
5047d9e51c770c89623082ecc2b3ffcc4815443437ac055a076de241ccc17446  evernightmail-0.1.0-dev-darwin-amd64.zip
5b13d6352701c9cf1baf289f6cf5edbbe48f03196670364b50d2e3bd111ec159  evernightmail-0.1.0-dev-darwin-arm64.zip
083ed61be6b94b973073a10c6bfbd90375bbff90f939c09022c32e613c8a7523  evernightmail-0.1.0-dev-linux-amd64.zip
c5f63e85e7b95d9fec79b1ebe5fe46083274f4cbea71179f6414a726410bd42d  evernightmail-0.1.0-dev-linux-arm64.zip
f23aeeeaf83f257dac5fb230cd18f3306021f4b0f1f155cc776a95462043bd92  evernightmail-0.1.0-dev-windows-amd64.zip
95b407671938273be8ee1bc6fb242415ce2c915e90fe5172ec666eca4f944c05  evernightmail-0.1.0-dev-windows-arm64.zip
```

`build-matrix.txt` 12 行全部 `status=OK`；`release-summary.json` format=1，记录 12 zip 与包内 24 个
二进制的 size/sha256。

## 4. 验证矩阵

| 项 | 结果 |
|---|---|
| build-summary 24/24、dirty=false、gitlinks/tool_sha 正确 | PASS |
| 12 zip、顶层文件集合/校验和/矩阵 | PASS |
| 包内 SHA256SUMS、禁止项、必需许可/元数据 | PASS |
| PE/ELF/Mach-O magic+架构、size/sha 对照 summary | PASS |
| Windows/amd64 四命令短冒烟 | PASS（login-server --help 含 introspection 新文案） |
| 其他五目标运行实测、PowerShell 7、发布上传/签名 | NOT_TESTED（不属本验收） |

## 5. 说明与限制

- 本文件数字来自**文档/help 修正后的正式产物**，生成于干净 HEAD `3586a52a2d92afbefe962ddbb5e565df82302caa`；
  产物保留在 `dist/release/evernight-0.1.0-dev/`，供交付与审计校验；本文件哈希更新由 Lead 最后 amend。
- 版本为 `0.1.0-dev`；zip 不保留 Unix 执行位（Linux/macOS 解压后需 `chmod +x bin/*`）。
- 仅 Windows/amd64 运行冒烟；其他五目标仅编译/类型/摘要检查，不宣称运行实测。
- 字体本体不随包；PDF 报告使用系统/外部字体。
- 198/200 验收证据以其各自文档为准，本文件不替代。
