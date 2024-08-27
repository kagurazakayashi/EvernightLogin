# EvernightMail 固定版本源码闭包与交付归档（步骤 249）

本文记录 EvernightLogin 父仓库所固定的子模块版本在**远端取不到**时的可复现获取方案：
用本地 Git 对象生成交付归档（git bundle），并新增一个源码闭包检查脚本，在全新临时目录里
按「bundle -> 本地对象 -> 远端」顺序重建固定的父版本与固定 Mail 版本，记录实际对象 ID、
失败分类和机器可读清单。

- 固定对象：EvernightMail **`aa7ccf57f6c0a8bb000a7dff6f101983ed6219fa`**（父仓库 gitlink）
- 交付归档：`dist/release/EvernightMail-aa7ccf5.bundle`
  （`dist/` 被 `.gitignore` 忽略，**归档本身不入 Git**，需要随发布渠道单独交付）
- 检查脚本：`scripts/mail-source-closure.ps1`
- 场景自检：`scripts/mail-source-closure-selftest.ps1`
- 机器可读清单：`dist/release/mail-source-closure.json`（由脚本生成）

> 本文数字与提交均为 **2026-11-26 01:00 前后（Asia/Shanghai）本机实测**；后续步骤可能改变
> 父仓库 HEAD，届时以新的 gitlink 与重新生成/校验的归档为准。

## 1. 问题与结论

父仓库固定提交 `b2289c8` 的 `EvernightMail` gitlink 指向 `aa7ccf5`，而该提交只在本地
Mail 仓库存在（本地 `main` 领先 `origin/main` 3 个提交）；远端 `origin/main` 仍是
`b9891ac`，既不包含 `aa7ccf5`，GitHub 也拒绝按 SHA 取不可达对象：

```text
$ git ls-remote https://github.com/kagurazakayashi/EvernightMail.git   # 经代理 127.0.0.1:23333
b9891ac569c7f5a0530ac74b73dfe8d5a9441b6e        HEAD
b9891ac569c7f5a0530ac74b73dfe8d5a9441b6e        refs/heads/main

$ git fetch https://github.com/kagurazakayashi/EvernightMail.git aa7ccf57f6c0a8bb000a7dff6f101983ed6219fa
fatal: remote error: upload-pack: not our ref aa7ccf57f6c0a8bb000a7dff6f101983ed6219fa
```

因此**父仓库的新克隆无法执行 `git submodule update --init`**：父仓库指针指向的对象在
Mail 远端不可得。用户本轮未授权 push 远端历史，本步不能替用户推送，故采用「交付归档 +
闭包检查」的方案：归档让固定版本可以从仓库之外取得，脚本让「固定父版本 + 固定子模块」的
闭包可被反复校验。**没有把父指针改回旧 Mail**，也没有覆盖/推送远端。

## 2. 固定版本的实际对象 ID（实测）

| 项目 | 值 |
|---|---|
| 父仓库提交 | `b2289c8105242b4215e643d7a9093717fb7748ed`（`生成本轮发布包与验收证据`，2024-08-26T20:04:37+08:00） |
| 父仓库 tree | `7e6805ff887ad4c5929b6801c58c7f531aaf79ab` |
| 父仓库 `origin/main` | `b2289c8…`（与 HEAD 一致） |
| gitlink 模式/路径 | `160000` / `EvernightMail` |
| Mail 固定提交 | `aa7ccf57f6c0a8bb000a7dff6f101983ed6219fa`（`补齐 EvernightMail 管理操作和 AI 使用覆盖`，2024-08-16T20:51:50+08:00） |
| Mail tree | `7a446ac1d7b7aaa702bd151632fd7f66a3448287` |
| Mail 分支/提交总数 | `main` / 50 |
| Mail 工作树 | 干净（`git status --porcelain` 0 行） |
| Mail `origin/main` | `b9891ac569c7f5a0530ac74b73dfe8d5a9441b6e`（本地 `main` 领先 3） |
| Mail 远端 URL | `git@github.com:kagurazakayashi/EvernightMail.git`（`.gitmodules` 的 `branch = main`） |

本步要固定并验证的三个 Mail 提交（对象 ID 必须与父 gitlink 一致，不能用旧 main 冒充）：

| 步骤 | 提交 | 提交信息 | 文件/行变更 |
|---|---|---|---|
| 219 | `d4479f7c462119aa484c4efcb1168a32585c6498` | 统一 EvernightMail 文件列表与管理分页 | 44 文件 +3787/−375 |
| 237 | `77aeb93174af118614ead95102e81e48cd04175a` | 补齐 EvernightMail 证书导入的 API 和 CLI | 20 文件 +1989/−85 |
| 238 | `aa7ccf57f6c0a8bb000a7dff6f101983ed6219fa` | 补齐 EvernightMail 管理操作和 AI 使用覆盖 | 20 文件 +1496/−140 |

## 3. 交付归档（git bundle）

生成（只读 Mail 仓库，不写其工作树/历史）：

```powershell
git -C EvernightMail bundle create dist\release\EvernightMail-aa7ccf5.bundle HEAD refs/heads/main
```

必须同时带上 `HEAD` 与 `refs/heads/main`：只写 `refs/heads/main` 时 bundle 没有 HEAD，
`git clone` 会得到「remote HEAD refers to nonexistent ref」的空工作树（本步实测踩过）。

| 字段 | 值 |
|---|---|
| 文件 | `dist/release/EvernightMail-aa7ccf5.bundle`（`.gitignore` 忽略，不入 Git） |
| 大小 | 1,597,571 字节 |
| SHA-256 | `43e0e0039dd631a6428f9a26b48289c54348b88a72ae195b3e9b615bc7ac35e5` |
| 内容 ref | `aa7ccf5… HEAD`（完整历史）与 `aa7ccf5… refs/heads/main` |
| Git 版本 | git 2.55.0（MSYS2） |

独立校验命令与预期结果（均为本步实测）：

```powershell
# 1) bundle 自身校验（verify 必须在一个 git 仓库内执行，否则报 need a repository）
git -C . bundle verify dist\release\EvernightMail-aa7ccf5.bundle
# -> The bundle contains these 2 refs / records a complete history / ... is okay

# 2) 全新克隆校验 HEAD、分支与干净状态
git clone --no-hardlinks dist\release\EvernightMail-aa7ccf5.bundle P:\go\tmp\mail-bundle-check
git -C P:\go\tmp\mail-bundle-check rev-parse HEAD          # aa7ccf57f6c0a8bb000a7dff6f101983ed6219fa
git -C P:\go\tmp\mail-bundle-check rev-parse --abbrev-ref HEAD   # main
git -C P:\go\tmp\mail-bundle-check status --porcelain      # 空

# 3) 归档完整性（防传输损坏）
Get-FileHash dist\release\EvernightMail-aa7ccf5.bundle -Algorithm SHA256
# -> 43e0e0039dd631a6428f9a26b48289c54348b88a72ae195b3e9b615bc7ac35e5
```

## 4. 隔离独立构建与 219/237/238 改动核验

从**归档克隆**（不是开发工作树）执行，证明固定版本自带可构建源码：

```powershell
$env:GOTOOLCHAIN='local'; $env:CGO_ENABLED='0'; $env:GOMAXPROCS='2'; $env:GOFLAGS='-mod=readonly'
cd <bundle 克隆目录>
go build ./...            # PASS 9.0s
go vet ./...              # PASS 3.5s
go build -trimpath -buildvcs=false -o ..\evernightmail.exe ./cmd/evernightmail
.\evernightmail.exe version   # EvernightMail 0.1.0-dev / module github.com/kagurazakayashi/EvernightMail
go test -count=1 -p=1 -timeout 300s ./internal/adminapi/ ./internal/certimport/ ./internal/config/ `
    ./internal/users/ ./internal/logging/ ./internal/errs/ ./cmd/evernightmail/
# -> 7 个包全部 ok
```

| 步骤 | 定向测试（归档版本上真实执行，全部 PASS） |
|---|---|
| 219 | `TestPage*` 9/9：用户游标/邮件同时间/范围与文件增长/授权先于分页/投递/流水/快照/运行列表/非法游标拒绝 |
| 237 | `internal/certimport` 4/4（PEM 成功与替换、PFX 与错误口令、密钥不匹配/过期/SAN 拒绝、坏输入拒绝）+ CLI TLS 导入 5/5（含拒绝 argv 明文口令） |
| 238 | `TestStep238*` 6/6（二进制输出与版本、原子写与文件上限、配置保存遮盖秘密、部分失败、配置保存检查、用户导入） |

隔离构建产物只写入临时目录并在结束时删除，未写入 Mail 工作树；`-trimpath` 与
`-buildvcs=false` 保证结果不依赖工作树路径。二进制 SHA-256：
`1b818aab9f77c2c905e889c4d91e5a1671048bbf99e3a9360730d26923a62cbd`（22,205,440 字节，
本次时点；不同 Go 补丁版本可能不同，只作为本次证据，不做跨机器恒定约束）。

## 5. 源码闭包检查脚本

### 5.1 用法

```powershell
# 默认：核对父仓库 HEAD 的 gitlink，优先用 dist/release 下的 bundle，在全新临时目录重建并清理
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\mail-source-closure.ps1

# 附隔离构建；指定临时目录与清单路径（P:/go/tmp/... 为本项目临时目录约定）
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\mail-source-closure.ps1 -Build `
    -WorkRoot P:\go\tmp\r11-249-closure -ManifestOut dist\release\mail-source-closure.json

# 只用本地 Mail 仓库对象（离线复核）
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\mail-source-closure.ps1 -Source local

# 只用交付归档（发布交付场景，最严格）
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\mail-source-closure.ps1 -Source bundle

# 允许访问远端（显式开关 + 代理；远端失败会按类别诊断而不是静默回退）
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\mail-source-closure.ps1 `
    -Source remote -AllowRemote -RemoteUrl https://github.com/kagurazakayashi/EvernightMail.git `
    -Proxy http://127.0.0.1:23333

# 失败分类自检（不访问仓库/网络）
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\mail-source-closure.ps1 -SelfTest
```

关键参数：`-ParentRepo`（默认脚本上一级）、`-ParentCommit`（默认 HEAD）、
`-Source auto|bundle|local|remote`、`-Bundle`、`-MailRepo`、`-RemoteUrl`、`-AllowRemote`、
`-Proxy`、`-WorkRoot`、`-ManifestOut`、`-Build`、`-FullParentCheckout`、`-Keep`、`-TimeoutSec`。
脚本对任何网络操作设置超时并禁用交互式口令提示；不会修改父仓库/Mail 工作树，也不会执行
`git add/commit/push`、子模块 init/update 或远端写操作。

### 5.2 检查流程

1. 解析父仓库固定提交；从**固定提交**（`git show <sha>:.gitmodules`、`git ls-tree <sha>`）读取
   URL 与 gitlink，避免工作树脏状态混入。
2. 在全新临时目录 `git init` + 只抓取固定提交（浅抓取，失败再退回完整抓取/HEAD 浅抓取），
   核对父固定提交对象、tree、gitlink 与 `.gitmodules` 的一致性（默认只检出 `.gitmodules`；
   `-FullParentCheckout` 才重建完整源码树——本机磁盘上完整 clone 需约 3 分钟，故默认不做）。
3. 按 **bundle -> 本地对象 -> 远端（需 `-AllowRemote`）** 顺序把固定 Mail 版本物化到
   临时副本的 `EvernightMail/`，核对 HEAD 与固定值一致、tree/提交数、工作树干净。
4. 可选 `-Build`：在隔离副本执行 `go build ./...` 与 `go build ./cmd/evernightmail`，
   运行 `version`，并发上限取 `floor(逻辑处理器/2)`，全部带超时。
5. 输出机器可读清单（默认 `dist/release/mail-source-closure.json`）：父提交/tree、gitlink、
   来源（bundle SHA-256/大小/refs）、实际 HEAD/tree/提交数/干净状态、构建结果、诊断列表、
   最终 `result` 与 `exit_code`。临时目录默认删除，`-Keep` 保留排查。

### 5.3 诊断码与退出码

| 诊断码 | 含义 | 退出码 |
|---|---|---|
| `PIN-MISSING` | 父固定提交没有把 `EvernightMail` 记为 `160000` gitlink | 2 |
| `PIN-MISMATCH` | 固定引用无法解析/不是提交对象 | 2 |
| `URL-MISMATCH` | `.gitmodules` 中 `EvernightMail` 地址不符合预期（默认 `github.com…/kagurazakayashi/EvernightMail`） | 3 |
| `BUNDLE-NOT-FOUND` | 指定/自动发现的交付归档不存在 | 4 |
| `BUNDLE-CORRUPT` | `git bundle verify` 失败（损坏/不是 bundle） | 4 |
| `BUNDLE-PIN-MISSING` | 归档有效但不包含固定提交（旧版本冒充） | 4 |
| `LOCAL-OBJECT-MISSING` | 本地 Mail 仓库缺少固定提交对象或不可用 | 5 |
| `REMOTE-AUTH-FAILED` | 远端认证失败（publickey/401/无凭据） | 6 |
| `REMOTE-OBJECT-MISSING` | 远端不提供固定对象（`not our ref`/未广告） | 7 |
| `REMOTE-URL-INVALID` | 仓库地址无效/不存在（404、非仓库目录） | 3 |
| `REMOTE-NETWORK-FAILED` | 网络不可达/超时/连接被拒 | 8 |
| `REMOTE-NOT-ALLOWED` / `SOURCE-UNAVAILABLE` | 需要远端但未显式允许；三种来源都不可用 | 8 |
| `CHECKOUT-MISMATCH` | 隔离副本 HEAD 或干净状态与固定值不符 | 9 |
| `BUILD-FAILED` | 隔离副本构建失败 | 10 |
| `WORKROOT-EXISTS` / `PARENT-*` | 临时目录已存在；父仓库取不到/不是仓库 | 1 |

成功返回 0。失败时**不会**回退成「旧 main 也算通过」：`auto` 模式下非显式候选失败记
warning 并继续回退，显式 `-Bundle`/`-Source bundle|local|remote` 失败直接失败；最终结果
与清单 `diagnostics` 一致。

### 5.4 场景自检（可重复执行）

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\mail-source-closure-selftest.ps1 `
    -IncludeNetwork -Proxy http://127.0.0.1:23333 -WorkRoot P:\go\tmp\r11-249-selftest
```

本步实测 12/12 PASS（其中 1 个分类自检共 9 个样例）：

| 场景 | 期望 |
|---|---|
| classification | 9/9 失败文本分类（含真实采集的 `not our ref` 文本） |
| success-bundle | 真实父仓库 + bundle + 隔离构建通过，清单 `gitlink=checkout=aa7ccf5` |
| local-object-missing | 合成父仓库指针指向不存在对象 -> exit 5 + `LOCAL-OBJECT-MISSING` |
| url-mismatch | `.gitmodules` 指向其他仓库 -> exit 3 + `URL-MISMATCH` |
| bundle-corrupt | 显式归档不是 bundle -> exit 4 + `BUNDLE-CORRUPT` |
| bundle-pin-missing | 用旧 `origin/main` 生成的归档 -> exit 4 + `BUNDLE-PIN-MISSING` |
| workroot-exists | 拒绝复用已存在临时目录 -> exit 1 + `WORKROOT-EXISTS` |
| remote-auth-failed | 回环假 git HTTP 服务 401 -> exit 6 + `REMOTE-AUTH-FAILED` |
| remote-url-invalid | 回环假 git HTTP 服务 404 -> exit 3 + `REMOTE-URL-INVALID` |
| remote-network-failed | 回环未监听端口 -> exit 8 + `REMOTE-NETWORK-FAILED` |
| remote-object-missing | 真实 GitHub 远端拒绝不可达 SHA -> exit 7 + `REMOTE-OBJECT-MISSING` |

自检只在一次性临时目录内创建合成父仓库（`git fast-import`）、假服务与旧版本 bundle，
结束时删除并停止所有子进程；不写父仓库/Mail 仓库工作树与历史。

## 6. 当前边界、未测项与用户后续动作

已实测：Windows 10 19045 + git 2.55.0 + PowerShell 5.1/7；bundle 生成/verify/克隆；
归档版本独立构建与 219/237/238 定向测试；闭包脚本成功与 12 类失败边界。

未测/未做：

- **未 push 任何远端历史**（用户未授权）：Mail 远端仍是 `b9891ac`，父仓库远端
  （`b2289c8`）因此引用一个远端不可得的子模块对象——这是当前可复现性缺口的根因。
- 交付归档在 `dist/release/`（被 `.gitignore` 忽略），**不随 Git 传递**；需要交付时由
  维护者复制到仓库之外的渠道（网盘/制品库/发布附件），并一并提供 SHA-256。
- Linux/macOS 与其他 PowerShell 版本未实测（脚本声明兼容 5.1/7，本次两种都跑过语法与
  分类自检；完整闭包场景只在 PowerShell 5.1 下执行）。
- 父仓库 `-FullParentCheckout` 未在本次执行（本机慢盘完整检出约需 3 分钟，默认路径已用
  「固定对象 + `.gitmodules`」证实父版本可重建）。
- GitHub 可达性依赖代理 `http://127.0.0.1:23333`；直连/其他镜像未验证。

用户后续动作（需要用户授权或执行）：

1. 授权后在 `EvernightMail` 执行 `git push origin main`，使远端包含
   `d4479f7`/`77aeb93`/`aa7ccf5`；推送后父仓库的新克隆才能 `submodule update --init`。
2. 若暂不推送，把 `dist/release/EvernightMail-aa7ccf5.bundle`、
   `EvernightMail-aa7ccf5.manifest.json` 与本文记录的 SHA-256 一起放到发布渠道，并在交付
   说明中写清「固定版本只能从该归档取得」。
3. 若改用其他 Mail 版本，必须同时更新父仓库 gitlink 并重新生成归档；**不得**把父指针改回
   缺少 219/237/238 功能的 `b9891ac`。

步骤 264（复核并补齐 EvernightMail 安全搜索入口）依赖本步固定的 Mail 源码：可从上述
bundle 克隆到固定 `aa7ccf5` 后再实施，不必依赖远端对象。
