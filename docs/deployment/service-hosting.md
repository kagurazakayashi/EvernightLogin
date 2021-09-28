# 服务托管（Windows 服务 / systemd / launchd）

本文给出把 login 进程交给操作系统托管的样例与注意事项。样例文件在 `samples/`：

- Windows：`samples/winsw-evernight-login.xml`、`samples/install-windows-service.ps1`
- Linux：`samples/evernight-login.service`
- macOS：`samples/com.example.evernight-login.plist`

## 1. 当前状态（重要）

- `cmd/login-server` 当前只实现 `--version`/`--help`，不带参数**立即以非零退出**，
  不会常驻监听。用它注册服务会表现为“服务启动失败/反复退出”，这是**诚实的行为**，
  不是配置错误。
- 因此托管样例有两个用途：
  1. 预置服务管理器配置与权限模型，待独立服务 HTTP 装配完成后直接复用；
  2. 托管本地工具任务（例如定时 `login-backup create`），这类命令是真实可用的。
- 不要用“自动重启+假健康检查”掩盖服务未实现的事实；在装配完成前不要把服务标记为
  生产可用。

## 2. Windows 服务

推荐 WinSW（或 NSSM）包装，避免把进程参数直接写进 `sc.exe` 后难以维护。

- 服务账号：使用专用本地账号或虚拟账号，拥有 `data/`、`logs/` 的读写权限与
  `secrets/`、`config/` 的只读权限；不要用 LocalSystem 长期运行 Web 服务。
- 工作目录必须显式设置（相对路径配置依赖工作目录）。
- 秘密通过受限 ACL 的文件或机器级环境变量注入；不要把秘密写进服务描述或命令行。
- 失败恢复：配置为“失败后重启（有次数上限）”，避免无限快速重启。
- 日志：标准输出/错误重定向到 `logs/` 并由统一轮转清理；不要把含敏感信息的日志
  放进共享目录。
- 安装/卸载命令（管理员 PowerShell）：

```powershell
# 以管理员身份运行
pwsh -File .\samples\install-windows-service.ps1 `
  -ServiceExe "C:\apps\evernight-login\bin\winsw.exe" `
  -WorkingDirectory "C:\apps\evernight-login"
```

参见 `samples/winsw-evernight-login.xml`。注册前先用交互方式运行一次二进制确认
`--version` 与退出码符合预期。

## 3. systemd

样例 `samples/evernight-login.service` 的关键加固项：

- `User=`/`Group=` 专用账号；
- `EnvironmentFile=` 只放非秘密配置，秘密用 `LoadCredential=`/受限文件；
- `NoNewPrivileges=true`、`PrivateTmp=true`、`ProtectSystem=strict`、
  `ProtectHome=true`、`ReadWritePaths=` 只列数据/日志/备份目录；
- `Restart=on-failure` 且 `RestartSec` 避免快速重启循环；
- `TimeoutStopSec` 与配置里的 `server.shutdown_timeout_seconds` 对齐；
- `LimitNOFILE`、内存/任务上限按容量设置，不做无限放宽。

安装：

```bash
sudo install -m 0644 samples/evernight-login.service /etc/systemd/system/evernight-login.service
sudo systemctl daemon-reload
sudo systemctl enable --now evernight-login.service
journalctl -u evernight-login.service -f
```

## 4. macOS launchd

样例 `samples/com.example.evernight-login.plist`：

- `UserName` 使用专用用户；
- `WorkingDirectory` 显式设置；
- `StandardOutPath`/`StandardErrorPath` 指向受控日志目录；
- `KeepAlive` 只在服务装配完成后启用，否则会反复拉起立即退出的进程。

安装到 `~/Library/LaunchAgents`（当前用户）或 `/Library/LaunchDaemons`（系统级，需 root）。

## 5. 定时任务（当前真实可用）

备份创建等本地工具适合用计划任务调用，例如：

```powershell
# Windows 计划任务示例（管理员）：每天 03:00 创建加密热备份
$action = New-ScheduledTaskAction -Execute "C:\apps\evernight-login\bin\login-backup.exe" `
  -Argument 'create --database "C:\apps\evernight-login\data\login.db" --key-file "C:\apps\evernight-login\secrets\master.key" --output "C:\apps\evernight-login\backups" --operator "scheduler" --config "C:\apps\evernight-login\config\login.yaml"' `
  -WorkingDirectory "C:\apps\evernight-login"
```

```bash
# Linux cron 示例：03:00 备份；保留策略按实际容量设置
0 3 * * *  /opt/evernight-login/bin/login-backup create --database /var/lib/evernight-login/login.db \
  --key-file /etc/evernight-login/master.key --output /var/backups/evernight-login \
  --operator cron --config /etc/evernight-login/login.yaml
```

注意：`login-backup create` 需要数据库已迁移、密钥文件可读、输出目录已存在且主密钥文件
**不能**放在备份输出目录内。备份创建会写安全审计；失败时按退出码区分错误类型
（0 成功、1 执行失败、2 参数错误、3 校验失败、4 解密失败等，以 `login-backup help` 为准）。

## 6. 日志与清理

- 访问日志由宿主注入的 `AccessLogWriter` 决定；独立服务装配后必须接入受控轮转，不能
  依赖容器/服务管理器无限保存。
- 不要把日志、备份、数据库放在同一目录；不要用“清空数据库”解决日志问题。
- 服务停止/重启、维护模式、恢复操作都要记录真实操作者与时间；日志不是安全审计的替代。

## 7. 已知限制

- 服务单元/Windows 服务样例**未在真实服务管理器上验收**；当前二进制不提供 HTTP 服务，
  注册后会立即退出（预期行为）。
- 未实现进程守护、双机主备、自动故障切换；SQLite 单实例部署。
- 没有“服务运行中禁止 CLI 应急操作”的进程锁装配：`loginctl root-recover` 等命令要求
  操作者确认停服/维护并取得排他锁，详见相关命令帮助。
