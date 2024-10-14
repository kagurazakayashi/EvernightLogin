# run-app.ps1 - run 入口核心逻辑（run.ps1 / run.cmd / run.sh 共用）。
#
# 职责：按当前平台在 dist/build 中定位 build.ps1 生成的产物并前台启动；
# 不重新构建、不修改源码、不写仓库文件、不读取数据库内容。
#
# 参数：
#   -Program <name>  auto（默认）| login-server | login-setup | loginctl |
#                    login-backup | evernightmail
#   -Config <path>   配置路径；缺省时使用当前目录 login.yaml（存在时）
#   -Exe <path>      直接指定可执行文件，跳过产物查找
#   -OutputDir <dir> 产物根目录（默认 <repo>/dist/build）
#   -GoOS/-GoArch    覆盖目标平台（默认当前主机）
#   -List            列出当前平台可用产物后退出
#   -Help            显示本入口的使用说明
#   其余参数         原样传给被启动的程序；建议用 -- 分隔，例如：
#                    .\run.ps1 -Program login-server -- --help
#
# 退出码：0 程序正常退出；2 参数/产物错误；3 login-server 缺少配置；
#         其余为被启动程序自身的退出码。
#
# auto 规则：显式 -Config，或当前目录存在 login.yaml 时启动 login-server；
# 否则启动 login-setup（零配置可用的本地初始化/维护控制台）。
#
# 参数解析不依赖 PowerShell 的 param 绑定，而是直接读取 $args：这样无论
# run.ps1 用 & 调用，还是 run.cmd 通过 powershell -File 调用，程序自身的
# -flag 都不会被脚本参数绑定吞掉或报错。
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$Program = 'auto'
$Config = ''
$Exe = ''
$OutputDir = ''
$GoOS = ''
$GoArch = ''
$List = $false
$Help = $false
$ProgramArguments = New-Object 'System.Collections.Generic.List[string]'

# Split-OptionToken 把 -Name / --Name / -Name=value 拆成名称与值；非选项返回 $null。
function Split-OptionToken([string]$token) {
    $body = ''
    if ($token.StartsWith('--')) {
        $body = $token.Substring(2)
    } elseif ($token.StartsWith('-')) {
        $body = $token.Substring(1)
    } else {
        return $null
    }
    $separator = $body.IndexOf('=')
    if ($separator -ge 0) {
        return @{
            Name     = $body.Substring(0, $separator)
            Value    = $body.Substring($separator + 1)
            HasValue = $true
        }
    }
    return @{ Name = $body; Value = ''; HasValue = $false }
}

$valueOptions = @('program', 'config', 'exe', 'outputdir', 'goos', 'goarch')
$tokens = @($args)
$index = 0
while ($index -lt $tokens.Count) {
    $token = [string]$tokens[$index]
    if ($token -eq '--') {
        $index++
        while ($index -lt $tokens.Count) {
            [void]$ProgramArguments.Add([string]$tokens[$index])
            $index++
        }
        break
    }
    $option = Split-OptionToken $token
    if ($null -eq $option) {
        # 第一个位置参数：其后全部视为程序参数。
        while ($index -lt $tokens.Count) {
            [void]$ProgramArguments.Add([string]$tokens[$index])
            $index++
        }
        break
    }
    $name = $option.Name.ToLowerInvariant()
    if ($valueOptions -contains $name) {
        $value = ''
        if ($option.HasValue) {
            $value = $option.Value
            $index++
        } elseif ($index + 1 -lt $tokens.Count) {
            $value = [string]$tokens[$index + 1]
            $index += 2
        } else {
            Write-Host ("[run] 选项 {0} 缺少值" -f $token) -ForegroundColor Red
            exit 2
        }
        if ($name -eq 'program') { $Program = $value }
        elseif ($name -eq 'config') { $Config = $value }
        elseif ($name -eq 'exe') { $Exe = $value }
        elseif ($name -eq 'outputdir') { $OutputDir = $value }
        elseif ($name -eq 'goos') { $GoOS = $value }
        elseif ($name -eq 'goarch') { $GoArch = $value }
        continue
    }
    if ($name -eq 'list') {
        $List = $true
        $index++
        continue
    }
    if ($name -eq 'help') {
        $Help = $true
        $index++
        continue
    }
    # 帮助/版本开关常在未写 -- 时直接跟在 -Program 后；其余未知选项视为拼写
    # 错误，避免把脚本选项笔误静默传给被启动程序。
    if ($name -eq 'h' -or $name -eq 'version' -or $name -eq 'v' -or $name -eq '?') {
        while ($index -lt $tokens.Count) {
            [void]$ProgramArguments.Add([string]$tokens[$index])
            $index++
        }
        break
    }
    Write-Host ("[run] 未知选项：{0}（程序参数请放在 -- 之后）" -f $token) -ForegroundColor Red
    exit 2
}

$RepoRoot = Split-Path -Parent $PSScriptRoot

# 程序名到产物区域的映射：Login 四程序在 login/，Mail 在 mail/。
$ProgramTable = [ordered]@{
    'login-server'  = 'login'
    'login-setup'   = 'login'
    'loginctl'      = 'login'
    'login-backup'  = 'login'
    'evernightmail' = 'mail'
}

function Show-Usage {
    Write-Host @'
用法：run.ps1 [选项] [-- 程序参数...]

选项：
  -Program <name>   auto（默认）| login-server | login-setup | loginctl |
                    login-backup | evernightmail
  -Config <path>    配置路径；缺省使用当前目录 login.yaml（存在时）
  -Exe <path>       直接指定可执行文件，跳过产物查找
  -OutputDir <dir>  产物根目录（默认 dist/build）
  -GoOS / -GoArch   覆盖目标平台（默认当前主机）
  -List             列出当前平台可用产物
  -Help             显示本说明

示例：
  .\run.ps1                                   # 有 login.yaml 启动服务，否则进入 login-setup
  .\run.ps1 -Program login-server             # 启动独立服务（serve --config login.yaml）
  .\run.ps1 -Program login-setup              # 本地初始化/维护控制台
  .\run.ps1 -Program login-server -- --help   # -- 之后的参数原样传给程序
  .\run.ps1 -List                             # 查看当前平台产物

产物缺失时先运行 .\build.ps1。
'@
}

if ($Help) {
    Show-Usage
    exit 0
}

# 解析当前主机平台：优先 go env；缺少 Go 时退回 OS 环境变量/uname。
function Resolve-HostPlatform {
    $resolvedGoos = ''
    $resolvedGoarch = ''
    $goCommand = Get-Command go -ErrorAction SilentlyContinue
    if ($null -ne $goCommand) {
        try {
            $resolvedGoos = ((& $goCommand.Source env GOOS) | Select-Object -First 1)
            $resolvedGoarch = ((& $goCommand.Source env GOARCH) | Select-Object -First 1)
        } catch {
            $resolvedGoos = ''
            $resolvedGoarch = ''
        }
    }
    if (-not [string]::IsNullOrWhiteSpace($resolvedGoos)) {
        $resolvedGoos = $resolvedGoos.Trim()
    }
    if (-not [string]::IsNullOrWhiteSpace($resolvedGoarch)) {
        $resolvedGoarch = $resolvedGoarch.Trim()
    }
    if ([string]::IsNullOrWhiteSpace($resolvedGoos)) {
        if ($env:OS -eq 'Windows_NT') {
            $resolvedGoos = 'windows'
        } elseif (Test-Path -LiteralPath '/proc') {
            $resolvedGoos = 'linux'
        } else {
            $resolvedGoos = 'darwin'
        }
    }
    if ([string]::IsNullOrWhiteSpace($resolvedGoarch)) {
        $machine = ''
        if ($env:OS -eq 'Windows_NT') {
            $machine = [string]$env:PROCESSOR_ARCHITECTURE
        } else {
            $uname = Get-Command uname -ErrorAction SilentlyContinue
            if ($null -ne $uname) {
                $machine = ((& $uname.Source -m) | Select-Object -First 1)
            }
        }
        switch ($machine.ToLowerInvariant()) {
            'amd64' { $resolvedGoarch = 'amd64' }
            'x86_64' { $resolvedGoarch = 'amd64' }
            'arm64' { $resolvedGoarch = 'arm64' }
            'aarch64' { $resolvedGoarch = 'arm64' }
            'x86' { $resolvedGoarch = '386' }
            'i386' { $resolvedGoarch = '386' }
            'i686' { $resolvedGoarch = '386' }
            default { $resolvedGoarch = 'amd64' }
        }
    }
    return @{ GoOS = $resolvedGoos; GoArch = $resolvedGoarch }
}

$hostPlatform = Resolve-HostPlatform
$targetGoos = if ([string]::IsNullOrWhiteSpace($GoOS)) { $hostPlatform.GoOS } else { $GoOS.Trim() }
$targetGoarch = if ([string]::IsNullOrWhiteSpace($GoArch)) { $hostPlatform.GoArch } else { $GoArch.Trim() }

if ([string]::IsNullOrWhiteSpace($OutputDir)) {
    $OutputDir = Join-Path $RepoRoot 'dist\build'
} else {
    $OutputDir = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputDir)
}

# 在产物根目录中查找目标平台的最新可执行文件；同一版本目录只保留最后构建的那个。
function Find-PlatformArtifact([string]$name, [string]$area, [string]$goos, [string]$goarch) {
    $areaRoot = Join-Path $OutputDir $area
    if (-not (Test-Path -LiteralPath $areaRoot -PathType Container)) {
        return $null
    }
    $suffix = ''
    if ($goos -eq 'windows') {
        $suffix = '.exe'
    }
    $best = $null
    foreach ($directory in @(Get-ChildItem -LiteralPath $areaRoot -Directory -ErrorAction SilentlyContinue)) {
        if ($directory.Name -notlike ($name + '_v*_' + $goos + '_' + $goarch)) {
            continue
        }
        $candidate = Join-Path $directory.FullName ($name + $suffix)
        if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
            continue
        }
        $item = Get-Item -LiteralPath $candidate
        if ($null -eq $best -or $item.LastWriteTimeUtc -gt $best.LastWriteTimeUtc) {
            $best = $item
        }
    }
    return $best
}

if ($List) {
    Write-Host ("[run] platform={0}/{1} output={2}" -f $targetGoos, $targetGoarch, $OutputDir)
    Write-Host ''
    foreach ($name in $ProgramTable.Keys) {
        $item = Find-PlatformArtifact -name $name -area $ProgramTable[$name] -goos $targetGoos -goarch $targetGoarch
        if ($null -eq $item) {
            Write-Host ("{0,-15} {1,10}  {2}" -f $name, '缺失', '-')
        } else {
            $sizeMb = [math]::Round($item.Length / 1MB, 2)
            Write-Host ("{0,-15} {1,7} MB  {2}" -f $name, $sizeMb, $item.FullName)
        }
    }
    Write-Host ''
    Write-Host '产物缺失时先运行 .\build.ps1。'
    exit 0
}

# 配置：显式 -Config 优先；否则仅当当前目录存在 login.yaml 时作为默认值。
$explicitConfig = -not [string]::IsNullOrWhiteSpace($Config)
$configCandidate = $Config
if (-not $explicitConfig -and (Test-Path -LiteralPath 'login.yaml' -PathType Leaf)) {
    $configCandidate = 'login.yaml'
}

$normalizedProgram = $Program.Trim().ToLowerInvariant()
if ($normalizedProgram -eq 'auto' -and -not [string]::IsNullOrWhiteSpace($Exe)) {
    $exeName = [System.IO.Path]::GetFileNameWithoutExtension($Exe).ToLowerInvariant()
    if ($ProgramTable.Contains($exeName)) {
        $normalizedProgram = $exeName
        Write-Host ("[run] 由 -Exe 推断程序：{0}" -f $exeName)
    } else {
        Write-Host ("[run] 无法从 -Exe 推断程序：{0}；请同时指定 -Program" -f $Exe) -ForegroundColor Red
        exit 2
    }
}
if ($normalizedProgram -eq 'auto') {
    if ($explicitConfig -or -not [string]::IsNullOrWhiteSpace($configCandidate)) {
        $normalizedProgram = 'login-server'
        Write-Host '[run] auto -> login-server（已指定 -Config 或存在 login.yaml）'
    } else {
        $normalizedProgram = 'login-setup'
        Write-Host '[run] auto -> login-setup（未发现 login.yaml；可用 -Program login-server 显式启动服务）'
    }
}
if (-not $ProgramTable.Contains($normalizedProgram)) {
    Write-Host ("[run] 未知程序：{0}" -f $Program) -ForegroundColor Red
    Write-Host ("[run] 可用程序：{0}" -f (($ProgramTable.Keys) -join ', '))
    exit 2
}

# 解析可执行文件：-Exe 优先，否则按程序/平台查找构建产物。
$artifact = $null
if (-not [string]::IsNullOrWhiteSpace($Exe)) {
    $artifact = Get-Item -LiteralPath $Exe -ErrorAction SilentlyContinue
    if ($null -eq $artifact -or $artifact.PSIsContainer) {
        Write-Host ("[run] 指定的可执行文件不存在：{0}" -f $Exe) -ForegroundColor Red
        exit 2
    }
} else {
    $artifact = Find-PlatformArtifact -name $normalizedProgram -area $ProgramTable[$normalizedProgram] -goos $targetGoos -goarch $targetGoarch
    if ($null -eq $artifact) {
        Write-Host ("[run] 未找到 {0} 的 {1}/{2} 产物。" -f $normalizedProgram, $targetGoos, $targetGoarch) -ForegroundColor Red
        Write-Host ("[run] 期望位置：{0}\{1}\{2}_v*_{3}_{4}\" -f $OutputDir, $ProgramTable[$normalizedProgram], $normalizedProgram, $targetGoos, $targetGoarch)
        Write-Host '[run] 请先运行 .\build.ps1（默认构建六目标）。'
        exit 2
    }
}

$finalArgs = New-Object 'System.Collections.Generic.List[string]'
foreach ($value in $ProgramArguments) {
    if ($null -ne $value) {
        [void]$finalArgs.Add([string]$value)
    }
}

function Test-ConfigArgument([string[]]$items) {
    foreach ($item in $items) {
        if ($item -eq '--config' -or $item -eq '-config' -or
            $item -like '--config=*' -or $item -like '-config=*') {
            return $true
        }
    }
    return $false
}

$wantsHelpOrVersion = $false
foreach ($token in @('-h', '--help', '-help', '--version', '-version', '-v')) {
    if ($finalArgs.Contains($token)) {
        $wantsHelpOrVersion = $true
        break
    }
}

# 按程序补齐配置参数：login-server 的 --config 必须位于 serve/init 之后，
# login-setup 的 -config 是主命令全局参数，必须位于子命令之前。
switch ($normalizedProgram) {
    'login-server' {
        if (-not (Test-ConfigArgument $finalArgs.ToArray())) {
            if ([string]::IsNullOrWhiteSpace($configCandidate)) {
                if (-not $wantsHelpOrVersion) {
                    Write-Host '[run] login-server 需要配置文件，但当前目录没有 login.yaml。' -ForegroundColor Yellow
                    Write-Host '      首次使用可先运行：.\run.ps1 -Program login-setup'
                    Write-Host '      已有配置可指定：.\run.ps1 -Config D:\login\config\login.yaml'
                    exit 3
                }
            } elseif ($finalArgs.Count -eq 0) {
                [void]$finalArgs.Add('serve')
                [void]$finalArgs.Add('--config')
                [void]$finalArgs.Add($configCandidate)
            } elseif ($finalArgs[0] -eq 'serve' -or $finalArgs[0] -eq 'init') {
                $finalArgs.Insert(1, '--config')
                $finalArgs.Insert(2, $configCandidate)
            }
        }
    }
    'login-setup' {
        if (-not $wantsHelpOrVersion -and
            -not (Test-ConfigArgument $finalArgs.ToArray()) -and
            -not [string]::IsNullOrWhiteSpace($configCandidate)) {
            $finalArgs.Insert(0, '-config')
            $finalArgs.Insert(1, $configCandidate)
        }
    }
}

Write-Host ("[run] program={0} platform={1}/{2}" -f $normalizedProgram, $targetGoos, $targetGoarch)
Write-Host ("[run] artifact={0}" -f $artifact.FullName)

$argumentArray = $finalArgs.ToArray()
& $artifact.FullName @argumentArray
$exitCode = $LASTEXITCODE
if ($null -eq $exitCode) {
    $exitCode = 0
}
exit $exitCode
