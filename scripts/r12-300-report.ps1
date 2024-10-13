# r12-300-report.ps1
#
# Convert the machine-readable result of scripts/r12-300-acceptance.ps1 into the
# Markdown report required by Step 300. Read-only on product code; the only
# writes are the report file (and nothing else).
#
# Usage (EvernightLogin root):
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts/r12-300-report.ps1 `
#       -SummaryPath P:/go/tmp/r12-300/r12-300-acceptance.json `
#       -OutPath .ai/lead/reports/round12/step300-acceptance-report.md

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$SummaryPath,
    [string]$OutPath = '.ai/lead/reports/round12/step300-acceptance-report.md'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$summaryPath = $SummaryPath
if (-not [System.IO.Path]::IsPathRooted($summaryPath)) {
    $summaryPath = Join-Path $root $summaryPath
}
if (-not (Test-Path $summaryPath)) {
    Write-Error "summary JSON not found: $summaryPath"
    exit 2
}
$data = Get-Content $summaryPath -Raw | ConvertFrom-Json
if ($null -eq $data -or $data.schema -ne 'evernight.step300.acceptance/v1') {
    Write-Error "unexpected summary schema: $($data.schema)"
    exit 2
}
if (-not [System.IO.Path]::IsPathRooted($OutPath)) {
    $OutPath = Join-Path $root $OutPath
}
$outDir = Split-Path -Parent $OutPath
if (-not (Test-Path $outDir)) {
    New-Item -ItemType Directory -Force $outDir | Out-Null
}

function Escape-MdCell {
    param([string]$Text)
    if ($null -eq $Text) { return '' }
    return (($Text -replace '\|', '\|') -replace '\r?\n', ' ')
}

function Format-CodeBlock {
    param([string]$Text, [string]$Language = 'text')
    if ([string]::IsNullOrWhiteSpace($Text)) { return '' }
    return ("``````{0}`n{1}`n``````" -f $Language, $Text.TrimEnd())
}

$counts = $data.counts
$overall = 'FAIL'
if ($counts.failed -eq 0 -and $counts.not_run -eq 0 -and $data.complete) {
    $overall = 'PASS'
} elseif ($counts.failed -eq 0) {
    $overall = 'INCOMPLETE'
}

$lines = New-Object System.Collections.Generic.List[string]
$lines.Add('# 步骤 300 合并验收执行报告')
$lines.Add('')
$lines.Add("- 生成时间：$($data.generated_at)")
$lines.Add("- 仓库/HEAD：``$($data.repo_root)`` / ``$($data.head)``")
$lines.Add("- 平台/Go：$($data.platform)；$($data.go_version)")
$lines.Add("- 运行窗口：$($data.started_at) → $($data.finished_at)（$($data.duration_seconds)s）")
$lines.Add("- 脏工作树条目：$($data.dirty_count)；work root：``$($data.work_root)``")
$lines.Add("- heavy-lock：owner=$($data.heavy_lock.owner) acquired=$($data.heavy_lock.acquired) no_lock=$($data.heavy_lock.no_lock)")
$lines.Add("- 机器可读汇总：``$summaryPath``")
$lines.Add('')
$lines.Add('## 1. 结论')
$lines.Add('')
$lines.Add("**总体：$overall**（complete=$($data.complete)）")
$lines.Add('')
$lines.Add('| 统计 | 数量 |')
$lines.Add('|---|---|')
$lines.Add("| PASS | $($counts.passed) |")
$lines.Add("| FAIL | $($counts.failed) |")
$lines.Add("| NOT_RUN | $($counts.not_run) |")
$lines.Add("| 合计 | $($counts.total) |")
$lines.Add('')
if ($data.dirty_count -gt 0) {
    $lines.Add('运行开始时工作树非干净（验收执行专用；不代表产品代码提交状态）：')
    $lines.Add('')
    $lines.Add('```text')
    foreach ($entry in $data.dirty_entries) { $lines.Add($entry) }
    $lines.Add('```')
    $lines.Add('')
}
$lines.Add('## 2. 套件明细')
$lines.Add('')
$lines.Add('| 套件 | 状态 | 退出码 | 耗时(s) | 命令 |')
$lines.Add('|---|---|---|---|---|')
foreach ($suite in $data.suites) {
    $lines.Add(("| {0} | {1} | {2} | {3} | ``{4}`` |" -f `
                (Escape-MdCell $suite.name), $suite.status, $suite.exit_code,
                $suite.duration_seconds, (Escape-MdCell $suite.command)))
}
$lines.Add('')
$failed = @($data.suites | Where-Object { $_.status -eq 'fail' })
$notRun = @($data.suites | Where-Object { $_.status -eq 'not_run' })
$lines.Add('## 3. 失败与未跑明细')
$lines.Add('')
if ($failed.Count -eq 0 -and $notRun.Count -eq 0) {
    $lines.Add('无 FAIL、无 NOT_RUN。')
} else {
    foreach ($suite in $failed) {
        $lines.Add("### FAIL：$($suite.name)（exit=$($suite.exit_code)，$($suite.duration_seconds)s）")
        $lines.Add('')
        $lines.Add("命令：``$($suite.command)``")
        $lines.Add('')
        $lines.Add((Format-CodeBlock $suite.tail))
        $lines.Add('')
    }
    foreach ($suite in $notRun) {
        $lines.Add("### NOT_RUN：$($suite.name)")
        $lines.Add('')
        $lines.Add((Format-CodeBlock $suite.tail))
        $lines.Add('')
    }
}
$lines.Add('## 4. 未测与边界（按套件输出/既有矩阵登记）')
$lines.Add('')
$lines.Add('- 其他平台/其他数据库：仅编译/静态，不宣称运行通过。')
$lines.Add('- 真实 Windows TTY 人工交互：若未单独执行则按 NOT_TESTED 记录，脚本模型/非 TTY smoke 不等于人工验收。')
$lines.Add('- 297–299（WS5）与 301/302 项：本报告只覆盖脚本实际执行套件；未执行项不得视为通过。')
$lines.Add('- 详细旧步骤映射与证据索引见 `.ai/lead/reports/round12/step300-acceptance-matrix.md`。')
$lines.Add('')
$lines.Add('## 5. 后续动作')
$lines.Add('')
$lines.Add('- 任何 FAIL：记录最小复现、修复后定向复跑并重新生成本报告；修复前不得进入发布。')
$lines.Add('- 任何 NOT_RUN：写明原因、影响与后续入口；不得用定向通过掩盖。')
$lines.Add('- 通过后由 Lead 决定进入 301/302 或补审。')

$markdown = ($lines -join "`n") + "`n"
$encoding = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($OutPath, $markdown, $encoding)
Write-Host ("report written: {0}" -f $OutPath)
Write-Host ("overall: {0} pass={1} fail={2} not_run={3} complete={4}" -f `
    $overall, $counts.passed, $counts.failed, $counts.not_run, $data.complete)
if ($failed.Count -gt 0) { exit 1 }
if (-not $data.complete) { exit 3 }
exit 0
