param(
  [string]$TaskName = "ApiSecurityScanner",
  [switch]$AtStartup = $false
)

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Resolve-Path (Join-Path $scriptDir "..")
$runner = Join-Path $repoRoot "scripts\run-app.ps1"

if (-not (Test-Path $runner)) {
  throw "Runner script not found: $runner"
}

$ps = (Get-Command powershell.exe).Source
$args = "-NoProfile -ExecutionPolicy Bypass -File `"$runner`""

$action = New-ScheduledTaskAction -Execute $ps -Argument $args -WorkingDirectory $repoRoot

if ($AtStartup) {
  $trigger = New-ScheduledTaskTrigger -AtStartup
  $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
  Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null
  Write-Host "Installed scheduled task '$TaskName' (AtStartup as SYSTEM)."
  exit 0
}

$trigger = New-ScheduledTaskTrigger -AtLogOn
$principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType InteractiveToken -RunLevel Limited
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null
Write-Host "Installed scheduled task '$TaskName' (AtLogOn for user $env:USERNAME)."

