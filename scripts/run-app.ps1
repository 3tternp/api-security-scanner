param(
  [switch]$Detach = $true,
  [int]$WaitSeconds = 180
)

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Resolve-Path (Join-Path $scriptDir "..")
Set-Location $repoRoot

function Test-DockerDaemon {
  try {
    docker version --format "{{.Server.Version}}" *> $null
    return ($LASTEXITCODE -eq 0)
  } catch {
    return $false
  }
}

function Start-DockerDesktop {
  $candidates = @(
    "C:\Program Files\Docker\Docker\Docker Desktop.exe",
    "C:\Program Files (x86)\Docker\Docker\Docker Desktop.exe"
  )

  foreach ($p in $candidates) {
    if (Test-Path $p) {
      Start-Process -FilePath $p | Out-Null
      return $true
    }
  }

  return $false
}

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
  throw "Docker CLI not found. Install Docker Desktop first."
}

if (-not (Test-DockerDaemon)) {
  $started = Start-DockerDesktop
  if (-not $started) {
    throw "Docker daemon is not available and Docker Desktop could not be started automatically."
  }

  $deadline = (Get-Date).AddSeconds($WaitSeconds)
  while ((Get-Date) -lt $deadline) {
    Start-Sleep -Seconds 2
    if (Test-DockerDaemon) { break }
  }

  if (-not (Test-DockerDaemon)) {
    throw "Docker daemon still not ready after waiting $WaitSeconds seconds."
  }
}

if ($Detach) {
  docker compose up -d --build
} else {
  docker compose up --build
}

