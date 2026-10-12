param(
  [string]$RollbackRef = '0e6bcee07a7d5415dc8f69929269dfa3dd65cdb0'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$safeRepo = $repoRoot.Replace('\', '/')
$tempRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
$drillRoot = Join-Path $tempRoot ('shadow-ai-release-drill-' + [guid]::NewGuid().ToString('N'))
$rollbackDir = Join-Path $drillRoot 'rollback'
$candidateProcess = $null
$rollbackProcess = $null
$oldPort = $env:PORT
$oldNodeEnv = $env:NODE_ENV
$oldLocalFixture = $env:SHADOW_LOCAL_FIXTURE

function Wait-Health([int]$port, [System.Diagnostics.Process]$process) {
  for ($attempt = 0; $attempt -lt 40; $attempt++) {
    if ($process.HasExited) { throw "Server exited before health check (code $($process.ExitCode))." }
    try {
      $health = Invoke-RestMethod -Uri "http://127.0.0.1:$port/health" -TimeoutSec 2
      if ($health.status -eq 'ok' -and $health.service -eq 'shadow-ai-detector') { return }
    } catch { }
    Start-Sleep -Milliseconds 150
  }
  throw 'Loopback health check timed out.'
}

function Stop-DrillProcess([System.Diagnostics.Process]$process) {
  if ($null -ne $process -and -not $process.HasExited) {
    Stop-Process -Id $process.Id -Force
    $process.WaitForExit(5000) | Out-Null
  }
}

try {
  New-Item -ItemType Directory -Path $rollbackDir -Force | Out-Null
  $rollbackSha = (& git -c "safe.directory=$safeRepo" rev-parse $RollbackRef).Trim()
  if ($LASTEXITCODE -ne 0) { throw 'Rollback ref is unavailable.' }
  $candidateSha = (& git -c "safe.directory=$safeRepo" rev-parse HEAD).Trim()
  if ($LASTEXITCODE -ne 0) { throw 'Candidate commit is unavailable.' }
  if ($candidateSha -eq $rollbackSha) { throw 'Candidate and rollback must be different commits.' }
  $changes = & git -c "safe.directory=$safeRepo" status --porcelain
  if ($LASTEXITCODE -ne 0 -or $changes) { throw 'Candidate working tree must be clean.' }

  Push-Location $repoRoot
  try {
    & npm.cmd run build
    if ($LASTEXITCODE -ne 0) { throw 'Candidate build failed.' }
  } finally { Pop-Location }

  $archivePath = Join-Path $drillRoot 'rollback.zip'
  & git -c "safe.directory=$safeRepo" archive --format=zip $rollbackSha -o $archivePath
  if ($LASTEXITCODE -ne 0) { throw 'Rollback archive failed.' }
  Expand-Archive -LiteralPath $archivePath -DestinationPath $rollbackDir

  Push-Location $rollbackDir
  try {
    & npm.cmd ci --offline --ignore-scripts
    if ($LASTEXITCODE -ne 0) { throw 'Offline rollback dependency install failed.' }
    & npm.cmd run build
    if ($LASTEXITCODE -ne 0) { throw 'Rollback build failed.' }
  } finally { Pop-Location }
  if (-not (Test-Path -LiteralPath (Join-Path $repoRoot 'dist/config/local-boundary.js'))) {
    throw 'Candidate boundary artifact is missing.'
  }
  if (Test-Path -LiteralPath (Join-Path $rollbackDir 'dist/config/local-boundary.js')) {
    throw 'Rollback artifact unexpectedly contains the candidate boundary.'
  }

  $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
  $listener.Start()
  $port = ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
  $listener.Stop()
  $env:PORT = [string]$port
  $env:NODE_ENV = 'development'
  $env:SHADOW_LOCAL_FIXTURE = '1'
  $nodePath = (Get-Command node.exe).Source

  $candidateProcess = Start-Process -FilePath $nodePath -ArgumentList 'dist/index.js' -WorkingDirectory $repoRoot -PassThru -WindowStyle Hidden -RedirectStandardOutput (Join-Path $drillRoot 'candidate.out') -RedirectStandardError (Join-Path $drillRoot 'candidate.err')
  Wait-Health $port $candidateProcess
  $candidateData = Invoke-RestMethod -Uri "http://127.0.0.1:$port/api/dashboard/summary" -TimeoutSec 2
  if ($candidateData.dataMode -ne 'synthetic-demo') { throw 'Candidate synthetic fixture check failed.' }
  Write-Output "CANDIDATE_OK sha=$candidateSha port=$port dataMode=$($candidateData.dataMode)"
  Stop-DrillProcess $candidateProcess

  $rollbackProcess = Start-Process -FilePath $nodePath -ArgumentList 'dist/index.js' -WorkingDirectory $rollbackDir -PassThru -WindowStyle Hidden -RedirectStandardOutput (Join-Path $drillRoot 'rollback.out') -RedirectStandardError (Join-Path $drillRoot 'rollback.err')
  Wait-Health $port $rollbackProcess
  $rollbackData = Invoke-RestMethod -Uri "http://127.0.0.1:$port/api/dashboard/summary" -TimeoutSec 2
  if ($rollbackData.dataMode -ne 'synthetic-demo') { throw 'Rollback synthetic fixture check failed.' }
  Write-Output "ROLLBACK_OK sha=$rollbackSha port=$port dataMode=$($rollbackData.dataMode)"
} finally {
  Stop-DrillProcess $candidateProcess
  Stop-DrillProcess $rollbackProcess
  $env:PORT = $oldPort
  $env:NODE_ENV = $oldNodeEnv
  $env:SHADOW_LOCAL_FIXTURE = $oldLocalFixture
  $resolvedDrill = [System.IO.Path]::GetFullPath($drillRoot)
  if ($resolvedDrill.StartsWith($tempRoot, [System.StringComparison]::OrdinalIgnoreCase) -and
      [System.IO.Path]::GetFileName($resolvedDrill) -like 'shadow-ai-release-drill-*' -and
      (Test-Path -LiteralPath $resolvedDrill)) {
    Remove-Item -LiteralPath $resolvedDrill -Recurse -Force
  }
}
