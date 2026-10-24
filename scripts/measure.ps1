param([string]$Executable)
$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path -Parent $PSScriptRoot
if (-not $Executable) { $Executable = Join-Path $taskRoot 'dist\TrueProxy\TrueProxy.exe' }
$taskOutput = Join-Path $taskRoot '.tools\benchmark'
New-Item -ItemType Directory -Path $taskOutput -Force | Out-Null
$taskPhaseFile = Join-Path $taskOutput 'phase.txt'
if (Test-Path -LiteralPath $taskPhaseFile) { Remove-Item -LiteralPath $taskPhaseFile }
$taskProcess = Start-Process -FilePath $Executable -ArgumentList @('--benchmark-ui', "`"$taskOutput`"") -WindowStyle Hidden -PassThru
$taskSamples = [System.Collections.Generic.List[object]]::new()
$taskWatch = [System.Diagnostics.Stopwatch]::StartNew()
while (-not $taskProcess.HasExited -and $taskWatch.Elapsed.TotalSeconds -lt 25) {
    $taskProcess.Refresh()
    $taskPhase = if (Test-Path -LiteralPath $taskPhaseFile) { Get-Content -LiteralPath $taskPhaseFile -Raw } else { 'starting' }
    $taskSamples.Add([pscustomobject]@{ phase = $taskPhase; seconds = $taskWatch.Elapsed.TotalSeconds; cpuSeconds = $taskProcess.TotalProcessorTime.TotalSeconds; workingSetBytes = $taskProcess.WorkingSet64; privateBytes = $taskProcess.PrivateMemorySize64 })
    Start-Sleep -Milliseconds 500
}
if (-not $taskProcess.HasExited) { throw "Benchmark did not finish. Test PID: $($taskProcess.Id)" }
if ($taskProcess.ExitCode -ne 0) { throw "Benchmark exited with $($taskProcess.ExitCode)" }
$taskResult = [ordered]@{ exeBytes = (Get-Item -LiteralPath $Executable).Length; scope = 'Isolated UI; interception and update HTTP requests disabled. CPU percent uses one logical core as 100%.' }
foreach ($taskPhase in @('visible', 'tray')) {
    $taskPhaseSamples = @($taskSamples | Where-Object phase -EQ $taskPhase | Select-Object -Skip 1)
    if ($taskPhaseSamples.Count -lt 2) { throw "Not enough samples for $taskPhase" }
    $taskFirst = $taskPhaseSamples[0]; $taskLast = $taskPhaseSamples[-1]
    $taskResult[$taskPhase] = @{ workingSetMiB = [Math]::Round(($taskPhaseSamples.workingSetBytes | Measure-Object -Average).Average / 1MB, 2); privateMiB = [Math]::Round(($taskPhaseSamples.privateBytes | Measure-Object -Average).Average / 1MB, 2); cpuPercentOfOneCore = [Math]::Round(100 * ($taskLast.cpuSeconds - $taskFirst.cpuSeconds) / ($taskLast.seconds - $taskFirst.seconds), 3); sampleSeconds = [Math]::Round($taskLast.seconds - $taskFirst.seconds, 2) }
}
$taskResult | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $taskOutput 'metrics.json') -Encoding utf8
$taskResult | ConvertTo-Json -Depth 5
