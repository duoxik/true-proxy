$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path -Parent $PSScriptRoot
$taskTools = Join-Path $taskRoot '.tools'
$taskArchive = Join-Path $taskTools 'WinDivert.zip'
$taskExpected = '63CB41763BB4B20F600B6DE04E991A9C2BE73279E317D4D82F237B150C5F3F15'
New-Item -ItemType Directory -Path $taskTools -Force | Out-Null
if (-not (Test-Path -LiteralPath $taskArchive)) {
    Invoke-WebRequest 'https://github.com/basil00/WinDivert/releases/download/v2.2.2/WinDivert-2.2.2-A.zip' -OutFile $taskArchive
}
if ((Get-FileHash -LiteralPath $taskArchive -Algorithm SHA256).Hash -ne $taskExpected) { throw 'WinDivert checksum mismatch' }
$taskDestination = Join-Path $taskRoot 'vendor\WinDivert'
Expand-Archive -LiteralPath $taskArchive -DestinationPath $taskDestination -Force
$taskSignature = Get-AuthenticodeSignature -LiteralPath (Join-Path $taskDestination 'WinDivert-2.2.2-A\x64\WinDivert64.sys')
if ($taskSignature.Status -ne 'Valid') { throw "Invalid WinDivert driver signature: $($taskSignature.Status)" }
Write-Output 'WinDivert 2.2.2: SHA-256 and driver signature verified. The driver has not been started.'
