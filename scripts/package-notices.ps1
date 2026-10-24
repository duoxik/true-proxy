param([Parameter(Mandatory)][string]$Destination)
$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path -Parent $PSScriptRoot
$taskMetadata = cargo metadata --locked --format-version 1 --filter-platform x86_64-pc-windows-gnu | ConvertFrom-Json -Depth 100
if ($LASTEXITCODE -ne 0) { throw 'Cannot read dependency metadata' }
$taskMetadata.packages | Select-Object name,version,license,repository | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $Destination 'DEPENDENCIES.json') -Encoding utf8
$taskLicenseRoot = Join-Path $Destination 'licenses'
New-Item -ItemType Directory -Path $taskLicenseRoot -Force | Out-Null
foreach ($taskPackage in $taskMetadata.packages) {
    if (-not $taskPackage.source) { continue }
    $taskPackagePath = Split-Path -Parent $taskPackage.manifest_path
    $taskLicenseFiles = Get-ChildItem -LiteralPath $taskPackagePath -File | Where-Object Name -Match '^(LICENSE|LICENCE|COPYING|NOTICE|COPYRIGHT)'
    if ($taskLicenseFiles) {
        $taskPackageDestination = Join-Path $taskLicenseRoot "$($taskPackage.name)-$($taskPackage.version)"
        New-Item -ItemType Directory -Path $taskPackageDestination -Force | Out-Null
        $taskLicenseFiles | Copy-Item -Destination $taskPackageDestination -Force
    }
}
$taskCache = Join-Path $taskRoot '.tools\licenses'
New-Item -ItemType Directory -Path $taskCache -Force | Out-Null
$taskUpstream = @{
    'slint-royalty-free-2.0.md' = 'https://raw.githubusercontent.com/slint-ui/slint/v1.18.1/LICENSES/LicenseRef-Slint-Royalty-free-2.0.md'
    'slint-fonts-OFL-1.1.txt' = 'https://raw.githubusercontent.com/slint-ui/slint/v1.18.1/LICENSES/OFL-1.1.txt'
    'slint-fonts-OFL-1.1-RFN.txt' = 'https://raw.githubusercontent.com/slint-ui/slint/v1.18.1/LICENSES/OFL-1.1-RFN.txt'
    'gcc-COPYING3.txt' = 'https://raw.githubusercontent.com/gcc-mirror/gcc/releases/gcc-16.2.0/COPYING3'
    'gcc-RUNTIME-EXCEPTION.txt' = 'https://raw.githubusercontent.com/gcc-mirror/gcc/releases/gcc-16.2.0/COPYING.RUNTIME'
    'winpthreads-COPYING.txt' = 'https://raw.githubusercontent.com/mingw-w64/mingw-w64/v14.0.0/mingw-w64-libraries/winpthreads/COPYING'
}
foreach ($taskName in $taskUpstream.Keys) {
    $taskCached = Join-Path $taskCache $taskName
    if (-not (Test-Path -LiteralPath $taskCached)) { Invoke-WebRequest $taskUpstream[$taskName] -OutFile $taskCached }
    $taskSubfolder = if ($taskName -like 'slint*') { 'slint' } else { 'toolchain' }
    $taskOutput = Join-Path $taskLicenseRoot $taskSubfolder
    New-Item -ItemType Directory -Path $taskOutput -Force | Out-Null
    Copy-Item -LiteralPath $taskCached -Destination $taskOutput -Force
}
