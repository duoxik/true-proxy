$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path -Parent $PSScriptRoot
$taskTools = Join-Path $taskRoot '.tools'
New-Item -ItemType Directory -Path $taskTools -Force | Out-Null
$env:CARGO_HOME = Join-Path $taskTools 'cargo'
$env:RUSTUP_HOME = Join-Path $taskTools 'rustup'

if (-not (Test-Path -LiteralPath (Join-Path $env:CARGO_HOME 'bin\cargo.exe'))) {
    $taskInstaller = Join-Path $taskTools 'rustup-init.exe'
    $taskUrl = 'https://static.rust-lang.org/rustup/dist/x86_64-pc-windows-msvc/rustup-init.exe'
    Invoke-WebRequest $taskUrl -OutFile $taskInstaller
    $taskChecksum = ((Invoke-WebRequest "$taskUrl.sha256").Content -split '\s+')[0]
    if ((Get-FileHash -LiteralPath $taskInstaller -Algorithm SHA256).Hash -ne $taskChecksum) { throw 'Rustup checksum mismatch' }
    & $taskInstaller -y --no-modify-path --profile minimal --default-host x86_64-pc-windows-gnu --default-toolchain 1.99.1 --component rustfmt --component clippy
    if ($LASTEXITCODE -ne 0) { throw 'Rust installation failed' }
}

$taskCompiler = Join-Path $taskTools 'winlibs\mingw64\bin\gcc.exe'
if (-not (Test-Path -LiteralPath $taskCompiler)) {
    $taskArchive = Join-Path $taskTools 'winlibs.zip'
    $taskExpected = '62AF32EA58ACDEA1318EA5DD8EB7017EAEE694DD40B269D52A59C769DCFEFB82'
    if (-not (Test-Path -LiteralPath $taskArchive)) {
        Invoke-WebRequest 'https://github.com/brechtsanders/winlibs_mingw/releases/download/16.2.0posix-23.1.3-14.0.0-msvcrt-r3/winlibs-x86_64-posix-seh-gcc-16.2.0-mingw-w64msvcrt-14.0.0-r3.zip' -OutFile $taskArchive
    }
    if ((Get-FileHash -LiteralPath $taskArchive -Algorithm SHA256).Hash -ne $taskExpected) { throw 'MinGW-w64 checksum mismatch' }
    Expand-Archive -LiteralPath $taskArchive -DestinationPath (Join-Path $taskTools 'winlibs') -Force
}
Write-Output 'Local Rust + MinGW-w64 are ready. Run scripts/dev.ps1 check. No global PATH changes were made.'
