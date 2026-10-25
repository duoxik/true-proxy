param(
    [ValidateSet('check', 'test', 'build', 'run', 'package', 'fmt', 'clippy', 'smoke', 'dns-probe')]
    [string]$Task = 'check',
    [string]$PackageDirectory = 'dist\TrueProxy',
    [string]$PackageArchive = 'dist\TrueProxy-windows-x64.zip'
)
$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path -Parent $PSScriptRoot
Push-Location -LiteralPath $taskRoot
try {
    $taskLocalCargo = Join-Path $taskRoot '.tools\cargo'
    $taskMingw = $null
    if (Test-Path -LiteralPath (Join-Path $taskLocalCargo 'bin\cargo.exe')) {
        $env:CARGO_HOME = $taskLocalCargo
        $env:RUSTUP_HOME = Join-Path $taskRoot '.tools\rustup'
        $env:PATH = "$taskLocalCargo\bin;$env:PATH"
        $taskMingw = Join-Path $taskRoot '.tools\winlibs\mingw64\bin'
        if (Test-Path -LiteralPath $taskMingw) {
            $env:PATH = "$taskMingw;$env:PATH"
            $env:CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER = Join-Path $taskMingw 'gcc.exe'
        }
    }
    if ($Task -ne 'fmt') {
        & (Join-Path $PSScriptRoot 'fetch-driver.ps1')
    }
    switch ($Task) {
        'check' { cargo check --locked --all-targets }
        'test' { cargo test --locked }
        'build' { cargo build --locked --release }
        'run' { cargo run --locked -- --paused }
        'fmt' { cargo fmt --all }
        'clippy' { cargo clippy --locked --all-targets -- -D warnings }
        'dns-probe' {
            cargo build --locked --example dns-route-client --example dns-route-probe
            if ($LASTEXITCODE -ne 0) { throw 'DNS probe build failed' }
            & (Join-Path $taskRoot 'target/debug/examples/dns-route-probe.exe') (Join-Path $taskRoot 'target/debug/examples/dns-route-client.exe') (Join-Path $taskRoot '.tools/dns-route-probe')
        }
        'smoke' {
            cargo build --locked
            if ($LASTEXITCODE -ne 0) { throw 'Build failed' }
            $taskPreviewExe = Join-Path $taskRoot 'target\debug\true-proxy.exe'
            foreach ($taskHidden in @($false, $true)) {
                $taskPreview = Join-Path $taskRoot $(if ($taskHidden) { '.tools\ui-smoke-tray' } else { '.tools\ui-smoke' })
                $taskArguments = @('--smoke-ui', "`"$taskPreview`"")
                if ($taskHidden) { $taskArguments += '--tray' }
                $taskProcess = Start-Process -FilePath $taskPreviewExe -ArgumentList $taskArguments -WindowStyle Hidden -Wait -PassThru
                if ($taskProcess.ExitCode -ne 0) { throw "UI process exited with $($taskProcess.ExitCode)" }
                $taskResult = Get-Content -LiteralPath (Join-Path $taskPreview 'result.txt')
                Write-Output $taskResult
                if ($taskResult -notlike 'PASS:*') { throw 'UI smoke test failed' }
            }
        }
        'package' {
            cargo build --locked --release
            if ($LASTEXITCODE -ne 0) { throw 'Release build failed' }
            $taskDist = [IO.Path]::GetFullPath($PackageDirectory, $taskRoot)
            $taskArchive = [IO.Path]::GetFullPath($PackageArchive, $taskRoot)
            New-Item -ItemType Directory -Path $taskDist -Force | Out-Null
            # Remove only these generated legacy outputs from earlier package versions.
            foreach ($taskOldFile in @('LICENSE', 'WinDivert.dll', 'WinDivert64.sys', 'libgcc_s_seh-1.dll', 'libwinpthread-1.dll')) {
                $taskOldPath = Join-Path $taskDist $taskOldFile
                if (Test-Path -LiteralPath $taskOldPath -PathType Leaf) { Remove-Item -LiteralPath $taskOldPath }
            }
            Copy-Item -LiteralPath (Join-Path $taskRoot 'target\release\true-proxy.exe') -Destination (Join-Path $taskDist 'TrueProxy.exe') -Force
            $taskDriver = Join-Path $taskRoot 'vendor\WinDivert\WinDivert-2.2.2-A'
            Copy-Item -LiteralPath (Join-Path $taskRoot 'README.md') -Destination $taskDist -Force
            Copy-Item -LiteralPath (Join-Path $taskRoot 'THIRD_PARTY_NOTICES.md') -Destination $taskDist -Force
            Copy-Item -LiteralPath (Join-Path $taskRoot 'docs') -Destination $taskDist -Recurse -Force
            Copy-Item -LiteralPath (Join-Path $taskDriver 'LICENSE') -Destination (Join-Path $taskDist 'LICENSE-WinDivert.txt') -Force
            # GNU builds need the matching exception and thread runtime DLLs next to the executable.
            if ($taskMingw -and (Test-Path -LiteralPath $taskMingw)) {
                $taskImports = & (Join-Path $taskMingw 'objdump.exe') -p (Join-Path $taskDist 'TrueProxy.exe')
                foreach ($taskDll in @('libgcc_s_seh-1.dll', 'libwinpthread-1.dll')) {
                    if ($taskImports -match "DLL Name:\s+$([regex]::Escape($taskDll))\s*$") {
                        Copy-Item -LiteralPath (Join-Path $taskMingw $taskDll) -Destination $taskDist -Force
                    }
                }
            }
            & (Join-Path $PSScriptRoot 'package-notices.ps1') -Destination $taskDist
            Get-ChildItem -LiteralPath $taskDist -File -Recurse | Where-Object LastWriteTime -LT ([datetime]'1980-01-01') | ForEach-Object { $_.LastWriteTime = [datetime]'2000-01-01' }
            New-Item -ItemType Directory -Path (Split-Path -Parent $taskArchive) -Force | Out-Null
            Compress-Archive -Path (Join-Path $taskDist '*') -DestinationPath $taskArchive -Force
            Write-Output "Portable build: $taskDist"
        }
    }
    if ($LASTEXITCODE -ne 0) { throw "Task $Task failed with exit code $LASTEXITCODE" }
} finally { Pop-Location }
