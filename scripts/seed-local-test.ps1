[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

function Get-ProfileEntry($Root, $Name, [switch]$Directory, [switch]$Required) {
    $path = Join-Path $Root $Name
    try {
        $attributes = [IO.File]::GetAttributes($path)
    } catch [IO.FileNotFoundException], [IO.DirectoryNotFoundException] {
        if ($Required) { throw "Required profile entry is missing at $path." }
        return
    }
    if (($attributes -band [IO.FileAttributes]::ReparsePoint) -or
        [bool]($attributes -band [IO.FileAttributes]::Directory) -ne $Directory.IsPresent) {
        throw "Profile entry at $path must be a regular file or directory of the expected type."
    }
    return $path
}

function Read-ProfileJson($Path, [long]$Limit = 2MB) {
    try {
        if ([IO.FileInfo]::new($Path).Length -gt $Limit) { throw 'Size limit exceeded' }
        $contents = [IO.File]::ReadAllText($Path)
        if (!$contents.TrimStart().StartsWith('{')) { throw 'Expected a JSON object' }
        $document = ConvertFrom-Json -InputObject $contents
        if ($document -isnot [pscustomobject]) { throw 'Expected a JSON object' }
        return $document
    } catch {
        # JSON parser errors can quote values from a private profile.
        throw "The profile file at $Path is invalid or unreadable."
    }
}

function Get-ProfileFiles($Root) {
    $config = Get-ProfileEntry $Root 'config.json' -Required
    $configuration = Read-ProfileJson $config
    # Windows PowerShell and PowerShell 7 use different integer types for JSON numbers.
    $version = $configuration.version
    if (($version -isnot [int] -and $version -isnot [long]) -or $version -notin @(1, 2) -or
        $configuration.proxies -isnot [array] -or $configuration.rules -isnot [array] -or
        $null -eq $configuration.default_action) {
        throw "The True Proxy configuration at $config is invalid."
    }
    'config.json'
    $appearance = Get-ProfileEntry $Root 'appearance.json'
    if ($appearance) {
        $null = Read-ProfileJson $appearance
        'appearance.json'
    }

    $xray = Get-ProfileEntry $Root 'xray' -Directory
    if (!$xray) { return }
    $settings = Get-ProfileEntry $xray 'settings.json'
    if ($settings) {
        $null = Read-ProfileJson $settings
        'xray\settings.json'
    }
    foreach ($name in @('subscription-device.dpapi', 'hpwnr-v1.0.3.exe')) {
        if (Get-ProfileEntry $xray $name) { "xray\$name" }
    }

    $manifest = Get-ProfileEntry $xray 'core.json'
    if ($manifest) {
        $core = Read-ProfileJson $manifest 4096
        if ($core.archive_sha256 -isnot [string] -or $core.archive_sha256 -notmatch '^[a-f0-9]{64}\z' -or
            $core.executable_sha256 -isnot [string] -or $core.executable_sha256 -notmatch '^[a-f0-9]{64}\z' -or
            $core.version -isnot [string] -or [string]::IsNullOrWhiteSpace($core.version)) {
            throw "The Xray-core manifest at $manifest is invalid."
        }
        $name = 'core-' + $core.archive_sha256
        $directory = Get-ProfileEntry $xray $name -Directory -Required
        'xray\core.json'
        foreach ($file in @('xray.exe', 'geoip.dat', 'geosite.dat', 'LICENSE')) {
            $null = Get-ProfileEntry $directory $file -Required
            "xray\$name\$file"
        }
    }

    $manifest = Get-ProfileEntry $xray 'geodata.json'
    if ($manifest) {
        $geo = Read-ProfileJson $manifest 4096
        if ($geo.directory -isnot [string] -or $geo.directory -cnotmatch '^geo-[0-9]{1,39}-[0-9]{1,10}\z') {
            throw "The Xray geodata manifest at $manifest is invalid."
        }
        $directory = Get-ProfileEntry $xray $geo.directory -Directory -Required
        'xray\geodata.json'
        foreach ($file in @('geoip.dat', 'geosite.dat')) {
            $null = Get-ProfileEntry $directory $file -Required
            "xray\$($geo.directory)\$file"
        }
    }

    $manifest = Get-ProfileEntry $xray 'hpwnr.json'
    if ($manifest) {
        $hpwnr = Read-ProfileJson $manifest 4096
        if ($hpwnr.sha256 -isnot [string] -or $hpwnr.sha256 -notmatch '^[a-f0-9]{64}\z' -or
            $hpwnr.version -isnot [string] -or [string]::IsNullOrWhiteSpace($hpwnr.version)) {
            throw "The hpwnr manifest at $manifest is invalid."
        }
        $name = 'hpwnr-' + $hpwnr.sha256 + '.exe'
        $null = Get-ProfileEntry $xray $name -Required
        'xray\hpwnr.json'
        "xray\$name"
    }
}

$localData = [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
if (![IO.Path]::IsPathRooted($localData)) { throw 'Could not locate LocalAppData.' }
$localData = [IO.Path]::GetFullPath($localData)
$destination = Join-Path $localData 'TrueProxy-LocalTest'
if (Get-ProfileEntry $localData 'TrueProxy-LocalTest' -Directory) {
    $null = Get-ProfileFiles $destination
    Write-Output $destination
    return
}

$source = Get-ProfileEntry $localData 'TrueProxy' -Directory -Required
$files = @(Get-ProfileFiles $source)
$stage = Join-Path $localData ('TrueProxy-LocalTest-' + [Guid]::NewGuid().ToString('N') + '.tmp')
$null = [IO.Directory]::CreateDirectory($stage)
try {
    foreach ($name in $files) {
        $target = Join-Path $stage $name
        $null = [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($target))
        [IO.File]::Copy((Join-Path $source $name), $target)
    }
    $null = Get-ProfileFiles $stage
    try {
        # Both paths are siblings. Move publishes the completed copy without overwriting.
        [IO.Directory]::Move($stage, $destination)
    } catch [IO.IOException] {
        if (!(Get-ProfileEntry $localData 'TrueProxy-LocalTest' -Directory)) { throw }
        $null = Get-ProfileFiles $destination
    }
} finally {
    if ([IO.Directory]::Exists($stage) -and
        [IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($stage)) -eq $localData -and
        (Get-ProfileEntry $localData ([IO.Path]::GetFileName($stage)) -Directory)) {
        Remove-Item -LiteralPath $stage -Recurse -Force
    }
}

Write-Output $destination
