param(
    [string]$OutDir = "dist\unix",
    [string]$WindowsManager,
    [switch]$Archive
)

$ErrorActionPreference = 'Stop'

function Set-ZipUnixPlatform([string]$Path) {
    # ZipArchive on Windows marks entries as DOS-origin even when Unix modes
    # are supplied. Set each central-directory "made by" platform to Unix so
    # standard Unix extractors can interpret those modes. This small release
    # never needs ZIP64; fail rather than silently misread an unexpected form.
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    $reader = New-Object IO.BinaryReader($stream)
    try {
        if ($stream.Length -lt 22) { throw 'Generated ZIP is incomplete.' }
        $stream.Position = $stream.Length - 22
        if ($reader.ReadUInt32() -ne 0x06054b50) { throw 'Generated ZIP has an unexpected end record.' }
        $stream.Position = $stream.Length - 12
        $entryCount = $reader.ReadUInt16()
        $centralSize = $reader.ReadUInt32()
        $centralStart = $reader.ReadUInt32()
        if ($entryCount -eq 65535 -or $centralStart -eq [uint32]::MaxValue -or $centralSize -eq [uint32]::MaxValue) {
            throw 'Unexpected ZIP64 release; explicit executable-mode packaging needs review.'
        }
        $position = [long]$centralStart
        for ($index = 0; $index -lt $entryCount; $index++) {
            $stream.Position = $position
            if ($reader.ReadUInt32() -ne 0x02014b50) { throw 'Generated ZIP central directory is invalid.' }
            $stream.Position = $position + 5
            $stream.WriteByte(3)
            $stream.Position = $position + 28
            $nameLength = $reader.ReadUInt16()
            $extraLength = $reader.ReadUInt16()
            $commentLength = $reader.ReadUInt16()
            $position += 46 + $nameLength + $extraLength + $commentLength
        }
        if ($position -ne ([long]$centralStart + $centralSize)) { throw 'Generated ZIP directory bounds do not match.' }
    }
    finally { $reader.Dispose(); $stream.Dispose() }
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$resolvedOutDir = [IO.Path]::GetFullPath($(if ([IO.Path]::IsPathRooted($OutDir)) { $OutDir } else { Join-Path $repoRoot $OutDir }))
$goCommand = Get-Command go -ErrorAction SilentlyContinue
$portableRoot = Join-Path $repoRoot 'build\_toolchain\go'
if ($goCommand) {
    $goExecutable = $goCommand.Source
} elseif (Test-Path -LiteralPath (Join-Path $portableRoot 'bin\go.exe')) {
    $goExecutable = Join-Path $portableRoot 'bin\go.exe'
} else {
    throw 'Go was not found; install Go 1.22 or newer, or prepare build\_toolchain\go.'
}

# Use the project's existing isolated caches without changing persistent settings.
$environmentNames = @('GOOS', 'GOARCH', 'CGO_ENABLED', 'GOROOT', 'GOPATH', 'GOCACHE', 'GOTMPDIR', 'GOTOOLCHAIN', 'GOENV')
$previousEnvironment = @{}
foreach ($name in $environmentNames) {
    $previousEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}
$utf8 = New-Object Text.UTF8Encoding($false)
$releaseFiles = New-Object 'System.Collections.Generic.List[string]'
$sums = New-Object 'System.Collections.Generic.List[string]'
$archiveStream = $null
$archiveObject = $null
Push-Location $repoRoot
try {
    if (-not $goCommand) { $env:GOROOT = $portableRoot }
    $env:GOPATH = Join-Path $repoRoot 'build\_gopath'
    $env:GOCACHE = Join-Path $repoRoot 'build\_gocache'
    $env:GOTMPDIR = Join-Path $repoRoot 'build\_gotmp'
    $env:GOTOOLCHAIN = 'local'
    $env:GOENV = 'off'
    $env:CGO_ENABLED = '0'
    New-Item -ItemType Directory -Force -Path $resolvedOutDir, $env:GOPATH, $env:GOCACHE, $env:GOTMPDIR | Out-Null

    foreach ($targetOS in @('darwin', 'linux')) {
        foreach ($targetArchitecture in @('amd64', 'arm64')) {
            $env:GOOS = $targetOS
            $env:GOARCH = $targetArchitecture
            $platform = "$targetOS-$targetArchitecture"
            $platformDirectory = Join-Path $resolvedOutDir $platform
            New-Item -ItemType Directory -Force -Path $platformDirectory | Out-Null
            foreach ($program in @('bridge-target', 'bridge-cli')) {
                $binaryPath = Join-Path $platformDirectory $program
                & $goExecutable build -trimpath -ldflags '-s -w' -o $binaryPath "./cmd/$program"
                if ($LASTEXITCODE -ne 0) { throw "$platform $program build failed (exit $LASTEXITCODE)." }
                $relativePath = "$platform/$program"
                $digest = (Get-FileHash -LiteralPath $binaryPath -Algorithm SHA256).Hash.ToLowerInvariant()
                $sums.Add("$digest  $relativePath")
                $releaseFiles.Add($relativePath)
                Write-Host "Generated $binaryPath"
            }
        }
    }

    if ($WindowsManager) {
        $managerSource = (Resolve-Path -LiteralPath $WindowsManager).Path
        $managerDirectory = Join-Path $resolvedOutDir 'manager-windows'
        New-Item -ItemType Directory -Force -Path $managerDirectory | Out-Null
        $managerDestination = Join-Path $managerDirectory 'bridge-cli.exe'
        Copy-Item -LiteralPath $managerSource -Destination $managerDestination -Force
        $digest = (Get-FileHash -LiteralPath $managerDestination -Algorithm SHA256).Hash.ToLowerInvariant()
        $sums.Add("$digest  manager-windows/bridge-cli.exe")
        $releaseFiles.Add('manager-windows/bridge-cli.exe')
    }

    # Always publish shell entrypoints with LF and no BOM, even from Windows.
    foreach ($launcher in @('start-unix.sh', 'Start.command')) {
        $source = Join-Path $repoRoot "scripts\$launcher"
        $contents = [IO.File]::ReadAllText($source).Replace("`r`n", "`n").Replace("`r", "`n")
        [IO.File]::WriteAllText((Join-Path $resolvedOutDir $launcher), $contents, $utf8)
        $releaseFiles.Add($launcher)
    }
    Copy-Item -LiteralPath (Join-Path $repoRoot 'docs\TESTING-UNIX.txt') -Destination (Join-Path $resolvedOutDir 'TESTING-UNIX.txt') -Force
    $releaseFiles.Add('TESTING-UNIX.txt')
    [IO.File]::WriteAllText((Join-Path $resolvedOutDir 'SHA256SUMS'), (($sums -join "`n") + "`n"), $utf8)
    $releaseFiles.Add('SHA256SUMS')
    Write-Host "Generated $resolvedOutDir (4 platforms, 8 binaries, entrypoints and SHA256SUMS)."

    if ($Archive) {
        # Do not infer Unix executable bits from NTFS or Windows tar behavior.
        # ZIP entries explicitly declare regular files with 0755/0644 modes.
        Add-Type -AssemblyName System.IO.Compression
        $archivePath = Join-Path (Split-Path -Parent $resolvedOutDir) 'RemoteBridge-unix.zip'
        $archiveStream = [IO.File]::Open($archivePath, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None)
        $archiveObject = New-Object IO.Compression.ZipArchive($archiveStream, [IO.Compression.ZipArchiveMode]::Create, $true)
        foreach ($relativePath in $releaseFiles) {
            $entry = $archiveObject.CreateEntry("unix/$relativePath", [IO.Compression.CompressionLevel]::Optimal)
            $isExecutable = $relativePath -match '^(darwin|linux)-(amd64|arm64)/bridge-(target|cli)$' -or $relativePath -in @('start-unix.sh', 'Start.command')
            $entry.ExternalAttributes = $(if ($isExecutable) { [int]0x81ed0000 } else { [int]0x81a40000 })
            $entryStream = $entry.Open()
            $sourceStream = [IO.File]::OpenRead((Join-Path $resolvedOutDir $relativePath))
            try { $sourceStream.CopyTo($entryStream) }
            finally { $sourceStream.Dispose(); $entryStream.Dispose() }
        }
        $archiveObject.Dispose()
        $archiveObject = $null
        $archiveStream.Dispose()
        $archiveStream = $null
        Set-ZipUnixPlatform $archivePath
        Write-Host "Generated $archivePath (explicit Unix file modes; only release files are included)."
    }
}
finally {
    if ($archiveObject) { $archiveObject.Dispose() }
    if ($archiveStream) { $archiveStream.Dispose() }
    Pop-Location
    foreach ($name in $environmentNames) {
        [Environment]::SetEnvironmentVariable($name, $previousEnvironment[$name], 'Process')
    }
}
