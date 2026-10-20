param(
    [string]$OutDir = "dist\windows-amd64",
    [switch]$Archive
)

$ErrorActionPreference = "Stop"

if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
    throw "Go was not found; install Go 1.22 or newer on the build machine."
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$resolvedOutDir = if ([System.IO.Path]::IsPathRooted($OutDir)) { $OutDir } else { Join-Path $repoRoot $OutDir }
New-Item -ItemType Directory -Force -Path $resolvedOutDir | Out-Null

$oldGOOS = $env:GOOS
$oldGOARCH = $env:GOARCH
$oldCGO = $env:CGO_ENABLED
try {
	Push-Location $repoRoot
	$env:GOOS = "windows"
	$env:GOARCH = "amd64"
	$env:CGO_ENABLED = "0"
	go build -trimpath -ldflags "-s -w -H windowsgui" -o (Join-Path $resolvedOutDir "bridge-target.exe") .\cmd\bridge-target
	if ($LASTEXITCODE -ne 0) { throw "bridge-target build failed (exit $LASTEXITCODE)" }
	go build -trimpath -ldflags "-s -w" -o (Join-Path $resolvedOutDir "bridge-cli.exe") .\cmd\bridge-cli
	if ($LASTEXITCODE -ne 0) { throw "bridge-cli build failed (exit $LASTEXITCODE)" }
	Copy-Item (Join-Path $repoRoot "scripts\bridge-target-admin.cmd") (Join-Path $resolvedOutDir "bridge-target-admin.cmd") -Force
	Copy-Item (Join-Path $repoRoot "REMOTE-BRIDGE-SSH.md") (Join-Path $resolvedOutDir "REMOTE-BRIDGE-SSH.md") -Force
	Copy-Item (Join-Path $repoRoot "docs\TESTING-WINRM.txt") (Join-Path $resolvedOutDir "TESTING-WINRM.txt") -Force
	Copy-Item (Join-Path $repoRoot "docs\托管会话设计.md") (Join-Path $resolvedOutDir "MANAGED-SESSIONS.md") -Force
	$packageSource = Join-Path $repoRoot "packages\openssh"
	$packageArchive = Join-Path $packageSource "OpenSSH-Win64.zip"
	$packageManifest = Join-Path $packageSource "manifest.json"
	if ((Test-Path -LiteralPath $packageArchive) -and (Test-Path -LiteralPath $packageManifest)) {
		$packageDestination = Join-Path $resolvedOutDir "packages\openssh"
		New-Item -ItemType Directory -Force -Path $packageDestination | Out-Null
		Copy-Item -LiteralPath $packageArchive (Join-Path $packageDestination "OpenSSH-Win64.zip") -Force
		Copy-Item -LiteralPath $packageManifest (Join-Path $packageDestination "manifest.json") -Force
		Write-Host "Generated $(Join-Path $packageDestination 'OpenSSH-Win64.zip')"
		Write-Host "Generated $(Join-Path $packageDestination 'manifest.json')"
	}
	Write-Host "Generated $(Join-Path $resolvedOutDir 'bridge-target.exe')"
	Write-Host "Generated $(Join-Path $resolvedOutDir 'bridge-cli.exe')"
	Write-Host "Generated $(Join-Path $resolvedOutDir 'bridge-target-admin.cmd')"
	Write-Host "Generated $(Join-Path $resolvedOutDir 'REMOTE-BRIDGE-SSH.md')"
	Write-Host "Generated $(Join-Path $resolvedOutDir 'TESTING-WINRM.txt')"
	if ($Archive) {
		$archivePath = Join-Path (Split-Path -Parent $resolvedOutDir) 'RemoteBridge-windows-amd64.zip'
		$buildRoot = [IO.Path]::GetFullPath((Join-Path $repoRoot 'build'))
		$archiveStage = [IO.Path]::GetFullPath((Join-Path $buildRoot ('_archive-' + [Guid]::NewGuid().ToString('N'))))
		if (-not $archiveStage.StartsWith($buildRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
			throw 'Archive staging path escaped the build directory.'
		}
		try {
			$archiveFiles = @('bridge-target.exe', 'bridge-cli.exe', 'bridge-target-admin.cmd', 'REMOTE-BRIDGE-SSH.md', 'TESTING-WINRM.txt', 'MANAGED-SESSIONS.md')
			if ((Test-Path -LiteralPath $packageArchive) -and (Test-Path -LiteralPath $packageManifest)) {
				$archiveFiles += @('packages\openssh\OpenSSH-Win64.zip', 'packages\openssh\manifest.json')
			}
			$archiveRelease = Join-Path $archiveStage 'windows-amd64'
			foreach ($relativeFile in $archiveFiles) {
				$stageFile = Join-Path $archiveRelease $relativeFile
				New-Item -ItemType Directory -Force -Path (Split-Path -Parent $stageFile) | Out-Null
				Copy-Item -LiteralPath (Join-Path $resolvedOutDir $relativeFile) -Destination $stageFile
			}
			Compress-Archive -LiteralPath $archiveRelease -DestinationPath $archivePath -Force
		}
		finally {
			if (Test-Path -LiteralPath $archiveStage) { Remove-Item -LiteralPath $archiveStage -Recurse -Force }
		}
		Write-Host "Generated $archivePath"
	}
}
finally {
	Pop-Location
    $env:GOOS = $oldGOOS
    $env:GOARCH = $oldGOARCH
    $env:CGO_ENABLED = $oldCGO
}
