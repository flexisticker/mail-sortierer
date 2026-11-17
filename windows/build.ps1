# Baut das Windows-Setup des Mail-Sortierers (läuft in der GitHub Action auf windows-latest).
# Ergebnis: dist-windows\Mail-Sortierer-Setup-<Version>.exe
param([string]$Build = '', [string]$Commit = '')
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$version = (Get-Content package.json -Raw | ConvertFrom-Json).version

# Programmordner zusammenstellen (wie im Docker-Image: src + public + Laufzeit-Pakete)
$b = Join-Path $PSScriptRoot 'build'
if (Test-Path $b) { Remove-Item -Recurse -Force $b }
New-Item -ItemType Directory -Force "$b\app", "$b\node" | Out-Null
Copy-Item package.json, package-lock.json "$b\app"
Copy-Item -Recurse src "$b\app\src"
Copy-Item -Recurse public "$b\app\public"
Push-Location "$b\app"
npm ci --omit=dev --no-audit --no-fund
if ($LASTEXITCODE) { Pop-Location; throw 'npm ci fehlgeschlagen' }
Pop-Location

# Node.js mit node:sqlite und Dienst-Wrapper WinSW (MIT-Lizenz)
$node = (Get-Command node).Source
Copy-Item $node "$b\node\node.exe"
& "$b\node\node.exe" -e "require('node:sqlite'); console.log('Node', process.version, 'mit node:sqlite')"
if ($LASTEXITCODE) { throw 'Node.js ohne node:sqlite' }
$nodeMin = [version]'22.23.5'
$nodeVer = [version]((& "$b\node\node.exe" -p 'process.versions.node').Trim())
if ($nodeVer -lt $nodeMin) { throw "Node.js $nodeVer ist älter als $nodeMin" }
Invoke-WebRequest 'https://github.com/winsw/winsw/releases/download/v2.12.0/WinSW-x64.exe' -OutFile "$b\Mail-Sortierer-Dienst.exe" -UseBasicParsing

# Inno Setup
$iscc = @("${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe", "$env:ProgramFiles\Inno Setup 6\ISCC.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $iscc) {
  choco install innosetup -y --no-progress | Out-Null
  $iscc = @("${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe", "$env:ProgramFiles\Inno Setup 6\ISCC.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
}
if (-not $iscc) { throw 'Inno Setup nicht gefunden' }
& $iscc "/DAppVersion=$version" "/DAppBuild=$Build" "/DAppCommit=$Commit" (Join-Path $PSScriptRoot 'Mail-Sortierer.iss')
if ($LASTEXITCODE) { throw 'Inno Setup fehlgeschlagen' }
Get-ChildItem dist-windows
