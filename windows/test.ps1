# Prüft das Setup auf dem GitHub-Windows-Rechner: still installieren, Dienst + Oberfläche, Rechte, drüber installieren, deinstallieren.
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$setup = Get-ChildItem (Join-Path $root 'dist-windows') -Filter 'Mail-Sortierer-Setup-*.exe' | Select-Object -First 1
if (-not $setup) { throw 'Setup nicht gefunden' }
$data = Join-Path $env:ProgramData 'Mail-Sortierer'

function Wait-Health {
  for ($i = 0; $i -lt 60; $i++) {
    try { $r = Invoke-RestMethod 'http://127.0.0.1:8110/health' -TimeoutSec 3; if ($r.ok) { return } } catch { }
    Start-Sleep 2
  }
  Get-ChildItem "$data\logs" -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "--- $($_.Name)"; Get-Content $_.FullName -Tail 30 }
  throw 'Mail-Sortierer antwortet nicht'
}

Write-Host '1) Installieren (still, mit Scanner-Ordner)'
$p = Start-Process $setup.FullName -ArgumentList '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', '/SP-', '/TASKS=scan', "/LOG=$env:TEMP\ms-setup.log" -Wait -PassThru
if ($p.ExitCode) { Get-Content "$env:TEMP\ms-setup.log" -Tail 40; throw "Setup Exit $($p.ExitCode)" }
Wait-Health
$svc = Get-Service 'Mail-Sortierer'
if ($svc.Status -ne 'Running') { throw 'Dienst läuft nicht' }
$html = (Invoke-WebRequest 'http://127.0.0.1:8110/einrichten' -UseBasicParsing).Content
if ($html -notmatch 'Konto anlegen') { throw 'Einrichtungsseite fehlt' }
if (-not (Test-Path 'C:\Scans')) { throw 'Scanner-Ordner wurde nicht angelegt' }
$xml = Get-Content "${env:ProgramFiles}\Mail-Sortierer\Mail-Sortierer-Dienst.xml" -Raw
if ($xml -notmatch 'SCAN_DIR" value="C:\\Scans') { throw 'SCAN_DIR fehlt in der Dienst-Konfiguration' }

Write-Host '2) Rechte am Datenordner'
$acl = (Get-Acl $data).Access | ForEach-Object { $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value }
if ($acl | Where-Object { $_ -notin @('S-1-5-18', 'S-1-5-32-544') }) { throw "Fremde Rechte am Datenordner: $acl" }

Write-Host '3) Notfall-Zugang'
$env:DATA_DIR = "$data\data"
& "${env:ProgramFiles}\Mail-Sortierer\node\node.exe" --no-warnings "${env:ProgramFiles}\Mail-Sortierer\app\src\reset-admin.js" test
if ($LASTEXITCODE) { throw 'Notfall-Zugang fehlgeschlagen' }

Write-Host '4) Drüber installieren (Sicherung muss entstehen)'
$p = Start-Process $setup.FullName -ArgumentList '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', '/SP-' -Wait -PassThru
if ($p.ExitCode) { throw "Update-Setup Exit $($p.ExitCode)" }
Wait-Health
if (-not (Get-ChildItem "$data\update-sicherungen" -Recurse -Filter 'mail-sortierer.sqlite')) { throw 'Keine Sicherung vor dem Update' }

Write-Host '5) Deinstallieren (Daten bleiben)'
$un = Get-ChildItem "${env:ProgramFiles}\Mail-Sortierer" -Filter 'unins*.exe' | Select-Object -First 1
$p = Start-Process $un.FullName -ArgumentList '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART' -Wait -PassThru
Start-Sleep 3
if (Get-Service 'Mail-Sortierer' -ErrorAction SilentlyContinue) { throw 'Dienst nach Deinstallation noch vorhanden' }
if (-not (Test-Path "$data\data\mail-sortierer.sqlite")) { throw 'Daten wurden gelöscht' }
Write-Host 'Alles in Ordnung.'
