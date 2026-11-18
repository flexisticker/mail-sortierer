@echo off
rem Postwart – Notfall-Zugang: setzt ein neues Passwort (braucht Administratorrechte).
net session >nul 2>&1 || (powershell -NoProfile -Command "Start-Process -Verb RunAs -FilePath '%~f0'" & exit /b)
cd /d "%~dp0app"
set DATA_DIR=%ProgramData%\Mail-Sortierer\data
"%~dp0node\node.exe" --no-warnings src\reset-admin.js
echo.
set /p NAME=Benutzername fuer das neue Passwort: 
if "%NAME%"=="" exit /b
"%~dp0node\node.exe" --no-warnings src\reset-admin.js "%NAME%"
echo.
pause
