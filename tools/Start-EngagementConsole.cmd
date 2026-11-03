@echo off
rem Opens the engagement console (double-click). Runs Windows PowerShell in STA mode with no console window.
start "" powershell.exe -NoProfile -STA -ExecutionPolicy Bypass -WindowStyle Hidden -File "%~dp0Start-EngagementConsole.ps1" %*
