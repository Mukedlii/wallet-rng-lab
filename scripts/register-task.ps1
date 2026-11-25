$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$start = Join-Path $root "scripts\start.ps1"
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$start`""
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
$settings = New-ScheduledTaskSettingsSet -RestartCount 5 -RestartInterval (New-TimeSpan -Minutes 2) -ExecutionTimeLimit ([TimeSpan]::Zero) -StartWhenAvailable
Register-ScheduledTask -TaskName "WalletRNGResearchEngine" -Action $action -Trigger $trigger -Settings $settings -Description "Starts the local Wallet RNG Research Engine at user logon." -Force | Out-Null
Write-Host "Scheduled task registered for $env:USERNAME."
