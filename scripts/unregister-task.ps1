$ErrorActionPreference = "Stop"
Unregister-ScheduledTask -TaskName "WalletRNGResearchEngine" -Confirm:$false -ErrorAction SilentlyContinue
Write-Host "Scheduled task removed."
