param([Parameter(Mandatory=$true)][string]$Backup)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
if (-not (Test-Path $Backup)) { throw "Backup ZIP not found." }
$temp = Join-Path $env:TEMP ("wallet-rng-restore-" + [guid]::NewGuid().ToString("N"))
Expand-Archive -LiteralPath $Backup -DestinationPath $temp
$incoming = Join-Path $temp "data"
if (-not (Test-Path $incoming)) { throw "Backup does not contain a data directory." }
$target = Join-Path $root "data"
if (Test-Path $target) {
  $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
  Move-Item $target (Join-Path $root ("data-before-restore-" + $stamp))
}
Copy-Item $incoming $target -Recurse
Remove-Item $temp -Recurse -Force
Write-Host "Restore completed. Run vault-check to verify your passphrase."
