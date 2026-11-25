$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$source = Join-Path $root "data"
if (-not (Test-Path $source)) { throw "No data directory found." }
$dest = Join-Path $root "backups"
New-Item -ItemType Directory -Force -Path $dest | Out-Null
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$archive = Join-Path $dest "wallet-rng-data-$stamp.zip"
Compress-Archive -Path $source -DestinationPath $archive -CompressionLevel Optimal
Get-ChildItem $dest -Filter "wallet-rng-data-*.zip" | Sort-Object LastWriteTime -Descending | Select-Object -Skip 7 | Remove-Item -Force
Write-Host "Encrypted vault/database backup created: $archive"
