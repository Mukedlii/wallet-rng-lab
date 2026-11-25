$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
foreach ($item in @(".env","data","backups")) {
  $path = Join-Path $root $item
  if (Test-Path $path) {
    & icacls $path /inheritance:r /grant:r "$($env:USERNAME):(OI)(CI)F" /T | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Failed to restrict permissions on $path" }
  }
}
Write-Host "Local data ACLs restricted to current Windows user."
