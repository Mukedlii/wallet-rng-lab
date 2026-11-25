param(
  [Parameter(Mandatory=$true)][string]$Patch,
  [switch]$Approve
)
$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $PSScriptRoot)
if (-not (Test-Path .venv\Scripts\python.exe)) { throw "Run scripts\install.ps1 first." }
$argsList = @("scripts\repair.py", $Patch)
if ($Approve) { $argsList += "--approve" }
& .\.venv\Scripts\python.exe @argsList
exit $LASTEXITCODE
