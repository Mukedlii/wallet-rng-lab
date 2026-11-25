$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $PSScriptRoot)
if (-not (Test-Path .venv\Scripts\python.exe)) { throw "Run scripts\install.ps1 first." }
if (Test-Path .env) { Get-Content .env | ForEach-Object { if ($_ -match '^\s*([^#=]+)=(.*)$') { [Environment]::SetEnvironmentVariable($matches[1].Trim(),$matches[2].Trim(),"Process") } } }
& .\.venv\Scripts\python.exe -m research_engine worker
