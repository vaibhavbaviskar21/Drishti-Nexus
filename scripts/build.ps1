# Build script for Windows: produces bin\drishti.exe (single static binary,
# web assets and IANA timezone data embedded; no cgo).

$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $PSScriptRoot)

if (-not (Get-Command "go" -ErrorAction SilentlyContinue)) {
    Write-Host "Error: Go is not installed or not in PATH" -ForegroundColor Red
    exit 1
}

$version = if ($env:DRISHTI_VERSION) { $env:DRISHTI_VERSION } else { "1.1.0-dev" }
$output = "bin\drishti.exe"

Write-Host "Go version:" -ForegroundColor Yellow
go version

Write-Host "`nBuilding $output (version $version)..." -ForegroundColor Yellow
$env:CGO_ENABLED = "0"
go build -ldflags="-s -w -X drishti-nexus/internal/version.Version=$version" -o $output ./cmd/drishti

if ($LASTEXITCODE -eq 0) {
    $sizeMB = [math]::Round((Get-Item $output).Length / 1MB, 2)
    Write-Host "`nBuild successful: $output ($sizeMB MB)" -ForegroundColor Green
    Write-Host "Run '.\$output help' to get started" -ForegroundColor Yellow
} else {
    Write-Host "`nBuild failed" -ForegroundColor Red
    exit 1
}
