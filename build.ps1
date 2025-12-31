# Build script for Windows
# Compiles Drishti Nexus into a single executable with embedded assets

$ErrorActionPreference = "Stop"

Write-Host "╔═══════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║   Building Drishti Nexus               ║" -ForegroundColor Cyan
Write-Host "╚═══════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Check if Go is installed
if (-not (Get-Command "go" -ErrorAction SilentlyContinue)) {
    Write-Host "Error: Go is not installed or not in PATH" -ForegroundColor Red
    exit 1
}

Write-Host "Go version:" -ForegroundColor Yellow
go version

Write-Host "`nDownloading dependencies..." -ForegroundColor Yellow
go mod download

Write-Host "`nBuilding executable..." -ForegroundColor Yellow

# Build with embedded FS and optimizations
$buildTime = Get-Date -Format "yyyy-MM-dd_HH:mm:ss"
$output = "drishti.exe"

go build -ldflags="-s -w" -o $output .

if ($LASTEXITCODE -eq 0) {
    Write-Host "`n✓ Build successful!" -ForegroundColor Green
    Write-Host ""
    
    $fileInfo = Get-Item $output
    $sizeKB = [math]::Round($fileInfo.Length / 1KB, 2)
    $sizeMB = [math]::Round($fileInfo.Length / 1MB, 2)
    
    Write-Host "Output: $output" -ForegroundColor Cyan
    Write-Host "Size: $sizeMB MB ($sizeKB KB)" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Run './$output help' to get started" -ForegroundColor Yellow
} else {
    Write-Host "`n✗ Build failed" -ForegroundColor Red
    exit 1
}
