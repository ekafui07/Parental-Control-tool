#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"
$PSScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host "================================================"
Write-Host "  PARENTAL CONTROL - BUILD FOR DEPLOYMENT"
Write-Host "================================================"
Write-Host ""

# Check .NET 8 SDK
Write-Host "Checking .NET 8 SDK..." -ForegroundColor Cyan
$dotnetVersion = & dotnet --version 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "[FAILED] .NET 8 SDK not found" -ForegroundColor Red
    Write-Host "Download from: https://dotnet.microsoft.com/download/dotnet/8.0" -ForegroundColor Yellow
    exit 1
}
Write-Host "[OK] .NET version: $dotnetVersion" -ForegroundColor Green
Write-Host ""

# Clean previous builds
Write-Host "Cleaning previous builds..." -ForegroundColor Cyan
Remove-Item -Path "$PSScriptRoot\bin\Release" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$PSScriptRoot\obj" -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "[OK] Clean complete" -ForegroundColor Green
Write-Host ""

# Build
Write-Host "Building Parental Control..." -ForegroundColor Cyan
& dotnet build "$PSScriptRoot\ParentalControl.csproj" --configuration Release
if ($LASTEXITCODE -ne 0) {
    Write-Host "[FAILED] Build failed" -ForegroundColor Red
    exit 1
}
Write-Host "[OK] Build successful" -ForegroundColor Green
Write-Host ""

# Publish as self-contained
Write-Host "Publishing self-contained executable..." -ForegroundColor Cyan
$publishDir = "$PSScriptRoot\bin\Release\publish"
& dotnet publish "$PSScriptRoot\ParentalControl.csproj" `
    --configuration Release `
    --self-contained `
    --runtime win-x64 `
    --output $publishDir

if ($LASTEXITCODE -ne 0) {
    Write-Host "[FAILED] Publish failed" -ForegroundColor Red
    exit 1
}
Write-Host "[OK] Published to: $publishDir" -ForegroundColor Green
Write-Host ""

# Find the exe
$exePath = Get-ChildItem -Path $publishDir -Filter "ParentalControl.exe" | Select-Object -First 1
if ($exePath) {
    $size = [math]::Round($exePath.Length / 1MB, 2)
    Write-Host "[OK] Executable: $($exePath.FullName)" -ForegroundColor Green
    Write-Host "[OK] Size: ${size} MB" -ForegroundColor Green
    Write-Host ""
    Write-Host "DEPLOYMENT READY!" -ForegroundColor Green
    Write-Host ""
    Write-Host "Next steps:" -ForegroundColor Yellow
    Write-Host "1. Copy $($publishDir) to deployment machine" -ForegroundColor White
    Write-Host "2. Run: ParentalControl.exe (as Administrator)" -ForegroundColor White
    Write-Host "   OR use INSTALL.bat for automatic service installation" -ForegroundColor White
} else {
    Write-Host "[FAILED] ParentalControl.exe not found" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "Press any key to exit..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
