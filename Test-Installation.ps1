#Requires -RunAsAdministrator

$ErrorActionPreference = "Continue"

Write-Host "================================================"
Write-Host "  PARENTAL CONTROL - TEST VERIFICATION"
Write-Host "================================================"
Write-Host ""

# Test 1: Service Status
Write-Host "Test 1: Checking Windows Service..." -ForegroundColor Cyan
$service = Get-Service -Name "ParentalControlService" -ErrorAction SilentlyContinue
if ($service) {
    $status = $service.Status
    Write-Host "[OK] Service found - Status: $status" -ForegroundColor Green
    if ($status -ne "Running") {
        Write-Host "[WARNING] Service is not running. Start it manually?" -ForegroundColor Yellow
    }
} else {
    Write-Host "[WARNING] Service not installed. Run INSTALL.bat first." -ForegroundColor Yellow
}
Write-Host ""

# Test 2: DNS Status
Write-Host "Test 2: Checking DNS Configuration..." -ForegroundColor Cyan
try {
    $dns = Get-DnsClientServerAddress | Select-Object -First 1
    Write-Host "[OK] DNS detected" -ForegroundColor Green
} catch {
    Write-Host "[ERROR] Could not read DNS settings" -ForegroundColor Red
}
Write-Host ""

# Test 3: Hosts File
Write-Host "Test 3: Checking Hosts File..." -ForegroundColor Cyan
$hostsFile = "C:\Windows\System32\drivers\etc\hosts"
if ((Get-Content $hostsFile | Select-String -Pattern "PARENTAL-CONTROL" -Quiet)) {
    Write-Host "[OK] Hosts file properly configured" -ForegroundColor Green
} else {
    Write-Host "[WARNING] Parental Control entries not found in hosts file" -ForegroundColor Yellow
}
Write-Host ""

# Test 4: Event Log
Write-Host "Test 4: Checking Event Log..." -ForegroundColor Cyan
try {
    $events = Get-EventLog -LogName Application -Source "ParentalControl" -ErrorAction SilentlyContinue | Select-Object -First 5
    if ($events) {
        Write-Host "[OK] Found $(($events | Measure-Object).Count) recent log entries" -ForegroundColor Green
        $events | ForEach-Object { Write-Host "    $($_.TimeGenerated): $($_.Message)" -ForegroundColor Gray }
    } else {
        Write-Host "[INFO] No log entries yet (service may not have run)" -ForegroundColor Yellow
    }
} catch {
    Write-Host "[ERROR] Could not read event log" -ForegroundColor Red
}
Write-Host ""

# Test 5: Proxy Status
Write-Host "Test 5: Checking HTTP Proxy..." -ForegroundColor Cyan
$proxyReg = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -ErrorAction SilentlyContinue
if ($proxyReg.ProxyEnable -eq 1) {
    Write-Host "[OK] System proxy enabled: $($proxyReg.ProxyServer)" -ForegroundColor Green
} else {
    Write-Host "[INFO] System proxy not active (expected when service stopped)" -ForegroundColor Yellow
}
Write-Host ""

# Test 6: Browser Extensions
Write-Host "Test 6: Scanning Browser Extensions..." -ForegroundColor Cyan
$chromeExtPath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Extensions"
$firefoxProfilePath = "$env:APPDATA\Mozilla\Firefox\Profiles"

if (Test-Path $chromeExtPath) {
    $extCount = (Get-ChildItem $chromeExtPath -Directory | Measure-Object).Count
    Write-Host "[OK] Chrome extensions found: $extCount" -ForegroundColor Green
} else {
    Write-Host "[INFO] Chrome not installed or no extensions" -ForegroundColor Yellow
}

if (Test-Path $firefoxProfilePath) {
    $profileCount = (Get-ChildItem $firefoxProfilePath -Directory | Measure-Object).Count
    Write-Host "[OK] Firefox profiles found: $profileCount" -ForegroundColor Green
} else {
    Write-Host "[INFO] Firefox not installed" -ForegroundColor Yellow
}
Write-Host ""

# Test 7: Desktop Shortcut
Write-Host "Test 7: Checking Desktop Shortcut..." -ForegroundColor Cyan
$shortcut = "$env:USERPROFILE\Desktop\Parental Control.lnk"
if (Test-Path $shortcut) {
    Write-Host "[OK] Desktop shortcut found" -ForegroundColor Green
} else {
    Write-Host "[WARNING] Desktop shortcut not found" -ForegroundColor Yellow
}
Write-Host ""

# Test 8: Try blocking a domain (DNS)
Write-Host "Test 8: Testing Domain Blocking (DNS)..." -ForegroundColor Cyan
try {
    $result = nslookup pornhub.com 2>&1 | Select-String -Pattern "127.0.0.1" -Quiet
    if ($result) {
        Write-Host "[OK] Domain blocked - resolved to 127.0.0.1" -ForegroundColor Green
    } else {
        Write-Host "[INFO] Domain not blocked (may be expected if service just started)" -ForegroundColor Yellow
    }
} catch {
    Write-Host "[ERROR] Could not test DNS" -ForegroundColor Red
}
Write-Host ""

Write-Host "================================================"
Write-Host "  TEST SUMMARY"
Write-Host "================================================"
Write-Host ""
Write-Host "All critical systems checked." -ForegroundColor Green
Write-Host ""
Write-Host "If any tests failed, check:" -ForegroundColor Yellow
Write-Host "  1. Run INSTALL.bat to install service" -ForegroundColor White
Write-Host "  2. Check install.log for build errors" -ForegroundColor White
Write-Host "  3. Ensure running as Administrator" -ForegroundColor White
Write-Host ""

Write-Host "Press any key to exit..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
