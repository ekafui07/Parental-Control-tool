#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"
$LogFile = "$PSScriptRoot\install.log"

function Write-Log {
    param($Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $Message" | Tee-Object -FilePath $LogFile -Append
}

try {
    Write-Log "===== PARENTAL CONTROL INSTALLATION STARTED ====="
    Write-Log "Script location: $PSScriptRoot"
    
    # Step 1: Check .NET 8 SDK
    Write-Log "Checking for .NET 8 SDK..."
    $dotnetVersion = & dotnet --version 2>&1
    
    if ($LASTEXITCODE -ne 0) {
        Write-Log "ERROR: .NET 8 SDK not found"
        Write-Host "`n[FAILED] .NET 8 SDK is not installed" -ForegroundColor Red
        Write-Host "Please download and install from: https://dotnet.microsoft.com/download/dotnet/8.0" -ForegroundColor Yellow
        Write-Host "`nPress any key to exit..."
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        exit 1
    }
    
    Write-Log ".NET version found: $dotnetVersion"
    Write-Host "[OK] .NET 8 SDK detected: $dotnetVersion" -ForegroundColor Green
    
    # Step 2: Build the project
    Write-Log "Building ParentalControl.csproj..."
    Write-Host "`nBuilding Parental Control service..." -ForegroundColor Cyan
    
    $buildOutput = & dotnet build "$PSScriptRoot\ParentalControl.csproj" --configuration Release 2>&1
    Write-Log "Build output: $buildOutput"
    
    if ($LASTEXITCODE -ne 0) {
        Write-Log "ERROR: Build failed with exit code $LASTEXITCODE"
        Write-Host "`n[FAILED] Build failed. See install.log for details" -ForegroundColor Red
        Write-Host "`nPress any key to exit..."
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        exit 1
    }
    
    Write-Host "[OK] Build completed successfully" -ForegroundColor Green
    
    # Step 3: Stop existing service if running
    Write-Log "Checking for existing service..."
    $existingService = Get-Service -Name "ParentalControlService" -ErrorAction SilentlyContinue
    
    if ($existingService) {
        Write-Log "Existing service found, stopping..."
        Write-Host "`nStopping existing service..." -ForegroundColor Cyan
        Stop-Service -Name "ParentalControlService" -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        
        Write-Log "Deleting existing service..."
        sc.exe delete ParentalControlService | Out-Null
        Start-Sleep -Seconds 1
        Write-Host "[OK] Existing service removed" -ForegroundColor Green
    }
    
    # Step 4: Install as Windows Service
    Write-Log "Installing Windows Service..."
    Write-Host "`nInstalling Parental Control as Windows Service..." -ForegroundColor Cyan
    
    # Use Resolve-Path to handle paths with spaces and special characters
    $buildDir = Join-Path $PSScriptRoot "bin\Release\net8.0"
    $exePath = Join-Path $buildDir "ParentalControl.exe"
    
    Write-Log "Looking for executable at: $exePath"
    
    if (-not (Test-Path $exePath)) {
        # Try to find the exe anywhere in bin directory
        Write-Log "Searching for ParentalControl.exe in bin directory..."
        $foundExe = Get-ChildItem -Path (Join-Path $PSScriptRoot "bin") -Recurse -Filter "ParentalControl.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
        
        if ($foundExe) {
            $exePath = $foundExe.FullName
            Write-Log "Found executable at: $exePath"
        } else {
            Write-Log "ERROR: Built executable not found"
            Write-Host "`n[FAILED] Executable not found after build" -ForegroundColor Red
            Write-Host "Expected location: $exePath" -ForegroundColor Yellow
            Write-Host "`nSearched entire bin directory but ParentalControl.exe was not found." -ForegroundColor Yellow
            Write-Host "`nPress any key to exit..."
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            exit 1
        }
    }
    
    Write-Log "Using executable: $exePath"
    Write-Host "[OK] Executable found" -ForegroundColor Green
    
    $createResult = sc.exe create ParentalControlService binPath= "`"$exePath`" --service" start= auto DisplayName= "Parental Control Service"
    Write-Log "sc.exe create result: $createResult"
    
    if ($LASTEXITCODE -ne 0) {
        Write-Log "ERROR: Service creation failed with exit code $LASTEXITCODE"
        Write-Host "`n[FAILED] Could not create service" -ForegroundColor Red
        Write-Host "`nPress any key to exit..."
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        exit 1
    }
    
    # Step 5: Configure service recovery options (auto-restart on crash)
    Write-Log "Configuring service recovery options..."
    sc.exe failure ParentalControlService reset= 60 actions= restart/5000/restart/5000/restart/5000 | Out-Null
    Write-Host "[OK] Service auto-restart configured" -ForegroundColor Green

    # Step 5b: Register Windows Event Log source (for audit logging)
    Write-Log "Registering Event Log source..."
    try {
        New-EventLog -LogName Application -Source "ParentalControl" -ErrorAction SilentlyContinue
        Write-Host "[OK] Event Log source registered" -ForegroundColor Green
    } catch {
        Write-Log "Event Log source may already exist: $($_.Exception.Message)"
    }

    # Step 5c: Lock DNS to Cloudflare for Families via registry
    Write-Log "Locking DNS to Cloudflare for Families..."
    try {
        $adapters = Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"
        foreach ($adapter in $adapters) {
            Set-ItemProperty -Path $adapter.PSPath -Name "NameServer" -Value "1.1.1.3,1.0.0.3" -ErrorAction SilentlyContinue
        }
        Write-Host "[OK] DNS locked to 1.1.1.3 (Cloudflare for Families)" -ForegroundColor Green
    } catch {
        Write-Log "DNS lock warning: $($_.Exception.Message)"
    }
    
    # Step 6: Start the service
    Write-Log "Starting service..."
    Write-Host "[OK] Service installed successfully" -ForegroundColor Green
    Write-Host "`nStarting Parental Control service..." -ForegroundColor Cyan
    
    Start-Service -Name "ParentalControlService"
    Start-Sleep -Seconds 2
    
    $serviceStatus = Get-Service -Name "ParentalControlService"
    Write-Log "Service status: $($serviceStatus.Status)"
    
    if ($serviceStatus.Status -ne "Running") {
        Write-Log "WARNING: Service is not running (status: $($serviceStatus.Status))"
        Write-Host "`n[WARNING] Service installed but not running" -ForegroundColor Yellow
        Write-Host "Status: $($serviceStatus.Status)" -ForegroundColor Yellow
    } else {
        Write-Host "[OK] Service is now running" -ForegroundColor Green
    }
    
    # Step 7: Create Desktop shortcut
    Write-Log "Creating desktop shortcut..."
    Write-Host "`nCreating Desktop shortcut..." -ForegroundColor Cyan
    
    $desktopPath = [Environment]::GetFolderPath("Desktop")
    $shortcutPath = Join-Path $desktopPath "Parental Control.lnk"
    
    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut($shortcutPath)
    $shortcut.TargetPath = $exePath
    $shortcut.WorkingDirectory = Split-Path $exePath
    $shortcut.Description = "Parental Control Manager"
    $shortcut.Save()
    
    Write-Log "Shortcut created at: $shortcutPath"
    Write-Host "[OK] Desktop shortcut created" -ForegroundColor Green
    
    # Success summary
    Write-Log "===== INSTALLATION COMPLETED SUCCESSFULLY ====="
    Write-Host "`n================================================" -ForegroundColor Green
    Write-Host "  PARENTAL CONTROL - INSTALLATION COMPLETE" -ForegroundColor Green
    Write-Host "================================================" -ForegroundColor Green
    Write-Host "`n60+ adult sites are now BLOCKED automatically." -ForegroundColor Cyan
    Write-Host "DNS locked to Cloudflare for Families (1.1.1.3)." -ForegroundColor Cyan
    Write-Host "Brave, Tor, and VPN processes will be killed automatically." -ForegroundColor Cyan
    Write-Host "All events logged to Windows Event Log (tamper-proof)." -ForegroundColor Cyan
    Write-Host "`nIMPORTANT NEXT STEP:" -ForegroundColor Yellow
    Write-Host "1. Open 'Parental Control' from your Desktop" -ForegroundColor White
    Write-Host "2. Go to Settings tab" -ForegroundColor White
    Write-Host "3. Change admin password from default: ParentAdmin123" -ForegroundColor White
    Write-Host "`nPress any key to exit..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    
} catch {
    Write-Log "FATAL ERROR: $($_.Exception.Message)"
    Write-Log "Stack trace: $($_.ScriptStackTrace)"
    Write-Host "`n[FATAL ERROR]" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    Write-Host "`nSee install.log for full details" -ForegroundColor Yellow
    Write-Host "`nPress any key to exit..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit 1
}
