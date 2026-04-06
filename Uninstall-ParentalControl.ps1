#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"
$LogFile = "$PSScriptRoot\uninstall.log"

function Write-Log {
    param($Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $Message" | Tee-Object -FilePath $LogFile -Append
}

# ============================================
# PASSWORD CHECK — Must pass before anything runs
# ============================================
function Get-PasswordHash {
    param([string]$Password)
    $saltedPassword = $Password + "ParentalControlSalt"
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($saltedPassword)
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    $hashBytes = $sha256.ComputeHash($bytes)
    return [Convert]::ToBase64String($hashBytes)
}

function Verify-AdminPassword {
    param([string]$InputPassword)

    # Load saved password hash (same file the app uses)
    $passwordFile = Join-Path $env:ProgramData "ParentalControl\admin.pwd"

    if (Test-Path $passwordFile) {
        $savedHash = (Get-Content $passwordFile -Raw).Trim()
    } else {
        # Fall back to default if not yet changed
        $savedHash = Get-PasswordHash "ParentAdmin123"
    }

    $inputHash = Get-PasswordHash $InputPassword
    return $inputHash -eq $savedHash
}

# Prompt for password using a GUI dialog
Add-Type -AssemblyName System.Windows.Forms

$form = New-Object System.Windows.Forms.Form
$form.Text = "Parental Control — Uninstall Authentication"
$form.Size = New-Object System.Drawing.Size(420, 200)
$form.StartPosition = "CenterScreen"
$form.FormBorderStyle = "FixedDialog"
$form.MaximizeBox = $false
$form.MinimizeBox = $false
$form.TopMost = $true

$label = New-Object System.Windows.Forms.Label
$label.Text = "Enter admin password to uninstall Parental Control:"
$label.Location = New-Object System.Drawing.Point(20, 25)
$label.Size = New-Object System.Drawing.Size(370, 20)
$form.Controls.Add($label)

$textBox = New-Object System.Windows.Forms.TextBox
$textBox.Location = New-Object System.Drawing.Point(20, 55)
$textBox.Size = New-Object System.Drawing.Size(360, 25)
$textBox.UseSystemPasswordChar = $true
$form.Controls.Add($textBox)

$okButton = New-Object System.Windows.Forms.Button
$okButton.Text = "Confirm Uninstall"
$okButton.Location = New-Object System.Drawing.Point(20, 100)
$okButton.Size = New-Object System.Drawing.Size(150, 32)
$okButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
$okButton.BackColor = [System.Drawing.Color]::DarkRed
$okButton.ForeColor = [System.Drawing.Color]::White
$okButton.FlatStyle = "Flat"
$form.Controls.Add($okButton)

$cancelButton = New-Object System.Windows.Forms.Button
$cancelButton.Text = "Cancel"
$cancelButton.Location = New-Object System.Drawing.Point(185, 100)
$cancelButton.Size = New-Object System.Drawing.Size(100, 32)
$cancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
$form.Controls.Add($cancelButton)

$form.AcceptButton = $okButton
$form.CancelButton = $cancelButton

$result = $form.ShowDialog()

if ($result -ne [System.Windows.Forms.DialogResult]::OK) {
    Write-Log "Uninstall cancelled by user."
    [System.Windows.Forms.MessageBox]::Show(
        "Uninstall cancelled.",
        "Cancelled",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Information
    ) | Out-Null
    exit 0
}

$enteredPassword = $textBox.Text

if (-not (Verify-AdminPassword $enteredPassword)) {
    Write-Log "FAILED uninstall attempt — wrong password."

    # Log to Windows Event Log as a bypass attempt
    try {
        Write-EventLog -LogName Application -Source "ParentalControl" `
            -EventId 1001 -EntryType Error `
            -Message "BYPASS ATTEMPT: Failed uninstall — incorrect password entered."
    } catch { }

    [System.Windows.Forms.MessageBox]::Show(
        "Incorrect password. Uninstall blocked.`n`nThis attempt has been logged.",
        "Access Denied",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Error
    ) | Out-Null
    exit 1
}

Write-Log "Password verified. Proceeding with uninstall."

# ============================================
# ACTUAL UNINSTALL (only runs after password check)
# ============================================
try {
    Write-Log "===== PARENTAL CONTROL UNINSTALLATION STARTED ====="

    # Step 1: Stop the service
    Write-Log "Stopping service..."
    Write-Host "Stopping Parental Control service..." -ForegroundColor Cyan

    $service = Get-Service -Name "ParentalControlService" -ErrorAction SilentlyContinue
    if ($service) {
        Stop-Service -Name "ParentalControlService" -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        Write-Host "[OK] Service stopped" -ForegroundColor Green
    } else {
        Write-Log "Service not found"
        Write-Host "[WARNING] Service not found" -ForegroundColor Yellow
    }

    # Step 2: Delete the service
    Write-Log "Deleting service..."
    Write-Host "Removing service..." -ForegroundColor Cyan
    sc.exe delete ParentalControlService | Out-Null
    Start-Sleep -Seconds 1
    Write-Host "[OK] Service removed" -ForegroundColor Green

    # Step 3: Clean hosts file
    Write-Log "Cleaning hosts file..."
    Write-Host "Cleaning hosts file..." -ForegroundColor Cyan

    $hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
    if (Test-Path $hostsPath) {
        $cleanedLines = Get-Content $hostsPath | Where-Object { $_ -notmatch "# PARENTAL-CONTROL" }
        Set-Content -Path $hostsPath -Value $cleanedLines
        Write-Host "[OK] Hosts file cleaned" -ForegroundColor Green
    }

    # Step 4: Remove desktop shortcut
    Write-Log "Removing desktop shortcut..."
    $desktopPath = [Environment]::GetFolderPath("Desktop")
    $shortcutPath = Join-Path $desktopPath "Parental Control.lnk"
    if (Test-Path $shortcutPath) {
        Remove-Item $shortcutPath -Force
        Write-Host "[OK] Desktop shortcut removed" -ForegroundColor Green
    }

    # Step 5: Remove data files
    Write-Log "Removing configuration files..."
    $dataPath = Join-Path $env:ProgramData "ParentalControl"
    if (Test-Path $dataPath) {
        Remove-Item $dataPath -Recurse -Force
        Write-Host "[OK] Configuration files removed" -ForegroundColor Green
    }

    Write-Log "===== UNINSTALLATION COMPLETED SUCCESSFULLY ====="
    Write-Host "`n================================================" -ForegroundColor Green
    Write-Host "  PARENTAL CONTROL - UNINSTALLED" -ForegroundColor Green
    Write-Host "================================================" -ForegroundColor Green
    Write-Host "`nAll blocking has been removed." -ForegroundColor Cyan
    Write-Host "`nPress any key to exit..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

} catch {
    Write-Log "ERROR: $($_.Exception.Message)"
    Write-Host "`n[ERROR]" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    Write-Host "`nSee uninstall.log for details" -ForegroundColor Yellow
    Write-Host "`nPress any key to exit..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit 1
}
