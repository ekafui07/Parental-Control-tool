@echo off
:: Parental Control - Uninstaller launcher

echo.
echo ================================================
echo   PARENTAL CONTROL - UNINSTALLATION
echo ================================================
echo.
echo Requesting Administrator privileges...
echo.

powershell -Command "Start-Process powershell -ArgumentList '-ExecutionPolicy Bypass -File \"%~dp0Uninstall-ParentalControl.ps1\"' -Verb RunAs -Wait"

echo.
echo Uninstallation process finished.
echo.
pause
