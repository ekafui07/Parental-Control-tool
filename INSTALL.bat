@echo off
:: Parental Control - One-click installer launcher
:: Double-click this file to install

echo.
echo ================================================
echo   PARENTAL CONTROL - INSTALLATION
echo ================================================
echo.
echo Requesting Administrator privileges...
echo.

powershell -Command "Start-Process powershell -ArgumentList '-ExecutionPolicy Bypass -File \"%~dp0Install-ParentalControl.ps1\"' -Verb RunAs -Wait"

echo.
echo Installation process finished.
echo Check the window above for results.
echo.
pause
