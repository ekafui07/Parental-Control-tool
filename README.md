

-----

# 🛡️ Parental Control Tool

A lightweight, robust Windows-native security application designed to monitor and restrict access to inappropriate online content. It operates silently as a background service, utilizing a multi-layered defense strategy—including DNS enforcement, system hosts file management, and active process monitoring—to ensure a safe digital environment.

## ⚠️ Disclaimer

**Legal and Ethical Use:** This software is provided "as-is" and is intended *strictly* for parents or legal guardians monitoring minor children on devices they legally own and control.

-----

## 📸 Screenshots

> (assets/active_block_list.png)
The Active Blocks tab showing monitored domains

-----

## 🚀 Key Features

  * **Multi-Layered Blocking:** Combines a hardcoded list of 60+ adult, gambling, and violence-related domains with keyword-based filtering, plus 20+ torrent sites.
  * **Video File Blocking:** Blocks all video formats (.mp4, .mkv, .avi, .mov, .flv, .webm, and 35+ more) via HTTP proxy interception and network packet inspection.
  * **DNS Enforcement:** Automatically locks system DNS settings to **Cloudflare for Families (1.1.1.3)** to filter out malware and adult content.
  * **Browser Extension Blocking:** Disables all extensions in Chrome, Edge, Firefox, Opera, Brave, and Vivaldi—new installations blocked via Group Policy.
  * **Bypass Prevention:** Continuously monitors and terminates processes for VPNs, proxy tools, and specialized browsers (like Tor or Brave) that could circumvent filters.
  * **Persistent Service:** Runs as a **Windows Service 24/7**, re-enforcing the system hosts file every 30 seconds and HTTP proxy every 60 seconds.
  * **Administrative Control:** Includes a Management GUI that requires a password to add custom blocks, remove blocks, or monitor protection status.
  * **Audit Logging:** Tracks blocked attempts and bypass activities directly in the **Windows Event Log**.

-----

## ⚙️ Prerequisites

Before installing, ensure your system meets the following requirements:

  * **OS:** Windows 10 or Windows 11
  * **Framework:** [.NET 8.0 SDK](Ensure you install the SDK, not just the Runtime) Download Link: https://dotnet.microsoft.com/en-us/download/dotnet/thank-you/sdk-8.0.419-windows-x64-installer
  * **Permissions:** Administrator privileges are strictly required.


-----

## 📥 Installation

1.  Clone or download this repository to your local machine.
2.  Navigate to the extracted folder.
3.  Right-click on `INSTALL.bat` and select **Run as Administrator**.
4.  Wait for the PowerShell script to build and install the service. You will see green `[OK]` messages upon success.
5.  A "Parental Control" shortcut will automatically appear on your Desktop.

> **Note:** If the installer stops or shows red `[FAILED]` messages, check the `install.log` file generated in the root directory. Common issues include missing the .NET 8 SDK or interference from Antivirus software.

-----

## 🖥️ Initial Configuration & Usage

Once installed, the blocking begins immediately. To manage the settings:

1.  Open the **Parental Control** app from your Desktop shortcut.
2.  **Admin Password:** `n0Zone2017` (hardcoded, cannot be changed)
3.  Use the GUI to:
      * Monitor live protection status (DNS, Proxy, Extensions, VPN blocking)
      * View recent audit log entries
      * Add custom domain blocks (requires password)
      * Remove custom blocks (requires password)
      * Force re-enforce all protections

From the GUI, you can monitor live protection status, view audit logs, and manually add or remove custom domain blocks.

-----

## 🛡️ Uninstallation

To completely remove the background service and all blocking rules:

1.  Navigate to the repository folder.
2.  Right-click `UNINSTALL.bat` and select **Run as Administrator**.
3.  Confirm any prompts.

-----

## 🤝 Contributing

Contributions, issues, and feature requests are welcome\!

1.  Fork the repository.
2.  Create your feature branch (`git checkout -b feature/AmazingFeature`).
3.  Commit your changes (`git commit -m 'Add some AmazingFeature'`).
4.  Push to the branch (`git push origin feature/AmazingFeature`).
5.  Open a Pull Request.

-----

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.