Here is the fully fleshed-out, professional README file. You can copy and paste this directly into your GitHub repository's `README.md` file.

-----

# 🛡️ Parental Control Tool

A lightweight, robust Windows-native security application designed to monitor and restrict access to inappropriate online content. It operates silently as a background service, utilizing a multi-layered defense strategy—including DNS enforcement, system hosts file management, and active process monitoring—to ensure a safe digital environment.

## ⚠️ Disclaimer

**Legal and Ethical Use:** This software is provided "as-is" and is intended *strictly* for parents or legal guardians monitoring minor children on devices they legally own and control. The author is not responsible for any system instability, data loss, or legal repercussions resulting from the use or misuse of this tool. Modifying system-level configurations (like the `hosts` file and DNS) carries inherent risks.

-----

## 📸 Screenshots

*(Replace the links below with actual screenshots of your application once uploaded to your repo)*

> (assets/active_block_list.png)
> *The Active Blocks tab showing monitored domains.*

> (assets/settings.png)
> *The Settings tab for administrative control.*

-----

## 🚀 Key Features

  * **Multi-Layered Blocking:** Combines a hardcoded list of over 60 major adult, gambling, and violence-related domains with keyword-based filtering.
  * **DNS Enforcement:** Automatically locks system DNS settings to **Cloudflare for Families (1.1.1.3)** to filter out malware and adult content.
  * **Bypass Prevention:** Continuously monitors and terminates processes for VPNs, proxy tools, and specialized browsers (like Tor or Brave) that could be used to circumvent filters.
  * **Persistent Service:** Runs as a **Windows Service 24/7**, re-enforcing the system hosts file every 30 seconds to prevent manual tampering.
  * **Administrative Control:** Includes a Management GUI that requires a password to add custom blocks, remove blocks, or change settings.
  * **Audit Logging:** Tracks blocked attempts and bypass activities directly in the **Windows Event Log**.

-----

## ⚙️ Prerequisites

Before installing, ensure your system meets the following requirements:

  * **OS:** Windows 10 or Windows 11
  * **Framework:** [.NET 8.0 SDK](https://dotnet.microsoft.com/download/dotnet/8.0) (Ensure you install the SDK, not just the Runtime)
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
2.  Navigate to the **Settings** tab.
3.  **CHANGE YOUR PASSWORD IMMEDIATELY.**
      * **Default Password:** `ParentAdmin123`

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