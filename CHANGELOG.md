# Changelog

All notable changes to this project are listed here, newest first. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions use `major.minor`.

## [1.2] - 2026-10-23

### Added
- **`Update-SecureBootCert-GUI.cmd`**: a window for the steps of `Update-SecureBootCert.ps1`, in a single file that opens with a double-click (asks for administrator rights once).
  - Shows Secure Boot, the Windows version, whether Windows UEFI CA 2023 is in the Secure Boot DB, whether KB5073724 is installed and the value of `AvailableUpdates`.
  - Lists the certificates found in the firmware (KEK and DB) with their status: valid, expired or expiring.
  - Lets you choose the steps: install KB5073724 (Windows 10 only), install all pending Windows updates, and deploy Windows UEFI CA 2023 to the Secure Boot DB.
  - Nothing is changed until you click **Start update** and confirm. The confirmation reminds you to have your BitLocker recovery key.
  - **Restart now** button (30 seconds to cancel with `shutdown /a`); two restarts are needed.
  - Log of every step at the bottom of the window.
- `CHANGELOG.md`, a version badge and a Changelog section in the README.
- `.gitattributes` to keep CRLF line endings in the GUI file.

### Changed
- The version number (1.2) is now in the header of `Update-SecureBootCert.ps1`, `RunMe.bat` and the GUI.

### Notes
- The GUI does not install the PSWindowsUpdate module that the script uses to download KB5073724; it uses the Microsoft Update Catalog download and DISM, as the script does next.
- `Update-SecureBootCert.ps1` and `RunMe.bat` behave as in 1.1 (only comment lines changed).

## [1.1] - 2026-07-13

### Changed
- Adjusted the expired-certificate logic for the post-June 2026 deadline.

## [1.0] - 2026-01-26

### Added
- First version: `Update-SecureBootCert.ps1`, `RunMe.bat` and the READMEs (English and Traditional Chinese).

[1.2]: ../../releases/tag/v1.2
[1.1]: ../../releases/tag/v1.1
[1.0]: ../../releases/tag/v1.0
