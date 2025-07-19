# SimpleIPTV Project

This project provides tools for interacting with IPTV services through a GUI, CLI, or standalone portal detection script. Below are the details for dependencies, usage, and additional notes.

## Dependencies

### GUI Version
- **tk**: Required for the graphical user interface. Install using your system's package manager:
  - **Debian/Ubuntu**: `sudo apt-get install python3-tk`
  - **Fedora**: `sudo dnf install python3-tkinter`
  - **Arch Linux**: `sudo pacman -S tk`
- **requests** and **cloudscraper**: Install via pip:
  ```bash
  pip install requests cloudscraper
  ```

### CLI Version
- **requests** and **cloudscraper**: Install via pip:
  ```bash
  pip install requests cloudscraper
  ```

### PortalDetect Standalone
- **requests** and **cloudscraper**: Install via pip:
  ```bash
  pip install requests cloudscraper
  ```

## Usage

### GUI
Run the graphical interface with:
```bash
python SimpleIptvGUI.py
```
This launches an interactive GUI for managing IPTV services.

### CLI
Run the interactive command-line interface with:
```bash
python SimpleIptv.py
```
The CLI is fully interactive, guiding you through the process without additional command-line arguments.

**Note**: The default output path for results is `/storage/emulated/0/hits/`. To change this:
- Open `SimpleIptv.py` in a text editor.
- Locate the output path variable (e.g., `output_path`) and modify it to your desired directory.
- Ensure the path is valid for your operating system (Linux/Windows).

### PortalDetect Standalone
Run the standalone portal detection script with:
```bash
python portaldetect-standalone.py
```
This script is also integrated into both the GUI and CLI versions, so you may not need to run it separately.

## Additional Notes
- **PortalDetect Integration**: The portal detection functionality is already included in both the GUI (`SimpleIptvGUI.py`) and CLI (`SimpleIptv.py`) versions, making the standalone script optional.
- **AppImage Build**: The provided build scripts for creating an AppImage are tailored for **Arch Linux**. If you're using another distribution, you may need to adapt the scripts or build process.
- **Cross-Platform Compatibility**: Ensure the output path is correctly set for your operating system, especially on Linux or Windows, as the default path (`/storage/emulated/0/hits/`) is Android-specific.
- **Python Version**: This project requires Python 3.x. Ensure you have it installed before running the scripts.
