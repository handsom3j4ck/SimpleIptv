# SimpleIptv

This project provides a MAC address bruteforce tool for IPTV services, offering a GUI, CLI, or standalone portal detection script to test and identify valid IPTV portal connections. It is intended strictly for educational purposes and should only be used in controlled environments with explicit permission from service providers. Unauthorized use may violate applicable laws and terms of service.

## Dependencies

### GUI Version

- **tk**: Required for the graphical user interface. Install using your system's package manager:

  - **Debian/Ubuntu**: `sudo apt-get install python3-tk`
  - **Arch Linux**: `sudo pacman -S tk`
  - **Windows**: Tkinter is included with Python 3.x installations. Ensure Python is installed from python.org.
  - **Android-Termux**: The GUI version is not supported on Android-Termux due to limitations with Tkinter on mobile platforms.

- **requests** and **cloudscraper**: Install via pip:

  ```bash
  pip install requests cloudscraper
  ```

- **python-pip**: Required to install Python packages. Install using your system's package manager:

  - **Debian/Ubuntu**: `sudo apt-get install python3-pip`
  - **Arch Linux**: `sudo pacman -S python-pip`
  - **Windows**: Pip is included with Python 3.x installations. Ensure Python is added to your system PATH during installation.
  - **Android-Termux**: `pkg install python-pip`

### CLI Version

- **requests** and **cloudscraper**: Install via pip:

  ```bash
  pip install requests cloudscraper
  ```

- **python-pip**: Required to install Python packages. Install using your system's package manager:

  - **Debian/Ubuntu**: `sudo apt-get install python3-pip`
  - **Arch Linux**: `sudo pacman -S python-pip`
  - **Windows**: Pip is included with Python 3.x installations. Ensure Python is added to your system PATH during installation.
  - **Android-Termux**: `pkg install python-pip`

### PortalDetect

- **requests** and **cloudscraper**: Install via pip:

  ```bash
  pip install requests cloudscraper
  ```

- **python-pip**: Required to install Python packages. Install using your system's package manager:

  - **Debian/Ubuntu**: `sudo apt-get install python3-pip`
  - **Arch Linux**: `sudo pacman -S python-pip`
  - **Windows**: Pip is included with Python 3.x installations. Ensure Python is added to your system PATH during installation.
  - **Android-Termux**: `pkg install python-pip`

## Usage

### GUI

Run the graphical interface with:

```bash
python SimpleIptvGUI.py
```

**Note**: The GUI version is not supported on Android-Termux due to Tkinter limitations on mobile platforms.

### CLI

Run command-line interface with:

```bash
python SimpleIptv.py
```

The CLI is fully interactive, guiding you through the process without additional command-line arguments.

**Note**: The default output path for results is `/storage/emulated/0/hits/`. To change this:

- Open `SimpleIptv.py` in a text editor.
- Locate the output path variable (e.g., `output_path`) and modify it to your desired directory.
- Ensure the path is valid for your operating system (Linux/Windows).

### PortalDetect

Run the standalone portal detection script with:

```bash
python PortalDetect.py
```

- **The portal detection functionality is already included in both the GUI (**`SimpleIptvGUI.py`**) and CLI (**`SimpleIptv.py`**) versions, making the standalone script optional.**

## Additional Notes

- **Pre-built AppImages available**
- **Cross-Platform Compatibility**: Ensure the output path is correctly set for your operating system, especially on Linux, Windows, as the default path (`/storage/emulated/0/hits/`) is Android-specific.
- **Python Version**: This project requires Python 3.x. Ensure you have it installed before running the scripts.
