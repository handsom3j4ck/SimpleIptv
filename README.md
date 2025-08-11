# SimpleIptv – IPTV Portal Scanner & MAC Brute-Force Tool

**SimpleIptv** is a Python-based tool designed to detect and test IPTV portal endpoints (e.g., MAG/STB portals) by scanning for valid configurations and brute-forcing MAC addresses. It supports **GUI**, **CLI**, and a **standalone portal detection script**, making it accessible for both beginners and advanced users.

> 🔒 **This tool is strictly for educational and authorized testing purposes only. Unauthorized access to IPTV services or network scanning without permission is illegal.**

---

## ⚠️ Legal and Ethical Warning

This project is intended **only** for:
- Educational research
- Penetration testing (with **explicit written authorization**)
- Network diagnostics in controlled environments
- Recovery of personal devices with proof of ownership

**Unauthorized use** to access, bypass, or exploit IPTV services may violate:
- **Computer Fraud and Abuse Act (CFAA)**
- **Digital Millennium Copyright Act (DMCA)**
- **ISP and service provider terms of service**

> 🛑 **The author and contributors are not responsible for any misuse, legal consequences, or damages resulting from unauthorized use.**

### ✅ Always:
- Obtain **written consent** before testing any system.
- Use in **isolated, authorized environments**.
- Respect **privacy, data ownership, and local laws**.

---

## 📦 Features

| Feature | Description |
|--------|-------------|
| **Portal Detection** | Automatically scans for valid IPTV portal endpoints (e.g., `c/portal.php`, `portalstb/portal.php`) using intelligent pattern matching. |
| **MAC Address Brute-Force** | Generates and tests random MAC addresses to find valid accounts. |
| **Expiration Detection** | Parses account expiration dates and filters hits by validity (e.g., skips accounts with less than 1 day remaining). |
| **Multi-threaded Scanning** | Supports up to 15 parallel bots for faster scanning. |
| **Custom MAC Prefix** | Allows user-defined MAC prefixes (e.g., `00:1A:79:`) for targeted scans. |
| **Cloudflare Bypass** | Uses `cloudscraper` to handle Cloudflare-protected portals. |
| **GUI (Tkinter)** | Full-featured graphical interface with real-time hit display, status updates, and dynamic column resizing. |
| **CLI Version** | Interactive command-line interface with progress tracking. |
| **Standalone PortalDetect** | Lightweight script to detect portal types only (no MAC scanning). |

> 🔗 **Note**: The **PortalDetect** functionality is already built into both the **GUI** and **CLI** versions. The standalone script is optional for users who only want endpoint detection.

---

## 📦 Dependencies

### Required for All Versions
- **Python 3.6+**
- `requests`
- `cloudscraper`

Install via pip:
```bash
pip install requests cloudscraper
```

### GUI Version (`SimpleIptvGUI.py`)
- **tkinter** (usually included with Python)
- Install if missing:
  - **Debian/Ubuntu**: `sudo apt-get install python3-tk`
  - **Arch Linux**: `sudo pacman -S tk`
  - **Windows**: Tkinter is included with Python from [python.org](https://python.org)
  - **Android-Termux**: Not supported (Tkinter not available)

### CLI Version (`SimpleIptv.py`)
- No additional dependencies beyond `requests` and `cloudscraper`

### PortalDetect (`PortalDetect.py`)
- Lightweight version for portal detection only
- Same dependencies as CLI

---

## 🛠️ Installation

1. **Clone the Repository**
   ```bash
   git clone https://github.com/handsom3j4ck/SimpleIptv.git
   cd SimpleIptv
   ```

2. **Install Dependencies**
   ```bash
   pip install requests cloudscraper
   ```

3. **(Optional) Install Tkinter for GUI**
   ```bash
   # Debian/Ubuntu
   sudo apt-get install python3-tk

   # Arch Linux
   sudo pacman -S tk
   ```

---

## 🎯 Usage

### 1. GUI Version (Recommended for Beginners)
Launch the graphical interface:
```bash
python SimpleIptvGUI.py
```

**Features:**
- Input validation with tooltips
- Real-time hit table with scrollbars
- Dynamic column resizing
- Portal detection dialog
- Pause/resume/stop controls
- Output file selection

> 📌 **Note**: GUI not supported on Android-Termux.

---

### 2. CLI Version (Interactive)
Run the command-line interface:
```bash
python SimpleIptv.py
```

The script will guide you through:
- Entering the portal URL
- Selecting scan attempts and bot count
- Choosing a MAC prefix (optional)
- Detecting portal type
- Starting the scan

---

### 3. PortalDetect (Standalone – Portal Detection Only)
Run the lightweight portal detection script:
```bash
python PortalDetect.py
```

- Enter a portal URL
- Automatically detects valid endpoints (e.g., `c/portal.php`, `server/load.php`)
- Outputs detected portal types

> 🔍 **Note**: This functionality is **already included** in both the GUI and CLI versions. Use this script only if you want **portal detection without MAC scanning**.

---

## 📁 Output Path

- **Default Output Path**: `/storage/emulated/0/hits/` (Android-specific)
- **To Change Output Path**:
  1. Open `SimpleIptv.py` or `SimpleIptvGUI.py` in a text editor
  2. Locate the `output_dir` or `output_file` variable
  3. Modify it to your desired path (e.g., `./hits/`, `/home/user/hits/`)
  4. Ensure the directory exists and is writable

> 💡 **Tip**: In the GUI version, you can **select the output file manually** using the "Select Output File" button.

---

## ⚙️ Customization

### Filter Hits by Expiration
To skip accounts with less than 1 day remaining, search for:
```python
# Check for negative or <1 day
```
You can modify the condition to:
- Skip accounts with less than 7 days: `if days < 7:`
- Skip expired accounts only: `if days < 0:`

### Add Custom MAC Prefixes
Edit the `mac_prefixes` list in any script:
```python
mac_prefixes = [
    'D4:CF:F9:', '33:44:CF:', '00:1A:79:',  # Add your own
]
```

### Add New Portal Endpoints
Modify the `endpoints` and `paths` lists to include custom portal paths:
```python
endpoints = [
    "c/portal.php",
    "custom_portal.php",
    # Add more
]

paths = [
    "/c/",
    "/myportal/",
    # Add more
]
```

---

## 🛑 Troubleshooting

| Issue | Solution |
|------|----------|
| `ModuleNotFoundError: No module named 'cloudscraper'` | Run `pip install cloudscraper` |
| `No module named 'tkinter'` | Install Tkinter: `sudo apt-get install python3-tk` |
| GUI not opening on Windows | Ensure Python was installed from [python.org](https://python.org) with Tkinter enabled |
| No hits found | Try a different portal type or increase scan attempts |
| Portal detection fails | The server may block requests; try a different URL or check connectivity |
| Output file not created | Ensure the output directory exists and is writable |

---


## 🙌 Acknowledgments

- Developers of `cloudscraper` and `requests`
- Open-source community for inspiration and feedback
- Security researchers in the IPTV and STB ecosystem

---

## 📬 Contact

For issues, suggestions, or responsible disclosure, please open a GitHub Issue.

> 🔐 **Do not use this tool for malicious purposes. Respect privacy, legality, and ethics.**

---

## 🏁 Disclaimer

**SimpleIptv** is a proof-of-concept tool for detecting and testing IPTV portal configurations. It is **not designed to exploit vulnerabilities** but to help understand network behavior and improve security.

Always act responsibly. Unauthorized access to systems you do not own or have permission to test is a crime.
