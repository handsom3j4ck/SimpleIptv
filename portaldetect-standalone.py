# requests cloudscraper

import os
import sys
import time
import re
import requests
import json
import logging
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

# List of endpoints, prioritized by commonality
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

def main():
    portal = input("Enter portal URL: ")
    if not portal.strip():
        print("Portal URL is required.")
        sys.exit(1)

    portal = clean_portal(portal)
    found_endpoints = detect_endpoints(portal)
    
    if not found_endpoints:
        print("No portal types detected.")
        sys.exit(1)

    print("\nDetected Portal Types:")
    for i, endpoint in enumerate(found_endpoints, 1):
        print(f"  Portal Type {i}: {endpoint}")

if __name__ == "__main__":
    main()