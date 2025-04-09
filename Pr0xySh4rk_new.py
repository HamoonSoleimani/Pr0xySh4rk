#!/usr/bin/env python3
import argparse
import base64
import concurrent.futures
import socket
import asyncio # Keep asyncio import, now used for UDP tests
import urllib.parse
import requests
import os
import signal
import sys
import json
import time
import subprocess
import re
import shutil
import urllib3 # For disabling warnings
import hashlib # For caching keys
from typing import List, Dict, Optional, Any, Tuple, Union
from pathlib import Path
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import random # For selecting Iran test targets

# --- Optional Dependency Imports ---
try:
    import ipaddress
except ImportError:
    ipaddress = None
    print("Warning: 'ipaddress' module not found. IPv6 address normalization might be limited.", file=sys.stderr)

try:
    from tqdm import tqdm
except ImportError:
    tqdm = None
    print("Warning: 'tqdm' module not found. Progress bar will not be displayed.", file=sys.stderr)
    # Simple fallback progress display function if tqdm is not available
    def fallback_tqdm(iterable, total=None, desc=None, **kwargs):
        # ... (fallback_tqdm implementation from your original script) ...
        if total is None:
            try:
                total = len(iterable)
            except TypeError:
                total = '?'
        current = 0
        start_time = time.monotonic()
        if desc:
            print(f"{desc}: ", file=sys.stderr, end='')

        last_update_time = start_time
        for item in iterable:
            yield item
            current += 1
            now = time.monotonic()
            # Update progress roughly every second or every 10 items
            if now - last_update_time > 1.0 or current % 10 == 0 or current == total:
                percentage = (current / total * 100) if isinstance(total, (int, float)) and total > 0 else 0
                elapsed = now - start_time
                eta_str = '?'
                if percentage > 0 and total != '?':
                    try:
                        eta = (elapsed / percentage) * (100 - percentage)
                        eta_str = str(timedelta(seconds=int(eta)))
                    except: # Handle potential division by zero or type errors
                        eta_str = '?'

                print(f"\r{desc}: [{percentage:3.0f}%] {current}/{total} | Elapsed: {timedelta(seconds=int(elapsed))}, ETA: {eta_str}   ", file=sys.stderr, end='')
                last_update_time = now
        print(file=sys.stderr) # Newline at the end

    # Use the fallback if tqdm is missing
    if tqdm is None:
        tqdm_progress = fallback_tqdm
    else:
        tqdm_progress = tqdm

try:
    import geoip2.database
    import geoip2.errors
except ImportError:
    geoip2 = None
    # GeoIP is now less critical with the Iran-focused checks, but keep the warning
    # print("Warning: 'geoip2' module not found. GeoIP database lookups (--geoip-db) are disabled.", file=sys.stderr)
    # print("         Install with: pip install geoip2-database", file=sys.stderr)

try:
    from dotenv import load_dotenv
    load_dotenv() # Load environment variables from .env file if it exists
    # print("Info: Loaded environment variables from .env file (if found).", file=sys.stderr)
except ImportError:
    pass # dotenv is optional

# Suppress only the InsecureRequestWarning from urllib3 needed during fetching
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- Constants ---
# ... (COUNTRY_FLAGS remain the same) ...
COUNTRY_FLAGS = {
    "AC": "🇦🇨", "AD": "🇦🇩", "AE": "🇦🇪", "AF": "🇦🇫", "AG": "🇦🇬", "AI": "🇦🇮", "AL": "🇦🇱", "AM": "🇦🇲",
    "AO": "🇦🇴", "AQ": "🇦🇶", "AR": "🇦🇷", "AS": "🇦🇸", "AT": "🇦🇹", "AU": "🇦🇺", "AW": "🇦🇼", "AX": "🇦🇽",
    "AZ": "🇦🇿", "BA": "🇧🇦", "BB": "🇧🇧", "BD": "🇧🇩", "BE": "🇧🇪", "BF": "🇧🇫", "BG": "🇧🇬", "BH": "🇧🇭",
    "BI": "🇧🇮", "BJ": "🇧🇯", "BL": "🇧🇱", "BM": "🇧🇲", "BN": "🇧🇳", "BO": "🇧🇴", "BQ": "🇧🇶", "BR": "🇧🇷",
    "BS": "🇧🇸", "BT": "🇧🇹", "BV": "🇧🇻", "BW": "🇧🇼", "BY": "🇧🇾", "BZ": "🇧🇿", "CA": "🇨🇦", "CC": "🇨🇨",
    "CD": "🇨🇩", "CF": "🇨🇫", "CG": "🇨🇬", "CH": "🇨🇭", "CI": "🇨🇮", "CK": "🇨🇰", "CL": "🇨🇱", "CM": "🇨🇲",
    "CN": "🇨🇳", "CO": "🇨🇴", "CR": "🇨🇷", "CU": "🇨🇺", "CV": "🇨🇻", "CW": "🇨🇼", "CX": "🇨🇽", "CY": "🇨🇾",
    "CZ": "🇨🇿", "DE": "🇩🇪", "DJ": "🇩🇯", "DK": "🇩🇰", "DM": "🇩🇲", "DO": "🇩🇴", "DZ": "🇩🇿", "EC": "🇪🇨",
    "EE": "🇪🇪", "EG": "🇪🇬", "EH": "🇪🇭", "ER": "🇪🇷", "ES": "🇪🇸", "ET": "🇪🇹", "EU": "🇪🇺", "FI": "🇫🇮",
    "FJ": "🇫🇯", "FK": "🇫🇰", "FM": "🇫🇲", "FO": "🇫🇴", "FR": "🇫🇷", "GA": "🇬🇦", "GB": "🇬🇧", "GD": "🇬🇩",
    "GE": "🇬🇪", "GF": "🇬🇫", "GG": "🇬🇬", "GH": "🇬🇭", "GI": "🇬🇮", "GL": "🇬🇱", "GM": "🇬🇲", "GN": "🇬🇳",
    "GP": "🇬🇵", "GQ": "🇬🇶", "GR": "🇬🇷", "GS": "🇬🇸", "GT": "🇬🇹", "GU": "🇬🇺", "GW": "🇬🇼", "GY": "🇬🇾",
    "HK": "🇭🇰", "HM": "🇭🇲", "HN": "🇭🇳", "HR": "🇭🇷", "HT": "🇭🇹", "HU": "🇭🇺", "ID": "🇮🇩", "IE": "🇮🇪",
    "IL": "🇮🇱", "IM": "🇮🇲", "IN": "🇮🇳", "IO": "🇮🇴", "IQ": "🇮🇶", "IR": "🇮🇷", "IS": "🇮🇸", "IT": "🇮🇹",
    "JE": "🇯🇪", "JM": "🇯🇲", "JO": "🇯🇴", "JP": "🇯🇵", "KE": "🇰🇪", "KG": "🇰🇬", "KH": "🇰🇭", "KI": "🇰🇮",
    "KM": "🇰🇲", "KN": "🇰🇳", "KP": "🇰🇵", "KR": "🇰🇷", "KW": "🇰🇼", "KY": "🇰🇾", "KZ": "🇰🇿", "LA": "🇱🇦",
    "LB": "🇱🇧", "LC": "🇱🇨", "LI": "🇱🇮", "LK": "🇱🇰", "LR": "🇱🇷", "LS": "🇱🇸", "LT": "🇱🇹", "LU": "🇱🇺",
    "LV": "🇱🇻", "LY": "🇱🇾", "MA": "🇲🇦", "MC": "🇲🇨", "MD": "🇲🇩", "ME": "🇲🇪", "MF": "🇲🇫", "MG": "🇲🇬",
    "MH": "🇲🇭", "MK": "🇲🇰", "ML": "🇲🇱", "MM": "🇲🇲", "MN": "🇲🇳", "MO": "🇲🇴", "MP": "🇲🇵", "MQ": "🇲🇶",
    "MR": "🇲🇷", "MS": "🇲🇸", "MT": "🇲🇹", "MU": "🇲🇺", "MV": "🇲🇻", "MW": "🇲🇼", "MX": "🇲🇽", "MY": "🇲🇾",
    "MZ": "🇲🇿", "NA": "🇳🇦", "NC": "🇳🇨", "NE": "🇳🇪", "NF": "🇳🇫", "NG": "🇳🇬", "NI": "🇳🇮", "NL": "🇳🇱",
    "NO": "🇳🇴", "NP": "🇳🇵", "NR": "🇳🇷", "NU": "🇳🇺", "NZ": "🇳🇿", "OM": "🇴🇲", "PA": "🇵🇦", "PE": "🇵🇪",
    "PF": "🇵🇫", "PG": "🇵🇬", "PH": "🇵🇭", "PK": "🇵🇰", "PL": "🇵🇱", "PM": "🇵🇲", "PN": "🇵🇳", "PR": "🇵🇷",
    "PS": "🇵🇸", "PT": "🇵🇹", "PW": "🇵🇼", "PY": "🇵🇾", "QA": "🇶🇦", "RE": "🇷🇪", "RO": "🇷🇴", "RS": "🇷🇸",
    "RU": "🇷🇺", "RW": "🇷🇼", "SA": "🇸🇦", "SB": "🇸🇧", "SC": "🇸🇨", "SD": "🇸🇩", "SE": "🇸🇪", "SG": "🇸🇬",
    "SH": "🇸🇭", "SI": "🇸🇮", "SJ": "🇸🇯", "SK": "🇸🇰", "SL": "🇸🇱", "SM": "🇸🇲", "SN": "🇸🇳", "SO": "🇸🇴",
    "SR": "🇸🇷", "SS": "🇸🇸", "ST": "🇸🇹", "SV": "🇸🇻", "SX": "🇸🇽", "SY": "🇸🇾", "SZ": "🇸🇿", "TA": "🇹🇦",
    "TC": "🇹🇨", "TD": "🇹🇩", "TF": "🇹🇫", "TG": "🇹🇬", "TH": "🇹🇭", "TJ": "🇹🇯", "TK": "🇹🇰", "TL": "🇹🇱",
    "TM": "🇹🇲", "TN": "🇹🇳", "TO": "🇹🇴", "TR": "🇹🇷", "TT": "🇹🇹", "TV": "🇹🇻", "TW": "🇹🇼", "TZ": "🇹🇿",
    "UA": "🇺🇦", "UG": "🇺🇬", "UM": "🇺🇲", "US": "🇺🇸", "UY": "🇺🇾", "UZ": "🇺🇿", "VA": "🇻🇦", "VC": "🇻🇨",
    "VE": "🇻🇪", "VG": "🇻🇬", "VI": "🇻🇮", "VN": "🇻🇳", "VU": "🇻🇺", "WF": "🇼🇫", "WS": "🇼🇸", "XK": "🇽🇰",
    "YE": "🇾🇪", "YT": "🇾🇹", "ZA": "🇿🇦", "ZM": "🇿🇲", "ZW": "🇿🇼",
}
DEFAULT_FLAG = "🏁" # Default flag if country code not found

# --- Default Settings ---
DEFAULT_TEST_URL = "https://cloudflare.com/cdn-cgi/trace" # Primary global test URL
DEFAULT_TEST_METHOD = "GET"
DEFAULT_BEST_CONFIGS_LIMIT = 100
DEFAULT_FETCH_TIMEOUT = 20
DEFAULT_XRAY_KNIFE_TIMEOUT_MS = 8000 # Slightly reduced default for faster fails? Keep user's 10000? Let's use 8000 as a balance.
DEFAULT_UDP_TIMEOUT_S = 5
PYTHON_SUBPROCESS_TIMEOUT_BUFFER_S = 15
DEFAULT_SPEEDTEST_AMOUNT_KB = 10000
DEFAULT_THREADS = min(32, os.cpu_count() * 2 + 4) if os.cpu_count() else 16
CACHE_DIR = Path(".proxy_cache")
CACHE_TTL_HOURS = 6

# --- Iran Specific Test Settings ---
# List of generally accessible Iranian domains/IPs for secondary testing
# These should ideally be stable and likely whitelisted within Iran, but potentially filtered from outside
# Use a mix of HTTP/HTTPS. Prefer domains over IPs.
# ** This list needs careful selection and maintenance! **
IRAN_TEST_TARGETS = [
    "https://www.irancell.ir/", # Major ISP
    "https://mci.ir/",          # Major ISP
    "https://www.digikala.com/", # Major E-commerce
    "https://www.shaparak.ir/", # Payment Network
    "https://rubika.ir/",      # Domestic Platform
    "http://www.irib.ir/",      # State Broadcaster (HTTP)
    "https://www.snapp.ir/",     # Ride Hailing / SuperApp
    # Add 1-2 more diverse targets if possible
    "https://www.bmi.ir/",      # Bank Melli Iran
]
IRAN_TEST_COUNT = 3 # Number of random targets to test per config
IRAN_TEST_TIMEOUT_S = 5 # Timeout for each Iran target test
IRAN_TEST_SUCCESS_THRESHOLD = 0.6 # Requires > 60% of tested Iran targets to succeed

# URLs for CDN/IP check (should NOT be behind Cloudflare ideally)
IP_CHECK_URLS = [
    "https://api.ipify.org?format=json",
    "http://ip-api.com/json", # Fallback HTTP
    # Add more alternatives if needed
]
IP_CHECK_TIMEOUT_S = 7

# Known CDN Organization Names (lowercase for matching)
CDN_ORGANIZATIONS = {"cloudflare", "akamai", "fastly", "google cloud", "amazon"}

# --- Global State ---
total_outbounds_count = 0
completed_outbounds_count = 0
is_ctrl_c_pressed = False
found_xray_knife_path: Optional[str] = None
geoip_reader: Optional['geoip2.database.Reader'] = None
args: Optional[argparse.Namespace] = None

# --- Dataclass for Test Results (Enhanced) ---
@dataclass
class TestResult:
    original_config: str
    source: Optional[str] = None
    status: str = "pending" # pending, passed, failed, timeout, broken, skipped, semi-passed
    reason: Optional[str] = None
    real_delay_ms: float = float('inf')
    download_speed_mbps: float = 0.0
    upload_speed_mbps: float = 0.0
    ip: Optional[str] = None
    location: Optional[str] = None # 2-letter country code
    flag: Optional[str] = None
    protocol: Optional[str] = None
    dedup_key_details: Dict[str, Any] = field(default_factory=dict)
    # --- New fields for enhanced testing ---
    cdn_check_ip: Optional[str] = None # IP reported by non-CDN check URL
    cdn_check_org: Optional[str] = None # Org/ISP reported by non-CDN check URL
    is_cdn_ip: Optional[bool] = None # Heuristic: Is the exit IP likely a CDN?
    iran_access_targets_tested: int = 0
    iran_access_targets_passed: int = 0
    iran_access_passed: Optional[bool] = None # Did it pass the Iran access test threshold?
    tls_fingerprint_type: Optional[str] = None # e.g., "chrome", "firefox", "random", "reality", "unknown"
    # --- Score fields ---
    resilience_score: float = 1.0 # Lower is better (protocol/transport bonus)
    combined_score: float = float('inf') # Final score, lower is better

# ---------------------------
# Signal Handler for Ctrl+C
# ---------------------------
def signal_handler(sig, frame):
    global is_ctrl_c_pressed
    if not is_ctrl_c_pressed:
        print("\nCtrl+C detected. Signaling workers to stop... Please wait for graceful shutdown.", file=sys.stderr)
        is_ctrl_c_pressed = True
    else:
        print("\nCtrl+C pressed again. Forcing exit...", file=sys.stderr)
        sys.exit(1) # Force exit on second Ctrl+C

# ---------------------------
# Find xray-knife Executable
# ---------------------------
def find_xray_knife(provided_path: Optional[str]) -> Optional[str]:
    # ... (find_xray_knife implementation from your original script - unchanged) ...
    global found_xray_knife_path
    if found_xray_knife_path:
        return found_xray_knife_path

    # 1. Check provided path (can be environment variable)
    path_to_check = provided_path or os.environ.get("XRAY_KNIFE_PATH")
    if path_to_check:
        ppath = Path(path_to_check).resolve() # Resolve to absolute path
        if ppath.is_file():
            try:
                os.access(str(ppath), os.X_OK)
                found_xray_knife_path = str(ppath)
                if args and args.verbose: print(f"Debug: Using xray-knife path: {found_xray_knife_path}", file=sys.stderr)
                return found_xray_knife_path
            except Exception as e:
                print(f"Warning: Path '{path_to_check}' exists but check failed: {e}", file=sys.stderr)
        else:
            print(f"Warning: Provided xray-knife path '{path_to_check}' not found or not a file.", file=sys.stderr)

    # 2. Try finding in PATH
    executable_name = "xray-knife"
    if sys.platform == "win32":
        executable_name += ".exe"

    found_in_path = shutil.which(executable_name)
    if found_in_path:
        found_xray_knife_path = found_in_path
        if args and args.verbose: print(f"Debug: Found xray-knife in PATH: {found_xray_knife_path}", file=sys.stderr)
        return found_xray_knife_path

    # 3. Try common relative paths
    script_dir = Path(__file__).parent.resolve()
    relative_paths_to_check = [
        script_dir / executable_name,
        script_dir / "bin" / executable_name, # Common subdir
        Path(".") / executable_name, # Current working directory
    ]
    for path_to_check in relative_paths_to_check:
        abs_path = path_to_check.resolve()
        if abs_path.is_file():
            try:
                 os.access(str(abs_path), os.X_OK)
                 found_xray_knife_path = str(abs_path)
                 if args and args.verbose: print(f"Debug: Found xray-knife at relative path: {found_xray_knife_path}", file=sys.stderr)
                 return found_xray_knife_path
            except Exception:
                 continue # Not executable or other issue

    return None


# ---------------------------
# Cache Handling Functions
# ---------------------------
# ... (get_cache_path, load_from_cache, save_to_cache from your original script - unchanged) ...
def get_cache_path(url: str) -> Path:
    url_hash = hashlib.sha256(url.encode('utf-8')).hexdigest()
    return CACHE_DIR / f"{url_hash}.cache"

def load_from_cache(url: str, ttl_hours: int = CACHE_TTL_HOURS) -> Optional[str]:
    if not CACHE_DIR.exists():
        return None
    cache_file = get_cache_path(url)
    if not cache_file.is_file():
        return None

    try:
        file_mod_time = datetime.fromtimestamp(cache_file.stat().st_mtime)
        if datetime.now() - file_mod_time > timedelta(hours=ttl_hours):
            # print(f"Cache expired for {url}", file=sys.stderr) # Debug
            return None # Cache expired

        # print(f"Loading from cache: {url}", file=sys.stderr) # Debug
        return cache_file.read_text('utf-8')
    except Exception as e:
        print(f"Warning: Could not read cache file {cache_file}: {e}", file=sys.stderr)
        return None

def save_to_cache(url: str, content: str):
    if not content: # Don't cache empty content
        return
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        cache_file = get_cache_path(url)
        cache_file.write_text(content, 'utf-8')
        # print(f"Saved to cache: {url}", file=sys.stderr) # Debug
    except Exception as e:
        print(f"Warning: Could not write cache file for {url}: {e}", file=sys.stderr)

# ---------------------------
# Fetching content from URLs (with Caching)
# ---------------------------
# ... (fetch_content from your original script - unchanged) ...
def fetch_content(url: str, proxy: Optional[str] = None, timeout: int = DEFAULT_FETCH_TIMEOUT, force_fetch: bool = False) -> Optional[str]:
    global args # Access global args

    if not force_fetch:
        cached_content = load_from_cache(url, args.cache_ttl if hasattr(args, 'cache_ttl') else CACHE_TTL_HOURS)
        if cached_content is not None:
            return cached_content

    session = requests.Session()
    proxies = None
    if proxy:
        proxies = {"http": proxy, "https": proxy}
    else:
        # Respect environment proxies unless explicitly overridden by --fetch-proxy
        pass

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0" # Firefox UA
    }
    try:
        response = session.get(
            url,
            timeout=timeout,
            proxies=proxies,
            verify=False, # Still disable SSL verification for subs
            headers=headers,
            allow_redirects=True
        )
        response.raise_for_status()
        response.encoding = response.apparent_encoding or 'utf-8'
        content = response.text
        save_to_cache(url, content) # Save fetched content to cache
        return content
    except requests.exceptions.Timeout:
        print(f"Error fetching {url}: Timeout after {timeout}s", file=sys.stderr)
    except requests.exceptions.ProxyError as e:
        print(f"Error fetching {url}: ProxyError - {e}", file=sys.stderr)
    except requests.exceptions.SSLError as e:
        print(f"Error fetching {url}: SSL Error - {e}", file=sys.stderr)
    except requests.exceptions.ConnectionError as e:
         print(f"Error fetching {url}: Connection Error - {e} (Check DNS/Network)", file=sys.stderr)
    except requests.exceptions.RequestException as e:
        print(f"Error fetching {url}: {type(e).__name__} - {e}", file=sys.stderr)
    except Exception as e:
        print(f"Unexpected error fetching {url}: {type(e).__name__} - {e}", file=sys.stderr)
    return None

# ---------------------------
# Parsing configuration content
# ---------------------------
# ... (parse_config_content from your original script - unchanged) ...
def parse_config_content(content: str, source_url: str) -> List[TestResult]:
    outbounds = []
    if not content:
        return outbounds

    try:
        decoded_content = content # Assume plaintext first
        try:
            # More robust base64 detection/cleaning
            content_no_space = ''.join(content.split())
            # Heuristic: check if it looks like base64 (alphanum, +, /, =) and length is plausible
            if len(content_no_space) > 10 and re.fullmatch(r'^[A-Za-z0-9+/=\s]*$', content):
                 padding = len(content_no_space) % 4
                 if padding:
                     content_no_space += '=' * (4 - padding)
                 # Check if the decoded content contains common protocol schemes as a sanity check
                 potential_decoded = base64.b64decode(content_no_space, validate=True).decode('utf-8', errors='ignore')
                 if any(proto in potential_decoded for proto in ["vless://", "vmess://", "trojan://", "ss://"]):
                      decoded_content = potential_decoded
                 # Fallback to latin-1 if utf-8 failed but base64 was valid
                 elif '://' in base64.b64decode(content_no_space, validate=True).decode('latin-1', errors='ignore'):
                      decoded_content = base64.b64decode(content_no_space, validate=True).decode('latin-1', errors='ignore')

        except (base64.binascii.Error, ValueError, TypeError):
             pass # If decode fails, assume it was plaintext

        supported_prefixes = (
            "vless://", "vmess://", "ss://", "ssr://", "trojan://",
            "tuic://", "hysteria://", "hysteria2://", "hy2://",
            "wg://", "wireguard://", "warp://",
            "socks://", "http://", "https://"
        )
        seen_configs_this_source = set()

        for line in decoded_content.splitlines():
            line = line.strip()
            if line and not line.startswith(("#", "//", ";")):
                 matched_prefix = None
                 for prefix in supported_prefixes:
                     # Make comparison case-insensitive for prefix matching
                     if line.lower().startswith(prefix):
                         matched_prefix = prefix
                         break

                 if matched_prefix:
                    # Normalize protocol name
                    protocol = matched_prefix.split("://", 1)[0].lower()
                    if protocol in ["wireguard", "warp", "wg"]: protocol = "wg"
                    elif protocol in ["hysteria2", "hy2"]: protocol = "hysteria" # Group hysteria variants
                    # elif protocol == "ssr": protocol = "ss" # Keep SSR distinct if needed, or group with SS
                    else: protocol = protocol # Keep others as is (vless, vmess, trojan, ss, tuic, socks, http)

                    if line not in seen_configs_this_source:
                        # Create TestResult with the normalized protocol
                        outbounds.append(TestResult(original_config=line, source=source_url, protocol=protocol))
                        seen_configs_this_source.add(line)

    except Exception as e:
        print(f"Error processing content from {source_url}: {type(e).__name__} - {e}", file=sys.stderr)

    return outbounds

# ---------------------------
# Helper to get server/port (Simplified from Script 2, for UDP/WG focus)
# ---------------------------
def get_server_port_basic(config_line: str) -> Tuple[Optional[str], Optional[int]]:
    """Extracts server hostname and port using basic urlparse. Good for WG/WARP."""
    # ... (get_server_port_basic from your original script - unchanged) ...
    try:
        parsed_url = urllib.parse.urlparse(config_line)
        hostname = parsed_url.hostname
        port = parsed_url.port

        # Handle potential IPv6 brackets in hostname from urlparse
        if hostname and hostname.startswith('[') and hostname.endswith(']'):
            hostname = hostname[1:-1]

        return hostname, port
    except Exception as e:
        # print(f"Debug: Error extracting server/port from {config_line[:60]}...: {e}", file=sys.stderr)
        return None, None

# ---------------------------
# Enhanced Server/Port/Details Extraction for Deduplication & Resilience Scoring
# ---------------------------
def extract_config_details_for_dedup(config_line: str) -> Dict[str, Any]:
    # This function is now crucial for resilience scoring too
    details = {
        "protocol": None, "address": None, "port": None,
        "host": None, "path": None, "net": None, # Transport type (ws, grpc, tcp, etc.)
        "tls": None, # Security type (tls, reality, none)
        "fp": None, # Fingerprint setting
        "type": None # Header type for Vmess HTTP
    }
    try:
        parsed_url = urllib.parse.urlparse(config_line)
        scheme = parsed_url.scheme.lower()

        # --- Protocol Normalization consistent with parsing ---
        if scheme in ["wireguard", "warp", "wg"]: details["protocol"] = "wg"
        elif scheme in ["hysteria2", "hy2"]: details["protocol"] = "hysteria"
        # elif scheme == "ssr": details["protocol"] = "ss" # Keep distinct or group
        else: details["protocol"] = scheme

        details["address"] = parsed_url.hostname
        details["port"] = parsed_url.port

        if details["address"] and details["address"].startswith('[') and details["address"].endswith(']'):
            details["address"] = details["address"][1:-1]

        query_params = urllib.parse.parse_qs(parsed_url.query)
        details["host"] = query_params.get("sni", query_params.get("host", [None]))[0] # SNI prio, fallback host
        details["path"] = query_params.get("path", [None])[0]
        details["net"] = query_params.get("type", query_params.get("network", query_params.get("net", [None])))[0] # ws, grpc, tcp, etc.
        details["tls"] = query_params.get("security", [None])[0] # tls, reality, none
        details["fp"] = query_params.get("fp", [None])[0] # Fingerprint

        # --- Protocol-specific parsing (Refined) ---
        if scheme == "vmess":
            try:
                # Handle URL safe base64 just in case
                base64_part = config_line[len("vmess://"):].split("#")[0].strip()
                base64_part = base64_part.replace('-', '+').replace('_', '/') # URL safe decode
                if len(base64_part) % 4 != 0: base64_part += '=' * (4 - len(base64_part) % 4)
                decoded_json = base64.b64decode(base64_part).decode('utf-8', errors='ignore')
                vmess_data = json.loads(decoded_json)

                details["address"] = vmess_data.get("add", details["address"])
                port_str = str(vmess_data.get("port", str(details["port"]) if details["port"] else None))
                details["port"] = int(port_str) if port_str and port_str.isdigit() else details["port"]
                details["host"] = vmess_data.get("sni", vmess_data.get("host", details["host"])) # Check sni first in json too
                details["path"] = vmess_data.get("path", details["path"])
                details["net"] = vmess_data.get("net", details["net"]) # ws, tcp, kcp, grpc etc.
                details["tls"] = vmess_data.get("tls", details["tls"]) # "tls" or ""/"none"
                details["type"] = vmess_data.get("type", details["type"]) # Header type for HTTP (none, http)

            except Exception as e:
                if args and args.verbose > 1: print(f"Debug: VMess JSON parse failed for {config_line[:30]}...: {e}", file=sys.stderr)
                pass # Keep parsed URL data on failure

        elif scheme == "ss":
             # SS address/port usually in userinfo@host:port
             at_parts = parsed_url.netloc.split('@')
             host_port_part = at_parts[-1] if len(at_parts) > 1 else parsed_url.netloc # Handle cases with/without userinfo
             host_port_part = host_port_part.split('#')[0] # Remove fragment

             # Try parsing host:port
             if ':' in host_port_part:
                  potential_host, port_str = host_port_part.rsplit(':', 1)
                  # Basic validation: port is numeric, host doesn't look like just userinfo
                  if port_str.isdigit() and potential_host:
                       details["address"] = potential_host
                       details["port"] = int(port_str)

             # Check for plugin options relevant to transport/tls
             plugin_opts = query_params.get("plugin", [""])[0]
             if "v2ray-plugin" in plugin_opts or "obfs-local" in plugin_opts:
                 if "tls" in plugin_opts: details["tls"] = "tls"
                 if "mode=websocket" in plugin_opts: details["net"] = "ws"
                 if "obfs=http" in plugin_opts: details["net"] = "http-obfs" # Or similar identifier
                 # Extract host/path from plugin args if possible (complex)
                 # Example: plugin=v2ray-plugin;tls;host=example.com;path=/ws
                 plugin_params = dict(item.split("=") for item in plugin_opts.split(";") if "=" in item)
                 details["host"] = plugin_params.get("host", details["host"])
                 details["path"] = plugin_params.get("path", details["path"])


        elif scheme in ["vless", "trojan"]:
             # Query params are primary source for VLESS/Trojan details
             details["net"] = query_params.get("type", details.get("net")) # ws, grpc, tcp (default)
             details["tls"] = query_params.get("security", details.get("tls")) # tls, reality, xtls
             details["host"] = query_params.get("sni", details.get("host")) # SNI
             details["fp"] = query_params.get("fp", details.get("fp")) # fingerprint
             # Path for WS, ServiceName for gRPC
             if details["net"] == "ws":
                  details["path"] = query_params.get("path", details.get("path"))
             elif details["net"] == "grpc":
                  details["path"] = query_params.get("serviceName", details.get("path")) # Use serviceName for gRPC path equiv.
             # Reality parameters
             if details["tls"] == "reality":
                 details["fp"] = query_params.get("fp", details.get("fp")) # fingerprint
                 # Could also extract pbk, sid if needed for finer deduplication

        # --- Post-processing and Normalization ---
        # Infer TCP if net is missing for common protocols
        if not details["net"] and details["protocol"] in ["vless", "vmess", "trojan", "ss", "socks", "http"]:
            details["net"] = "tcp"
        # Infer TLS if port is 443 and security not specified (basic heuristic)
        if not details["tls"] and details["port"] == 443 and details["protocol"] in ["vless", "vmess", "trojan"]:
            details["tls"] = "tls" # Assume TLS on 443 if not otherwise specified
        elif details["tls"] == "none": # Normalize "none"
            details["tls"] = None

        # Basic validation
        if not details["address"] or details["port"] is None or not (0 < details["port"] < 65536):
            return {} # Invalid for deduplication/analysis

        # Normalize IPv6
        addr = details["address"]
        if ipaddress and addr and ':' in addr:
             try:
                 ip_addr = ipaddress.ip_address(addr)
                 if isinstance(ip_addr, ipaddress.IPv6Address):
                     details["address"] = ip_addr.compressed
             except ValueError: pass # Keep domain name

        # Use address as host/SNI if missing (important fallback)
        if not details["host"]:
             details["host"] = details["address"]

        try: details["port"] = int(details["port"])
        except (ValueError, TypeError): return {}

        # Clean up empty strings to None
        for key in ["host", "path", "net", "tls", "fp", "type"]:
            if isinstance(details.get(key), str) and not details[key]:
                details[key] = None

        return details

    except Exception as e:
        if args and args.verbose > 1: print(f"Debug: Detail extract failed for {config_line[:30]}...: {e}", file=sys.stderr)
        return {}


# ---------------------------
# Get deduplication key
# ---------------------------
def get_dedup_key(config_result: TestResult) -> Optional[tuple]:
    details = extract_config_details_for_dedup(config_result.original_config)
    config_result.dedup_key_details = details # Store details for later use

    proto = details.get("protocol")
    addr = details.get("address")
    port = details.get("port")

    if not proto or not addr or port is None:
        return None # Cannot deduplicate

    # Base key: protocol, address, port
    key_parts = [proto, addr, port]

    # Add transport details for relevant protocols to make key more specific
    # Use normalized values (None if not applicable/present)
    net = details.get("net")
    tls = details.get("tls")
    host = details.get("host", addr) # Use host/SNI, fallback to address
    path = details.get("path") # Path for ws, serviceName for grpc

    if proto in ["vless", "vmess", "trojan", "tuic", "hysteria", "ss"] and net != "tcp": # Add details for non-plain-TCP
        key_parts.extend([
            net, # ws, grpc, etc.
            tls, # tls, reality, none
            host,
            path
        ])
    elif proto == "ss" and net == "tcp": # For plain SS, maybe add plugin info if exists?
        plugin = details.get("plugin", None) # Crude check for now
        if plugin: key_parts.append(plugin[:20]) # Add truncated plugin info

    # Consider adding fingerprint 'fp' to key if present? Might be too specific.
    # if details.get("fp"): key_parts.append(details["fp"])

    return tuple(key_parts)

# ---------------------------
# Deduplicate outbounds based on deduplication key
# ---------------------------
# ... (deduplicate_outbounds from your original script - unchanged logic, uses new get_dedup_key) ...
def deduplicate_outbounds(outbounds: List[TestResult]) -> List[TestResult]:
    dedup_dict: Dict[tuple, TestResult] = {}
    skipped_count = 0
    processed_count = 0
    duplicates_found = 0

    print("Starting deduplication...", file=sys.stderr)
    for config_result in outbounds:
        processed_count += 1
        key = get_dedup_key(config_result)
        if key is None:
            # If verbose, print why it was skipped
            if args and args.verbose > 1:
                 print(f"Debug: Skipping deduplication for config (invalid key): {config_result.original_config[:60]}...", file=sys.stderr)
            skipped_count += 1
            continue

        if key not in dedup_dict:
            dedup_dict[key] = config_result
        else:
             duplicates_found +=1
             # Optional: Prioritize based on source? For now, first seen wins.
             # Or maybe keep the one with more details parsed?

    kept_count = len(dedup_dict)
    print(f"Deduplication: Processed {processed_count} configs. Kept {kept_count} unique. "
          f"Removed {duplicates_found} duplicates. Skipped {skipped_count} (invalid/unparseable key).", file=sys.stderr)
    return list(dedup_dict.values())

# ---------------------------
# GeoIP Lookup using Database (Optional)
# ---------------------------
def get_geoip_location(ip_address: str, reader: Optional['geoip2.database.Reader']) -> Optional[str]:
    """Looks up the country code for an IP using the provided geoip2 reader."""
    # ... (get_geoip_location from your original script - unchanged) ...
    if not reader or not ip_address or not geoip2:
        return None
    try:
        # Remove brackets if it's a formatted IPv6 address
        ip_address_cleaned = ip_address.strip("[]")
        response = reader.country(ip_address_cleaned)
        return response.country.iso_code # Return 2-letter code (e.g., 'US')
    except geoip2.errors.AddressNotFoundError:
        return None
    except ValueError: # Handle invalid IP format passed to geoip
        # print(f"Debug: Invalid IP format for GeoIP: {ip_address}", file=sys.stderr)
        return None
    except Exception as e:
        # print(f"Debug: GeoIP lookup error for {ip_address}: {e}", file=sys.stderr)
        return None

# ---------------------------
# Regex patterns for parsing xray-knife output
# ---------------------------
# ... (Patterns from your original script - unchanged) ...
REAL_DELAY_PATTERN = re.compile(r"(?:Real Delay|Latency):\s*(\d+)\s*ms", re.IGNORECASE)
DOWNLOAD_SPEED_PATTERN = re.compile(r"Downloaded\s*[\d.]+\s*[MK]?B\s*-\s*Speed:\s*([\d.]+)\s*([mk]?)bps", re.IGNORECASE)
UPLOAD_SPEED_PATTERN = re.compile(r"Uploaded\s*[\d.]+\s*[MK]?B\s*-\s*Speed:\s*([\d.]+)\s*([mk]?)bps", re.IGNORECASE)
IP_INFO_PATTERN = re.compile(r"\bip=(?P<ip>[\d\.a-fA-F:]+)\b(?:.*?\bloc=(?P<loc>[A-Z]{2})\b)?", re.IGNORECASE | re.DOTALL)
XRAY_KNIFE_FAIL_REASON_PATTERN = re.compile(r"\[-\].*?(?:failed|error|timeout)[:\s]+(.*)", re.IGNORECASE)
CONTEXT_DEADLINE_PATTERN = re.compile(r"context deadline exceeded", re.IGNORECASE)
IO_TIMEOUT_PATTERN = re.compile(r"i/o timeout", re.IGNORECASE)
CONNECTION_REFUSED_PATTERN = re.compile(r"connection refused", re.IGNORECASE)
DNS_ERROR_PATTERN = re.compile(r"(?:no such host|dns query failed|could not resolve host)", re.IGNORECASE)
HANDSHAKE_ERROR_PATTERN = re.compile(r"handshake failed|tls handshake error", re.IGNORECASE)

# --- NEW Pattern for xray-knife curl output ---
# Matches JSON output from ip-api.com or ipify.org
IP_API_JSON_PATTERN = re.compile(r'"query"\s*:\s*"(?P<ip>[\d\.a-fA-F:]+)",.*?"org"\s*:\s*"(?P<org>[^"]*)"', re.IGNORECASE | re.DOTALL)
IPIFY_JSON_PATTERN = re.compile(r'"ip"\s*:\s*"(?P<ip>[\d\.a-fA-F:]+)"', re.IGNORECASE | re.DOTALL)


# -----------------------------------------------------
# --- UDP Test Logic (WireGuard/WARP) - UNCHANGED ---
# -----------------------------------------------------
async def _test_wg_udp_async(result_obj: TestResult, args: argparse.Namespace) -> TestResult:
    """Async core logic for UDP test."""
    # ... (Async UDP test implementation from your original script - unchanged) ...
    global is_ctrl_c_pressed, geoip_reader

    if is_ctrl_c_pressed:
        result_obj.status = "skipped"
        result_obj.reason = "Interrupted by user"
        return result_obj

    config_line = result_obj.original_config
    server, port = get_server_port_basic(config_line) # Use basic parser for WG
    timeout = args.udp_timeout

    # Reset results specifically for UDP test
    result_obj.real_delay_ms = float('inf')
    result_obj.download_speed_mbps = 0.0 # UDP test doesn't measure speed
    result_obj.upload_speed_mbps = 0.0
    result_obj.ip = None # UDP test doesn't reliably get external IP
    result_obj.location = None
    result_obj.flag = None
    result_obj.status = "pending"
    result_obj.reason = None
    # Reset enhanced fields too
    result_obj.cdn_check_ip = None
    result_obj.cdn_check_org = None
    result_obj.is_cdn_ip = None
    result_obj.iran_access_passed = None
    result_obj.tls_fingerprint_type = None
    result_obj.resilience_score = 1.0 # Default neutral for WG
    result_obj.combined_score = float('inf')


    if not server or not port:
        result_obj.status = "broken"
        result_obj.reason = "Could not parse server/port"
        # print(f"UDP Test: Invalid server/port for {config_line[:60]}...", file=sys.stderr)
        return result_obj

    resolved_ip = None
    try:
        # Resolve hostname to IP address first
        loop = asyncio.get_running_loop()
        addr_info = await loop.getaddrinfo(server, port, family=socket.AF_UNSPEC, type=socket.SOCK_DGRAM)
        if not addr_info:
            raise socket.gaierror(f"No address info found for {server}")
        ipv4_info = next((info for info in addr_info if info[0] == socket.AF_INET), None)
        chosen_info = ipv4_info or addr_info[0]
        resolved_ip = chosen_info[4][0] # The IP address string
        family = chosen_info[0] # Address family (AF_INET or AF_INET6)

    except (socket.gaierror, socket.herror) as e:
        result_obj.status = "failed"
        result_obj.reason = f"DNS resolution failed: {e}"
        return result_obj
    except Exception as e: # Catch other unexpected resolution errors
        result_obj.status = "broken"
        result_obj.reason = f"DNS unexpected error: {e}"
        return result_obj

    # --- GeoIP Lookup based on resolved server IP (if available) ---
    if geoip_reader and resolved_ip:
        db_location = get_geoip_location(resolved_ip, geoip_reader)
        if db_location:
            result_obj.location = db_location
            result_obj.flag = COUNTRY_FLAGS.get(db_location.upper(), DEFAULT_FLAG)
        result_obj.ip = resolved_ip # Store resolved IP


    transport = None
    start_time = 0
    try:
        loop = asyncio.get_running_loop()
        start_time = loop.time()

        conn_future = loop.create_datagram_endpoint(
            lambda: asyncio.DatagramProtocol(),
            remote_addr=(resolved_ip, port),
            family=family
        )
        transport, protocol_instance = await asyncio.wait_for(conn_future, timeout=timeout)
        transport.sendto(b'\x00')
        await asyncio.sleep(0.05) # Small delay after send

        end_time = loop.time()
        delay = (end_time - start_time) * 1000

        result_obj.real_delay_ms = max(1.0, delay)
        result_obj.status = "passed"
        result_obj.reason = "UDP connection successful"

    except asyncio.TimeoutError:
        result_obj.status = "timeout"
        result_obj.reason = f"UDP connection timed out after {timeout:.1f}s"
    except socket.gaierror as e:
        result_obj.status = "failed"
        result_obj.reason = f"DNS error during connection: {e}"
    except OSError as e:
        result_obj.status = "failed"
        result_obj.reason = f"OS error: {e.strerror} (code {e.errno})"
    except Exception as e:
        result_obj.status = "broken"
        result_obj.reason = f"UDP test unexpected error: {type(e).__name__} - {e}"
    finally:
        if transport:
            try: transport.close()
            except Exception: pass

    # --- Calculate Combined Score for UDP ---
    if result_obj.status == "passed":
        reference_delay = 1000.0 # 1 second reference
        normalized_delay = min(result_obj.real_delay_ms / reference_delay, 1.0)
        result_obj.combined_score = normalized_delay # Score based solely on delay
        # WG is generally resilient, assign a slightly better resilience score
        result_obj.resilience_score = 0.8 # Lower is better
        result_obj.combined_score *= result_obj.resilience_score

        # Mark as semi-passed if speedtest was globally requested
        if args.speedtest:
            result_obj.status = "semi-passed"
            result_obj.reason = "Passed UDP, speed test N/A"
    else:
         result_obj.combined_score = float('inf')

    return result_obj

def test_wg_udp_sync(result_obj: TestResult, args: argparse.Namespace) -> TestResult:
    """Synchronous wrapper for the async UDP test."""
    # ... (Sync UDP wrapper implementation from your original script - unchanged) ...
    try:
        # Ensure an event loop exists for this thread if needed, or run directly
        return asyncio.run(_test_wg_udp_async(result_obj, args))
    except RuntimeError as e:
        if "cannot be called from a running event loop" in str(e):
             # Attempt to get the existing loop and run within it
             try:
                 loop = asyncio.get_running_loop()
                 # Check if loop is running; if so, schedule it. If not, run until complete.
                 if loop.is_running():
                     # This is tricky in a sync context; maybe just fail?
                     # Or use loop.call_soon_threadsafe? For simplicity, let's fail for now.
                     print(f"Warning: UDP test called from running loop for {result_obj.original_config[:50]}... Cannot run directly.", file=sys.stderr)
                     result_obj.status = "broken"
                     result_obj.reason = "Asyncio loop conflict"
                 else:
                     return loop.run_until_complete(_test_wg_udp_async(result_obj, args))
             except RuntimeError: # If get_running_loop fails, create a new one
                  return asyncio.run(_test_wg_udp_async(result_obj, args))

             # Default failure if we couldn't run it
             result_obj.status = "broken"
             result_obj.reason = "Asyncio loop conflict"
             result_obj.real_delay_ms = float('inf')
             result_obj.combined_score = float('inf')
             return result_obj
        else:
             # Handle other potential RuntimeErrors during asyncio.run
             result_obj.status = "broken"
             result_obj.reason = f"Asyncio runtime error: {e}"
             result_obj.real_delay_ms = float('inf')
             result_obj.combined_score = float('inf')
             return result_obj
    except Exception as e:
        # Catch any other unexpected errors during the sync call
        print(f"Critical error in test_wg_udp_sync for {result_obj.original_config[:50]}...: {e}", file=sys.stderr)
        result_obj.status = "broken"
        result_obj.reason = f"Sync wrapper error: {e}"
        result_obj.real_delay_ms = float('inf')
        result_obj.combined_score = float('inf')
        return result_obj
# -------------------------------------------------------
# --- END UDP Test Logic ---
# -------------------------------------------------------


# -----------------------------------------------------
# --- NEW: Helper Function to Run Command via xray-knife net curl ---
# -----------------------------------------------------
def run_xray_knife_curl(
    config_link: str,
    target_url: str,
    method: str = "GET",
    timeout_ms: int = 5000, # Shorter timeout for these checks
    xray_knife_path: str = None,
    args: argparse.Namespace = None,
    verbose: bool = False
) -> Tuple[bool, str, str]:
    """
    Runs xray-knife net curl to make a request through the proxy.
    Returns (success_boolean, stdout, stderr).
    """
    global is_ctrl_c_pressed
    if is_ctrl_c_pressed or not xray_knife_path:
        return False, "", "Skipped or xray-knife not found"

    command = [
        xray_knife_path, "net", "curl",
        "-c", config_link,
        "-url", target_url,
        "-m", str(timeout_ms),
        "-X", method.upper(),
        "-z", args.xray_knife_core if args else "auto",
    ]
    if args and args.xray_knife_insecure:
        command.append("-e") # Allow insecure

    python_timeout = (timeout_ms / 1000.0) + PYTHON_SUBPROCESS_TIMEOUT_BUFFER_S / 2 # Shorter buffer for curl checks

    if verbose: print(f"      Running curl: {' '.join(command)}", file=sys.stderr)

    try:
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='replace',
            timeout=python_timeout,
            check=False, # Don't throw exception on non-zero exit code
            env=os.environ.copy()
        )
        stdout = process.stdout
        stderr = process.stderr
        # Success condition: return code 0 and some output or specific success markers if needed
        # For simple reachability, RC 0 might be enough. Look for HTTP status in output?
        # Let's consider RC 0 as success for now. stderr might contain connection info.
        success = process.returncode == 0
        if not success and verbose:
             print(f"      Curl failed (RC={process.returncode}): {stderr[:100]}...", file=sys.stderr)
        return success, stdout, stderr

    except subprocess.TimeoutExpired:
        if verbose: print(f"      Curl timed out: {target_url}", file=sys.stderr)
        return False, "", f"Timeout after {python_timeout:.1f}s"
    except Exception as e:
        if verbose: print(f"      Curl error: {e}", file=sys.stderr)
        return False, "", f"Subprocess error: {type(e).__name__}"

# -----------------------------------------------------
# --- NEW: Enhanced Check Functions (run after main test passes) ---
# -----------------------------------------------------

def perform_cdn_check(result_obj: TestResult, xray_knife_path: str, args: argparse.Namespace):
    """
    Performs a check using a non-CDN IP checker URL through the proxy.
    Updates result_obj with cdn_check_ip, cdn_check_org, is_cdn_ip.
    """
    global is_ctrl_c_pressed
    if is_ctrl_c_pressed: return

    if args.verbose: print(f"    Performing CDN check for {result_obj.original_config[:50]}...", file=sys.stderr)

    check_url = random.choice(IP_CHECK_URLS) # Use a random checker
    success, stdout, stderr = run_xray_knife_curl(
        result_obj.original_config,
        check_url,
        method="GET",
        timeout_ms=int(IP_CHECK_TIMEOUT_S * 1000),
        xray_knife_path=xray_knife_path,
        args=args,
        verbose=args.verbose > 1 # More verbose for sub-checks
    )

    if success and stdout:
        ip_address = None
        org_name = None
        # Try parsing known JSON formats
        try:
            if "ip-api.com" in check_url:
                match = IP_API_JSON_PATTERN.search(stdout)
                if match:
                    ip_address = match.group("ip")
                    org_name = match.group("org")
            elif "ipify.org" in check_url:
                 match = IPIFY_JSON_PATTERN.search(stdout)
                 if match:
                      ip_address = match.group("ip")
                      # ipify doesn't provide org, maybe do secondary lookup if needed? For now, None.
                      org_name = None # Or try parsing stderr for potential info?
            # Fallback: try loading as generic JSON if patterns fail
            if not ip_address:
                try:
                    data = json.loads(stdout)
                    ip_address = data.get("ip") or data.get("query")
                    org_name = data.get("org") or data.get("isp")
                except json.JSONDecodeError:
                    if args.verbose > 1: print(f"      CDN Check: Failed to parse JSON: {stdout[:100]}...", file=sys.stderr)

        except Exception as e:
            if args.verbose > 1: print(f"      CDN Check: Error parsing output: {e}", file=sys.stderr)

        if ip_address:
            result_obj.cdn_check_ip = ip_address
            if org_name: result_obj.cdn_check_org = org_name.strip()

            # Heuristic: Check if organization name suggests a CDN
            if org_name and any(cdn in org_name.lower() for cdn in CDN_ORGANIZATIONS):
                result_obj.is_cdn_ip = True
            elif org_name: # If org exists but doesn't match CDN list
                result_obj.is_cdn_ip = False
            # else: is_cdn_ip remains None

            if args.verbose: print(f"      CDN Check OK: IP={ip_address}, Org={org_name}, IsCDN={result_obj.is_cdn_ip}", file=sys.stderr)
            return # Success

    # If check failed or no IP found
    result_obj.is_cdn_ip = None # Cannot determine
    if args.verbose: print(f"      CDN Check Failed or No IP found.", file=sys.stderr)


def perform_iran_access_test(result_obj: TestResult, xray_knife_path: str, args: argparse.Namespace):
    """
    Tests connectivity to a random subset of Iranian target URLs through the proxy.
    Updates result_obj with iran_access_* fields.
    """
    global is_ctrl_c_pressed
    if is_ctrl_c_pressed or not IRAN_TEST_TARGETS: return

    targets_to_test = random.sample(IRAN_TEST_TARGETS, min(len(IRAN_TEST_TARGETS), IRAN_TEST_COUNT))
    passed_count = 0
    tested_count = len(targets_to_test)
    result_obj.iran_access_targets_tested = tested_count

    if args.verbose: print(f"    Performing Iran access test ({tested_count} targets) for {result_obj.original_config[:50]}...", file=sys.stderr)

    for target_url in targets_to_test:
        if is_ctrl_c_pressed: break
        # Use HEAD request for speed, fallback to GET if needed? HEAD is usually sufficient.
        success, _, stderr = run_xray_knife_curl(
            result_obj.original_config,
            target_url,
            method="HEAD", # Faster check
            timeout_ms=int(IRAN_TEST_TIMEOUT_S * 1000),
            xray_knife_path=xray_knife_path,
            args=args,
            verbose=args.verbose > 1
        )
        if success:
            # Additional check: Ensure stderr doesn't contain fatal errors like "connection refused"
            # Sometimes RC can be 0 even if the connection wasn't fully successful at HTTP level.
            if not any(err in stderr.lower() for err in ["connection refused", "context deadline exceeded", "i/o timeout"]):
                 passed_count += 1
                 if args.verbose > 1: print(f"      Iran Access OK: {target_url}", file=sys.stderr)
            elif args.verbose > 1: print(f"      Iran Access Failed (RC=0, but error in stderr): {target_url} - {stderr[:100]}...", file=sys.stderr)
        elif args.verbose > 1: print(f"      Iran Access Failed (RC!=0): {target_url}", file=sys.stderr)


    result_obj.iran_access_targets_passed = passed_count
    if tested_count > 0:
        success_ratio = passed_count / tested_count
        result_obj.iran_access_passed = success_ratio >= IRAN_TEST_SUCCESS_THRESHOLD
    else:
        result_obj.iran_access_passed = None # No test performed

    if args.verbose: print(f"      Iran Access Result: {passed_count}/{tested_count} passed. Overall: {result_obj.iran_access_passed}", file=sys.stderr)


def check_tls_fingerprint_params(result_obj: TestResult):
    """
    Checks config parameters for known TLS fingerprint settings (fp, reality).
    Updates result_obj.tls_fingerprint_type.
    """
    details = result_obj.dedup_key_details
    fp = details.get("fp")
    tls_sec = details.get("tls")

    if tls_sec == "reality":
        result_obj.tls_fingerprint_type = "reality" # Reality usually implies good fingerprinting
    elif fp:
        fp_lower = fp.lower()
        if "chrome" in fp_lower: result_obj.tls_fingerprint_type = "chrome"
        elif "firefox" in fp_lower: result_obj.tls_fingerprint_type = "firefox"
        elif "safari" in fp_lower: result_obj.tls_fingerprint_type = "safari"
        elif "ios" in fp_lower: result_obj.tls_fingerprint_type = "ios"
        elif "android" in fp_lower: result_obj.tls_fingerprint_type = "android"
        elif "random" in fp_lower: result_obj.tls_fingerprint_type = "random"
        else: result_obj.tls_fingerprint_type = "custom" # Unknown specific FP
    else:
         result_obj.tls_fingerprint_type = "unknown" # No fp setting found

    if args and args.verbose > 1:
        print(f"      TLS Fingerprint Check: Type={result_obj.tls_fingerprint_type} (from params fp='{fp}', sec='{tls_sec}')", file=sys.stderr)


def calculate_resilience_score(result_obj: TestResult) -> float:
    """
    Calculates a score multiplier based on protocol, transport, and security.
    Lower score is better (more resilient).
    """
    details = result_obj.dedup_key_details
    protocol = details.get("protocol")
    net = details.get("net") # ws, grpc, tcp, etc.
    tls = details.get("tls") # tls, reality, none

    base_score = 1.0 # Neutral

    if protocol == "vless":
        if tls == "reality": base_score *= 0.6 # VLESS+Reality is very good
        elif net == "ws" and tls == "tls": base_score *= 0.8 # VLESS+WS+TLS is good
        elif net == "grpc" and tls == "tls": base_score *= 0.85 # VLESS+gRPC+TLS also good
        elif net == "tcp" and tls == "tls": base_score *= 0.95 # VLESS+TCP+TLS (XTLS?) okay
        else: base_score *= 1.1 # Basic VLESS/TCP less resilient

    elif protocol == "trojan":
        if net == "grpc" and tls == "tls": base_score *= 0.8 # Trojan+gRPC is good
        elif net == "ws" and tls == "tls": base_score *= 0.85 # Trojan+WS also good
        elif net == "tcp" and tls == "tls": base_score *= 0.9 # Basic Trojan okay
        else: base_score *= 1.1 # Trojan without TLS? Less common/resilient

    elif protocol == "vmess":
        if net == "ws" and tls == "tls": base_score *= 0.9 # VMess+WS+TLS is okay
        elif net == "grpc" and tls == "tls": base_score *= 0.95 # VMess+gRPC less common?
        else: base_score *= 1.2 # Basic VMess/TCP/KCP less resilient now

    elif protocol == "ss": # Shadowsocks
        # SS resilience depends heavily on encryption and plugin
        plugin = details.get("plugin")
        if plugin and "v2ray-plugin" in plugin and "ws" in plugin and "tls" in plugin:
            base_score *= 0.95 # SS+WS+TLS via v2ray-plugin
        elif plugin and "obfs" in plugin:
            base_score *= 1.1 # SS with simple HTTP obfs? Maybe less effective
        else:
            base_score *= 1.3 # Basic SS (depends heavily on AEAD cipher)

    # Hysteria/TUIC are UDP-based, resilience depends on implementation (QUIC obfuscation)
    elif protocol in ["hysteria", "tuic"]:
         base_score *= 0.9 # Generally considered reasonably resilient

    # Raw SOCKS/HTTP proxies are usually easily blocked
    elif protocol in ["socks", "http"]:
        base_score *= 1.5

    # Penalize lack of TLS where expected
    if protocol in ["vless", "vmess", "trojan"] and not tls:
        base_score *= 1.2 # Increase score (make worse) if TLS is missing

    # Add bonus if fingerprint looks good
    if result_obj.tls_fingerprint_type in ["chrome", "firefox", "safari", "ios", "android", "reality"]:
        base_score *= 0.95 # Small bonus for good fingerprint mimicry

    result_obj.resilience_score = round(base_score, 3)
    if args and args.verbose > 1:
        print(f"      Resilience Score: {result_obj.resilience_score} (Proto: {protocol}, Net: {net}, TLS: {tls})", file=sys.stderr)

    return result_obj.resilience_score


# -----------------------------------------------------
# --- Main Testing Function (Modified for Enhanced Checks) ---
# -----------------------------------------------------
def test_config_with_xray_knife(result_obj: TestResult, xray_knife_path: str, args: argparse.Namespace) -> TestResult:
    global is_ctrl_c_pressed, geoip_reader
    if is_ctrl_c_pressed:
        result_obj.status = "skipped"; result_obj.reason = "Interrupted"; return result_obj
    if not xray_knife_path:
         result_obj.status = "broken"; result_obj.reason = "xray-knife not found"; return result_obj

    # --- Initial Connectivity & Speed Test (Same as before) ---
    config_link = result_obj.original_config
    command = [
        xray_knife_path, "net", "http",
        "-c", config_link, "-v",
        "-d", str(args.xray_knife_timeout_ms),
        "--url", args.test_url,
        "--method", args.test_method,
        "-z", args.xray_knife_core
    ]
    if args.speedtest:
        command.append("-p")
        # ... (speedtest amount parsing logic from original script) ...
        speed_amount_str = str(args.speedtest_amount).lower()
        kb_amount = DEFAULT_SPEEDTEST_AMOUNT_KB # Default
        try:
            if speed_amount_str.endswith('mb'):
                 kb_amount = int(speed_amount_str[:-2].strip()) * 1024
            elif speed_amount_str.endswith('kb'):
                 kb_amount = int(speed_amount_str[:-2].strip())
            else:
                 kb_amount = int(speed_amount_str.strip()) # Assume KB if no unit
            if kb_amount <= 0: raise ValueError("Speedtest amount must be positive")
        except ValueError:
            if args.verbose: print(f"Warning: Invalid --speedtest-amount '{args.speedtest_amount}'. Using default {DEFAULT_SPEEDTEST_AMOUNT_KB}kb.", file=sys.stderr)
            kb_amount = DEFAULT_SPEEDTEST_AMOUNT_KB
        command.extend(["-a", str(kb_amount)])

    if args.ip_info: command.append("--rip") # Still useful for basic GeoIP
    if args.xray_knife_insecure: command.append("-e")

    python_timeout = (args.xray_knife_timeout_ms / 1000.0) + PYTHON_SUBPROCESS_TIMEOUT_BUFFER_S
    env = os.environ.copy()
    process_output = ""
    process_error = ""
    process = None

    # Reset results before test
    result_obj.real_delay_ms = float('inf')
    result_obj.download_speed_mbps = 0.0
    result_obj.upload_speed_mbps = 0.0
    result_obj.ip = None
    result_obj.location = None
    result_obj.flag = None
    result_obj.cdn_check_ip = None
    result_obj.cdn_check_org = None
    result_obj.is_cdn_ip = None
    result_obj.iran_access_targets_tested = 0
    result_obj.iran_access_targets_passed = 0
    result_obj.iran_access_passed = None
    result_obj.tls_fingerprint_type = None
    result_obj.resilience_score = 1.0 # Reset to neutral
    result_obj.combined_score = float('inf')


    try:
        if args.verbose: print(f"  Testing main connectivity: {config_link[:60]}...", file=sys.stderr)
        process = subprocess.run(
            command, capture_output=True, text=True, encoding='utf-8', errors='replace',
            timeout=python_timeout, check=False, env=env
        )
        process_output = process.stdout
        process_error = process.stderr
    except subprocess.TimeoutExpired:
        result_obj.status = "timeout"; result_obj.reason = f"Main test timeout (> {python_timeout:.1f}s)"; return result_obj
    except FileNotFoundError:
        result_obj.status = "broken"; result_obj.reason = f"xray-knife missing at '{xray_knife_path}'"; is_ctrl_c_pressed = True; return result_obj
    except PermissionError:
        result_obj.status = "broken"; result_obj.reason = f"Permission denied for xray-knife"; is_ctrl_c_pressed = True; return result_obj
    except Exception as e:
        result_obj.status = "broken"; result_obj.reason = f"Subprocess error: {e}"; return result_obj

    # --- Parse Initial Test Output ---
    full_output = process_output + "\n" + process_error
    # ... (Parsing delay, speed, ip, location from original script) ...
    delay_match = REAL_DELAY_PATTERN.search(full_output)
    if delay_match:
        try: result_obj.real_delay_ms = float(delay_match.group(1))
        except ValueError: pass

    def parse_speed(match: Optional[re.Match]) -> float:
        # ... (parse_speed implementation from original script) ...
        if not match: return 0.0
        try:
            speed_val = float(match.group(1))
            unit = match.group(2).lower()
            if unit == 'k': return speed_val / 1000.0 # kbps to Mbps
            elif unit == 'm': return speed_val # Mbps
            else: return speed_val / 1000000.0 # Assume bps
        except (ValueError, IndexError):
             return 0.0

    download_match = DOWNLOAD_SPEED_PATTERN.search(full_output)
    result_obj.download_speed_mbps = parse_speed(download_match)
    upload_match = UPLOAD_SPEED_PATTERN.search(full_output)
    result_obj.upload_speed_mbps = parse_speed(upload_match)

    ip_info_search_area = process_output
    ip_match = IP_INFO_PATTERN.search(ip_info_search_area)
    if ip_match:
        result_obj.ip = ip_match.group("ip")
        result_obj.location = ip_match.group("loc") # May be None

    # Optional: Enhance GeoIP with DB if available and needed
    db_location = None
    ip_for_geoip = result_obj.ip or result_obj.dedup_key_details.get("address") # Prioritize reported IP
    if geoip_reader and ip_for_geoip:
        db_location = get_geoip_location(ip_for_geoip, geoip_reader)
        if db_location:
            result_obj.location = db_location # Prefer DB location
    if result_obj.location:
        result_obj.flag = COUNTRY_FLAGS.get(result_obj.location.upper(), DEFAULT_FLAG)


    # --- Determine Initial Status and Reason ---
    fail_reason = None
    current_status = "pending"
    # ... (Logic to determine status: timeout, failed, broken based on output patterns and return code - from original script) ...
    if CONTEXT_DEADLINE_PATTERN.search(full_output):
        current_status = "timeout"; fail_reason = f"Internal timeout (>{args.xray_knife_timeout_ms}ms)"
    elif IO_TIMEOUT_PATTERN.search(full_output):
        current_status = "timeout"; fail_reason = "I/O timeout"
    elif CONNECTION_REFUSED_PATTERN.search(full_output):
        current_status = "failed"; fail_reason = "Connection refused"
    elif DNS_ERROR_PATTERN.search(full_output):
        current_status = "failed"; fail_reason = "DNS resolution failed"
    elif HANDSHAKE_ERROR_PATTERN.search(full_output):
        current_status = "failed"; fail_reason = "TLS handshake failed"
    else:
         # Check last few lines for generic fail messages
         search_lines = (process_output.splitlines() + process_error.splitlines())[-5:]
         for line in reversed(search_lines):
              fail_match = XRAY_KNIFE_FAIL_REASON_PATTERN.search(line)
              if fail_match:
                   reason_text = fail_match.group(1).strip()
                   # Avoid overly long/generic reasons
                   if len(reason_text) < 100 and 'stack trace' not in reason_text and reason_text != "null":
                       fail_reason = reason_text
                       if current_status == "pending": current_status = "failed"
                       break

    # Determine final initial status
    if current_status == "pending":
        if process and process.returncode != 0:
            current_status = "broken"
            error_details = process_error.strip() or process_output.strip()
            fail_reason = fail_reason or f"x-knife exited {process.returncode}. Output: {error_details[:100]}"
        elif result_obj.real_delay_ms <= args.xray_knife_timeout_ms:
            current_status = "passed"
            fail_reason = None
            if args.speedtest and (result_obj.download_speed_mbps == 0.0 and result_obj.upload_speed_mbps == 0.0):
                 if not download_match and not upload_match: # Speed test requested but no speed lines found
                      current_status = "semi-passed"
                      fail_reason = "Passed delay, speed test N/A"
        elif result_obj.real_delay_ms > args.xray_knife_timeout_ms:
             current_status = "timeout"
             fail_reason = f"Delay {result_obj.real_delay_ms:.0f}ms > limit {args.xray_knife_timeout_ms}ms"
        else: # Should not happen if delay parsed?
             current_status = "broken"
             fail_reason = fail_reason or f"Unknown status (RC={process.returncode if process else 'N/A'})"


    result_obj.status = current_status
    result_obj.reason = fail_reason

    # --- Run Enhanced Checks ONLY if Initial Test Passed ---
    if result_obj.status in ["passed", "semi-passed"]:
        if args.verbose: print(f"  Initial test PASSED ({result_obj.real_delay_ms:.0f}ms). Running enhanced checks...", file=sys.stderr)

        # 1. Check TLS Fingerprint Params (quick check from parsed data)
        check_tls_fingerprint_params(result_obj)

        # 2. Calculate Resilience Score (quick calculation from parsed data)
        calculate_resilience_score(result_obj) # Updates result_obj.resilience_score

        # 3. Perform CDN Check (runs xray-knife curl)
        perform_cdn_check(result_obj, xray_knife_path, args)

        # 4. Perform Iran Access Test (runs xray-knife curl multiple times)
        perform_iran_access_test(result_obj, xray_knife_path, args)

        # Optional: Adjust status based on enhanced checks?
        # For now, let's keep status as "passed"/"semi-passed" but rely on the score.
        # We could add a check here: if iran_access_passed is False, downgrade status to 'failed'?
        # if result_obj.iran_access_passed is False:
        #     result_obj.status = "failed"
        #     result_obj.reason = f"Failed Iran access test ({result_obj.iran_access_targets_passed}/{result_obj.iran_access_targets_tested})"
        # This might be too aggressive, let's use the score first.

    # --- Calculate FINAL Combined Score ---
    if result_obj.status in ["passed", "semi-passed"]:
         # --- Base Score Component (Delay/Speed) ---
         delay_norm_factor = max(100, args.xray_knife_timeout_ms) # Normalize against timeout
         normalized_delay = min(result_obj.real_delay_ms / delay_norm_factor, 1.0)

         # Inverse speed (higher speed = lower score component), capped
         # Give speed less weight compared to delay and reliability checks
         max_speed_cap = 100.0 # Cap speed contribution at 100 Mbps
         inv_download = 1.0 / (1.0 + min(result_obj.download_speed_mbps, max_speed_cap))
         inv_upload = 1.0 / (1.0 + min(result_obj.upload_speed_mbps, max_speed_cap))

         # Weights for base score components
         delay_weight = 0.60
         dl_weight = 0.20 # Reduced weight
         ul_weight = 0.10 # Reduced weight
         speed_weight = 0.10 # Placeholder if only one speed metric needed?

         base_score_component = (delay_weight * normalized_delay)
         if args.speedtest and result_obj.status == "passed": # Only include speed if fully passed test
              base_score_component += (dl_weight * inv_download + ul_weight * inv_upload)
         else: # If semi-passed or no speedtest, distribute speed weight back to delay? Or just ignore. Let's ignore.
             base_score_component = normalized_delay # Score purely on delay if speed not applicable/tested

         # --- Penalties/Bonuses from Enhanced Checks ---
         # Start with the resilience score multiplier
         current_score = base_score_component * result_obj.resilience_score

         # Penalties (add to score, higher is worse)
         # Heavy penalty if Iran access test failed decisively
         if result_obj.iran_access_passed is False:
              current_score += 0.8 # Significant penalty
         # Moderate penalty if CDN check failed or indicated non-CDN (might be less desirable)
         elif result_obj.is_cdn_ip is False: # Explicitly non-CDN
              current_score += 0.2
         elif result_obj.is_cdn_ip is None and result_obj.cdn_check_ip is not None: # Check failed to determine org
              current_score += 0.1

         # Bonus (subtract from score, lower is better)
         # Small bonus if Iran access test passed
         if result_obj.iran_access_passed is True:
             current_score -= 0.1
         # Small bonus if exit IP seems to be from a CDN
         if result_obj.is_cdn_ip is True:
             current_score -= 0.05

         # Ensure score doesn't go below zero due to bonuses
         result_obj.combined_score = max(0.01, current_score) # Ensure positive score

         if args.verbose:
             print(f"      Score Calculation: Base={base_score_component:.3f}, Resilience={result_obj.resilience_score:.3f}, IranAccessOK={result_obj.iran_access_passed}, CDN={result_obj.is_cdn_ip} -> Final Score={result_obj.combined_score:.4f}", file=sys.stderr)


    else: # Failed, timeout, broken, skipped
         result_obj.combined_score = float('inf')
         # Ensure reason is set for non-passed states
         if result_obj.status not in ["passed", "semi-passed", "pending", "skipped"] and not result_obj.reason:
              result_obj.reason = f"Failed/Timeout/Broken (RC={process.returncode if process else 'N/A'})"


    return result_obj


# ---------------------------
# Worker function for ThreadPoolExecutor (Dispatches based on protocol)
# ---------------------------
def run_test_worker(result_obj: TestResult, xray_knife_path: Optional[str], args: argparse.Namespace) -> TestResult:
    global is_ctrl_c_pressed
    if is_ctrl_c_pressed:
        if result_obj.status == "pending":
            result_obj.status = "skipped"; result_obj.reason = "Interrupted"
        return result_obj

    tested_result = None
    try:
        # --- Dispatch based on protocol ---
        if result_obj.protocol == "wg":
            if args.verbose: print(f"Testing WG/WARP via UDP: {result_obj.original_config[:60]}...", file=sys.stderr)
            tested_result = test_wg_udp_sync(result_obj, args) # UDP test remains unchanged
        else:
            # Use enhanced xray-knife test for all other protocols
            if args.verbose: print(f"Testing via xray-knife (enhanced): {result_obj.original_config[:60]}...", file=sys.stderr)
            tested_result = test_config_with_xray_knife(result_obj, xray_knife_path, args)

    except Exception as e:
         print(f"\nCRITICAL ERROR in worker for {result_obj.original_config[:50]}: {type(e).__name__} - {e}", file=sys.stderr)
         import traceback
         traceback.print_exc(file=sys.stderr) # Print stack trace for worker errors
         if tested_result is None: tested_result = result_obj
         tested_result.status = "broken"; tested_result.reason = f"Worker error: {e}"
         tested_result.combined_score = float('inf'); tested_result.real_delay_ms = float('inf')

    return tested_result


# ---------------------------
# Saving configurations
# ---------------------------
# ... (save_configs from your original script - unchanged) ...
def save_configs(outbounds: List[str], filepath: str, base64_encode: bool):
    if not outbounds:
        print(f"Warning: No configs to save to '{filepath}'.", file=sys.stderr)
        return

    output_path = Path(filepath)
    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)

        content_to_write = ""
        if base64_encode:
            combined = "\n".join(outbounds)
            encoded = base64.b64encode(combined.encode('utf-8')).decode("utf-8")
            content_to_write = encoded
        else:
            content_to_write = "\n".join(config.strip() for config in outbounds) + "\n"

        with output_path.open("w", encoding='utf-8') as outfile:
            outfile.write(content_to_write)

        encoding_type = "Base64 encoded" if base64_encode else "plaintext"
        print(f"\nSuccessfully saved {len(outbounds)} final configs to '{output_path.resolve()}' ({encoding_type}).")

    except IOError as e:
        print(f"\nError saving config to '{filepath}': {e}", file=sys.stderr)
    except Exception as e:
        print(f"\nUnexpected error saving config: {e}", file=sys.stderr)

# ---------------------------
# Save Detailed Results (CSV and Optional JSON) - Enhanced Headers/Fields
# ---------------------------
def save_detailed_results(results: List[TestResult], csv_filepath: Optional[str] = None, json_filepath: Optional[str] = None):
    if not results:
        print("No detailed results to save.")
        return

    # --- Save CSV ---
    if csv_filepath:
        csv_path = Path(csv_filepath)
        try:
            csv_path.parent.mkdir(parents=True, exist_ok=True)
            import csv
            # Add new fields to headers
            headers = [
                "status", "real_delay_ms", "download_speed_mbps", "upload_speed_mbps",
                "ip", "location", "flag", "protocol", "reason",
                "combined_score", # Add score
                "resilience_score", # Add score component
                "is_cdn_ip", "cdn_check_ip", "cdn_check_org", # CDN check results
                "iran_access_passed", "iran_targets_passed", "iran_targets_tested", # Iran check results
                "tls_fingerprint_type", # TLS FP check result
                "source", "original_config",
                "dedup_protocol", "dedup_address", "dedup_port", "dedup_host", "dedup_net", "dedup_tls", "dedup_path", "dedup_fp" # Dedup details
            ]

            with csv_path.open('w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=headers, quoting=csv.QUOTE_MINIMAL, extrasaction='ignore')
                writer.writeheader()
                for result in results:
                     # Format potentially infinite/None values for CSV
                     delay_csv = f"{result.real_delay_ms:.0f}" if result.real_delay_ms != float('inf') else ''
                     dl_speed_csv = f"{result.download_speed_mbps:.2f}" if result.download_speed_mbps > 0 else ''
                     ul_speed_csv = f"{result.upload_speed_mbps:.2f}" if result.upload_speed_mbps > 0 else ''
                     score_csv = f"{result.combined_score:.4f}" if result.combined_score != float('inf') else ''
                     resil_score_csv = f"{result.resilience_score:.3f}" if result.resilience_score != float('inf') else '' # Usually not inf

                     def format_bool(b): return str(b) if b is not None else ''
                     def format_str(s): return str(s) if s is not None else ''

                     row = {
                        "status": result.status,
                        "real_delay_ms": delay_csv,
                        "download_speed_mbps": dl_speed_csv,
                        "upload_speed_mbps": ul_speed_csv,
                        "ip": format_str(result.ip),
                        "location": format_str(result.location),
                        "flag": format_str(result.flag),
                        "protocol": format_str(result.protocol),
                        "reason": (result.reason or '').replace('\n', ' ').replace('\r', ''),
                        "combined_score": score_csv,
                        "resilience_score": resil_score_csv,
                        "is_cdn_ip": format_bool(result.is_cdn_ip),
                        "cdn_check_ip": format_str(result.cdn_check_ip),
                        "cdn_check_org": format_str(result.cdn_check_org),
                        "iran_access_passed": format_bool(result.iran_access_passed),
                        "iran_targets_passed": format_str(result.iran_access_targets_passed),
                        "iran_targets_tested": format_str(result.iran_access_targets_tested),
                        "tls_fingerprint_type": format_str(result.tls_fingerprint_type),
                        "source": format_str(result.source),
                        "original_config": result.original_config,
                        # Dedup details from the stored dict
                        "dedup_protocol": format_str(result.dedup_key_details.get("protocol")),
                        "dedup_address": format_str(result.dedup_key_details.get("address")),
                        "dedup_port": format_str(result.dedup_key_details.get("port")),
                        "dedup_host": format_str(result.dedup_key_details.get("host")),
                        "dedup_net": format_str(result.dedup_key_details.get("net")),
                        "dedup_tls": format_str(result.dedup_key_details.get("tls")),
                        "dedup_path": format_str(result.dedup_key_details.get("path")),
                        "dedup_fp": format_str(result.dedup_key_details.get("fp")),
                     }
                     writer.writerow(row)
            print(f"Successfully saved {len(results)} detailed results to '{csv_path.resolve()}' (CSV).")

        except IOError as e: print(f"\nError saving detailed CSV results to '{csv_filepath}': {e}", file=sys.stderr)
        except ImportError: print("\nError: Could not import 'csv' module. Cannot save detailed CSV results.", file=sys.stderr)
        except Exception as e: print(f"\nUnexpected error saving detailed CSV results: {e}", file=sys.stderr)

    # --- Save JSON ---
    if json_filepath:
        json_path = Path(json_filepath)
        try:
            json_path.parent.mkdir(parents=True, exist_ok=True)
            results_list = []
            for result in results:
                # Convert dataclass to dict, handle infinity/None
                result_dict = {
                    "status": result.status,
                    "reason": result.reason,
                    "real_delay_ms": result.real_delay_ms if result.real_delay_ms != float('inf') else None,
                    "download_speed_mbps": result.download_speed_mbps,
                    "upload_speed_mbps": result.upload_speed_mbps,
                    "ip": result.ip,
                    "location": result.location,
                    "flag": result.flag,
                    "protocol": result.protocol,
                    "combined_score": result.combined_score if result.combined_score != float('inf') else None,
                    "resilience_score": result.resilience_score,
                    "cdn_check_ip": result.cdn_check_ip,
                    "cdn_check_org": result.cdn_check_org,
                    "is_cdn_ip": result.is_cdn_ip,
                    "iran_access_passed": result.iran_access_passed,
                    "iran_targets_passed": result.iran_access_targets_passed,
                    "iran_targets_tested": result.iran_access_targets_tested,
                    "tls_fingerprint_type": result.tls_fingerprint_type,
                    "source": result.source,
                    "original_config": result.original_config,
                    "dedup_details": result.dedup_key_details, # Keep the raw dict here
                }
                results_list.append(result_dict)

            with json_path.open('w', encoding='utf-8') as jsonfile:
                json.dump(results_list, jsonfile, indent=2, ensure_ascii=False)

            print(f"Successfully saved {len(results)} detailed results to '{json_path.resolve()}' (JSON).")

        except IOError as e: print(f"\nError saving detailed JSON results to '{json_filepath}': {e}", file=sys.stderr)
        except Exception as e: print(f"\nUnexpected error saving detailed JSON results: {e}", file=sys.stderr)

# ---------------------------
# Rename and limit configs - Now uses the refined combined_score
# ---------------------------
def filter_rename_limit_configs(
    tested_results: List[TestResult],
    limit_per_protocol: int,
    name_prefix: str,
    include_countries: Optional[List[str]] = None,
    exclude_countries: Optional[List[str]] = None
) -> List[str]:
    global args # Access global args

    # --- 1. Filter working configs ---
    # Keep status "passed" or "semi-passed" (UDP test might be semi-passed)
    working_results = [r for r in tested_results if r.status in ["passed", "semi-passed"]]
    print(f"\nFound {len(working_results)} working configs initially (status 'passed' or 'semi-passed').")

    # --- 2. Apply GeoIP filters (if used) ---
    filtered_results = []
    if include_countries or exclude_countries:
        geoip_was_enabled = args.ip_info or args.geoip_db # Check if GeoIP was possible
        # Commented out the warning as GeoIP is less central now
        # if not geoip_was_enabled:
        #      print("Warning: Country filtering requested, but GeoIP info might be limited.", file=sys.stderr)

        inc = set(c.upper() for c in include_countries) if include_countries else None
        exc = set(c.upper() for c in exclude_countries) if exclude_countries else None
        skipped_by_filter = 0

        for r in working_results:
            loc = r.location.upper() if r.location else None
            included = True
            # Filter logic: Only exclude if location known and matches exclude list.
            # Only include if location known and matches include list (if include list exists).
            # Keep configs with unknown location unless an exclude list is present? Or exclude unknowns if include list present?
            # Decision: Keep unknown location configs UNLESS an explicit include list is given.
            if loc:
                if exc and loc in exc: included = False
                if inc and loc not in inc: included = False
            elif inc: # If location is unknown AND an include list exists, exclude it
                included = False

            if included:
                filtered_results.append(r)
            else:
                skipped_by_filter += 1

        print(f"Filtered {skipped_by_filter} configs based on country rules (--include/--exclude). Kept {len(filtered_results)}.")
        working_results = filtered_results
    else:
        print("No country filters applied.")


    if not working_results:
        print("No working configs remain after filtering. Nothing to rename/save.", file=sys.stderr)
        return []

    # --- 3. Group by protocol, Sort by **NEW SCORE**, Limit, and Rename ---
    protocol_map = {
        "ss": "SS", "ssr": "SSR", "shadowsocks": "SS", "vless": "VL", "vmess": "VM",
        "trojan": "TR", "tuic": "TU", "hysteria": "HY", "socks": "SK", "http": "HT",
        "wg": "WG",
    }
    renamed_configs: List[str] = []
    protocol_groups: Dict[str, List[TestResult]] = {}

    for result in working_results:
        proto_norm = result.protocol or "unknown"
        # Use the normalized protocol name from parsing directly
        abbr = protocol_map.get(proto_norm, proto_norm[:2].upper()) # Get abbreviation or use first 2 letters
        protocol_groups.setdefault(abbr, []).append(result)

    total_renamed_count = 0
    print(f"Renaming and limiting up to {limit_per_protocol} configs per protocol based on combined score...")
    for abbr, group_list in protocol_groups.items():
        # --- SORTING IS KEY: Use combined_score (lower is better), then delay as tie-breaker ---
        group_list.sort(key=lambda r: (r.combined_score, r.real_delay_ms))
        limited_list = group_list[:limit_per_protocol]
        total_renamed_count += len(limited_list)

        for i, result in enumerate(limited_list, start=1):
            config = result.original_config
            flag = result.flag or DEFAULT_FLAG
            # Add indicators to the name for quick reference?
            iran_ok_indicator = "[IR✅]" if result.iran_access_passed is True else "[IR❌]" if result.iran_access_passed is False else "[IR?]"
            cdn_indicator = "[CDN]" if result.is_cdn_ip is True else ""
            fp_indicator = f"[{result.tls_fingerprint_type[:4]}]" if result.tls_fingerprint_type and result.tls_fingerprint_type != "unknown" else ""

            # Construct new tag
            # Example: 🔒Pr0xySh4rk🦈[VL][01][🇩🇪][IR✅][CDN][REAL]
            new_tag = f"🔒{name_prefix}🦈[{abbr}][{i:02d}][{flag}]{iran_ok_indicator}{cdn_indicator}{fp_indicator}"
            safe_tag = urllib.parse.quote(new_tag) # URL encode the tag
            base_part = config.split("#", 1)[0]
            new_config = f"{base_part}#{safe_tag}"
            renamed_configs.append(new_config)

    print(f"Prepared {total_renamed_count} renamed configs across {len(protocol_groups)} protocols.")
    renamed_configs.sort(key=lambda x: x.split("#", 1)[-1]) # Sort final list by tag for consistency
    return renamed_configs


# ---------------------------
# Fetch and parse subscription worker
# ---------------------------
# ... (fetch_and_parse_subscription_worker from your original script - unchanged) ...
def fetch_and_parse_subscription_worker(url: str, proxy: Optional[str], timeout: int, force_fetch: bool) -> List[TestResult]:
    content = fetch_content(url, proxy, timeout, force_fetch)
    if content:
        parsed_results = parse_config_content(content, url)
        if args and args.verbose > 1 and parsed_results:
            print(f"Debug: Parsed {len(parsed_results)} configs from {url}", file=sys.stderr)
        return parsed_results
    else:
        return []


# ---------------------------
# Print Summary Statistics - Enhanced
# ---------------------------
def print_protocol_statistics(tested_results: List[TestResult]):
    global args
    if not tested_results: return

    print("\n--- Protocol Statistics (Enhanced) ---")
    protocol_stats: Dict[str, Dict[str, Any]] = {}
    total_tested_count = len(tested_results)

    for result in tested_results:
         proto_norm = result.protocol or "unknown" # Already normalized

         if proto_norm not in protocol_stats:
              protocol_stats[proto_norm] = {
                   "tested_count": 0, "passed_count": 0, "semi_passed_count": 0,
                   "failed_count": 0, "timeout_count": 0, "broken_count": 0, "skipped_count": 0,
                   "total_delay": 0.0, "valid_delay_count": 0, "min_delay": float('inf'), "max_delay": 0.0,
                   "total_dl_speed": 0.0, "valid_dl_count": 0, "max_dl_speed": 0.0,
                   "total_ul_speed": 0.0, "valid_ul_count": 0, "max_ul_speed": 0.0,
                   "total_score": 0.0, "valid_score_count": 0, "min_score": float('inf'), "max_score": 0.0, # Score stats
                   "locations": set(),
                   "iran_access_passed_count": 0, # New stats
                   "cdn_ip_count": 0,
                   "good_fp_count": 0,
              }

         stats = protocol_stats[proto_norm]
         stats["tested_count"] += 1
         status_key = f"{result.status}_count"
         if status_key in stats: stats[status_key] += 1
         if result.location: stats["locations"].add(f"{result.flag}{result.location.upper()}")

         # Accumulate detailed stats for working configs only
         if result.status in ["passed", "semi-passed"]:
             delay = result.real_delay_ms
             if delay != float('inf'):
                 stats["total_delay"] += delay
                 stats["valid_delay_count"] += 1
                 stats["min_delay"] = min(stats['min_delay'], delay)
                 stats["max_delay"] = max(stats['max_delay'], delay)

             dl_speed = result.download_speed_mbps
             if dl_speed > 0: # Only count non-zero speed
                 stats["total_dl_speed"] += dl_speed
                 stats["valid_dl_count"] += 1
                 stats["max_dl_speed"] = max(stats['max_dl_speed'], dl_speed)

             ul_speed = result.upload_speed_mbps
             if ul_speed > 0:
                 stats["total_ul_speed"] += ul_speed
                 stats["valid_ul_count"] += 1
                 stats["max_ul_speed"] = max(stats['max_ul_speed'], ul_speed)

             score = result.combined_score
             if score != float('inf'):
                 stats["total_score"] += score
                 stats["valid_score_count"] += 1
                 stats["min_score"] = min(stats["min_score"], score)
                 stats["max_score"] = max(stats["max_score"], score)

             # Count enhanced check passes
             if result.iran_access_passed is True: stats["iran_access_passed_count"] += 1
             if result.is_cdn_ip is True: stats["cdn_ip_count"] += 1
             if result.tls_fingerprint_type not in ["unknown", "custom", "random", None]: # Count known good/reality
                 stats["good_fp_count"] += 1


    sorted_protocols = sorted(protocol_stats.keys())
    for protocol in sorted_protocols:
        stats = protocol_stats[protocol]
        total_tested = stats["tested_count"]
        working_count = stats['passed_count'] + stats['semi_passed_count']
        working_perc = (working_count / total_tested * 100) if total_tested > 0 else 0

        # Format averages safely
        avg_delay_str = f"{stats['total_delay'] / stats['valid_delay_count']:.0f}ms" if stats["valid_delay_count"] > 0 else "N/A"
        min_delay_str = "N/A" if stats['min_delay'] == float('inf') else f"{stats['min_delay']:.0f}ms"
        max_delay_str = "N/A" if stats['max_delay'] == 0.0 and stats['min_delay'] == float('inf') else f"{stats['max_delay']:.0f}ms"

        avg_dl_str = f"{stats['total_dl_speed'] / stats['valid_dl_count']:.2f} Mbps" if args.speedtest and stats["valid_dl_count"] > 0 else "N/A"
        max_dl_str = f"{stats['max_dl_speed']:.2f} Mbps" if args.speedtest and stats["valid_dl_count"] > 0 else "N/A"
        avg_ul_str = f"{stats['total_ul_speed'] / stats['valid_ul_count']:.2f} Mbps" if args.speedtest and stats["valid_ul_count"] > 0 else "N/A"
        max_ul_str = f"{stats['max_ul_speed']:.2f} Mbps" if args.speedtest and stats["valid_ul_count"] > 0 else "N/A"

        avg_score_str = f"{stats['total_score'] / stats['valid_score_count']:.3f}" if stats["valid_score_count"] > 0 else "N/A"
        min_score_str = "N/A" if stats['min_score'] == float('inf') else f"{stats['min_score']:.3f}"
        max_score_str = "N/A" if stats['max_score'] == 0.0 and stats['min_score'] == float('inf') else f"{stats['max_score']:.3f}"

        loc_summary = ", ".join(sorted(list(stats["locations"]))) if stats["locations"] else "None"
        speed_note = ""
        if protocol == "wg": speed_note = " (Speed N/A)" if args.speedtest else ""

        print(f"Protocol: {protocol.upper():<8} (Tested: {total_tested}, Working: {working_count} [{working_perc:.1f}%])")
        print(f"  Status: Pass:{stats['passed_count']}, Semi:{stats['semi_passed_count']}, "
              f"Fail:{stats['failed_count']}, Timeout:{stats['timeout_count']}, "
              f"Broken:{stats['broken_count']}, Skip:{stats['skipped_count']}")
        print(f"  Delay (Avg/Min/Max): {avg_delay_str} / {min_delay_str} / {max_delay_str}")
        if args.speedtest:
             print(f"  DL Speed (Avg/Max): {avg_dl_str} / {max_dl_str}{speed_note}")
             print(f"  UL Speed (Avg/Max): {avg_ul_str} / {max_ul_str}{speed_note}")
        # Show score and enhanced stats for working configs
        print(f"  Score (Avg/Min/Max): {avg_score_str} / {min_score_str} / {max_score_str} (Lower is better)")
        if working_count > 0: # Only show percentages if there are working configs
             iran_pass_perc = (stats['iran_access_passed_count'] / working_count * 100) if working_count > 0 else 0
             cdn_perc = (stats['cdn_ip_count'] / working_count * 100) if working_count > 0 else 0
             fp_perc = (stats['good_fp_count'] / working_count * 100) if working_count > 0 else 0
             print(f"  Enhanced (Working): IranAccessOK: {stats['iran_access_passed_count']} [{iran_pass_perc:.0f}%], CDN IP: {stats['cdn_ip_count']} [{cdn_perc:.0f}%], Good FP: {stats['good_fp_count']} [{fp_perc:.0f}%]")
        else:
             print(f"  Enhanced (Working): IranAccessOK: 0, CDN IP: 0, Good FP: 0")

        # Show GeoIP if attempted
        if args.ip_info or args.geoip_db:
             print(f"  Locations Found: {loc_summary}")
        print("-" * 30)

    print(f"Total Configs Tested: {total_tested_count}")
    total_working = sum(p['passed_count'] + p['semi_passed_count'] for p in protocol_stats.values())
    total_working_perc = (total_working / total_tested_count * 100) if total_tested_count > 0 else 0
    print(f"Overall Working: {total_working} [{total_working_perc:.1f}%]")

# ---------------------------
# Main function
# ---------------------------
def main():
    global is_ctrl_c_pressed, total_outbounds_count, completed_outbounds_count, args, geoip_reader
    signal.signal(signal.SIGINT, signal_handler)

    # --- Argument Parsing ---
    parser = argparse.ArgumentParser(
        description="Pr0xySh4rk Config Manager (Enhanced for Iran) - Fetch, Test (Standard + Heuristics), Filter, Rename, Save.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    # ... (Keep most arguments from original: Input/Output, Fetching, Common Testing, xray-knife specific, UDP specific, Filtering, Misc) ...
    # Input/Output Group
    io_group = parser.add_argument_group('Input/Output Options')
    io_group.add_argument("--input", "-i", required=True, help="Input file containing subscription URLs (one per line, plaintext or base64 list).")
    io_group.add_argument("--output", "-o", required=True, help="Output file for the best merged/renamed configs.")
    io_group.add_argument("--output-format", choices=["base64", "text"], default="base64", help="Encoding for the main output config file.")
    io_group.add_argument("--output-csv", help="Optional output file path for detailed test results in CSV format.")
    io_group.add_argument("--output-json", help="Optional output file path for detailed test results in JSON format.")
    io_group.add_argument("--name-prefix", default="Pr0xySh4rk", help="Prefix for renaming final configs.")

    # Fetching Group
    fetch_group = parser.add_argument_group('Fetching Options')
    fetch_group.add_argument("--fetch-proxy", metavar="PROXY_URL", help="Proxy (e.g., socks5://127.0.0.1:1080) for fetching subscription URLs.")
    fetch_group.add_argument("--fetch-timeout", type=int, default=DEFAULT_FETCH_TIMEOUT, metavar="SEC", help="Timeout in seconds for fetching each subscription URL.")
    fetch_group.add_argument("--no-cache", action="store_true", help="Disable loading from cache and force fetching all subscription URLs.")
    fetch_group.add_argument("--clear-cache", action="store_true", help="Clear the subscription cache directory before running.")
    fetch_group.add_argument("--cache-ttl", type=int, default=CACHE_TTL_HOURS, metavar="HOURS", help="Cache validity period in hours.")

    # Testing Group (Common)
    test_common_group = parser.add_argument_group('Common Testing Options')
    test_common_group.add_argument("--threads", "-t", type=int, default=DEFAULT_THREADS, metavar="N", help="Number of concurrent threads for fetching and testing.")
    test_common_group.add_argument("--speedtest", "-p", action="store_true", help="Enable speed testing (only applies to xray-knife tests).")
    test_common_group.add_argument("--ip-info", "--rip", action="store_true", help="Get IP/Location via xray-knife (--rip). Still useful for basic GeoIP.")
    test_common_group.add_argument("--geoip-db", metavar="PATH", help="Path to GeoLite2-Country.mmdb database file for GeoIP lookups (Optional, less critical now).")

    # Testing Group (xray-knife specific - for non-WG)
    test_xray_group = parser.add_argument_group('Testing Options (xray-knife - for non-WG/WARP)')
    test_xray_group.add_argument("--xray-knife-path", metavar="PATH", help="Path to xray-knife executable. Required if non-WG configs are present.")
    test_xray_group.add_argument("--xray-knife-core", choices=["auto", "xray", "singbox"], default="auto", help="Core engine for xray-knife.")
    test_xray_group.add_argument("--xray-knife-timeout-ms", type=int, default=DEFAULT_XRAY_KNIFE_TIMEOUT_MS, metavar="MS", help="Max delay for primary xray-knife test in milliseconds.")
    test_xray_group.add_argument("--xray-knife-insecure", action="store_true", help="Allow insecure TLS connections during xray-knife testing (-e).")
    test_xray_group.add_argument("--test-url", default=DEFAULT_TEST_URL, metavar="URL", help="Primary URL used by xray-knife for connectivity/delay tests.")
    test_xray_group.add_argument("--test-method", default=DEFAULT_TEST_METHOD, metavar="METHOD", help="HTTP method used by xray-knife for primary testing.")
    test_xray_group.add_argument("--speedtest-amount", "-a", type=str, default=f"{DEFAULT_SPEEDTEST_AMOUNT_KB}kb", metavar="AMOUNT[kb|mb]", help="Data amount for xray-knife speed test (e.g., 10000kb, 15mb).")

    # Testing Group (UDP specific - for WG/WARP)
    test_udp_group = parser.add_argument_group('Testing Options (UDP - for WG/WARP)')
    test_udp_group.add_argument("--udp-timeout", type=float, default=DEFAULT_UDP_TIMEOUT_S, metavar="SEC", help="Timeout in seconds for UDP tests (WG/WARP).")

    # Filtering & Concurrency Group
    filter_group = parser.add_argument_group('Filtering & Output Options')
    filter_group.add_argument("--limit", "-l", type=int, default=DEFAULT_BEST_CONFIGS_LIMIT, metavar="N", help="Maximum number of best configs to save *per protocol* based on the combined score.")
    filter_group.add_argument("--include-countries", metavar="CC", help="Comma-separated list of 2-letter country codes to include (e.g., US,DE,JP). Requires GeoIP info.")
    filter_group.add_argument("--exclude-countries", metavar="CC", help="Comma-separated list of 2-letter country codes to exclude (e.g., CN,RU,IR). Requires GeoIP info.")

    # Misc Group
    misc_group = parser.add_argument_group('Miscellaneous Options')
    misc_group.add_argument("--protocol-stats", action="store_true", help="Show enhanced summary statistics for each protocol after testing.")
    misc_group.add_argument("--verbose", "-v", action="count", default=0, help="Increase verbosity (-v, -vv). -v shows basic test steps, -vv shows sub-check details.")


    args = parser.parse_args()

    # --- Initial Setup ---
    print("\n--- Pr0xySh4rk Config Manager (Enhanced for Iran) ---")
    print(f"Test Mode: Enhanced xray-knife (non-WG), UDP (WG/WARP)")
    print(f"Using {args.threads} threads. Config limit per protocol: {args.limit}.")
    print(f"Xray-Knife Timeout (Main Test): {args.xray_knife_timeout_ms}ms. UDP Timeout: {args.udp_timeout}s.")
    print(f"Speedtest (xray-knife only): {'Enabled' if args.speedtest else 'Disabled'}. GeoIP Checks: {'Enabled' if args.ip_info or args.geoip_db else 'Disabled'}")
    print(f"Enhanced Checks: CDN IP, Iran Access ({IRAN_TEST_COUNT} targets, thr={IRAN_TEST_SUCCESS_THRESHOLD*100:.0f}%), TLS FP Params, Resilience Scoring")
    if args.xray_knife_timeout_ms < 5000 and args.speedtest:
        print("Warning: Low primary xray-knife timeout with speedtest enabled may lead to inaccurate speed results.", file=sys.stderr)
    if args.verbose > 0:
        print(f"Verbose Level: {args.verbose}", file=sys.stderr)


    if args.clear_cache:
        if CACHE_DIR.exists():
            print(f"Clearing cache directory: {CACHE_DIR.resolve()}", file=sys.stderr)
            try: shutil.rmtree(CACHE_DIR)
            except OSError as e: print(f"Warning: Could not fully clear cache: {e}", file=sys.stderr)
        else: print("Cache directory not found, nothing to clear.", file=sys.stderr)

    # --- Find xray-knife ---
    xray_knife_executable = find_xray_knife(args.xray_knife_path)
    # Error if needed is deferred until after parsing/deduplication

    # --- Load GeoIP Database (Optional) ---
    if args.geoip_db:
        if not geoip2: print("Warning: --geoip-db specified, but 'geoip2' module is not installed. DB lookup disabled.", file=sys.stderr)
        else:
            db_path = Path(args.geoip_db).resolve()
            if not db_path.is_file(): print(f"Warning: GeoIP database file not found at: {db_path}", file=sys.stderr)
            else:
                try:
                    geoip_reader = geoip2.database.Reader(str(db_path))
                    if args.verbose: print(f"Loaded GeoIP database: {db_path}", file=sys.stderr)
                except Exception as e:
                    print(f"Warning: Error loading GeoIP database '{db_path}': {e}", file=sys.stderr)
                    geoip_reader = None

    # --- Read Subscription URLs ---
    subscription_urls = []
    try:
        input_path = Path(args.input)
        if not input_path.is_file():
            print(f"Error: Input file '{args.input}' not found.", file=sys.stderr); sys.exit(1)
        # ... (Robust input reading: try base64, then utf-8 - from original script) ...
        raw_bytes = input_path.read_bytes()
        decoded_content = None
        try:
             cleaned_bytes = bytes(filter(lambda x: not chr(x).isspace(), raw_bytes))
             if len(cleaned_bytes) % 4 != 0: cleaned_bytes += b'=' * (4 - len(cleaned_bytes) % 4)
             potential_decoded = base64.b64decode(cleaned_bytes, validate=True).decode('utf-8', errors='ignore')
             # Simple check if it contains URLs or proxy links
             if '://' in potential_decoded or '\n' in potential_decoded:
                  decoded_content = potential_decoded
                  if args.verbose: print("Input file decoded as Base64.", file=sys.stderr)
             else: raise ValueError("Decoded content doesn't look like URLs/configs")
        except (base64.binascii.Error, ValueError, UnicodeDecodeError):
             try:
                  decoded_content = raw_bytes.decode('utf-8')
                  if args.verbose: print("Input file read as plaintext UTF-8.", file=sys.stderr)
             except UnicodeDecodeError:
                  print(f"Error: Input file '{args.input}' is not valid Base64 nor UTF-8 text.", file=sys.stderr); sys.exit(1)

        if decoded_content:
             subscription_urls = [line.strip() for line in decoded_content.splitlines() if line.strip() and line.strip().startswith(("http://", "https://")) and '://' in line] # Simple validation
        print(f"Read {len(subscription_urls)} URLs from '{args.input}'.", file=sys.stderr)

    except Exception as e:
        print(f"Error reading input file '{args.input}': {e}", file=sys.stderr); sys.exit(1)

    if not subscription_urls:
        print("No valid subscription URLs found. Exiting.", file=sys.stderr); sys.exit(0)

    # --- Fetch and Parse Subscriptions Concurrently ---
    print(f"\nFetching {len(subscription_urls)} subscriptions (Cache TTL: {args.cache_ttl}h)...")
    all_parsed_results: List[TestResult] = []
    fetch_futures = []
    try:
        # Use ThreadPoolExecutor for fetching I/O
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads, thread_name_prefix="Fetcher") as executor:
             # Prepare futures
             for url in subscription_urls:
                  if is_ctrl_c_pressed: break
                  future = executor.submit(fetch_and_parse_subscription_worker, url, args.fetch_proxy, args.fetch_timeout, args.no_cache)
                  fetch_futures.append(future)

             # Process completed futures with progress bar
             prog_desc = "Fetching Subs"
             if args.verbose > 0: prog_desc = None # Disable tqdm desc if verbose msgs expected
             progress_bar_fetch = tqdm_progress(concurrent.futures.as_completed(fetch_futures), total=len(fetch_futures), desc=prog_desc, unit="URL", disable=prog_desc is None)

             for future in progress_bar_fetch:
                 if is_ctrl_c_pressed: break
                 try:
                      results_list = future.result()
                      if results_list: all_parsed_results.extend(results_list)
                 except Exception as exc: print(f'\nSubscription worker generated an exception: {exc}', file=sys.stderr)

        if is_ctrl_c_pressed: print("\nFetching interrupted by user.", file=sys.stderr)

    except Exception as e: print(f"\nError during subscription fetching phase: {e}", file=sys.stderr)

    initial_config_count = len(all_parsed_results)
    print(f"Fetched a total of {initial_config_count} potential configs.")
    if not all_parsed_results and not is_ctrl_c_pressed:
        print("No configs found after fetching. Exiting.", file=sys.stderr)
        if geoip_reader: geoip_reader.close()
        sys.exit(0)

    # --- Deduplicate ---
    print("\nDeduplicating configs...")
    unique_results = deduplicate_outbounds(all_parsed_results)
    total_outbounds_count = len(unique_results)
    if total_outbounds_count == 0:
        print("No unique configs to test after deduplication. Exiting.", file=sys.stderr)
        if geoip_reader: geoip_reader.close()
        sys.exit(0)

    # --- Check if xray-knife is needed and available ---
    needs_xray_knife = any(res.protocol != "wg" for res in unique_results)
    if needs_xray_knife and not xray_knife_executable:
         print("\nError: xray-knife executable is required for testing non-WG/WARP configs but was not found.", file=sys.stderr)
         print("Please ensure it's in your PATH, provide --xray-knife-path, or set XRAY_KNIFE_PATH environment variable.", file=sys.stderr)
         if geoip_reader: geoip_reader.close(); sys.exit(1)
    elif needs_xray_knife and args.verbose:
         print(f"Using xray-knife for non-WG tests: {xray_knife_executable}")


    # --- Test Configs Concurrently ---
    print(f"\nStarting enhanced tests on {total_outbounds_count} unique configs...")
    tested_results: List[TestResult] = []
    completed_outbounds_count = 0
    test_futures = []
    executor = None
    try:
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=args.threads, thread_name_prefix="Tester")
        for result_obj in unique_results:
            if is_ctrl_c_pressed: break
            future = executor.submit(run_test_worker, result_obj, xray_knife_executable, args)
            test_futures.append(future)

        # Process results as they complete with progress bar
        prog_desc_test = "Testing Configs"
        # Disable tqdm bar if verbose to avoid clutter, but keep counter
        disable_tqdm_bar = args.verbose > 0
        if disable_tqdm_bar: prog_desc_test = None # No description text if verbose

        progress_bar_test = tqdm_progress(
            concurrent.futures.as_completed(test_futures),
            total=total_outbounds_count,
            desc=prog_desc_test,
            unit="config",
            disable=disable_tqdm_bar # Disable the bar itself if verbose
        )

        for future in progress_bar_test:
            # Check for Ctrl+C inside the loop too
            if is_ctrl_c_pressed and not future.done():
                try: future.cancel()
                except: pass # Ignore errors cancelling
                continue # Skip processing cancelled future

            try:
                tested_result = future.result()
                tested_results.append(tested_result)
                # Print verbose output ONLY if verbose is set (no double printing with tqdm fallback)
                if args.verbose > 0 and tested_result.status != 'skipped':
                    status_line = format_result_line(tested_result, args) # Use helper
                    # Print directly to stderr if verbose, tqdm handles its own updates
                    print(status_line, file=sys.stderr)

            except concurrent.futures.CancelledError:
                 continue # Just skip cancelled ones
            except Exception as exc:
                 print(f'\nTester worker execution resulted in exception: {exc}', file=sys.stderr)
                 # Optionally log the specific config that failed? Difficult here.
            finally:
                 completed_outbounds_count += 1
                 # Update tqdm description manually if verbose to show progress count
                 if disable_tqdm_bar and progress_bar_test:
                     progress_bar_test.set_description_str(f"Testing Configs: {completed_outbounds_count}/{total_outbounds_count}")


    except KeyboardInterrupt:
         print("\nKeyboardInterrupt caught in main testing loop. Signaling shutdown...", file=sys.stderr)
         is_ctrl_c_pressed = True # Ensure flag is set
    except Exception as e:
         print(f"\nError during testing phase: {type(e).__name__} - {e}", file=sys.stderr)
         import traceback
         traceback.print_exc(file=sys.stderr)
    finally:
         # Progress bar cleanup handled by tqdm_progress context usually, but close explicitly if needed
         # if progress_bar_test and hasattr(progress_bar_test, 'close'): progress_bar_test.close()

         # Shutdown executor
         if executor:
             print("\nWaiting for test workers to shut down gracefully...", file=sys.stderr)
             # Python 3.9+ has cancel_futures=True option
             cancel_opt = hasattr(concurrent.futures, 'thread') and sys.version_info >= (3, 9)
             shutdown_wait = not is_ctrl_c_pressed # Wait if not interrupted
             try:
                executor.shutdown(wait=shutdown_wait, cancel_futures=cancel_opt and is_ctrl_c_pressed)
                print("Test workers shut down.", file=sys.stderr)
             except Exception as e:
                print(f"Error during executor shutdown: {e}", file=sys.stderr)

    # --- Final Steps ---
    print(f"\nTesting completed. Processed {len(tested_results)} out of {total_outbounds_count} unique configs.")

    # --- Filter by Country, Rename, Limit, Save ---
    inc_countries = args.include_countries.split(',') if args.include_countries else None
    exc_countries = args.exclude_countries.split(',') if args.exclude_countries else None

    final_renamed_configs = filter_rename_limit_configs(
        tested_results, args.limit, args.name_prefix, inc_countries, exc_countries
    )
    if final_renamed_configs:
         save_configs(final_renamed_configs, args.output, args.output_format == "base64")
    else:
         print(f"\nNo working configs matched the criteria to save to '{args.output}'.")

    # --- Save Detailed Results (Optional) ---
    if args.output_csv or args.output_json:
        # Sort detailed results by the new combined score primarily
        tested_results.sort(key=lambda r: (r.combined_score, r.protocol or "zzz", r.real_delay_ms))
        print(f"\nSaving detailed test results for all {len(tested_results)} tested configs...")
        save_detailed_results(tested_results, args.output_csv, args.output_json)

    # --- Protocol Statistics (Optional) ---
    if args.protocol_stats:
        # Sort results before stats for consistency if needed (already sorted for saving)
        print_protocol_statistics(tested_results)

    # --- Cleanup ---
    if geoip_reader:
        try: geoip_reader.close(); print("\nClosed GeoIP database reader.")
        except Exception: pass

    print("\n--- Pr0xySh4rk Enhanced Run Finished ---")


# Helper function to format result line (Enhanced for new info)
def format_result_line(tested_result: TestResult, args: argparse.Namespace) -> str:
    delay_str = f"{tested_result.real_delay_ms:>4.0f}ms" if tested_result.real_delay_ms != float('inf') else "----ms"

    # Speed info (only if speedtest enabled and relevant)
    show_speed = args.speedtest and tested_result.protocol != "wg"
    dl_speed_str = f"DL:{tested_result.download_speed_mbps:>5.1f}" if show_speed and tested_result.download_speed_mbps > 0 else ""
    ul_speed_str = f"UL:{tested_result.upload_speed_mbps:>5.1f}" if show_speed and tested_result.upload_speed_mbps > 0 else ""
    speed_pad = 19 # Width for combined speed string

    # Geo info
    flag_str = tested_result.flag or ("?" if args.ip_info or args.geoip_db else "")
    loc_str = f"({tested_result.location})" if tested_result.location else ""
    geo_str = f"{flag_str}{loc_str}"
    geo_pad = 8

    # Enhanced check indicators
    iran_ok_sym = "✅" if tested_result.iran_access_passed is True else "❌" if tested_result.iran_access_passed is False else "?"
    cdn_sym = "C" if tested_result.is_cdn_ip is True else "c" if tested_result.is_cdn_ip is False else "?"
    fp_sym = ""
    fp_type = tested_result.tls_fingerprint_type
    if fp_type == "reality": fp_sym = "R"
    elif fp_type in ["chrome", "firefox", "safari", "ios", "android"]: fp_sym = "F" # Standard FP
    elif fp_type == "random": fp_sym = "r"
    elif fp_type == "custom": fp_sym = "u" # Unknown/custom FP
    else: fp_sym = "?" # No FP info
    enhanced_str = f"[IR:{iran_ok_sym}|{cdn_sym}|{fp_sym}]"
    enhanced_pad = 10

    # Status color
    status_color_map = {
        "passed": "\033[92m", "semi-passed": "\033[93m", "failed": "\033[91m",
        "timeout": "\033[95m", "broken": "\033[91m", "skipped": "\033[90m", "pending": "\033[37m",
    }
    status_color = status_color_map.get(tested_result.status, "\033[0m")
    reset_color = "\033[0m"

    # Config display
    max_len = 45 # Shorter display for verbose mode
    display_config = tested_result.original_config
    if len(display_config) > max_len: display_config = display_config[:max_len-3] + "..."

    # Reason
    reason_str = f" ({tested_result.reason})" if tested_result.reason and tested_result.status not in ['passed', 'pending', 'semi-passed'] else ""

    # Score
    score_str = f"S:{tested_result.combined_score:.2f}" if tested_result.combined_score != float('inf') else "S:---"
    score_pad = 7

    # Combine parts
    line = (
        f"{status_color}{tested_result.status.upper():<7}{reset_color} "
        f"{delay_str:<7} {(dl_speed_str + ' ' + ul_speed_str).strip():<{speed_pad}} "
        f"{geo_str:<{geo_pad}} "
        f"{enhanced_str:<{enhanced_pad}} "
        f"{score_str:<{score_pad}} "
        f"{display_config}{reason_str}"
    )
    return line.strip() # Remove potential trailing space if speed is empty


if __name__ == "__main__":
    if tqdm is None:
        tqdm_progress = fallback_tqdm
    else:
        tqdm_progress = tqdm

    try: CACHE_DIR.mkdir(parents=True, exist_ok=True)
    except Exception as e: print(f"Warning: Could not create cache directory '{CACHE_DIR}': {e}", file=sys.stderr)

    # Set default asyncio policy on Windows if needed for UDP tests
    # if sys.platform == "win32":
    #    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    main()
