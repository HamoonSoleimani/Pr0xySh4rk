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
import traceback # For better error logging

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
                # Ensure total is an integer for ETA calculation if possible
                eta_total = total
                if not isinstance(total, (int, float)): eta_total = 0 # Avoid error if total is '?'

                if percentage > 0 and eta_total > 0:
                    try:
                        eta = (elapsed / percentage) * (100 - percentage)
                        eta_str = str(timedelta(seconds=int(eta)))
                    except (ZeroDivisionError, OverflowError, TypeError): # Handle potential math errors
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
    # print("Warning: 'geoip2' module not found. Optional GeoIP DB lookups disabled.", file=sys.stderr)

try:
    from dotenv import load_dotenv
    load_dotenv() # Load environment variables from .env file if it exists
    # print("Info: Loaded environment variables from .env file (if found).", file=sys.stderr)
except ImportError:
    pass # dotenv is optional

# Suppress only the InsecureRequestWarning from urllib3 needed during fetching
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- Constants ---
# Country Code to Flag Emoji Mapping (Remains the same)
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
DEFAULT_XRAY_KNIFE_TIMEOUT_MS = 8000 # Default timeout for main connectivity/speed test
DEFAULT_UDP_TIMEOUT_S = 5
PYTHON_SUBPROCESS_TIMEOUT_BUFFER_S = 15
DEFAULT_SPEEDTEST_AMOUNT_KB = 10000
DEFAULT_THREADS = min(32, os.cpu_count() * 2 + 4) if os.cpu_count() else 16
CACHE_DIR = Path(".proxy_cache")
CACHE_TTL_HOURS = 6
DEFAULT_DNS_TIMEOUT_S = 5 # Timeout for preliminary DNS check

# --- Iran Specific Test Settings ---
# List of generally accessible Iranian domains/IPs for secondary testing
# ** This list needs careful selection and maintenance! **
IRAN_TEST_TARGETS = [
    "https://www.irancell.ir/", "https://mci.ir/", "https://www.digikala.com/",
    "https://www.shaparak.ir/", "https://rubika.ir/", "http://www.irib.ir/",
    "https://www.snapp.ir/", "https://www.bmi.ir/", "https://www.divar.ir/" # Added another major site
]
IRAN_TEST_COUNT = 3 # Number of random targets to test per config
IRAN_TEST_TIMEOUT_S = 5 # Timeout for each Iran target test via curl
IRAN_TEST_SUCCESS_THRESHOLD = 0.6 # Requires >= 60% of tested Iran targets to succeed

# URLs for CDN/IP/ASN check (should NOT be behind Cloudflare ideally)
IP_CHECK_URLS = [
    "https://api.ipify.org?format=json", # Minimal, JSON IP
    "http://ip-api.com/json/?fields=status,message,query,countryCode,isp,org,as,asname", # JSON with ASN/Org
    "https://ipinfo.io/json", # JSON with ASN/Org
    "http://icanhazip.com", # Plain text IP (fallback)
    "https://api.myip.com", # JSON IP
]
IP_CHECK_TIMEOUT_S = 7 # Timeout for IP check via curl

# Known CDN Organization/ASN Names (lowercase for matching) - Expanded
CDN_ORGANIZATIONS = {"cloudflare", "akamai", "fastly", "google cloud", "amazon", "google", "microsoft azure", "azure", "level3"}
CDN_ASNS = {"AS13335", "AS15169", "AS16509", "AS20940"} # Example ASNs (Cloudflare, Google, Amazon, Akamai)

# --- Global State ---
total_outbounds_count = 0
completed_outbounds_count = 0
is_ctrl_c_pressed = False
found_xray_knife_path: Optional[str] = None
geoip_reader: Optional['geoip2.database.Reader'] = None
args: Optional[argparse.Namespace] = None

# --- Dataclass for Test Results (Enhanced Further) ---
@dataclass
class TestResult:
    original_config: str
    source: Optional[str] = None
    status: str = "pending" # pending, dns-failed, passed, failed, timeout, broken, skipped, semi-passed
    reason: Optional[str] = None
    # Basic Test Results
    real_delay_ms: float = float('inf')
    download_speed_mbps: float = 0.0
    upload_speed_mbps: float = 0.0
    # Geo/IP Info
    ip: Optional[str] = None # IP from primary test (--rip) or GeoIP DB lookup
    location: Optional[str] = None # 2-letter country code
    flag: Optional[str] = None
    # Enhanced Check Results
    cdn_check_ip: Optional[str] = None # IP reported by secondary non-CDN check URL
    cdn_check_org: Optional[str] = None # Org/ISP reported by secondary check URL
    cdn_check_asn: Optional[str] = None # ASN reported by secondary check URL (e.g., "AS13335")
    is_cdn_ip: Optional[bool] = None # Heuristic: Is the exit IP likely a CDN (based on Org/ASN)?
    iran_access_targets_tested: int = 0
    iran_access_targets_passed: int = 0
    iran_access_passed: Optional[bool] = None # Did it pass the Iran access test threshold?
    iran_test_http_version: Optional[str] = None # Max HTTP version seen in successful Iran tests (e.g., "1.1", "2", "3")
    tls_fingerprint_type: Optional[str] = None # e.g., "chrome", "firefox", "reality", "unknown"
    # Config Details & Scores
    protocol: Optional[str] = None
    dedup_key_details: Dict[str, Any] = field(default_factory=dict)
    resilience_score: float = 1.0 # Multiplier based on config structure (lower=better)
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
        sys.exit(1)

# ---------------------------
# Find xray-knife Executable
# ---------------------------
def find_xray_knife(provided_path: Optional[str]) -> Optional[str]:
    """Finds the xray-knife executable based on provided path, ENV, or standard locations."""
    global found_xray_knife_path, args
    if found_xray_knife_path:
        return found_xray_knife_path

    paths_to_check = []
    # 1. Provided path / ENV var
    env_path = os.environ.get("XRAY_KNIFE_PATH")
    if provided_path: paths_to_check.append(Path(provided_path))
    if env_path: paths_to_check.append(Path(env_path))

    # 2. PATH environment variable
    executable_name = "xray-knife" + (".exe" if sys.platform == "win32" else "")
    path_env = os.environ.get("PATH", "").split(os.pathsep)
    for p_dir in path_env:
        paths_to_check.append(Path(p_dir) / executable_name)

    # 3. Common relative paths
    script_dir = Path(__file__).parent.resolve()
    paths_to_check.extend([
        script_dir / executable_name,
        script_dir / "bin" / executable_name,
        Path(".") / executable_name,
    ])

    # Check candidate paths
    for p in paths_to_check:
        try:
            abs_path = p.resolve()
            if abs_path.is_file() and os.access(str(abs_path), os.X_OK):
                found_xray_knife_path = str(abs_path)
                # Avoid printing during initial module load if args not parsed yet
                if args and args.verbose > 1: print(f"Debug: Found xray-knife at: {found_xray_knife_path}", file=sys.stderr)
                return found_xray_knife_path
        except Exception: # Ignore errors like permission denied for non-existent paths etc.
            continue

    # Not found yet
    # Try shutil.which as a final fallback (covers PATH again, but might catch edge cases)
    found_in_which = shutil.which(executable_name)
    if found_in_which:
         found_xray_knife_path = found_in_which
         if args and args.verbose > 1: print(f"Debug: Found xray-knife via shutil.which: {found_xray_knife_path}", file=sys.stderr)
         return found_xray_knife_path

    if args and args.verbose: print(f"Debug: xray-knife not found in standard locations.", file=sys.stderr)
    return None

# ---------------------------
# Cache Handling Functions
# ---------------------------
def get_cache_path(url: str) -> Path:
    url_hash = hashlib.sha256(url.encode('utf-8')).hexdigest()
    return CACHE_DIR / f"{url_hash}.cache"

def load_from_cache(url: str, ttl_hours: int = CACHE_TTL_HOURS) -> Optional[str]:
    if not CACHE_DIR.exists(): return None
    cache_file = get_cache_path(url)
    if not cache_file.is_file(): return None
    try:
        file_mod_time = datetime.fromtimestamp(cache_file.stat().st_mtime)
        if datetime.now() - file_mod_time > timedelta(hours=ttl_hours): return None
        return cache_file.read_text('utf-8')
    except Exception as e:
        print(f"Warning: Could not read cache file {cache_file}: {e}", file=sys.stderr)
        return None

def save_to_cache(url: str, content: str):
    if not content: return
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        get_cache_path(url).write_text(content, 'utf-8')
    except Exception as e:
        print(f"Warning: Could not write cache file for {url}: {e}", file=sys.stderr)

# ---------------------------
# Fetching content from URLs (with Caching)
# ---------------------------
def fetch_content(url: str, proxy: Optional[str] = None, timeout: int = DEFAULT_FETCH_TIMEOUT, force_fetch: bool = False) -> Optional[str]:
    global args
    if not force_fetch:
        cached_content = load_from_cache(url, args.cache_ttl if hasattr(args, 'cache_ttl') else CACHE_TTL_HOURS)
        if cached_content is not None: return cached_content

    session = requests.Session()
    proxies = {"http": proxy, "https": proxy} if proxy else None
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0"}
    try:
        response = session.get(url, timeout=timeout, proxies=proxies, verify=False, headers=headers, allow_redirects=True)
        response.raise_for_status()
        response.encoding = response.apparent_encoding or 'utf-8' # Try to guess encoding
        content = response.text
        save_to_cache(url, content)
        return content
    except requests.exceptions.Timeout as e:
        print(f"Error fetching {url}: Timeout after {timeout}s. {e}", file=sys.stderr)
    except requests.exceptions.ProxyError as e:
        print(f"Error fetching {url}: Proxy Error - {e}", file=sys.stderr)
    except requests.exceptions.SSLError as e:
        print(f"Error fetching {url}: SSL Error - {e}", file=sys.stderr)
    except requests.exceptions.ConnectionError as e:
         # Make connection errors more specific if possible (e.g., DNS)
         if "NameResolutionError" in str(e) or "nodename nor servname provided" in str(e).lower() or "name or service not known" in str(e).lower():
              print(f"Error fetching {url}: DNS resolution failed - {e} (Check DNS/Network)", file=sys.stderr)
         else:
              print(f"Error fetching {url}: Connection Error - {e} (Check Network/Firewall)", file=sys.stderr)
    except requests.exceptions.RequestException as e:
        print(f"Error fetching {url}: {type(e).__name__} - {e}", file=sys.stderr)
    except Exception as e:
        print(f"Unexpected error fetching {url}: {type(e).__name__} - {e}", file=sys.stderr)
        if args and args.verbose > 1: traceback.print_exc(file=sys.stderr)
    return None

# ---------------------------
# Parsing configuration content
# ---------------------------
def parse_config_content(content: str, source_url: str) -> List[TestResult]:
    global args
    outbounds = []
    if not content: return outbounds

    try:
        # --- Base64 Detection ---
        decoded_content = content
        try:
            content_no_space = ''.join(content.split())
            # Stricter base64 check: length is multiple of 4 (after padding attempt), contains valid chars
            padding = len(content_no_space) % 4
            if padding: content_no_space += '=' * (4 - padding)
            if re.fullmatch(r'^[A-Za-z0-9+/=\s]*$', content) and len(content_no_space) % 4 == 0 and len(content_no_space) > 20:
                 potential_decoded = base64.b64decode(content_no_space, validate=True).decode('utf-8', errors='ignore')
                 # Sanity check: contains common schemes or newlines?
                 if any(proto in potential_decoded for proto in ["vless://", "vmess://", "trojan://", "ss://"]) or '\n' in potential_decoded:
                      decoded_content = potential_decoded
                 elif '://' in base64.b64decode(content_no_space, validate=True).decode('latin-1', errors='ignore'):
                      decoded_content = base64.b64decode(content_no_space, validate=True).decode('latin-1', errors='ignore')
        except (base64.binascii.Error, ValueError, TypeError, UnicodeDecodeError):
             pass # Assume plaintext if decode fails

        # --- Line-by-line Parsing ---
        supported_prefixes = (
            "vless://", "vmess://", "ss://", "ssr://", "trojan://", "tuic://",
            "hysteria://", "hysteria2://", "hy2://", "wg://", "wireguard://", "warp://",
            "socks://", "http://", "https://"
        )
        seen_configs_this_source = set()

        for line_num, line in enumerate(decoded_content.splitlines()):
            line = line.strip()
            if not line or line.startswith(("#", "//", ";")): continue

            matched_prefix = None
            for prefix in supported_prefixes:
                if line.lower().startswith(prefix):
                    matched_prefix = prefix
                    break

            if matched_prefix:
                # Normalize protocol name
                protocol = matched_prefix.split("://", 1)[0].lower()
                if protocol in ["wireguard", "warp", "wg"]: protocol = "wg"
                elif protocol in ["hysteria2", "hy2"]: protocol = "hysteria"
                # Optional: Group SSR with SS? -> elif protocol == "ssr": protocol = "ss"

                # Basic structural sanity check (e.g., check for '@' in user/pass protocols)
                # This is very basic and might miss valid formats, use with caution
                looks_valid = True
                if protocol in ["vless", "trojan", "ss", "ssr"] and '@' not in line.split('#')[0]:
                    if args and args.verbose > 1: print(f"Debug: Possible invalid structure (missing '@'?): {line[:60]}...", file=sys.stderr)
                    # looks_valid = False # Disabled for now, might be too strict

                if looks_valid and line not in seen_configs_this_source:
                    outbounds.append(TestResult(original_config=line, source=source_url, protocol=protocol))
                    seen_configs_this_source.add(line)
                elif not looks_valid:
                    if args and args.verbose > 0: print(f"Warning: Skipping potentially invalid config structure: {line[:60]}...", file=sys.stderr)


    except Exception as e:
        print(f"Error processing content from {source_url}: {type(e).__name__} - {e}", file=sys.stderr)
        if args and args.verbose > 1: traceback.print_exc(file=sys.stderr)

    return outbounds


# ---------------------------
# Helper to get server/port (Simplified for WG/UDP)
# ---------------------------
def get_server_port_basic(config_line: str) -> Tuple[Optional[str], Optional[int]]:
    """Extracts server hostname and port using basic urlparse. Good for WG/WARP/DNS."""
    try:
        parsed_url = urllib.parse.urlparse(config_line)
        hostname = parsed_url.hostname
        port = parsed_url.port
        if hostname and hostname.startswith('[') and hostname.endswith(']'):
            hostname = hostname[1:-1] # Strip brackets for IPv6
        # Basic validation
        if not hostname or port is None or not (0 < port < 65536):
            return None, None
        return hostname, port
    except Exception: return None, None


# ---------------------------
# Enhanced Server/Port/Details Extraction (Corrected for Hashability)
# ---------------------------
def extract_config_details_for_dedup(config_line: str) -> Dict[str, Any]:
    """Extracts detailed config parameters for deduplication and scoring. Ensures hashable values."""
    global args
    details = { # Initialize all potential keys to None for consistency
        "protocol": None, "address": None, "port": None, "host": None, "path": None,
        "net": None, "tls": None, "fp": None, "type": None, "plugin": None,
    }
    try:
        parsed_url = urllib.parse.urlparse(config_line)
        scheme = parsed_url.scheme.lower()

        # --- Protocol Normalization ---
        if scheme in ["wireguard", "warp", "wg"]: details["protocol"] = "wg"
        elif scheme in ["hysteria2", "hy2"]: details["protocol"] = "hysteria"
        else: details["protocol"] = scheme

        details["address"] = parsed_url.hostname
        details["port"] = parsed_url.port
        if details["address"] and details["address"].startswith('[') and details["address"].endswith(']'):
            details["address"] = details["address"][1:-1]

        # --- Parameter Extraction (Ensuring Hashability) ---
        query_params = urllib.parse.parse_qs(parsed_url.query)
        def get_param(key_list: List[str], default: Any = None) -> Optional[str]:
            """Helper to safely get the first element from query_params."""
            for key in key_list:
                val_list = query_params.get(key)
                if val_list and val_list[0]: return val_list[0] # Return first non-empty value
            return default

        details["host"] = get_param(["sni", "host"]) # SNI priority
        details["path"] = get_param(["path"])
        details["net"] = get_param(["type", "network", "net"]) # ws, grpc, tcp, etc.
        details["tls"] = get_param(["security", "tls"]) # tls, reality, none, ""
        details["fp"] = get_param(["fp"]) # Fingerprint

        # --- Protocol-specific Parsing ---
        if scheme == "vmess":
            try:
                base64_part = config_line[len("vmess://"):].split("#")[0].strip()
                base64_part = base64_part.replace('-', '+').replace('_', '/')
                if len(base64_part) % 4 != 0: base64_part += '=' * (4 - len(base64_part) % 4)
                vmess_data = json.loads(base64.b64decode(base64_part).decode('utf-8', errors='ignore'))
                # Override with JSON data if present, keeping URL params as fallback
                details["address"] = vmess_data.get("add", details["address"])
                port_str = str(vmess_data.get("port", str(details["port"]) if details["port"] else None))
                details["port"] = int(port_str) if port_str and port_str.isdigit() else details["port"]
                details["host"] = vmess_data.get("sni", vmess_data.get("host", details["host"]))
                details["path"] = vmess_data.get("path", details["path"])
                details["net"] = vmess_data.get("net", details["net"])
                details["tls"] = vmess_data.get("tls", details["tls"]) # Note: might be "" or "tls"
                details["type"] = vmess_data.get("type", details["type"]) # Header type
            except Exception as e:
                if args and args.verbose > 1: print(f"Debug: VMess JSON parse failed: {e}", file=sys.stderr)

        elif scheme == "ss":
             at_parts = parsed_url.netloc.split('@')
             host_port_part = (at_parts[-1] if len(at_parts) > 1 else parsed_url.netloc).split('#')[0]
             if ':' in host_port_part:
                  potential_host, port_str = host_port_part.rsplit(':', 1)
                  if port_str.isdigit() and potential_host and not re.match(r'^[a-zA-Z0-9+/=]+:[a-zA-Z0-9+/=]+$', potential_host):
                       details["address"] = potential_host
                       details["port"] = int(port_str)
             # Plugin processing
             plugin_opts = get_param(["plugin"])
             if plugin_opts:
                 details["plugin"] = plugin_opts # Store raw plugin string
                 if "v2ray-plugin" in plugin_opts or "obfs-local" in plugin_opts:
                     if "tls" in plugin_opts: details["tls"] = "tls" # Set security based on plugin
                     if "mode=websocket" in plugin_opts: details["net"] = "ws"
                     if "obfs=http" in plugin_opts: details["net"] = "http-obfs"
                     try:
                         plugin_params = dict(item.split("=", 1) for item in plugin_opts.split(";") if "=" in item)
                         details["host"] = plugin_params.get("host", details["host"])
                         details["path"] = plugin_params.get("path", details["path"])
                     except ValueError: pass

        elif scheme in ["vless", "trojan"]:
             # Use get_param helper for consistency
             details["net"] = get_param(["type", "network", "net"], details.get("net"))
             details["tls"] = get_param(["security"], details.get("tls"))
             details["host"] = get_param(["sni"], details.get("host"))
             details["fp"] = get_param(["fp"], details.get("fp"))
             # Path/ServiceName logic
             if details["net"] == "grpc":
                  details["path"] = get_param(["serviceName"], details.get("path"))
             else: # Includes ws, tcp, etc.
                  details["path"] = get_param(["path"], details.get("path"))

        # --- Post-processing and Normalization ---
        if not details["net"] and details["protocol"] in ["vless", "vmess", "trojan", "ss", "socks", "http"]:
            details["net"] = "tcp"
        # Normalize tls values: "" or "none" become None
        if details["tls"] in ["", "none"]: details["tls"] = None
        # Infer TLS on 443 as fallback heuristic
        if not details["tls"] and details["port"] == 443 and details["protocol"] in ["vless", "vmess", "trojan"]:
            details["tls"] = "tls"

        # --- Validation ---
        if not details["address"] or not isinstance(details["port"], int) or not (0 < details["port"] < 65536):
            if args and args.verbose > 1: print(f"Debug: Invalid addr/port in details: {details}", file=sys.stderr)
            return {}

        # Normalize IPv6
        addr = details["address"]
        if ipaddress and addr and ':' in addr:
             try: details["address"] = ipaddress.ip_address(addr).compressed
             except ValueError: pass # Keep domain name

        # Default host/SNI to address if missing
        if not details["host"]: details["host"] = details["address"]

        # --- Final Cleanup: Ensure all values are hashable (str, int, None, bool) ---
        final_details = {}
        for k, v in details.items():
            if isinstance(v, (str, int, type(None), bool)):
                final_details[k] = v if v != "" else None # Convert empty strings to None
            else:
                # This shouldn't happen with the corrected logic, but as a safeguard:
                if args and args.verbose: print(f"Warning: Converting potentially unhashable type '{type(v)}' for key '{k}' to string: {v}", file=sys.stderr)
                try:
                    final_details[k] = str(v) if v is not None else None
                except:
                     if args and args.verbose: print(f"Error: Could not convert value for key '{k}' to string. Skipping detail.", file=sys.stderr)
                     final_details[k] = None # Fallback to None

        return final_details

    except Exception as e:
        if args and args.verbose > 1: print(f"Debug: Detail extraction failed: {e}\n{traceback.format_exc()}", file=sys.stderr)
        return {} # Return empty dict on any unexpected error


# ---------------------------
# Get deduplication key
# ---------------------------
def get_dedup_key(config_result: TestResult) -> Optional[tuple]:
    """Generates a hashable key for deduplication based on significant config details."""
    details = extract_config_details_for_dedup(config_result.original_config)
    config_result.dedup_key_details = details # Store details for later use

    proto = details.get("protocol")
    addr = details.get("address")
    port = details.get("port")

    if not proto or not addr or port is None: return None # Essential info missing

    # Base key: protocol, address, port
    key_parts: List[Any] = [proto, addr, port]

    # Add more specific details based on protocol and transport to refine key
    net = details.get("net")
    tls = details.get("tls")
    host = details.get("host") # Already defaulted to addr if needed
    path = details.get("path")
    fp = details.get("fp")
    plugin = details.get("plugin") # For SS

    # Use a consistent order for key components
    if proto in ["vless", "vmess", "trojan", "tuic", "hysteria", "ss"]:
        key_parts.extend([net, tls, host, path, fp])
        if proto == "ss": key_parts.append(plugin) # Add plugin info for SS

    # Convert list to tuple for hashability
    # Ensure all elements within are hashable (should be guaranteed by extract_config_details)
    try:
        hash(tuple(key_parts)) # Test hashability
        return tuple(key_parts)
    except TypeError as e:
         if args and args.verbose: print(f"Error: Deduplication key generation failed - unhashable element in {key_parts}: {e}", file=sys.stderr)
         return None


# ---------------------------
# Deduplicate outbounds based on deduplication key
# ---------------------------
def deduplicate_outbounds(outbounds: List[TestResult]) -> List[TestResult]:
    """Removes duplicate configurations based on a generated deduplication key."""
    dedup_dict: Dict[tuple, TestResult] = {}
    skipped_count = 0; processed_count = 0; duplicates_found = 0
    print("Starting deduplication...", file=sys.stderr)

    for config_result in outbounds:
        processed_count += 1
        key = get_dedup_key(config_result)
        if key is None:
            if args and args.verbose > 1: print(f"Debug: Skipping deduplication (invalid key): {config_result.original_config[:60]}...", file=sys.stderr)
            skipped_count += 1
            continue

        if key not in dedup_dict:
            dedup_dict[key] = config_result
        else: duplicates_found +=1

    kept_count = len(dedup_dict)
    print(f"Deduplication: Processed {processed_count}. Kept {kept_count} unique. Removed {duplicates_found} duplicates. Skipped {skipped_count}.", file=sys.stderr)
    return list(dedup_dict.values())

# ---------------------------
# GeoIP Lookup using Database (Optional)
# ---------------------------
def get_geoip_location(ip_address: str, reader: Optional['geoip2.database.Reader']) -> Optional[str]:
    """Looks up the country code for an IP using the provided geoip2 reader."""
    if not reader or not ip_address or not geoip2: return None
    try:
        ip_address_cleaned = ip_address.strip("[]")
        response = reader.country(ip_address_cleaned)
        return response.country.iso_code
    except (geoip2.errors.AddressNotFoundError, ValueError): return None
    except Exception: return None # Ignore other geoip errors


# ---------------------------
# Regex patterns for parsing outputs
# ---------------------------
REAL_DELAY_PATTERN = re.compile(r"(?:Real Delay|Latency):\s*(\d+)\s*ms", re.IGNORECASE)
DOWNLOAD_SPEED_PATTERN = re.compile(r"Downloaded\s*[\d.]+\s*[MKG]?B\s*-\s*Speed:\s*([\d.]+)\s*([mk]?)bps", re.IGNORECASE) # Allow G for GiB
UPLOAD_SPEED_PATTERN = re.compile(r"Uploaded\s*[\d.]+\s*[MKG]?B\s*-\s*Speed:\s*([\d.]+)\s*([mk]?)bps", re.IGNORECASE)
IP_INFO_PATTERN = re.compile(r"\bip=(?P<ip>[\d\.a-fA-F:]+)\b(?:.*?\bloc=(?P<loc>[A-Z]{2})\b)?", re.IGNORECASE | re.DOTALL)
XRAY_KNIFE_FAIL_REASON_PATTERN = re.compile(r"\[-\].*?(?:failed|error|timeout)[:\s]+(.*)", re.IGNORECASE)
CONTEXT_DEADLINE_PATTERN = re.compile(r"context deadline exceeded", re.IGNORECASE)
IO_TIMEOUT_PATTERN = re.compile(r"i/o timeout", re.IGNORECASE)
CONNECTION_REFUSED_PATTERN = re.compile(r"connection refused", re.IGNORECASE)
DNS_ERROR_PATTERN = re.compile(r"(?:no such host|dns query failed|could not resolve host|name resolution failed)", re.IGNORECASE)
HANDSHAKE_ERROR_PATTERN = re.compile(r"(?:handshake failed|tls handshake error|ssl handshake)", re.IGNORECASE)
HTTP_VERSION_PATTERN = re.compile(r"HTTP/(?P<version>[1-3](?:\.[01])?)", re.IGNORECASE) # Matches HTTP/1.0, 1.1, 2, 3

# IP Check JSON/Text Parsers
IP_API_JSON_PATTERN = re.compile(r'"query"\s*:\s*"(?P<ip>[\d\.a-fA-F:]+)"(?:.*?"isp"\s*:\s*"(?P<isp>[^"]*)")?(?:.*?"org"\s*:\s*"(?P<org>[^"]*)")?(?:.*?"as"\s*:\s*"(?P<as>[^"]*)")?', re.IGNORECASE | re.DOTALL)
IPIFY_JSON_PATTERN = re.compile(r'"ip"\s*:\s*"(?P<ip>[\d\.a-fA-F:]+)"', re.IGNORECASE | re.DOTALL)
IPINFO_JSON_PATTERN = re.compile(r'"ip"\s*:\s*"(?P<ip>[\d\.a-fA-F:]+)"(?:.*?"org"\s*:\s*"(?P<org>[^"]*)")?(?:.*?"asn"\s*:\s*{\s*"asn"\s*:\s*"(?P<asn>[^"]*)"[^}]*})?', re.IGNORECASE | re.DOTALL)
MYIP_JSON_PATTERN = re.compile(r'"ip"\s*:\s*"(?P<ip>[\d\.a-fA-F:]+)".*?"country"\s*:\s*"(?P<country>[^"]*)".*?(?:"cc"\s*:\s*"(?P<cc>[A-Z]{2})")?', re.IGNORECASE | re.DOTALL)
ICANHAZIP_PATTERN = re.compile(r"^([\d\.a-fA-F:]+)$") # Plain IP address


# -----------------------------------------------------
# --- Preliminary DNS Check ---
# -----------------------------------------------------
async def preliminary_dns_check(hostname: str, port: int, timeout: float = DEFAULT_DNS_TIMEOUT_S) -> bool:
    """Performs a non-blocking DNS lookup for the given hostname."""
    global args
    if not hostname or not ipaddress or ':' in hostname or hostname == 'localhost': # Skip for IPs/localhost
        return True
    try:
        loop = asyncio.get_running_loop()
        await asyncio.wait_for(
            loop.getaddrinfo(hostname, port, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM),
            timeout=timeout
        )
        if args and args.verbose > 1: print(f"      DNS Check OK: {hostname}", file=sys.stderr)
        return True
    except asyncio.TimeoutError:
        if args and args.verbose: print(f"    DNS Check Timeout: {hostname}", file=sys.stderr)
        return False
    except socket.gaierror as e:
        if args and args.verbose: print(f"    DNS Check Failed: {hostname} ({e})", file=sys.stderr)
        return False
    except Exception as e: # Catch other unexpected errors
        if args and args.verbose: print(f"    DNS Check Error: {hostname} ({type(e).__name__}: {e})", file=sys.stderr)
        return False

# -----------------------------------------------------
# --- UDP Test Logic (WireGuard/WARP) - UNCHANGED ---
# -----------------------------------------------------
async def _test_wg_udp_async(result_obj: TestResult, args: argparse.Namespace) -> TestResult:
    """Async core logic for UDP test."""
    global is_ctrl_c_pressed, geoip_reader

    # Reset results including enhanced fields
    result_obj.status = "pending"; result_obj.reason = None
    result_obj.real_delay_ms = float('inf'); result_obj.download_speed_mbps = 0.0; result_obj.upload_speed_mbps = 0.0
    result_obj.ip = None; result_obj.location = None; result_obj.flag = None
    result_obj.cdn_check_ip = None; result_obj.cdn_check_org = None; result_obj.cdn_check_asn = None; result_obj.is_cdn_ip = None
    result_obj.iran_access_passed = None; result_obj.iran_test_http_version = None
    result_obj.tls_fingerprint_type = None; result_obj.resilience_score = 1.0; result_obj.combined_score = float('inf')

    if is_ctrl_c_pressed:
        result_obj.status = "skipped"; result_obj.reason = "Interrupted"; return result_obj

    config_line = result_obj.original_config
    server, port = get_server_port_basic(config_line) # Use basic parser for WG
    timeout = args.udp_timeout

    if not server or not port:
        result_obj.status = "broken"; result_obj.reason = "Could not parse server/port"; return result_obj

    # --- Preliminary DNS Check (already done in worker, but can double check async) ---
    # dns_ok = await preliminary_dns_check(server, port, timeout)
    # if not dns_ok:
    #    result_obj.status = "dns-failed"; result_obj.reason = "Preliminary DNS failed"; return result_obj

    resolved_ip = result_obj.dedup_key_details.get("resolved_ip") # Use if pre-resolved
    family = socket.AF_INET if resolved_ip and '.' in resolved_ip else socket.AF_INET6 if resolved_ip else None

    if not resolved_ip: # Resolve if not done already
        try:
            loop = asyncio.get_running_loop()
            addr_info = await asyncio.wait_for(
                 loop.getaddrinfo(server, port, family=socket.AF_UNSPEC, type=socket.SOCK_DGRAM),
                 timeout=timeout # Use UDP timeout for DNS here too?
            )
            if not addr_info: raise socket.gaierror(f"No address info for {server}")
            ipv4_info = next((info for info in addr_info if info[0] == socket.AF_INET), None)
            chosen_info = ipv4_info or addr_info[0]
            resolved_ip = chosen_info[4][0]
            family = chosen_info[0]
        except (socket.gaierror, asyncio.TimeoutError) as e:
            result_obj.status = "dns-failed"; result_obj.reason = f"DNS resolution failed: {e}"; return result_obj
        except Exception as e:
            result_obj.status = "broken"; result_obj.reason = f"DNS unexpected error: {e}"; return result_obj

    # --- GeoIP Lookup based on resolved server IP ---
    if geoip_reader and resolved_ip:
        db_location = get_geoip_location(resolved_ip, geoip_reader)
        if db_location:
            result_obj.location = db_location
            result_obj.flag = COUNTRY_FLAGS.get(db_location.upper(), DEFAULT_FLAG)
        result_obj.ip = resolved_ip # Store resolved IP

    # --- UDP Connection Test ---
    transport = None; start_time = 0
    try:
        loop = asyncio.get_running_loop(); start_time = loop.time()
        conn_future = loop.create_datagram_endpoint(lambda: asyncio.DatagramProtocol(), remote_addr=(resolved_ip, port), family=family)
        transport, _ = await asyncio.wait_for(conn_future, timeout=timeout)
        transport.sendto(b'\x00') # Send minimal payload
        await asyncio.sleep(0.05) # Small delay after send
        delay = (loop.time() - start_time) * 1000
        result_obj.real_delay_ms = max(1.0, delay)
        result_obj.status = "passed"; result_obj.reason = "UDP connection successful"
    except asyncio.TimeoutError:
        result_obj.status = "timeout"; result_obj.reason = f"UDP timeout ({timeout:.1f}s)"
    except OSError as e:
        result_obj.status = "failed"; result_obj.reason = f"OS error: {e.strerror} ({e.errno})"
    except Exception as e:
        result_obj.status = "broken"; result_obj.reason = f"UDP test unexpected error: {e}"
    finally:
        if transport:
            try: transport.close()
            except Exception: pass

    # --- Calculate Combined Score for UDP ---
    if result_obj.status == "passed":
        reference_delay = 1000.0 # 1 second reference
        normalized_delay = min(result_obj.real_delay_ms / reference_delay, 1.0)
        # WG is generally resilient, assign a better base resilience score
        result_obj.resilience_score = 0.75 # Lower is better
        result_obj.combined_score = normalized_delay * result_obj.resilience_score
        if args.speedtest: # Mark as semi-passed if speedtest requested globally
            result_obj.status = "semi-passed"; result_obj.reason = "Passed UDP, speed test N/A"
    else: result_obj.combined_score = float('inf')

    return result_obj

def test_wg_udp_sync(result_obj: TestResult, args: argparse.Namespace) -> TestResult:
    """Synchronous wrapper for the async UDP test."""
    try:
        # Try getting existing loop or run in new one
        try: loop = asyncio.get_running_loop()
        except RuntimeError: loop = None
        if loop and loop.is_running():
            # If called from within an already running loop (e.g., nested async),
            # we cannot easily run another async function synchronously.
            # Fail gracefully in this specific scenario.
            print(f"Warning: UDP test cannot run nested in running event loop for {result_obj.original_config[:50]}...", file=sys.stderr)
            result_obj.status = "broken"; result_obj.reason = "Asyncio loop conflict"; return result_obj
        else:
            # Run the async function in a new event loop or the non-running existing one
            return asyncio.run(_test_wg_udp_async(result_obj, args))
    except Exception as e:
        print(f"Critical error in test_wg_udp_sync: {e}", file=sys.stderr)
        if args and args.verbose > 1: traceback.print_exc(file=sys.stderr)
        result_obj.status = "broken"; result_obj.reason = f"Sync wrapper error: {e}"; return result_obj

# -----------------------------------------------------
# --- Helper Function to Run Command via xray-knife net curl ---
# -----------------------------------------------------
def run_xray_knife_curl(
    config_link: str, target_url: str, method: str = "GET",
    timeout_ms: int = 5000, xray_knife_path: str = None,
    args: argparse.Namespace = None, verbose_level: int = 0, # Use level
    extra_headers: Optional[List[str]] = None
) -> Tuple[bool, str, str]:
    """Runs xray-knife net curl. Returns (success_bool, stdout, stderr)."""
    global is_ctrl_c_pressed
    if is_ctrl_c_pressed or not xray_knife_path:
        return False, "", "Skipped or xray-knife not found"

    command = [
        xray_knife_path, "net", "curl", "-s", # Add -s to silence progress meter
        "-c", config_link, "-url", target_url,
        "-m", str(timeout_ms), "-X", method.upper(),
        "-z", args.xray_knife_core if args else "auto",
        "-v" # Always add -v to get header info in stderr for HTTP version parsing
    ]
    if args and args.xray_knife_insecure: command.append("-e")
    if extra_headers:
        for header in extra_headers: command.extend(["-H", header])

    # Use slightly shorter buffer for these quicker checks
    python_timeout = (timeout_ms / 1000.0) + max(5.0, PYTHON_SUBPROCESS_TIMEOUT_BUFFER_S / 2)

    if verbose_level > 1: print(f"        Running curl: {' '.join(command)}", file=sys.stderr)

    try:
        process = subprocess.run(
            command, capture_output=True, text=True, encoding='utf-8', errors='replace',
            timeout=python_timeout, check=False, env=os.environ.copy()
        )
        # Success = RC 0 AND no critical errors in stderr (e.g., timeout, refused)
        success = process.returncode == 0 and not any(err in process.stderr.lower() for err in ["timeout", "refused", "deadline", "resolve host"])

        if verbose_level > 1 and not success:
             print(f"        Curl failed (RC={process.returncode}): {process.stderr[:150].replace(chr(10),' ')}...", file=sys.stderr)
        elif verbose_level > 2 and success: # Very verbose success log
             print(f"        Curl OK (RC=0): {process.stderr[:150].replace(chr(10),' ')}...", file=sys.stderr)

        return success, process.stdout, process.stderr
    except subprocess.TimeoutExpired:
        if verbose_level > 0: print(f"      Curl timed out (> {python_timeout:.1f}s): {target_url}", file=sys.stderr)
        return False, "", f"Timeout after {python_timeout:.1f}s"
    except Exception as e:
        if verbose_level > 0: print(f"      Curl error: {e}", file=sys.stderr)
        return False, "", f"Subprocess error: {type(e).__name__}"

# -----------------------------------------------------
# --- Enhanced Check Functions ---
# -----------------------------------------------------

def perform_cdn_check(result_obj: TestResult, xray_knife_path: str, args: argparse.Namespace):
    """Performs IP/ASN/Org check using non-CDN URL. Updates result_obj."""
    global is_ctrl_c_pressed, args
    if is_ctrl_c_pressed: return
    if args.verbose > 0: print(f"    Performing CDN/ASN check...", file=sys.stderr)

    check_url = random.choice(IP_CHECK_URLS)
    # Add specific headers if needed by the service
    headers = ["Accept: application/json"] if "ipinfo.io" in check_url else None

    success, stdout, stderr = run_xray_knife_curl(
        result_obj.original_config, check_url, method="GET",
        timeout_ms=int(IP_CHECK_TIMEOUT_S * 1000),
        xray_knife_path=xray_knife_path, args=args, verbose_level=args.verbose, # Pass verbose level
        extra_headers=headers
    )

    ip_address, org_name, asn_str = None, None, None
    if success and (stdout or stderr): # Check stderr too for curl -v output
        output_to_parse = stdout if stdout else stderr # Prefer stdout if exists

        try:
            if "ip-api.com" in check_url:
                match = IP_API_JSON_PATTERN.search(output_to_parse)
                if match:
                    ip_address = match.group("ip")
                    org_name = match.group("org") or match.group("isp") # Fallback to ISP
                    asn_match = match.group("as")
                    if asn_match: asn_str = asn_match.split(" ")[0] # Extract AS number like "AS12345"
            elif "ipinfo.io" in check_url:
                 match = IPINFO_JSON_PATTERN.search(output_to_parse)
                 if match:
                      ip_address = match.group("ip")
                      org_name = match.group("org")
                      if match.group("asn"): asn_str = match.group("asn")
            elif "ipify.org" in check_url or "api.myip.com" in check_url: # JSON IP only
                 match = IPIFY_JSON_PATTERN.search(output_to_parse) or MYIP_JSON_PATTERN.search(output_to_parse)
                 if match: ip_address = match.group("ip")
                 # Org/ASN not directly available
            elif "icanhazip.com" in check_url: # Plain text IP
                 match = ICANHAZIP_PATTERN.search(output_to_parse.strip())
                 if match: ip_address = match.group(1)

            # Fallback: Try parsing generic JSON if patterns fail
            if not ip_address and '{' in output_to_parse and '}' in output_to_parse:
                try:
                    data = json.loads(output_to_parse)
                    ip_address = data.get("ip") or data.get("query")
                    org_name = data.get("org") or data.get("isp")
                    # Try different ASN structures
                    asn_data = data.get("asn")
                    if isinstance(asn_data, dict): asn_str = asn_data.get("asn")
                    elif isinstance(asn_data, str): asn_str = asn_data.split(" ")[0]
                    if not asn_str and org_name and org_name.startswith("AS"): asn_str = org_name.split(" ")[0] # Guess from Org

                except json.JSONDecodeError:
                    if args.verbose > 1: print(f"      CDN Check: Failed to parse fallback JSON", file=sys.stderr)
        except Exception as e:
            if args.verbose > 1: print(f"      CDN Check: Error parsing output: {e}", file=sys.stderr)

    if ip_address:
        result_obj.cdn_check_ip = ip_address.strip()
        result_obj.cdn_check_org = org_name.strip() if org_name else None
        result_obj.cdn_check_asn = asn_str.strip() if asn_str else None

        # Heuristic: Check if Org or ASN suggests a CDN
        org_lower = result_obj.cdn_check_org.lower() if result_obj.cdn_check_org else ""
        is_cdn_org = any(cdn in org_lower for cdn in CDN_ORGANIZATIONS)
        is_cdn_asn = result_obj.cdn_check_asn in CDN_ASNS if result_obj.cdn_check_asn else False

        result_obj.is_cdn_ip = is_cdn_org or is_cdn_asn # True if either matches

        if args.verbose > 0: print(f"      CDN Check OK: IP={result_obj.cdn_check_ip}, Org={result_obj.cdn_check_org}, ASN={result_obj.cdn_check_asn}, IsCDN={result_obj.is_cdn_ip}", file=sys.stderr)
    else:
        result_obj.is_cdn_ip = None # Cannot determine
        if args.verbose > 0: print(f"      CDN Check Failed or No IP found.", file=sys.stderr)


def perform_iran_access_test(result_obj: TestResult, xray_knife_path: str, args: argparse.Namespace):
    """Tests connectivity to Iranian targets, updates result_obj, checks HTTP version."""
    global is_ctrl_c_pressed, args
    if is_ctrl_c_pressed or not IRAN_TEST_TARGETS: return

    targets_to_test = random.sample(IRAN_TEST_TARGETS, min(len(IRAN_TEST_TARGETS), IRAN_TEST_COUNT))
    passed_count = 0
    tested_count = len(targets_to_test)
    result_obj.iran_access_targets_tested = tested_count
    max_http_version = 0.0 # Track max HTTP version seen (e.g., 1.1, 2.0)

    if args.verbose > 0: print(f"    Performing Iran access test ({tested_count} targets)...", file=sys.stderr)

    for target_url in targets_to_test:
        if is_ctrl_c_pressed: break
        # Use HEAD for speed, but capture stderr (-v) for HTTP version
        success, stdout, stderr = run_xray_knife_curl(
            result_obj.original_config, target_url, method="HEAD",
            timeout_ms=int(IRAN_TEST_TIMEOUT_S * 1000),
            xray_knife_path=xray_knife_path, args=args, verbose_level=args.verbose
        )
        if success:
             passed_count += 1
             # Try to parse HTTP version from stderr (e.g., "HTTP/1.1 200 OK")
             http_match = HTTP_VERSION_PATTERN.search(stderr)
             if http_match:
                 try:
                     version = float(http_match.group("version"))
                     max_http_version = max(max_http_version, version)
                 except ValueError: pass # Ignore if version isn't float
             if args.verbose > 1: print(f"      Iran Access OK: {target_url}", file=sys.stderr)
        elif args.verbose > 1: print(f"      Iran Access Failed: {target_url}", file=sys.stderr)

    result_obj.iran_access_targets_passed = passed_count
    if tested_count > 0:
        result_obj.iran_access_passed = (passed_count / tested_count) >= IRAN_TEST_SUCCESS_THRESHOLD
    else: result_obj.iran_access_passed = None

    # Store max HTTP version seen
    if max_http_version > 0:
        result_obj.iran_test_http_version = f"{max_http_version:.1f}".replace(".0", "") # Format as "1.1", "2", "3"
    else: result_obj.iran_test_http_version = None


    if args.verbose > 0: print(f"      Iran Access Result: {passed_count}/{tested_count} passed. Overall: {result_obj.iran_access_passed}. MaxHTTP: {result_obj.iran_test_http_version or 'N/A'}", file=sys.stderr)


def check_tls_fingerprint_params(result_obj: TestResult):
    """Checks config parameters for TLS fingerprint settings. Updates result_obj."""
    details = result_obj.dedup_key_details
    fp = details.get("fp")
    tls_sec = details.get("tls")
    fp_type = "unknown" # Default

    if tls_sec == "reality": fp_type = "reality"
    elif fp:
        fp_lower = fp.lower()
        # Prioritize specific browser names
        if "chrome" in fp_lower: fp_type = "chrome"
        elif "firefox" in fp_lower: fp_type = "firefox"
        elif "safari" in fp_lower: fp_type = "safari"
        elif "ios" in fp_lower: fp_type = "ios"
        elif "android" in fp_lower: fp_type = "android"
        elif "edge" in fp_lower: fp_type = "edge"
        elif "random" in fp_lower or "rand" in fp_lower: fp_type = "random"
        else: fp_type = "custom" # Specific but not recognized browser/os
    result_obj.tls_fingerprint_type = fp_type

    if args and args.verbose > 1:
        print(f"      TLS Fingerprint Check: Type={result_obj.tls_fingerprint_type}", file=sys.stderr)


def calculate_resilience_score(result_obj: TestResult) -> float:
    """Calculates a score multiplier based on config structure. Lower is better."""
    details = result_obj.dedup_key_details
    protocol = details.get("protocol")
    net = details.get("net")
    tls = details.get("tls")
    score = 1.0 # Neutral base

    # Protocol Tiering (Lower is better)
    if protocol == "vless": score *= 0.8
    elif protocol == "trojan": score *= 0.85
    elif protocol in ["hysteria", "tuic"]: score *= 0.9 # UDP based
    elif protocol == "vmess": score *= 1.0
    elif protocol == "ss": score *= 1.1 # Depends heavily on plugin/cipher
    elif protocol == "wg": score *= 0.75 # Generally reliable, simple
    elif protocol in ["socks", "http"]: score *= 1.5 # Easy to block
    else: score *= 1.2 # Unknown/other protocols

    # Transport & Security Modifiers
    if protocol in ["vless", "trojan", "vmess", "ss"]:
        if tls == "reality": score *= 0.7 # Reality is top tier
        elif net == "grpc" and tls == "tls": score *= 0.85 # gRPC+TLS is good
        elif net == "ws" and tls == "tls": score *= 0.9 # WS+TLS is decent
        elif net == "tcp" and tls == "tls": score *= 0.95 # Basic TLS (XTLS?)
        elif not tls: score *= 1.25 # Penalize lack of TLS/Reality
        # Specific SS plugin checks
        if protocol == "ss":
            plugin = details.get("plugin")
            if plugin and "v2ray-plugin" in plugin and "ws" in plugin and "tls" in plugin:
                score *= 0.95 # Override base SS score if good plugin found
            elif plugin and "obfs" in plugin: score *= 1.05 # Simple obfs is meh

    # Fingerprint Bonus
    good_fps = {"reality", "chrome", "firefox", "safari", "ios", "android", "edge"}
    if result_obj.tls_fingerprint_type in good_fps:
        score *= 0.9 # Bonus for good known fingerprint
    elif result_obj.tls_fingerprint_type == "random":
        score *= 0.95 # Slight bonus for randomized

    result_obj.resilience_score = round(max(0.1, score), 3) # Ensure score > 0
    if args and args.verbose > 1:
        print(f"      Resilience Score: {result_obj.resilience_score} (P:{protocol}, N:{net}, T:{tls}, F:{result_obj.tls_fingerprint_type})", file=sys.stderr)
    return result_obj.resilience_score


# -----------------------------------------------------
# --- Main Testing Function (xray-knife - Enhanced) ---
# -----------------------------------------------------
def test_config_with_xray_knife(result_obj: TestResult, xray_knife_path: str, args: argparse.Namespace) -> TestResult:
    """Performs comprehensive tests using xray-knife. Updates result_obj."""
    global is_ctrl_c_pressed, geoip_reader, args

    # Reset results before test
    result_obj.status = "pending"; result_obj.reason = None
    result_obj.real_delay_ms = float('inf'); result_obj.download_speed_mbps = 0.0; result_obj.upload_speed_mbps = 0.0
    result_obj.ip = None; result_obj.location = None; result_obj.flag = None
    result_obj.cdn_check_ip = None; result_obj.cdn_check_org = None; result_obj.cdn_check_asn = None; result_obj.is_cdn_ip = None
    result_obj.iran_access_passed = None; result_obj.iran_access_targets_passed = 0; result_obj.iran_access_targets_tested = 0; result_obj.iran_test_http_version = None
    result_obj.tls_fingerprint_type = None; result_obj.resilience_score = 1.0; result_obj.combined_score = float('inf')

    if is_ctrl_c_pressed:
        result_obj.status = "skipped"; result_obj.reason = "Interrupted"; return result_obj
    if not xray_knife_path:
         result_obj.status = "broken"; result_obj.reason = "xray-knife missing"; return result_obj
    # DNS check already performed in worker

    # --- Initial Connectivity & Speed Test ---
    config_link = result_obj.original_config
    command = [
        xray_knife_path, "net", "http", "-v", # -v needed for basic IP/Loc parsing
        "-c", config_link, "-d", str(args.xray_knife_timeout_ms),
        "--url", args.test_url, "--method", args.test_method,
        "-z", args.xray_knife_core
    ]
    if args.speedtest:
        command.append("-p")
        # Speedtest amount parsing (robust)
        speed_amount_str = str(args.speedtest_amount).lower().strip()
        kb_amount = DEFAULT_SPEEDTEST_AMOUNT_KB
        try:
            num_part = re.match(r'^([\d.]+)', speed_amount_str)
            if num_part:
                num = float(num_part.group(1))
                if 'mb' in speed_amount_str: kb_amount = int(num * 1024)
                elif 'kb' in speed_amount_str: kb_amount = int(num)
                else: kb_amount = int(num) # Assume KB if no unit
            if kb_amount <= 0: raise ValueError("Amount must be positive")
        except (ValueError, TypeError):
            if args.verbose: print(f"Warning: Invalid speedtest amount '{args.speedtest_amount}'. Using {DEFAULT_SPEEDTEST_AMOUNT_KB}kb.", file=sys.stderr)
            kb_amount = DEFAULT_SPEEDTEST_AMOUNT_KB
        command.extend(["-a", str(kb_amount)])

    if args.ip_info: command.append("--rip") # Get basic IP/Loc from primary test
    if args.xray_knife_insecure: command.append("-e")

    python_timeout = (args.xray_knife_timeout_ms / 1000.0) + PYTHON_SUBPROCESS_TIMEOUT_BUFFER_S
    process, process_output, process_error = None, "", ""

    try:
        if args.verbose > 0: print(f"  Testing main connectivity...", file=sys.stderr)
        process = subprocess.run(
            command, capture_output=True, text=True, encoding='utf-8', errors='replace',
            timeout=python_timeout, check=False, env=os.environ.copy()
        )
        process_output = process.stdout; process_error = process.stderr
    except subprocess.TimeoutExpired:
        result_obj.status = "timeout"; result_obj.reason = f"Main test timeout (> {python_timeout:.1f}s)"; return result_obj
    except FileNotFoundError: # Should be caught by initial check, but good backup
        result_obj.status = "broken"; result_obj.reason = f"xray-knife missing at '{xray_knife_path}'"; is_ctrl_c_pressed = True; return result_obj
    except PermissionError:
        result_obj.status = "broken"; result_obj.reason = f"Permission denied for xray-knife"; is_ctrl_c_pressed = True; return result_obj
    except Exception as e:
        result_obj.status = "broken"; result_obj.reason = f"Subprocess error: {e}"; return result_obj

    # --- Parse Initial Test Output ---
    full_output = process_output + "\n" + process_error
    # Delay
    delay_match = REAL_DELAY_PATTERN.search(full_output)
    if delay_match:
        try: result_obj.real_delay_ms = float(delay_match.group(1))
        except ValueError: pass
    # Speed
    def parse_speed(match: Optional[re.Match]) -> float:
        if not match: return 0.0
        try:
            speed_val = float(match.group(1)); unit = match.group(2).lower()
            if unit == 'k': return speed_val / 1000.0
            elif unit == 'm': return speed_val
            else: return speed_val / 1000000.0 # Assume bps if no unit
        except (ValueError, IndexError): return 0.0
    result_obj.download_speed_mbps = parse_speed(DOWNLOAD_SPEED_PATTERN.search(full_output))
    result_obj.upload_speed_mbps = parse_speed(UPLOAD_SPEED_PATTERN.search(full_output))
    # IP/Location (--rip output or GeoIP DB)
    ip_match = IP_INFO_PATTERN.search(process_output) # Search stdout primarily for --rip
    if ip_match:
        result_obj.ip = ip_match.group("ip")
        result_obj.location = ip_match.group("loc")
    # Fallback/Enhance with GeoIP DB if enabled and needed
    ip_for_geoip = result_obj.ip # Use IP from --rip if available
    if not ip_for_geoip and result_obj.dedup_key_details.get("resolved_ip"):
         ip_for_geoip = result_obj.dedup_key_details["resolved_ip"] # Use pre-resolved IP
    if geoip_reader and ip_for_geoip:
        db_location = get_geoip_location(ip_for_geoip, geoip_reader)
        if db_location: result_obj.location = db_location # Prefer DB location
        if not result_obj.ip: result_obj.ip = ip_for_geoip # Store the IP used for lookup if rip didn't provide one
    if result_obj.location:
        result_obj.flag = COUNTRY_FLAGS.get(result_obj.location.upper(), DEFAULT_FLAG)


    # --- Determine Initial Status based on Main Test ---
    fail_reason = None; current_status = "pending"
    if CONTEXT_DEADLINE_PATTERN.search(full_output): current_status = "timeout"; fail_reason = f"Internal timeout (>{args.xray_knife_timeout_ms}ms)"
    elif IO_TIMEOUT_PATTERN.search(full_output): current_status = "timeout"; fail_reason = "I/O timeout"
    elif CONNECTION_REFUSED_PATTERN.search(full_output): current_status = "failed"; fail_reason = "Connection refused"
    elif DNS_ERROR_PATTERN.search(full_output): current_status = "dns-failed"; fail_reason = "DNS resolution failed (proxy level)" # Specific DNS status
    elif HANDSHAKE_ERROR_PATTERN.search(full_output): current_status = "failed"; fail_reason = "TLS/SSL handshake failed"
    else: # Check generic error messages
         search_lines = (process_output.splitlines() + process_error.splitlines())[-5:]
         for line in reversed(search_lines):
              fail_match = XRAY_KNIFE_FAIL_REASON_PATTERN.search(line)
              if fail_match:
                   reason_text = fail_match.group(1).strip().replace('\n', ' ')
                   if len(reason_text) < 100 and 'stack trace' not in reason_text and reason_text not in ["null", ""]:
                       fail_reason = reason_text; current_status = "failed"; break
    # Final status determination
    if current_status == "pending":
        if process and process.returncode != 0:
            current_status = "broken"; fail_reason = fail_reason or f"x-knife exit {process.returncode}"
        elif result_obj.real_delay_ms <= args.xray_knife_timeout_ms: # Passed delay check
            current_status = "passed"
            if args.speedtest and (result_obj.download_speed_mbps == 0.0 and result_obj.upload_speed_mbps == 0.0) and not (DOWNLOAD_SPEED_PATTERN.search(full_output) or UPLOAD_SPEED_PATTERN.search(full_output)):
                 current_status = "semi-passed"; fail_reason = "Passed delay, speed N/A" # Speed test requested but no results
        elif result_obj.real_delay_ms > args.xray_knife_timeout_ms: # Exceeded delay timeout
             current_status = "timeout"; fail_reason = f"Delay > {args.xray_knife_timeout_ms}ms"
        else: # Should not happen? Fallback broken
             current_status = "broken"; fail_reason = fail_reason or "Unknown status after main test"

    result_obj.status = current_status; result_obj.reason = fail_reason

    # --- Run Enhanced Checks ONLY if Initial Test Passed/SemiPassed ---
    if result_obj.status in ["passed", "semi-passed"]:
        if args.verbose > 0: print(f"  Initial test {result_obj.status.upper()} ({result_obj.real_delay_ms:.0f}ms). Running enhanced checks...", file=sys.stderr)
        check_tls_fingerprint_params(result_obj)
        calculate_resilience_score(result_obj)
        perform_cdn_check(result_obj, xray_knife_path, args)
        perform_iran_access_test(result_obj, xray_knife_path, args)
        # Optional: Downgrade status based on checks? Currently handled by score.
        # if result_obj.iran_access_passed is False:
        #    result_obj.status = "failed"; result_obj.reason = "Failed Iran access test"

    # --- Calculate FINAL Combined Score ---
    if result_obj.status in ["passed", "semi-passed"]:
         # --- Base Score (Delay/Speed) ---
         delay_norm = min(result_obj.real_delay_ms / max(100, args.xray_knife_timeout_ms), 1.0)
         # Speed component (lower weight, capped)
         speed_comp = 0.0; max_speed = 100.0; dl_weight = 0.15; ul_weight = 0.05
         if args.speedtest and result_obj.status == "passed":
              inv_dl = 1.0 / (1.0 + min(result_obj.download_speed_mbps, max_speed))
              inv_ul = 1.0 / (1.0 + min(result_obj.upload_speed_mbps, max_speed))
              speed_comp = dl_weight * inv_dl + ul_weight * inv_ul
         # Weighting: Delay 80%, Speed 20% (if applicable)
         base_score_comp = (0.8 * delay_norm + speed_comp) if speed_comp > 0 else delay_norm

         # --- Apply Modifiers ---
         current_score = base_score_comp * result_obj.resilience_score # Apply structure bonus/penalty

         # Penalties (Higher score = worse)
         if result_obj.iran_access_passed is False: current_score += 0.8 # Heavy penalty
         elif result_obj.is_cdn_ip is False: current_score += 0.2 # Moderate penalty if confirmed non-CDN
         elif result_obj.is_cdn_ip is None and result_obj.cdn_check_ip is not None: current_score += 0.1 # Small penalty if CDN check failed/inconclusive
         # Bonus (Lower score = better)
         if result_obj.iran_access_passed is True: current_score -= 0.1
         if result_obj.is_cdn_ip is True: current_score -= 0.05
         # Bonus for HTTP/2 or HTTP/3 on Iran tests
         if result_obj.iran_test_http_version in ["2", "3"]: current_score -= 0.05

         result_obj.combined_score = max(0.01, current_score) # Ensure positive score
         if args.verbose > 1: print(f"      Score Calc: Base={base_score_comp:.3f}, Resil={result_obj.resilience_score:.3f}, Modifiers -> Final={result_obj.combined_score:.4f}", file=sys.stderr)
    else: # Failed, timeout, broken, dns-failed, skipped
         result_obj.combined_score = float('inf')
         if result_obj.status not in ["passed", "semi-passed", "pending", "skipped"] and not result_obj.reason:
              result_obj.reason = f"Failed/Timeout/Broken (RC={process.returncode if process else 'N/A'})" # Ensure reason set

    return result_obj

# ---------------------------
# Worker function for ThreadPoolExecutor
# ---------------------------
async def run_test_worker_async(result_obj: TestResult, xray_knife_path: Optional[str], args: argparse.Namespace) -> TestResult:
    """Async wrapper for test dispatching, includes preliminary DNS."""
    global is_ctrl_c_pressed
    if is_ctrl_c_pressed:
        if result_obj.status == "pending": result_obj.status = "skipped"; result_obj.reason = "Interrupted"
        return result_obj

    # --- Preliminary DNS Check (only if address seems like a hostname) ---
    details = result_obj.dedup_key_details
    hostname = details.get("address")
    port = details.get("port")
    resolved_ip = None # Store resolved IP here if successful

    if hostname and port and not (ipaddress and (':' in hostname or '.' in hostname) and try_parse_ip(hostname)): # Check if it looks like a hostname
        if args.verbose > 0: print(f"  Performing preliminary DNS check for {hostname}...", file=sys.stderr)
        try:
            loop = asyncio.get_running_loop()
            addr_info = await asyncio.wait_for(
                loop.getaddrinfo(hostname, port, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM),
                timeout=DEFAULT_DNS_TIMEOUT_S
            )
            # Store first resolved IP (prefer IPv4) for potential use later
            ipv4_info = next((info for info in addr_info if info[0] == socket.AF_INET), None)
            chosen_info = ipv4_info or addr_info[0]
            resolved_ip = chosen_info[4][0]
            result_obj.dedup_key_details["resolved_ip"] = resolved_ip # Store in details
            if args.verbose > 1: print(f"      DNS Check OK: {hostname} -> {resolved_ip}", file=sys.stderr)

        except (asyncio.TimeoutError, socket.gaierror) as e:
            if args.verbose > 0: print(f"    DNS Check Failed: {hostname} ({e})", file=sys.stderr)
            result_obj.status = "dns-failed"; result_obj.reason = f"Preliminary DNS failed: {e}"; return result_obj
        except Exception as e:
             if args.verbose > 0: print(f"    DNS Check Error: {hostname} ({type(e).__name__}: {e})", file=sys.stderr)
             result_obj.status = "dns-failed"; result_obj.reason = f"Preliminary DNS error: {e}"; return result_obj
    elif args.verbose > 1 and hostname: print(f"      Skipping DNS check (likely IP address): {hostname}", file=sys.stderr)

    # --- Dispatch to appropriate test function ---
    try:
        if result_obj.protocol == "wg":
            # WG test is already async, call directly
            return await _test_wg_udp_async(result_obj, args)
        else:
            # Run sync xray-knife test in executor to avoid blocking event loop
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(
                None, # Use default executor (ThreadPoolExecutor)
                test_config_with_xray_knife,
                result_obj, xray_knife_path, args
            )
    except Exception as e:
         print(f"\nCRITICAL ERROR in worker dispatch for {result_obj.original_config[:50]}: {type(e).__name__} - {e}", file=sys.stderr)
         traceback.print_exc(file=sys.stderr)
         result_obj.status = "broken"; result_obj.reason = f"Worker dispatch error: {e}"
         return result_obj

def try_parse_ip(address: str) -> bool:
    """Helper to check if a string is likely an IP address."""
    if not ipaddress or not address: return False
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False

# ---------------------------
# Saving configurations
# ---------------------------
def save_configs(outbounds: List[str], filepath: str, base64_encode: bool):
    if not outbounds:
        print(f"Warning: No final configs to save to '{filepath}'.", file=sys.stderr); return
    output_path = Path(filepath)
    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        content = "\n".join(outbounds)
        if base64_encode: content = base64.b64encode(content.encode('utf-8')).decode("utf-8")
        else: content += "\n" # Add trailing newline for text format
        output_path.write_text(content, encoding='utf-8')
        encoding_type = "Base64 encoded" if base64_encode else "plaintext"
        print(f"\nSuccessfully saved {len(outbounds)} final configs to '{output_path.resolve()}' ({encoding_type}).")
    except IOError as e: print(f"\nError saving config to '{filepath}': {e}", file=sys.stderr)
    except Exception as e: print(f"\nUnexpected error saving config: {e}", file=sys.stderr)

# ---------------------------
# Save Detailed Results (CSV and Optional JSON) - Enhanced Fields
# ---------------------------
def save_detailed_results(results: List[TestResult], csv_filepath: Optional[str] = None, json_filepath: Optional[str] = None):
    if not results: print("No detailed results to save."); return

    # Helper for safe formatting
    def format_val(val, precision=None):
        if val is None: return ''
        if isinstance(val, bool): return str(val)
        if isinstance(val, float):
            if val == float('inf'): return ''
            return f"{val:.{precision}f}" if precision is not None else str(val)
        return str(val).replace('\n', ' ').replace('\r', '')

    # --- Save CSV ---
    if csv_filepath:
        csv_path = Path(csv_filepath); print(f"Saving detailed CSV results to {csv_path.resolve()}...")
        try:
            csv_path.parent.mkdir(parents=True, exist_ok=True)
            import csv
            headers = [ # Ensure order and completeness
                "status", "reason", "real_delay_ms", "download_speed_mbps", "upload_speed_mbps",
                "ip", "location", "flag", "protocol",
                "combined_score", "resilience_score",
                "is_cdn_ip", "cdn_check_ip", "cdn_check_org", "cdn_check_asn",
                "iran_access_passed", "iran_targets_passed", "iran_targets_tested", "iran_test_http_version",
                "tls_fingerprint_type",
                "source", "original_config",
                "dedup_protocol", "dedup_address", "dedup_port", "dedup_host", "dedup_net", "dedup_tls", "dedup_path", "dedup_fp", "dedup_plugin"
            ]
            with csv_path.open('w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=headers, quoting=csv.QUOTE_MINIMAL, extrasaction='ignore')
                writer.writeheader()
                for res in results:
                    row = {
                        "status": res.status, "reason": format_val(res.reason),
                        "real_delay_ms": format_val(res.real_delay_ms, 0),
                        "download_speed_mbps": format_val(res.download_speed_mbps, 2) if res.download_speed_mbps > 0 else '',
                        "upload_speed_mbps": format_val(res.upload_speed_mbps, 2) if res.upload_speed_mbps > 0 else '',
                        "ip": format_val(res.ip), "location": format_val(res.location), "flag": format_val(res.flag), "protocol": format_val(res.protocol),
                        "combined_score": format_val(res.combined_score, 4), "resilience_score": format_val(res.resilience_score, 3),
                        "is_cdn_ip": format_val(res.is_cdn_ip), "cdn_check_ip": format_val(res.cdn_check_ip), "cdn_check_org": format_val(res.cdn_check_org), "cdn_check_asn": format_val(res.cdn_check_asn),
                        "iran_access_passed": format_val(res.iran_access_passed), "iran_targets_passed": format_val(res.iran_access_targets_passed), "iran_targets_tested": format_val(res.iran_access_targets_tested), "iran_test_http_version": format_val(res.iran_test_http_version),
                        "tls_fingerprint_type": format_val(res.tls_fingerprint_type),
                        "source": format_val(res.source), "original_config": res.original_config,
                        # Dedup details - use format_val
                        "dedup_protocol": format_val(res.dedup_key_details.get("protocol")), "dedup_address": format_val(res.dedup_key_details.get("address")),
                        "dedup_port": format_val(res.dedup_key_details.get("port")), "dedup_host": format_val(res.dedup_key_details.get("host")),
                        "dedup_net": format_val(res.dedup_key_details.get("net")), "dedup_tls": format_val(res.dedup_key_details.get("tls")),
                        "dedup_path": format_val(res.dedup_key_details.get("path")), "dedup_fp": format_val(res.dedup_key_details.get("fp")),
                        "dedup_plugin": format_val(res.dedup_key_details.get("plugin"))
                    }
                    writer.writerow(row)
            print(f"Successfully saved {len(results)} detailed results to CSV.")
        except ImportError: print("Error: 'csv' module import failed. Cannot save CSV.", file=sys.stderr)
        except Exception as e: print(f"Error saving detailed CSV: {e}", file=sys.stderr)

    # --- Save JSON ---
    if json_filepath:
        json_path = Path(json_filepath); print(f"Saving detailed JSON results to {json_path.resolve()}...")
        try:
            json_path.parent.mkdir(parents=True, exist_ok=True)
            results_list = []
            for res in results:
                res_dict = {k: v for k, v in res.__dict__.items()} # Convert dataclass to dict
                # Replace inf with None for JSON compatibility
                if res_dict.get('real_delay_ms') == float('inf'): res_dict['real_delay_ms'] = None
                if res_dict.get('combined_score') == float('inf'): res_dict['combined_score'] = None
                results_list.append(res_dict)
            with json_path.open('w', encoding='utf-8') as jsonfile:
                json.dump(results_list, jsonfile, indent=2, ensure_ascii=False, default=str) # Use default=str for any remaining non-serializable types
            print(f"Successfully saved {len(results)} detailed results to JSON.")
        except Exception as e: print(f"Error saving detailed JSON: {e}", file=sys.stderr)


# ---------------------------
# Rename and limit configs - Uses combined_score and adds indicators
# ---------------------------
def filter_rename_limit_configs(
    tested_results: List[TestResult], limit_per_protocol: int, name_prefix: str,
    include_countries: Optional[List[str]] = None, exclude_countries: Optional[List[str]] = None
) -> List[str]:
    global args

    # Filter working configs (passed or semi-passed)
    working_results = [r for r in tested_results if r.status in ["passed", "semi-passed"]]
    print(f"\nFound {len(working_results)} working configs initially.")

    # Apply GeoIP filters
    filtered_results = []
    if include_countries or exclude_countries:
        inc = {c.upper() for c in include_countries} if include_countries else None
        exc = {c.upper() for c in exclude_countries} if exclude_countries else None
        skipped_by_filter = 0
        for r in working_results:
            loc = r.location.upper() if r.location else None
            included = True
            if loc: # If location is known
                if exc and loc in exc: included = False
                if inc and loc not in inc: included = False
            elif inc: included = False # Exclude unknowns if include list is present
            if included: filtered_results.append(r)
            else: skipped_by_filter += 1
        print(f"Filtered {skipped_by_filter} configs by country rules. Kept {len(filtered_results)}.")
        working_results = filtered_results
    else: print("No country filters applied.")

    if not working_results:
        print("No working configs remain after filtering.", file=sys.stderr); return []

    # Group by protocol, Sort by combined_score, Limit, and Rename
    protocol_map = {
        "ss": "SS", "ssr": "SSR", "shadowsocks": "SS", "vless": "VL", "vmess": "VM",
        "trojan": "TR", "tuic": "TU", "hysteria": "HY", "socks": "SK", "http": "HT", "wg": "WG",
    }
    renamed_configs: List[str] = []; protocol_groups: Dict[str, List[TestResult]] = {}

    for result in working_results:
        proto_norm = result.protocol or "unknown"
        abbr = protocol_map.get(proto_norm, proto_norm[:2].upper())
        protocol_groups.setdefault(abbr, []).append(result)

    total_renamed_count = 0
    print(f"Renaming and limiting up to {limit_per_protocol} configs per protocol by combined score...")
    for abbr, group_list in protocol_groups.items():
        group_list.sort(key=lambda r: (r.combined_score, r.real_delay_ms)) # Sort by score, then delay
        limited_list = group_list[:limit_per_protocol]
        total_renamed_count += len(limited_list)

        for i, result in enumerate(limited_list, start=1):
            flag = result.flag or DEFAULT_FLAG
            # Indicators for tag
            iran_ok = "✅" if result.iran_access_passed is True else "❌" if result.iran_access_passed is False else "?"
            cdn = "C" if result.is_cdn_ip is True else "c" if result.is_cdn_ip is False else "?"
            fp = ""
            fp_map = {"reality": "R", "chrome": "F", "firefox": "F", "safari": "F", "ios": "F", "android": "F", "edge": "F", "random": "r", "custom": "u"}
            fp = fp_map.get(result.tls_fingerprint_type, "?") if result.tls_fingerprint_type else "?"
            http_v = result.iran_test_http_version or "?"

            # Construct new tag: Prefix[Proto][Index][Flag][IR|CDN|FP|HTTPVer]Score
            score_tag = f"{result.combined_score:.2f}" if result.combined_score != float('inf') else "inf"
            new_tag = f"🔒{name_prefix}🦈[{abbr}][{i:02d}][{flag}][{iran_ok}|{cdn}|{fp}|H{http_v}]S={score_tag}"
            safe_tag = urllib.parse.quote(new_tag)
            base_part = result.original_config.split("#", 1)[0]
            renamed_configs.append(f"{base_part}#{safe_tag}")

    print(f"Prepared {total_renamed_count} renamed configs across {len(protocol_groups)} protocols.")
    renamed_configs.sort(key=lambda x: x.split("#", 1)[-1]) # Sort final list by tag
    return renamed_configs

# ---------------------------
# Fetch and parse subscription worker (sync)
# ---------------------------
def fetch_and_parse_subscription_worker(url: str, proxy: Optional[str], timeout: int, force_fetch: bool) -> List[TestResult]:
    """Fetches content and parses configs for a single URL."""
    content = fetch_content(url, proxy, timeout, force_fetch)
    if content:
        parsed_results = parse_config_content(content, url)
        if args and args.verbose > 1 and parsed_results: print(f"Debug: Parsed {len(parsed_results)} from {url}", file=sys.stderr)
        return parsed_results
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

    # Aggregate stats
    for result in tested_results:
         proto_norm = result.protocol or "unknown"
         if proto_norm not in protocol_stats:
              protocol_stats[proto_norm] = {
                   "tested": 0, "passed": 0, "semi_passed": 0, "dns_failed": 0, "failed": 0, "timeout": 0, "broken": 0, "skipped": 0,
                   "delays": [], "dl_speeds": [], "ul_speeds": [], "scores": [], "locations": set(),
                   "iran_ok": 0, "cdn_ip": 0, "good_fp": 0, "http_v": {"1.1": 0, "2": 0, "3": 0, "other": 0}
              }
         stats = protocol_stats[proto_norm]
         stats["tested"] += 1
         status_key = result.status.replace('-', '_') # dns-failed -> dns_failed
         if status_key in stats: stats[status_key] += 1
         else: stats[status_key] = 1 # Handle unexpected statuses?

         if result.location: stats["locations"].add(f"{result.flag}{result.location.upper()}")
         if result.status in ["passed", "semi-passed"]:
             if result.real_delay_ms != float('inf'): stats["delays"].append(result.real_delay_ms)
             if result.download_speed_mbps > 0: stats["dl_speeds"].append(result.download_speed_mbps)
             if result.upload_speed_mbps > 0: stats["ul_speeds"].append(result.upload_speed_mbps)
             if result.combined_score != float('inf'): stats["scores"].append(result.combined_score)
             if result.iran_access_passed is True: stats["iran_ok"] += 1
             if result.is_cdn_ip is True: stats["cdn_ip"] += 1
             if result.tls_fingerprint_type not in ["unknown", "custom", "random", None]: stats["good_fp"] += 1
             http_v = result.iran_test_http_version
             if http_v in stats["http_v"]: stats["http_v"][http_v] += 1
             elif http_v: stats["http_v"]["other"] += 1

    # Print aggregated stats
    sorted_protocols = sorted(protocol_stats.keys())
    for protocol in sorted_protocols:
        stats = protocol_stats[protocol]
        total = stats["tested"]
        working = stats.get('passed', 0) + stats.get('semi_passed', 0)
        working_perc = (working / total * 100) if total > 0 else 0

        # Helper for safe stats calculation
        def calc_stats(data: List[Union[float, int]]):
            if not data: return "N/A", "N/A", "N/A"
            avg = sum(data) / len(data)
            min_v = min(data)
            max_v = max(data)
            prec = 0 if all(isinstance(x, int) or x.is_integer() for x in data) else (2 if any(x < 10 for x in data) else 1)
            return f"{avg:.{prec}f}", f"{min_v:.{prec}f}", f"{max_v:.{prec}f}"

        avg_delay, min_delay, max_delay = calc_stats(stats["delays"])
        avg_dl, _, max_dl = calc_stats(stats["dl_speeds"])
        avg_ul, _, max_ul = calc_stats(stats["ul_speeds"])
        avg_score, min_score, max_score = calc_stats(stats["scores"])

        print(f"Protocol: {protocol.upper():<8} (Tested: {total}, Working: {working} [{working_perc:.1f}%])")
        status_str = ", ".join(f"{k.replace('_','-')}:{v}" for k,v in stats.items() if k in ["passed","semi_passed","dns_failed","failed","timeout","broken","skipped"] and v > 0)
        print(f"  Status: {status_str}")
        print(f"  Delay (Avg/Min/Max ms): {avg_delay} / {min_delay} / {max_delay}")
        if args.speedtest:
            note = " (Speed N/A)" if protocol == "wg" else ""
            print(f"  DL Speed (Avg/Max Mbps): {avg_dl} / {max_dl}{note}")
            print(f"  UL Speed (Avg/Max Mbps): {avg_ul} / {max_ul}{note}")
        print(f"  Score (Avg/Min/Max): {avg_score} / {min_score} / {max_score}")
        if working > 0:
            iran_perc = (stats['iran_ok'] / working * 100) if working > 0 else 0
            cdn_perc = (stats['cdn_ip'] / working * 100) if working > 0 else 0
            fp_perc = (stats['good_fp'] / working * 100) if working > 0 else 0
            http_v_str = ", ".join(f"H{k}:{v}" for k,v in stats['http_v'].items() if v > 0)
            print(f"  Enhanced (Working%): IranOK: {iran_perc:.0f}%, CDN IP: {cdn_perc:.0f}%, Good FP: {fp_perc:.0f}%")
            if http_v_str: print(f"  HTTP Versions (Working): {http_v_str}")
        if stats["locations"]: print(f"  Locations: {', '.join(sorted(list(stats['locations'])))}")
        print("-" * 30)

    total_working = sum(p.get('passed', 0) + p.get('semi_passed', 0) for p in protocol_stats.values())
    total_perc = (total_working / total_tested_count * 100) if total_tested_count > 0 else 0
    print(f"Total Tested: {total_tested_count}, Overall Working: {total_working} [{total_perc:.1f}%]")


# ---------------------------
# Main Orchestration Function
# ---------------------------
async def main_async():
    """Asynchronous main function to manage fetching and testing."""
    global is_ctrl_c_pressed, total_outbounds_count, args, geoip_reader, xray_knife_executable

    # --- Initial Setup & Arg Parsing ---
    # (Argument parsing remains synchronous at the start)
    # ... Code within main() before testing loop ...

    # --- Read Subscription URLs (Sync) ---
    # ... Code from main() ...
    print("\n--- Pr0xySh4rk Config Manager (Enhanced++ for Iran) ---")
    print(f"Test Mode: Enhanced xray-knife (non-WG), UDP (WG/WARP), Preliminary DNS")
    print(f"Using {args.threads} workers. Config limit/protocol: {args.limit}.")
    print(f"Timeouts(ms): Main={args.xray_knife_timeout_ms}, UDP={args.udp_timeout*1000}, Iran={IRAN_TEST_TIMEOUT_S*1000}, IP={IP_CHECK_TIMEOUT_S*1000}, DNS={DEFAULT_DNS_TIMEOUT_S*1000}")
    print(f"Speedtest: {'Enabled' if args.speedtest else 'Disabled'}. GeoIP DB: {'Enabled' if geoip_reader else 'Disabled'}")
    print(f"Enhanced Checks: CDN/ASN, Iran Access ({IRAN_TEST_COUNT} targets, >{IRAN_TEST_SUCCESS_THRESHOLD*100:.0f}%), HTTP Ver, TLS FP, Resilience Score")
    if args.verbose > 0: print(f"Verbose Level: {args.verbose}", file=sys.stderr)

    if args.clear_cache: # Cache clearing (Sync)
        if CACHE_DIR.exists():
            print(f"Clearing cache directory: {CACHE_DIR.resolve()}", file=sys.stderr)
            try: shutil.rmtree(CACHE_DIR)
            except OSError as e: print(f"Warning: Could not fully clear cache: {e}", file=sys.stderr)
        else: print("Cache directory not found, nothing to clear.", file=sys.stderr)

    # Find xray-knife (Sync)
    xray_knife_executable = find_xray_knife(args.xray_knife_path)

    # Load GeoIP DB (Sync)
    if args.geoip_db:
        if not geoip2: print("Warning: --geoip-db specified, but 'geoip2' module not installed.", file=sys.stderr)
        else:
            db_path = Path(args.geoip_db).resolve()
            if not db_path.is_file(): print(f"Warning: GeoIP DB not found: {db_path}", file=sys.stderr)
            else:
                try: geoip_reader = geoip2.database.Reader(str(db_path))
                except Exception as e: print(f"Warning: Error loading GeoIP DB '{db_path}': {e}", file=sys.stderr)

    subscription_urls = [] # Read input file (Sync)
    try:
        input_path = Path(args.input)
        if not input_path.is_file(): print(f"Error: Input file '{args.input}' not found.", file=sys.stderr); sys.exit(1)
        raw_bytes = input_path.read_bytes(); decoded_content = None
        try: # Try Base64
             cleaned_bytes = bytes(filter(lambda x: not chr(x).isspace(), raw_bytes))
             if len(cleaned_bytes) % 4 != 0: cleaned_bytes += b'=' * (4 - len(cleaned_bytes) % 4)
             potential_decoded = base64.b64decode(cleaned_bytes, validate=True).decode('utf-8', errors='ignore')
             if '://' in potential_decoded or '\n' in potential_decoded:
                  decoded_content = potential_decoded
                  if args.verbose > 1: print("Input file decoded as Base64.", file=sys.stderr)
             else: raise ValueError("Decoded content doesn't look like URLs/configs")
        except (base64.binascii.Error, ValueError, UnicodeDecodeError): # Try UTF-8
             try: decoded_content = raw_bytes.decode('utf-8'); print("Input file read as plaintext UTF-8.", file=sys.stderr)
             except UnicodeDecodeError: print(f"Error: Input file '{args.input}' invalid.", file=sys.stderr); sys.exit(1)
        if decoded_content:
             subscription_urls = [line.strip() for line in decoded_content.splitlines() if line.strip().startswith(("http://", "https://"))]
        print(f"Read {len(subscription_urls)} URLs from '{args.input}'.", file=sys.stderr)
    except Exception as e: print(f"Error reading input file '{args.input}': {e}", file=sys.stderr); sys.exit(1)
    if not subscription_urls: print("No valid subscription URLs found. Exiting.", file=sys.stderr); sys.exit(0)


    # --- Fetch and Parse Subscriptions Concurrently (Sync using ThreadPool) ---
    print(f"\nFetching {len(subscription_urls)} subscriptions (Cache TTL: {args.cache_ttl}h)...")
    all_parsed_results: List[TestResult] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads, thread_name_prefix="Fetcher") as executor:
        fetch_futures = [executor.submit(fetch_and_parse_subscription_worker, url, args.fetch_proxy, args.fetch_timeout, args.no_cache) for url in subscription_urls]
        prog_desc = "Fetching Subs"; disable_tqdm = args.verbose > 0
        if disable_tqdm: prog_desc = None
        progress_bar = tqdm_progress(concurrent.futures.as_completed(fetch_futures), total=len(fetch_futures), desc=prog_desc, unit="URL", disable=disable_tqdm)
        for future in progress_bar:
             if is_ctrl_c_pressed: break
             try: results_list = future.result(); all_parsed_results.extend(results_list)
             except Exception as exc: print(f'\nSubscription worker error: {exc}', file=sys.stderr)
    if is_ctrl_c_pressed: print("\nFetching interrupted.", file=sys.stderr)
    print(f"Fetched {len(all_parsed_results)} potential configs.")
    if not all_parsed_results and not is_ctrl_c_pressed: print("No configs found. Exiting.", file=sys.stderr); sys.exit(0)

    # --- Deduplicate (Sync) ---
    unique_results = deduplicate_outbounds(all_parsed_results)
    total_outbounds_count = len(unique_results)
    if total_outbounds_count == 0: print("No unique configs after deduplication. Exiting.", file=sys.stderr); sys.exit(0)

    # Check if xray-knife needed (Sync)
    needs_xray_knife = any(res.protocol != "wg" for res in unique_results)
    if needs_xray_knife and not xray_knife_executable:
         print("\nError: xray-knife executable required but not found.", file=sys.stderr); sys.exit(1)
    elif needs_xray_knife and args.verbose: print(f"Using xray-knife: {xray_knife_executable}")

    # --- Test Configs Concurrently (Async using asyncio.gather) ---
    print(f"\nStarting enhanced tests on {total_outbounds_count} unique configs...")
    tested_results: List[TestResult] = []
    completed_outbounds_count = 0

    # Limit concurrency using asyncio.Semaphore
    semaphore = asyncio.Semaphore(args.threads)
    async def bounded_worker(result_obj):
        async with semaphore:
            return await run_test_worker_async(result_obj, xray_knife_executable, args)

    tasks = [bounded_worker(res) for res in unique_results]
    prog_desc_test = "Testing Configs"; disable_tqdm_test = args.verbose > 0
    if disable_tqdm_test: prog_desc_test = None

    progress_bar_test = tqdm_progress(asyncio.as_completed(tasks), total=total_outbounds_count, desc=prog_desc_test, unit="config", disable=disable_tqdm_test)
    test_start_time = time.monotonic()

    try:
        for future in progress_bar_test:
             if is_ctrl_c_pressed: # Check flag
                  # Try to cancel remaining tasks (best effort)
                  for task in tasks:
                      if not task.done(): task.cancel()
                  break # Exit the loop

             try:
                 tested_result = await future # Get result from completed future
                 tested_results.append(tested_result)
                 if args.verbose > 0 and tested_result.status != 'skipped':
                     print(format_result_line(tested_result, args), file=sys.stderr)
             except asyncio.CancelledError:
                 if args.verbose > 1: print("Debug: Task cancelled.", file=sys.stderr)
                 continue # Skip cancelled tasks
             except Exception as exc: # Catch errors from within the worker task
                  print(f'\nTester worker execution resulted in exception: {exc}', file=sys.stderr)
                  traceback.print_exc(file=sys.stderr)
             finally:
                 completed_outbounds_count += 1
                 if disable_tqdm_test and progress_bar_test: # Manual progress update if tqdm bar disabled
                      elapsed_test = time.monotonic() - test_start_time
                      rate = completed_outbounds_count / elapsed_test if elapsed_test > 0 else 0
                      eta_s = (total_outbounds_count - completed_outbounds_count) / rate if rate > 0 else 0
                      eta_str = str(timedelta(seconds=int(eta_s))) if rate > 0 else '?'
                      print(f"\rTesting: {completed_outbounds_count}/{total_outbounds_count} | Rate: {rate:.1f}/s | ETA: {eta_str}   ", file=sys.stderr, end='')

        if disable_tqdm_test: print() # Newline after manual progress

    except KeyboardInterrupt: # Catch Ctrl+C during await loop
         print("\nKeyboardInterrupt caught during testing. Signaling shutdown...", file=sys.stderr)
         is_ctrl_c_pressed = True
         for task in tasks: # Cancel pending tasks on interrupt
             if not task.done(): task.cancel()
    finally:
        # Ensure progress bar closes if it exists and has a close method
        if hasattr(progress_bar_test, 'close'): progress_bar_test.close()


    print(f"\nTesting completed. Processed {len(tested_results)} out of {total_outbounds_count}.")
    if is_ctrl_c_pressed: print("Testing was interrupted by user.", file=sys.stderr)

    # --- Final Steps (Sync) ---
    # Filter, Rename, Limit, Save
    inc_countries = args.include_countries.split(',') if args.include_countries else None
    exc_countries = args.exclude_countries.split(',') if args.exclude_countries else None
    final_renamed_configs = filter_rename_limit_configs(tested_results, args.limit, args.name_prefix, inc_countries, exc_countries)
    if final_renamed_configs:
         save_configs(final_renamed_configs, args.output, args.output_format == "base64")
    else: print(f"No working configs matched criteria to save to '{args.output}'.")

    # Save Detailed Results
    if args.output_csv or args.output_json:
        tested_results.sort(key=lambda r: (r.combined_score, r.protocol or "zzz", r.real_delay_ms))
        save_detailed_results(tested_results, args.output_csv, args.output_json)

    # Protocol Statistics
    if args.protocol_stats:
        print_protocol_statistics(tested_results)

    # Cleanup
    if geoip_reader:
        try: geoip_reader.close(); print("\nClosed GeoIP database reader.")
        except Exception: pass

    print("\n--- Pr0xySh4rk Enhanced++ Run Finished ---")

# ---------------------------
# Entry Point
# ---------------------------
if __name__ == "__main__":
    # --- Argument Parsing ---
    parser = argparse.ArgumentParser(
        description="Pr0xySh4rk Config Manager (Enhanced++ for Iran) - Fetch, Test, Filter, Score, Rename, Save.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    # Input/Output Group
    io_group = parser.add_argument_group('Input/Output Options')
    io_group.add_argument("--input", "-i", required=True, help="Input file (URLs or Base64 list).")
    io_group.add_argument("--output", "-o", required=True, help="Output file for best configs.")
    io_group.add_argument("--output-format", choices=["base64", "text"], default="base64", help="Encoding for the main output file.")
    io_group.add_argument("--output-csv", help="Optional CSV file for detailed results.")
    io_group.add_argument("--output-json", help="Optional JSON file for detailed results.")
    io_group.add_argument("--name-prefix", default="Pr0xySh4rk", help="Prefix for renaming final configs.")
    # Fetching Group
    fetch_group = parser.add_argument_group('Fetching Options')
    fetch_group.add_argument("--fetch-proxy", metavar="PROXY", help="Proxy for fetching subscriptions (e.g., socks5://127.0.0.1:1080).")
    fetch_group.add_argument("--fetch-timeout", type=int, default=DEFAULT_FETCH_TIMEOUT, metavar="SEC", help="Timeout for fetching each URL.")
    fetch_group.add_argument("--no-cache", action="store_true", help="Force fetch, ignore cache.")
    fetch_group.add_argument("--clear-cache", action="store_true", help="Clear subscription cache before run.")
    fetch_group.add_argument("--cache-ttl", type=int, default=CACHE_TTL_HOURS, metavar="HR", help="Cache validity period (hours).")
    # Testing Group (Common)
    test_common_group = parser.add_argument_group('Common Testing Options')
    test_common_group.add_argument("--threads", "-t", type=int, default=DEFAULT_THREADS, metavar="N", help="Max concurrent test workers (Semaphore limit for async).")
    test_common_group.add_argument("--speedtest", "-p", action="store_true", help="Enable speed testing (xray-knife only).")
    test_common_group.add_argument("--ip-info", "--rip", action="store_true", help="Get IP/Location via xray-knife main test (--rip).")
    test_common_group.add_argument("--geoip-db", metavar="PATH", help="Path to GeoLite2-Country.mmdb (Optional).")
    # Testing Group (xray-knife specific)
    test_xray_group = parser.add_argument_group('Testing Options (xray-knife - non-WG)')
    test_xray_group.add_argument("--xray-knife-path", metavar="PATH", help="Path to xray-knife executable.")
    test_xray_group.add_argument("--xray-knife-core", choices=["auto", "xray", "singbox"], default="auto", help="Core engine for xray-knife.")
    test_xray_group.add_argument("--xray-knife-timeout-ms", type=int, default=DEFAULT_XRAY_KNIFE_TIMEOUT_MS, metavar="MS", help="Timeout for primary xray-knife test (ms).")
    test_xray_group.add_argument("--xray-knife-insecure", action="store_true", help="Allow insecure TLS connections (-e).")
    test_xray_group.add_argument("--test-url", default=DEFAULT_TEST_URL, metavar="URL", help="Primary URL for connectivity/delay tests.")
    test_xray_group.add_argument("--test-method", default=DEFAULT_TEST_METHOD, metavar="METH", help="HTTP method for primary test.")
    test_xray_group.add_argument("--speedtest-amount", "-a", type=str, default=f"{DEFAULT_SPEEDTEST_AMOUNT_KB}kb", metavar="AMT[kb|mb]", help="Data amount for speed test (e.g., 5000kb, 10mb).")
    # Testing Group (UDP specific)
    test_udp_group = parser.add_argument_group('Testing Options (UDP - WG/WARP)')
    test_udp_group.add_argument("--udp-timeout", type=float, default=DEFAULT_UDP_TIMEOUT_S, metavar="SEC", help="Timeout for UDP tests (WG/WARP).")
    # Filtering & Output Group
    filter_group = parser.add_argument_group('Filtering & Output Options')
    filter_group.add_argument("--limit", "-l", type=int, default=DEFAULT_BEST_CONFIGS_LIMIT, metavar="N", help="Max configs to save per protocol (by score).")
    filter_group.add_argument("--include-countries", metavar="CC", help="Include only these country codes (comma-sep, e.g., US,DE).")
    filter_group.add_argument("--exclude-countries", metavar="CC", help="Exclude these country codes (comma-sep, e.g., CN,RU).")
    # Misc Group
    misc_group = parser.add_argument_group('Miscellaneous Options')
    misc_group.add_argument("--protocol-stats", action="store_true", help="Show enhanced summary statistics after testing.")
    misc_group.add_argument("--verbose", "-v", action="count", default=0, help="Increase verbosity (-v, -vv).")

    args = parser.parse_args() # Parse args synchronously first

    # Setup TQDM fallback/instance
    if tqdm is None: tqdm_progress = fallback_tqdm
    else: tqdm_progress = tqdm
    try: CACHE_DIR.mkdir(parents=True, exist_ok=True)
    except Exception as e: print(f"Warning: Could not create cache dir '{CACHE_DIR}': {e}", file=sys.stderr)

    # Set signal handler
    signal.signal(signal.SIGINT, signal_handler)

    # Run the main asynchronous logic
    try:
        asyncio.run(main_async())
    except KeyboardInterrupt:
        # This might catch Ctrl+C if it happens outside the main testing loop's try/except
        print("\nKeyboardInterrupt caught in top level. Exiting.", file=sys.stderr)
        is_ctrl_c_pressed = True # Ensure flag is set
    except Exception as e:
        print(f"\nUnhandled top-level exception: {type(e).__name__} - {e}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        sys.exit(1) # Exit with error code on unexpected failure


# Helper function to format result line (Enhanced for new info)
def format_result_line(tested_result: TestResult, args: argparse.Namespace) -> str:
    """Formats a single result line for verbose output."""
    delay_str = f"{tested_result.real_delay_ms:>4.0f}ms" if tested_result.real_delay_ms != float('inf') else "----ms"
    # Speed
    show_speed = args.speedtest and tested_result.protocol != "wg"
    dl = tested_result.download_speed_mbps; ul = tested_result.upload_speed_mbps
    spd_str = ""
    if show_speed and (dl > 0 or ul > 0): spd_str = f"D:{dl:>5.1f} U:{ul:>5.1f}"
    spd_pad = 16
    # Geo
    flag = tested_result.flag or ("?" if args.ip_info or args.geoip_db else "")
    loc = f"({tested_result.location})" if tested_result.location else ""
    geo_str = f"{flag}{loc}"; geo_pad = 8
    # Enhanced Indicators: [IR|CDN|ASN|FP|HTTP]
    ir = "✅" if tested_result.iran_access_passed is True else "❌" if tested_result.iran_access_passed is False else "?"
    cdn= "C" if tested_result.is_cdn_ip is True else "c" if tested_result.is_cdn_ip is False else "?"
    asn = "A" if tested_result.cdn_check_asn else "?" # Simple ASN indicator
    fp_map = {"reality": "R", "chrome": "F", "firefox": "F", "safari": "F", "ios": "F", "android": "F", "edge": "F", "random": "r", "custom": "u"}
    fp = fp_map.get(tested_result.tls_fingerprint_type, "?") if tested_result.tls_fingerprint_type else "?"
    http = tested_result.iran_test_http_version or "?"
    enh_str = f"[{ir}|{cdn}|{asn}|{fp}|H{http}]"; enh_pad = 13 # Adjusted padding
    # Score
    score = tested_result.combined_score
    score_str = f"S:{score:.2f}" if score != float('inf') else "S:---"; score_pad = 7
    # Config display
    cfg_str = tested_result.original_config; max_len = 40 # Shorter config display
    if len(cfg_str) > max_len: cfg_str = cfg_str[:max_len-3] + "..."
    # Status Color
    colors = {"passed": "92", "semi-passed": "93", "failed": "91", "dns-failed": "91", "timeout": "95", "broken": "91", "skipped": "90", "pending": "37"}
    color = colors.get(tested_result.status, "0")
    stat_str = f"\033[{color}m{tested_result.status.upper():<7}\033[0m" # Padded status
    # Reason
    reason = f" ({tested_result.reason})" if tested_result.reason and tested_result.status not in ['passed', 'pending', 'semi-passed'] else ""
    # Combine
    line = f"{stat_str} {delay_str:<7} {spd_str:<{spd_pad}} {geo_str:<{geo_pad}} {enh_str:<{enh_pad}} {score_str:<{score_pad}} {cfg_str}{reason}"
    return line.strip()
