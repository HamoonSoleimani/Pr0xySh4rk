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
                if percentage > 0:
                    eta = (elapsed / percentage) * (100 - percentage)
                    eta_str = str(timedelta(seconds=int(eta)))
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
    print("Warning: 'geoip2' module not found. GeoIP database lookups (--geoip-db) are disabled.", file=sys.stderr)
    print("         Install with: pip install geoip2-database", file=sys.stderr)

try:
    from dotenv import load_dotenv
    load_dotenv() # Load environment variables from .env file if it exists
    print("Info: Loaded environment variables from .env file (if found).", file=sys.stderr)
except ImportError:
    pass # dotenv is optional

# Suppress only the InsecureRequestWarning from urllib3 needed during fetching
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- Constants ---
# Country Code to Flag Emoji Mapping (Source: https://github.com/google/region-flags, simplified)
# Add more as needed
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
DEFAULT_TEST_URL = "https://cloudflare.com/cdn-cgi/trace" # Default for --test-url
DEFAULT_TEST_METHOD = "GET"
DEFAULT_BEST_CONFIGS_LIMIT = 100
DEFAULT_FETCH_TIMEOUT = 20 # Increased fetch timeout slightly
DEFAULT_XRAY_KNIFE_TIMEOUT_MS = 10000 # Increased default xray-knife timeout
DEFAULT_UDP_TIMEOUT_S = 5 # Default timeout for UDP tests (WireGuard/WARP)
PYTHON_SUBPROCESS_TIMEOUT_BUFFER_S = 15 # Python subprocess timeout buffer
DEFAULT_SPEEDTEST_AMOUNT_KB = 10000
DEFAULT_THREADS = min(32, os.cpu_count() * 2 + 4) if os.cpu_count() else 16 # Slightly increased default threads
CACHE_DIR = Path(".proxy_cache") # Directory for caching subscription content
CACHE_TTL_HOURS = 6 # Cache validity period

# --- Global State ---
total_outbounds_count = 0
completed_outbounds_count = 0
is_ctrl_c_pressed = False
found_xray_knife_path: Optional[str] = None
geoip_reader: Optional['geoip2.database.Reader'] = None
args: Optional[argparse.Namespace] = None # Define args in the global scope

# --- Dataclass for Test Results ---
@dataclass
class TestResult:
    original_config: str
    source: Optional[str] = None
    status: str = "pending" # pending, passed, failed, timeout, broken, skipped, semi-passed
    reason: Optional[str] = None
    real_delay_ms: float = float('inf')
    download_speed_mbps: float = 0.0 # Note: UDP test does not measure speed
    upload_speed_mbps: float = 0.0   # Note: UDP test does not measure speed
    ip: Optional[str] = None         # Note: UDP test does not get external IP easily
    location: Optional[str] = None # 2-letter country code (e.g., US)
    flag: Optional[str] = None # Emoji flag
    protocol: Optional[str] = None
    dedup_key_details: Dict[str, Any] = field(default_factory=dict) # Store details used for deduplication
    combined_score: float = float('inf') # Lower is better

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
                print(f"Using xray-knife path: {found_xray_knife_path}", file=sys.stderr)
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
        print(f"Found xray-knife in PATH: {found_xray_knife_path}", file=sys.stderr)
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
                 print(f"Found xray-knife at relative path: {found_xray_knife_path}", file=sys.stderr)
                 return found_xray_knife_path
            except Exception:
                 continue # Not executable or other issue

    # No error print here, as xray-knife might not be needed if only WG configs are present
    # Error will be raised later if a non-WG test requires it.
    return None

# ---------------------------
# Cache Handling Functions
# ---------------------------
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
def parse_config_content(content: str, source_url: str) -> List[TestResult]:
    outbounds = []
    if not content:
        return outbounds

    try:
        decoded_content = content # Assume plaintext first
        try:
            content_cleaned = ''.join(content.split())
            if len(content_cleaned) > 20 and re.fullmatch(r'[A-Za-z0-9+/=\s]+', content):
                 missing_padding = len(content_cleaned) % 4
                 if missing_padding:
                      content_cleaned += '=' * (4 - missing_padding)
                 decoded_bytes = base64.b64decode(content_cleaned, validate=True)
                 try:
                      decoded_content = decoded_bytes.decode('utf-8')
                 except UnicodeDecodeError:
                      decoded_content = decoded_bytes.decode('latin-1', errors='ignore')
        except (base64.binascii.Error, ValueError, TypeError):
             pass # If decode fails, assume it was plaintext

        supported_prefixes = (
            "vless://", "vmess://", "ss://", "ssr://", "trojan://",
            "tuic://", "hysteria://", "hysteria2://", "hy2://",
            "wg://", "wireguard://", "warp://", # Added warp://
            "socks://", "http://", "https://"
        )
        seen_configs_this_source = set()

        for line in decoded_content.splitlines():
            line = line.strip()
            if line and not line.startswith(("#", "//", ";")):
                 matched_prefix = None
                 for prefix in supported_prefixes:
                     if line.lower().startswith(prefix):
                         matched_prefix = prefix
                         break

                 if matched_prefix:
                    # Normalize protocol name
                    protocol = matched_prefix.split("://", 1)[0].lower()
                    if protocol in ["wireguard", "warp", "wg"]: # Normalize all WG variants
                        protocol = "wg"
                    elif protocol in ["hysteria2", "hy2"]: protocol = "hysteria"
                    # elif protocol == "ssr": protocol = "ss" # Keep SSR distinct for now

                    if line not in seen_configs_this_source:
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
    try:
        parsed_url = urllib.parse.urlparse(config_line)
        hostname = parsed_url.hostname
        port = parsed_url.port

        # Handle potential IPv6 brackets in hostname from urlparse
        if hostname and hostname.startswith('[') and hostname.endswith(']'):
            hostname = hostname[1:-1]

        return hostname, port
    except Exception as e:
        print(f"Debug: Error extracting server/port from {config_line[:60]}...: {e}", file=sys.stderr)
        return None, None

# ---------------------------
# Enhanced Server/Port/Details Extraction for Deduplication (Keep the detailed one from script 1)
# ---------------------------
def extract_config_details_for_dedup(config_line: str) -> Dict[str, Any]:
    details = {"protocol": None, "address": None, "port": None, "host": None, "path": None, "net": None, "type": None}
    try:
        parsed_url = urllib.parse.urlparse(config_line)
        scheme = parsed_url.scheme.lower()

        # --- Protocol Normalization consistent with parsing ---
        if scheme in ["wireguard", "warp", "wg"]:
            details["protocol"] = "wg"
        elif scheme in ["hysteria2", "hy2"]:
            details["protocol"] = "hysteria"
        # elif scheme == "ssr": details["protocol"] = "ss" # Keep SSR distinct
        else:
            details["protocol"] = scheme

        details["address"] = parsed_url.hostname # Use hostname as address initially
        details["port"] = parsed_url.port

        # Handle potential IPv6 brackets in address
        if details["address"] and details["address"].startswith('[') and details["address"].endswith(']'):
            details["address"] = details["address"][1:-1]

        query_params = urllib.parse.parse_qs(parsed_url.query)
        details["host"] = query_params.get("sni", [None])[0] or query_params.get("host", [None])[0] # SNI or Host header
        details["path"] = query_params.get("path", [None])[0]
        details["net"] = query_params.get("type", [None])[0] or query_params.get("net", [None])[0] # Network type (ws, grpc)

        # --- Protocol-specific parsing ---
        if scheme == "vmess":
            try:
                base64_part = config_line[len("vmess://"):].split("#")[0].strip()
                if len(base64_part) % 4 != 0: base64_part += '=' * (4 - len(base64_part) % 4)
                decoded_json = base64.b64decode(base64_part).decode('utf-8', errors='ignore')
                vmess_data = json.loads(decoded_json)
                details["address"] = vmess_data.get("add", details["address"])
                port_str = str(vmess_data.get("port", str(details["port"]) if details["port"] else None))
                details["port"] = int(port_str) if port_str and port_str.isdigit() else details["port"]
                details["host"] = vmess_data.get("sni", vmess_data.get("host", details["host"]))
                details["path"] = vmess_data.get("path", details["path"])
                details["net"] = vmess_data.get("net", details["net"])
                details["type"] = vmess_data.get("type", details["type"]) # Header type for HTTP
            except Exception: pass # Keep parsed URL data on failure

        elif scheme == "ss":
            # Simplified SS parsing for dedup: focus on host/port from netloc
            at_parts = parsed_url.netloc.split('@')
            host_port = at_parts[-1]
            if ':' in host_port:
                potential_host, port_str = host_port.rsplit(':', 1)
                if port_str.isdigit():
                    # Overwrite address/port if found reliably in netloc
                    details["address"] = potential_host
                    details["port"] = int(port_str)
            elif len(at_parts) == 1 and not details["address"] and not details["port"]:
                 # Try decoding the whole netloc if it looks like base64 and no '@' was present
                 try:
                      maybe_b64 = parsed_url.netloc.split("#")[0]
                      if len(maybe_b64) % 4 != 0: maybe_b64 += '=' * (4 - len(maybe_b64) % 4)
                      decoded_ss = base64.b64decode(maybe_b64).decode('utf-8', errors='ignore')
                      if '@' in decoded_ss and ':' in decoded_ss.split('@')[-1]:
                           host_port_decoded = decoded_ss.split('@')[-1]
                           potential_host, port_str = host_port_decoded.rsplit(':', 1)
                           if port_str.isdigit():
                                details["address"] = potential_host
                                details["port"] = int(port_str)
                 except Exception: pass

        elif scheme in ["vless", "trojan"]:
             details["host"] = query_params.get("sni", details.get("host"))
             details["path"] = query_params.get("path", details.get("path"))
             details["net"] = query_params.get("type", details.get("net"))
             if details["net"] == "grpc":
                 details["path"] = query_params.get("serviceName", [details.get("path")])[0]

        # --- Basic validation and normalization ---
        if not details["address"] or details["port"] is None or not (0 < details["port"] < 65536):
            # print(f"Debug: Invalid address/port for dedup: {details}", file=sys.stderr)
            return {} # Invalid for deduplication

        # Normalize IPv6 using ipaddress module if available
        addr = details["address"]
        if ipaddress and addr and ':' in addr:
             try:
                 ip_addr = ipaddress.ip_address(addr)
                 if isinstance(ip_addr, ipaddress.IPv6Address):
                     details["address"] = ip_addr.compressed # Use compressed form without brackets here
             except ValueError: pass # Not a valid IP, keep as is (e.g., domain)

        # Use address as host if host/SNI is missing (common case)
        if not details["host"]:
             details["host"] = details["address"]

        # Convert port to int just to be sure
        try:
            details["port"] = int(details["port"])
        except (ValueError, TypeError):
            return {} # Invalid port

        return details

    except Exception as e:
        # print(f"Debug: Error extracting details from {config_line[:60]}...: {e}", file=sys.stderr) # Reduce noise
        return {}

# ---------------------------
# Get deduplication key
# ---------------------------
def get_dedup_key(config_result: TestResult) -> Optional[tuple]:
    details = extract_config_details_for_dedup(config_result.original_config)
    config_result.dedup_key_details = details # Store details

    # Basic key components: protocol, address, port
    proto = details.get("protocol")
    addr = details.get("address")
    port = details.get("port")

    if not proto or not addr or port is None:
        return None # Cannot deduplicate without these essentials

    key_parts = [proto, addr, port]

    # Stricter deduplication for transport protocols (ws, grpc)
    net = details.get("net")
    if proto in ["vless", "vmess", "trojan", "tuic"] and net in ["ws", "grpc"]:
         key_parts.extend([
             net,
             details.get("path", ""),
             details.get("host", addr) # Use host/SNI if available, else address
         ])
    # Add other protocol-specific important fields if needed here

    return tuple(key_parts)

# ---------------------------
# Deduplicate outbounds based on deduplication key
# ---------------------------
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
            skipped_count += 1
            continue

        if key not in dedup_dict:
            dedup_dict[key] = config_result
        else:
             duplicates_found +=1
             # Optional: Prioritize based on source? For now, first seen wins.

    kept_count = len(dedup_dict)
    print(f"Deduplication: Processed {processed_count} configs. Kept {kept_count} unique. "
          f"Removed {duplicates_found} duplicates. Skipped {skipped_count} (invalid/unparseable key).", file=sys.stderr)
    return list(dedup_dict.values())

# ---------------------------
# GeoIP Lookup using Database
# ---------------------------
def get_geoip_location(ip_address: str, reader: Optional['geoip2.database.Reader']) -> Optional[str]:
    """Looks up the country code for an IP using the provided geoip2 reader."""
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

# -----------------------------------------------------
# --- NEW: UDP Test Logic (for WireGuard/WARP only) ---
# -----------------------------------------------------
async def _test_wg_udp_async(result_obj: TestResult, args: argparse.Namespace) -> TestResult:
    """Async core logic for UDP test."""
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

    if not server or not port:
        result_obj.status = "broken"
        result_obj.reason = "Could not parse server/port"
        # print(f"UDP Test: Invalid server/port for {config_line[:60]}...", file=sys.stderr)
        return result_obj

    resolved_ip = None
    try:
        # Resolve hostname to IP address first
        # Use asyncio's resolver for non-blocking DNS lookup
        loop = asyncio.get_running_loop()
        addr_info = await loop.getaddrinfo(server, port, family=socket.AF_UNSPEC, type=socket.SOCK_DGRAM)
        if not addr_info:
            raise socket.gaierror(f"No address info found for {server}")
        # Prefer IPv4 if available, otherwise take first entry
        ipv4_info = next((info for info in addr_info if info[0] == socket.AF_INET), None)
        chosen_info = ipv4_info or addr_info[0]
        resolved_ip = chosen_info[4][0] # The IP address string
        family = chosen_info[0] # Address family (AF_INET or AF_INET6)
        # print(f"Debug UDP: Resolved {server} to {resolved_ip}", file=sys.stderr)

    except (socket.gaierror, socket.herror) as e:
        result_obj.status = "failed"
        result_obj.reason = f"DNS resolution failed: {e}"
        # print(f"UDP Test: DNS failed for {server}:{port}", file=sys.stderr)
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
        # Store the resolved IP if GeoIP lookup was attempted
        result_obj.ip = resolved_ip # Store resolved IP, even if location not found


    transport = None
    start_time = 0
    try:
        loop = asyncio.get_running_loop()
        start_time = loop.time()
        # print(f"UDP Test: Connecting to {resolved_ip}:{port} (timeout: {timeout}s)...", file=sys.stderr)

        # Create UDP socket and send a small test packet
        # Using DatagramProtocol for potential future receive logic, though not strictly needed for send-only test
        conn_future = loop.create_datagram_endpoint(
            lambda: asyncio.DatagramProtocol(), # Simple protocol, does nothing on receive
            remote_addr=(resolved_ip, port),
            family=family # Use the family determined during resolution
        )

        # Wait for the connection (endpoint creation) with timeout
        transport, protocol_instance = await asyncio.wait_for(conn_future, timeout=timeout)

        # Send a minimal payload (e.g., null bytes, could be anything small)
        # This primarily tests reachability and initiates potential handshake/response implicitly
        transport.sendto(b'\x00')

        # Wait a very short time - this isn't measuring response time directly,
        # but rather the time to establish the endpoint and send.
        # A successful send here implies the port is likely open.
        # True latency measurement requires a ping-pong, which is complex for WG without a client.
        await asyncio.sleep(0.05) # Small delay after send

        end_time = loop.time()
        delay = (end_time - start_time) * 1000

        # Consider the test passed if no exception occurred within the timeout
        result_obj.real_delay_ms = max(1.0, delay) # Ensure delay is at least 1ms if very fast
        result_obj.status = "passed"
        result_obj.reason = "UDP connection successful" # Simple success message
        # print(f"UDP Test: Success for {server}:{port}, approx delay={delay:.0f}ms", file=sys.stderr)

    except asyncio.TimeoutError:
        result_obj.status = "timeout"
        result_obj.reason = f"UDP connection timed out after {timeout:.1f}s"
        # print(f"UDP Test: Timeout for {server}:{port}", file=sys.stderr)
    except socket.gaierror as e: # Should have been caught earlier, but double-check
        result_obj.status = "failed"
        result_obj.reason = f"DNS error during connection: {e}"
    except OSError as e:
        # Handle specific OS errors like 'Network is unreachable' or 'Connection refused' (less common for UDP)
        result_obj.status = "failed"
        result_obj.reason = f"OS error: {e.strerror} (code {e.errno})"
        # print(f"UDP Test: OS Error for {server}:{port}: {e}", file=sys.stderr)
    except Exception as e:
        result_obj.status = "broken"
        result_obj.reason = f"UDP test unexpected error: {type(e).__name__} - {e}"
        # print(f"UDP Test: Error for {server}:{port}: {e}", file=sys.stderr)
    finally:
        if transport:
            try:
                transport.close()
            except Exception:
                pass # Ignore errors during close

    # --- Calculate Combined Score for UDP ---
    if result_obj.status == "passed":
        # Score based solely on delay for UDP tests
        # Normalize against the UDP timeout for consistency? Or a fixed value?
        # Using a fixed reference like 1000ms might be better than variable UDP timeout.
        reference_delay = 1000.0 # e.g., 1 second reference for scoring
        normalized_delay = min(result_obj.real_delay_ms / reference_delay, 1.0) # Cap score at 1.0
        result_obj.combined_score = normalized_delay
        # If speedtest was globally requested, mark as semi-passed as speed not tested
        if args.speedtest:
            result_obj.status = "semi-passed"
            result_obj.reason = "Passed UDP, speed test N/A"
    else:
         result_obj.combined_score = float('inf') # Failed/timeout configs get worst score

    return result_obj

def test_wg_udp_sync(result_obj: TestResult, args: argparse.Namespace) -> TestResult:
    """Synchronous wrapper for the async UDP test."""
    try:
        # Ensure an event loop exists for this thread if needed, or run directly
        return asyncio.run(_test_wg_udp_async(result_obj, args))
    except RuntimeError as e:
        # Handle case where asyncio.run is called on a loop that's already running
        # (less likely in ThreadPoolExecutor, but possible in some contexts)
        if "cannot be called from a running event loop" in str(e):
             print(f"Warning: UDP test called from running loop for {result_obj.original_config[:50]}... Skipping.", file=sys.stderr)
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
# --- END NEW UDP Test Logic ---
# -------------------------------------------------------


# ---------------------------
# Test config using xray-knife subprocess (for non-WG protocols)
# ---------------------------
def test_config_with_xray_knife(result_obj: TestResult, xray_knife_path: str, args: argparse.Namespace) -> TestResult:
    global is_ctrl_c_pressed, geoip_reader
    if is_ctrl_c_pressed:
        result_obj.status = "skipped"
        result_obj.reason = "Interrupted by user"
        return result_obj

    # Check if xray-knife path is actually found, error if not
    if not xray_knife_path:
         result_obj.status = "broken"
         result_obj.reason = "xray-knife executable not found (required for this protocol)"
         print(f"ERROR: {result_obj.reason}. Please provide the path via --xray-knife-path or ensure it's in PATH.", file=sys.stderr)
         # is_ctrl_c_pressed = True # Optionally stop all tests if knife is missing
         return result_obj


    config_link = result_obj.original_config
    command = [
        xray_knife_path,
        "net",
        "http", # Assume http test mode
        "-c", config_link,
        "-v", # Verbose needed for parsing results
        "-d", str(args.xray_knife_timeout_ms),
        "--url", args.test_url,
        "--method", args.test_method,
        "-z", args.xray_knife_core # Specify core
    ]

    if args.speedtest:
        command.append("-p")
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
            print(f"Warning: Invalid --speedtest-amount '{args.speedtest_amount}'. Using default {DEFAULT_SPEEDTEST_AMOUNT_KB}kb.", file=sys.stderr)
            kb_amount = DEFAULT_SPEEDTEST_AMOUNT_KB
        command.extend(["-a", str(kb_amount)])


    if args.ip_info:
        command.append("--rip") # Request IP info from xray-knife

    if args.xray_knife_insecure:
        command.append("-e") # Enable insecure TLS

    python_timeout = (args.xray_knife_timeout_ms / 1000.0) + PYTHON_SUBPROCESS_TIMEOUT_BUFFER_S
    env = os.environ.copy()
    process_output = ""
    process_error = ""

    try:
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='replace',
            timeout=python_timeout,
            check=False,
            env=env
        )
        process_output = process.stdout
        process_error = process.stderr

    except subprocess.TimeoutExpired:
        result_obj.status = "timeout"
        result_obj.reason = f"Subprocess timed out after {python_timeout:.1f}s"
        result_obj.real_delay_ms = float('inf')
        return result_obj
    except FileNotFoundError: # Should be caught by initial check, but good backup
        result_obj.status = "broken"
        result_obj.reason = f"xray-knife not found at '{xray_knife_path}'"
        print(f"CRITICAL ERROR: {result_obj.reason}", file=sys.stderr)
        is_ctrl_c_pressed = True
        return result_obj
    except PermissionError:
        result_obj.status = "broken"
        result_obj.reason = f"Permission denied executing xray-knife at '{xray_knife_path}'"
        print(f"CRITICAL ERROR: {result_obj.reason}. Ensure it has execute permissions.", file=sys.stderr)
        is_ctrl_c_pressed = True
        return result_obj
    except Exception as e:
        result_obj.status = "broken"
        result_obj.reason = f"Subprocess error: {type(e).__name__} - {e}"
        print(f"ERROR testing {config_link[:60]}... : {result_obj.reason}", file=sys.stderr)
        return result_obj

    # --- Parse Output ---
    full_output = process_output + "\n" + process_error
    stdout_lines = process_output.splitlines()
    stderr_lines = process_error.splitlines()

    # Reset results before parsing (ensure clean state)
    result_obj.real_delay_ms = float('inf')
    result_obj.download_speed_mbps = 0.0
    result_obj.upload_speed_mbps = 0.0
    result_obj.ip = None
    result_obj.location = None
    result_obj.flag = None

    delay_match = REAL_DELAY_PATTERN.search(full_output)
    if delay_match:
        try: result_obj.real_delay_ms = float(delay_match.group(1))
        except ValueError: pass

    def parse_speed(match: Optional[re.Match]) -> float:
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

    ip_info_search_area = process_output # Search primarily stdout for trace
    ip_match = IP_INFO_PATTERN.search(ip_info_search_area)
    if ip_match:
        result_obj.ip = ip_match.group("ip")
        result_obj.location = ip_match.group("loc") # May be None

    # --- GeoIP Enhancement ---
    db_location = None
    ip_for_geoip = result_obj.ip # Use IP from xray-knife if available
    if not ip_for_geoip and result_obj.dedup_key_details.get("address"):
         # Fallback: try resolving the config address for GeoIP if DB exists
         # This adds overhead, maybe only do if geoip_reader is present?
         if geoip_reader:
              try:
                   addr_str = result_obj.dedup_key_details["address"]
                   # Basic check if it's likely an IP, not domain
                   if re.match(r'^[\d\.:a-fA-F]+$', addr_str):
                        ip_for_geoip = addr_str
                        result_obj.ip = ip_for_geoip # Store the resolved address as IP
                   # Optionally add DNS lookup here if needed, but increases complexity/time
              except Exception: pass # Ignore errors in fallback

    if geoip_reader and ip_for_geoip:
        db_location = get_geoip_location(ip_for_geoip, geoip_reader)
        if db_location:
            result_obj.location = db_location # Prefer DB location

    if result_obj.location:
        result_obj.flag = COUNTRY_FLAGS.get(result_obj.location.upper(), DEFAULT_FLAG)


    # --- Determine Status and Reason ---
    fail_reason = None
    current_status = "pending" # Local status tracker before assigning to result_obj

    if CONTEXT_DEADLINE_PATTERN.search(full_output):
        current_status = "timeout"
        fail_reason = f"Internal timeout (>{args.xray_knife_timeout_ms}ms)"
    elif IO_TIMEOUT_PATTERN.search(full_output):
         current_status = "timeout"
         fail_reason = "I/O timeout"
    elif CONNECTION_REFUSED_PATTERN.search(full_output):
         current_status = "failed"
         fail_reason = "Connection refused"
    elif DNS_ERROR_PATTERN.search(full_output):
         current_status = "failed"
         fail_reason = "DNS resolution failed"
    elif HANDSHAKE_ERROR_PATTERN.search(full_output):
         current_status = "failed"
         fail_reason = "TLS handshake failed"
    else:
         search_lines = (stdout_lines + stderr_lines)[-5:]
         for line in reversed(search_lines):
              fail_match = XRAY_KNIFE_FAIL_REASON_PATTERN.search(line)
              if fail_match:
                   reason_text = fail_match.group(1).strip()
                   if len(reason_text) < 100 and 'stack trace' not in reason_text:
                       fail_reason = reason_text
                       # If we found a fail message, tentatively set status to failed
                       if current_status == "pending":
                           current_status = "failed"
                       break

    # Determine final status based on results and exit code
    if current_status == "pending": # Only if not already set by error patterns
        if process.returncode != 0:
            current_status = "broken"
            error_details = process_error.strip() or process_output.strip()
            fail_reason = fail_reason or f"x-knife exited {process.returncode}. Output: {error_details[:100]}"
        elif result_obj.real_delay_ms <= args.xray_knife_timeout_ms: # Successfully parsed delay within timeout
            current_status = "passed"
            fail_reason = None # Clear reason if passed
            if args.speedtest and (result_obj.download_speed_mbps == 0.0 and result_obj.upload_speed_mbps == 0.0):
                if not download_match and not upload_match: # Speed test requested but no speed lines found
                     current_status = "semi-passed"
                     fail_reason = "Passed delay, speed test N/A or failed"
        elif result_obj.real_delay_ms > args.xray_knife_timeout_ms: # Parsed delay but exceeded timeout
            current_status = "timeout"
            fail_reason = f"Delay {result_obj.real_delay_ms:.0f}ms > limit {args.xray_knife_timeout_ms}ms"
        else: # Catch-all if status still pending
            current_status = "broken"
            fail_reason = fail_reason or f"Unknown status (RC={process.returncode}, Delay={result_obj.real_delay_ms:.0f}ms)"

    # Assign final status and reason
    result_obj.status = current_status
    result_obj.reason = fail_reason

    # Refine reason if still None for non-passed states
    if result_obj.status not in ["passed", "semi-passed", "pending", "skipped"] and not result_obj.reason:
         result_obj.reason = f"Failed/Timeout/Broken (RC={process.returncode})"


    # --- Calculate Combined Score ---
    if result_obj.status in ["passed", "semi-passed"]:
         delay_norm_factor = max(100, args.xray_knife_timeout_ms)
         normalized_delay = min(result_obj.real_delay_ms / delay_norm_factor, 1.0)

         inv_download = 1.0 / (1.0 + min(result_obj.download_speed_mbps, 150.0)) # Cap at 150 Mbps
         inv_upload = 1.0 / (1.0 + min(result_obj.upload_speed_mbps, 150.0)) # Cap at 150 Mbps

         delay_weight = 0.60
         dl_weight = 0.25
         ul_weight = 0.15

         if args.speedtest and result_obj.status == "passed": # Only include speed if speedtest enabled AND status is fully passed
             result_obj.combined_score = (delay_weight * normalized_delay +
                                          dl_weight * inv_download +
                                          ul_weight * inv_upload)
         else: # Score based only on delay if no speedtest or semi-passed
             result_obj.combined_score = normalized_delay
    else:
         result_obj.combined_score = float('inf') # Failed/timeout configs get worst score

    return result_obj

# ---------------------------
# Worker function for ThreadPoolExecutor (integrates with tqdm)
# Now dispatches based on protocol
# ---------------------------
def run_test_worker(result_obj: TestResult, xray_knife_path: Optional[str], args: argparse.Namespace) -> TestResult:
    global is_ctrl_c_pressed

    if is_ctrl_c_pressed:
        if result_obj.status == "pending":
            result_obj.status = "skipped"
            result_obj.reason = "Interrupted by user"
        return result_obj

    tested_result = None
    try:
        # --- Dispatch based on protocol ---
        if result_obj.protocol == "wg":
            # Use UDP test for WireGuard/WARP
            if args.verbose: print(f"Testing WG/WARP via UDP: {result_obj.original_config[:60]}...", file=sys.stderr)
            tested_result = test_wg_udp_sync(result_obj, args)
        else:
            # Use xray-knife for all other protocols
            if args.verbose: print(f"Testing via xray-knife: {result_obj.original_config[:60]}...", file=sys.stderr)
            # Pass the potentially None xray_knife_path, the function handles the error if needed
            tested_result = test_config_with_xray_knife(result_obj, xray_knife_path, args)
        # --- End Dispatch ---

    except Exception as e:
         # Catch unexpected errors during the test call itself
         print(f"\nCRITICAL ERROR in worker for {result_obj.original_config[:50]}: {type(e).__name__} - {e}", file=sys.stderr)
         if tested_result is None: tested_result = result_obj # Ensure we return the object
         tested_result.status = "broken"
         tested_result.reason = f"Worker execution error: {e}"
         tested_result.combined_score = float('inf')
         tested_result.real_delay_ms = float('inf')

    # Format result line for logging/verbose output is handled outside by format_result_line helper
    return tested_result


# ---------------------------
# Saving configurations
# ---------------------------
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
# Save Detailed Results (CSV and Optional JSON)
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
            import csv # Import only when needed
            headers = [
                "status", "real_delay_ms", "download_speed_mbps", "upload_speed_mbps",
                "ip", "location", "flag", "protocol", "reason", "source", "original_config",
                "dedup_address", "dedup_port", "dedup_host", "dedup_net", "dedup_path"
            ]

            with csv_path.open('w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=headers, quoting=csv.QUOTE_MINIMAL, extrasaction='ignore')
                writer.writeheader()
                for result in results:
                     # Format potentially infinite/None values for CSV
                     delay_csv = f"{result.real_delay_ms:.0f}" if result.real_delay_ms != float('inf') else ''
                     dl_speed_csv = f"{result.download_speed_mbps:.2f}" if result.download_speed_mbps > 0 else ''
                     ul_speed_csv = f"{result.upload_speed_mbps:.2f}" if result.upload_speed_mbps > 0 else ''

                     row = {
                        "status": result.status,
                        "real_delay_ms": delay_csv,
                        "download_speed_mbps": dl_speed_csv,
                        "upload_speed_mbps": ul_speed_csv,
                        "ip": result.ip or '',
                        "location": result.location or '',
                        "flag": result.flag or '',
                        "protocol": result.protocol or '',
                        "reason": (result.reason or '').replace('\n', ' ').replace('\r', ''),
                        "source": result.source or '',
                        "original_config": result.original_config,
                        "dedup_address": result.dedup_key_details.get("address", ""),
                        "dedup_port": result.dedup_key_details.get("port", ""),
                        "dedup_host": result.dedup_key_details.get("host", ""),
                        "dedup_net": result.dedup_key_details.get("net", ""),
                        "dedup_path": result.dedup_key_details.get("path", ""),
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
                # Convert dataclass to dict for JSON serialization, handle infinity
                result_dict = {
                    "status": result.status,
                    "real_delay_ms": result.real_delay_ms if result.real_delay_ms != float('inf') else None,
                    "download_speed_mbps": result.download_speed_mbps,
                    "upload_speed_mbps": result.upload_speed_mbps,
                    "ip": result.ip,
                    "location": result.location,
                    "flag": result.flag,
                    "protocol": result.protocol,
                    "reason": result.reason,
                    "source": result.source,
                    "original_config": result.original_config,
                    "dedup_details": result.dedup_key_details,
                    "combined_score": result.combined_score if result.combined_score != float('inf') else None,
                }
                results_list.append(result_dict)

            with json_path.open('w', encoding='utf-8') as jsonfile:
                json.dump(results_list, jsonfile, indent=2, ensure_ascii=False)

            print(f"Successfully saved {len(results)} detailed results to '{json_path.resolve()}' (JSON).")

        except IOError as e: print(f"\nError saving detailed JSON results to '{json_filepath}': {e}", file=sys.stderr)
        except Exception as e: print(f"\nUnexpected error saving detailed JSON results: {e}", file=sys.stderr)


# ---------------------------
# Rename and limit configs by protocol based on score and GeoIP filters
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
    working_results = [r for r in tested_results if r.status in ["passed", "semi-passed"]]
    print(f"\nFound {len(working_results)} working configs initially (status 'passed' or 'semi-passed').")

    # --- 2. Apply GeoIP filters (if any) ---
    filtered_results = []
    if include_countries or exclude_countries:
        # Check if GeoIP info was likely gathered
        geoip_was_enabled = args.ip_info or args.geoip_db
        if not geoip_was_enabled:
             print("Warning: Country filtering requested (--include/--exclude-countries), but neither --ip-info (for xray-knife) nor --geoip-db was enabled. Filtering may be ineffective.", file=sys.stderr)

        inc = set(c.upper() for c in include_countries) if include_countries else None
        exc = set(c.upper() for c in exclude_countries) if exclude_countries else None
        skipped_by_filter = 0

        for r in working_results:
            loc = r.location.upper() if r.location else None
            included = True
            if loc is None and (inc or exc): # Cannot filter if location is unknown
                 # Keep unknown locations unless explicitly excluded (e.g., by matching None?) - Currently keeps unknowns.
                 pass
            elif inc and loc not in inc:
                included = False
            elif exc and loc in exc:
                included = False

            if included:
                filtered_results.append(r)
            else:
                skipped_by_filter += 1

        print(f"Filtered {skipped_by_filter} configs based on country rules. Kept {len(filtered_results)}.")
        working_results = filtered_results
    else:
        print("No country filters applied.")


    if not working_results:
        print("No working configs remain after filtering. Nothing to rename/save.", file=sys.stderr)
        return []

    # --- 3. Group by protocol, Sort, Limit, and Rename ---
    protocol_map = {
        "ss": "SS", "ssr": "SSR", "shadowsocks": "SS",
        "vless": "VL",
        "vmess": "VM",
        "trojan": "TR",
        "tuic": "TU",
        "hysteria": "HY", # Covers hysteria, hysteria2, hy2
        "socks": "SK", "socks5": "SK",
        "http": "HT", "https": "HT",
        "wg": "WG", # Covers wg, wireguard, warp
    }
    renamed_configs: List[str] = []
    protocol_groups: Dict[str, List[TestResult]] = {}

    for result in working_results:
        proto_norm = result.protocol or "unknown" # Already normalized during parsing
        abbr = protocol_map.get(proto_norm, proto_norm[:2].upper())
        protocol_groups.setdefault(abbr, []).append(result)

    total_renamed_count = 0
    print(f"Renaming and limiting up to {limit_per_protocol} configs per protocol...")
    for abbr, group_list in protocol_groups.items():
        group_list.sort(key=lambda r: (r.combined_score, r.real_delay_ms)) # Sort by score, then delay
        limited_list = group_list[:limit_per_protocol]
        total_renamed_count += len(limited_list)

        for i, result in enumerate(limited_list, start=1):
            config = result.original_config
            flag = result.flag or DEFAULT_FLAG
            new_tag = f"🔒{name_prefix}🦈[{abbr}][{i:02d}][{flag}]"
            safe_tag = urllib.parse.quote(new_tag)
            base_part = config.split("#", 1)[0]
            new_config = f"{base_part}#{safe_tag}"
            renamed_configs.append(new_config)

    print(f"Prepared {total_renamed_count} renamed configs across {len(protocol_groups)} protocols.")
    renamed_configs.sort(key=lambda x: x.split("#", 1)[-1]) # Sort final list by tag
    return renamed_configs

# ---------------------------
# Fetch and parse subscription worker
# ---------------------------
def fetch_and_parse_subscription_worker(url: str, proxy: Optional[str], timeout: int, force_fetch: bool) -> List[TestResult]:
    content = fetch_content(url, proxy, timeout, force_fetch)
    if content:
        parsed_results = parse_config_content(content, url)
        return parsed_results
    else:
        return []

# ---------------------------
# Print Summary Statistics
# ---------------------------
def print_protocol_statistics(tested_results: List[TestResult]):
    global args
    if not tested_results: return

    print("\n--- Protocol Statistics ---")
    protocol_stats: Dict[str, Dict[str, Any]] = {}
    total_tested_count = len(tested_results)

    for result in tested_results: # Iterate over all tested results
         proto_raw = result.protocol or "unknown"
         proto_norm = proto_raw # Already normalized ('wg', 'hysteria', etc.)

         if proto_norm not in protocol_stats:
              protocol_stats[proto_norm] = {
                   "tested_count": 0, "passed_count": 0, "semi_passed_count": 0,
                   "failed_count": 0, "timeout_count": 0, "broken_count": 0, "skipped_count": 0,
                   "total_delay": 0.0, "valid_delay_count": 0, "min_delay": float('inf'), "max_delay": 0.0,
                   "total_dl_speed": 0.0, "valid_dl_count": 0, "max_dl_speed": 0.0,
                   "total_ul_speed": 0.0, "valid_ul_count": 0, "max_ul_speed": 0.0,
                   "locations": set(),
              }

         stats = protocol_stats[proto_norm]
         stats["tested_count"] += 1
         status_key = f"{result.status}_count"
         if status_key in stats: stats[status_key] += 1
         if result.location: stats["locations"].add(f"{result.flag}{result.location.upper()}")

         # Accumulate stats for working configs only
         if result.status in ["passed", "semi-passed"]:
             delay = result.real_delay_ms
             if delay != float('inf'):
                 stats["total_delay"] += delay
                 stats["valid_delay_count"] += 1
                 stats["min_delay"] = min(stats["min_delay"], delay)
                 stats["max_delay"] = max(stats["max_delay"], delay)

             # Only accumulate speed if > 0 (xray-knife tests might yield 0 speed)
             # UDP tests will always have 0 speed here.
             dl_speed = result.download_speed_mbps
             if dl_speed > 0:
                 stats["total_dl_speed"] += dl_speed
                 stats["valid_dl_count"] += 1
                 stats["max_dl_speed"] = max(stats["max_dl_speed"], dl_speed)

             ul_speed = result.upload_speed_mbps
             if ul_speed > 0:
                 stats["total_ul_speed"] += ul_speed
                 stats["valid_ul_count"] += 1
                 stats["max_ul_speed"] = max(stats["max_ul_speed"], ul_speed)

    sorted_protocols = sorted(protocol_stats.keys())
    for protocol in sorted_protocols:
        stats = protocol_stats[protocol]
        total_tested = stats["tested_count"]
        working_count = stats['passed_count'] + stats['semi_passed_count']

        avg_delay_str = "N/A"
        if stats["valid_delay_count"] > 0:
             avg_delay = stats["total_delay"] / stats["valid_delay_count"]
             avg_delay_str = f"{avg_delay:.0f}ms"
        min_delay_str = "N/A" if stats['min_delay'] == float('inf') else f"{stats['min_delay']:.0f}ms"
        max_delay_str = "N/A" if stats['max_delay'] == 0.0 and stats['min_delay'] == float('inf') else f"{stats['max_delay']:.0f}ms"

        avg_dl_str, max_dl_str = "N/A", "N/A"
        if args.speedtest and stats["valid_dl_count"] > 0:
             avg_dl = stats["total_dl_speed"] / stats["valid_dl_count"]
             avg_dl_str = f"{avg_dl:.2f} Mbps"
             max_dl_str = f"{stats['max_dl_speed']:.2f} Mbps"

        avg_ul_str, max_ul_str = "N/A", "N/A"
        if args.speedtest and stats["valid_ul_count"] > 0:
             avg_ul = stats["total_ul_speed"] / stats["valid_ul_count"]
             avg_ul_str = f"{avg_ul:.2f} Mbps"
             max_ul_str = f"{stats['max_ul_speed']:.2f} Mbps"

        loc_summary = ", ".join(sorted(list(stats["locations"]))) if stats["locations"] else "None"
        speed_note = ""
        if protocol == "wg":
            speed_note = " (Speed N/A for UDP test)" if args.speedtest else ""


        print(f"Protocol: {protocol.upper():<8} (Tested: {total_tested}, Working: {working_count})")
        print(f"  Status: Pass:{stats['passed_count']}, Semi:{stats['semi_passed_count']}, "
              f"Fail:{stats['failed_count']}, Timeout:{stats['timeout_count']}, "
              f"Broken:{stats['broken_count']}, Skip:{stats['skipped_count']}")
        print(f"  Delay (Avg/Min/Max): {avg_delay_str} / {min_delay_str} / {max_delay_str}")
        if args.speedtest:
             # Only show speed stats if they were potentially measured (i.e., not WG)
             if protocol != "wg" or (stats["valid_dl_count"] > 0 or stats["valid_ul_count"] > 0): # Show if *any* speed was recorded (unlikely for WG)
                  print(f"  DL Speed (Avg/Max): {avg_dl_str} / {max_dl_str}{speed_note}")
                  print(f"  UL Speed (Avg/Max): {avg_ul_str} / {max_ul_str}{speed_note}")
             elif protocol == "wg":
                  print(f"  DL Speed (Avg/Max): N/A / N/A{speed_note}")
                  print(f"  UL Speed (Avg/Max): N/A / N/A{speed_note}")

        # Show GeoIP if attempted for any protocol
        # Note: For WG, location depends on --geoip-db lookup of server IP
        geoip_attempted = args.ip_info or args.geoip_db
        if geoip_attempted:
             print(f"  Locations Found: {loc_summary}")
        print("-" * 30)

    print(f"Total Configs Tested: {total_tested_count}")
    print(f"Overall Working: {sum(p['passed_count'] + p['semi_passed_count'] for p in protocol_stats.values())}")


# ---------------------------
# Main function
# ---------------------------
def main():
    global is_ctrl_c_pressed, total_outbounds_count, completed_outbounds_count, args, geoip_reader
    signal.signal(signal.SIGINT, signal_handler)

    # --- Argument Parsing ---
    parser = argparse.ArgumentParser(
        description="Pr0xySh4rk Config Manager - Fetch, Test (xray-knife OR UDP for WG/WARP), Filter, Rename, Save.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

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
    test_common_group.add_argument("--speedtest", "-p", action="store_true", help="Enable speed testing (only applies to xray-knife tests, not WG/WARP UDP tests).")
    test_common_group.add_argument("--ip-info", "--rip", action="store_true", help="Get IP/Location via xray-knife (--rip). Applies only to non-WG tests.")
    test_common_group.add_argument("--geoip-db", metavar="PATH", help="Path to GeoLite2-Country.mmdb database file for GeoIP lookups (used by both test methods if available). Requires 'geoip2-database'.")

    # Testing Group (xray-knife specific - for non-WG)
    test_xray_group = parser.add_argument_group('Testing Options (xray-knife - for non-WG/WARP)')
    test_xray_group.add_argument("--xray-knife-path", metavar="PATH", help="Path to xray-knife executable. Required if non-WG configs are present.")
    test_xray_group.add_argument("--xray-knife-core", choices=["auto", "xray", "singbox"], default="auto", help="Core engine for xray-knife.")
    test_xray_group.add_argument("--xray-knife-timeout-ms", type=int, default=DEFAULT_XRAY_KNIFE_TIMEOUT_MS, metavar="MS", help="Max delay for xray-knife test in milliseconds.")
    test_xray_group.add_argument("--xray-knife-insecure", action="store_true", help="Allow insecure TLS connections during xray-knife testing (-e).")
    test_xray_group.add_argument("--test-url", default=DEFAULT_TEST_URL, metavar="URL", help="URL used by xray-knife for connectivity/delay tests.")
    test_xray_group.add_argument("--test-method", default=DEFAULT_TEST_METHOD, metavar="METHOD", help="HTTP method used by xray-knife for testing.")
    test_xray_group.add_argument("--speedtest-amount", "-a", type=str, default=f"{DEFAULT_SPEEDTEST_AMOUNT_KB}kb", metavar="AMOUNT[kb|mb]", help="Data amount for xray-knife speed test (e.g., 10000kb, 15mb).")

    # Testing Group (UDP specific - for WG/WARP)
    test_udp_group = parser.add_argument_group('Testing Options (UDP - for WG/WARP)')
    test_udp_group.add_argument("--udp-timeout", type=float, default=DEFAULT_UDP_TIMEOUT_S, metavar="SEC", help="Timeout in seconds for UDP tests (WG/WARP).")


    # Filtering & Concurrency Group
    filter_group = parser.add_argument_group('Filtering & Output Options')
    filter_group.add_argument("--limit", "-l", type=int, default=DEFAULT_BEST_CONFIGS_LIMIT, metavar="N", help="Maximum number of best configs to save *per protocol*.")
    filter_group.add_argument("--include-countries", metavar="CC", help="Comma-separated list of 2-letter country codes to include (e.g., US,DE,JP). Requires GeoIP info.")
    filter_group.add_argument("--exclude-countries", metavar="CC", help="Comma-separated list of 2-letter country codes to exclude (e.g., CN,RU,IR). Requires GeoIP info.")

    # Misc Group
    misc_group = parser.add_argument_group('Miscellaneous Options')
    misc_group.add_argument("--protocol-stats", action="store_true", help="Show summary statistics for each protocol after testing.")
    misc_group.add_argument("--verbose", "-v", action="store_true", help="Show verbose output during testing.")

    args = parser.parse_args()

    # --- Initial Setup ---
    print("\n--- Pr0xySh4rk Config Manager ---")
    print(f"Test Mode: xray-knife (non-WG), UDP (WG/WARP)")
    print(f"Using {args.threads} threads. Config limit per protocol: {args.limit}.")
    print(f"Xray-Knife Timeout: {args.xray_knife_timeout_ms}ms. UDP Timeout: {args.udp_timeout}s.")
    print(f"Speedtest (xray-knife only): {'Enabled' if args.speedtest else 'Disabled'}. GeoIP: {'Enabled' if args.ip_info or args.geoip_db else 'Disabled'}")
    if args.xray_knife_timeout_ms < 5000 and args.speedtest:
        print("Warning: Low xray-knife timeout with speedtest enabled may lead to inaccurate speed results or timeouts.", file=sys.stderr)

    if args.clear_cache:
        if CACHE_DIR.exists():
            print(f"Clearing cache directory: {CACHE_DIR.resolve()}", file=sys.stderr)
            try: shutil.rmtree(CACHE_DIR)
            except OSError as e: print(f"Warning: Could not fully clear cache: {e}", file=sys.stderr)
        else: print("Cache directory not found, nothing to clear.", file=sys.stderr)

    # --- Find xray-knife (only strictly needed if non-WG configs exist) ---
    # We find it here, but error checking is deferred until it's actually needed
    xray_knife_executable = find_xray_knife(args.xray_knife_path)
    if not xray_knife_executable:
        print("Info: xray-knife executable not found initially. It will be required if non-WG/WARP configs are tested.", file=sys.stderr)

    # --- Load GeoIP Database ---
    if args.geoip_db:
        if not geoip2:
            print("Error: --geoip-db specified, but 'geoip2' module is not installed. Cannot use GeoIP DB.", file=sys.stderr)
            # Don't exit, maybe xray-knife --rip is enough for non-WG
        else:
            db_path = Path(args.geoip_db).resolve()
            if not db_path.is_file():
                print(f"Error: GeoIP database file not found at: {db_path}", file=sys.stderr)
            else:
                try:
                    geoip_reader = geoip2.database.Reader(str(db_path))
                    print(f"Loaded GeoIP database: {db_path}", file=sys.stderr)
                except Exception as e:
                    print(f"Error loading GeoIP database '{db_path}': {e}", file=sys.stderr)
                    geoip_reader = None # Disable GeoIP DB if loading failed

    # --- Read Subscription URLs ---
    subscription_urls = []
    try:
        input_path = Path(args.input)
        if not input_path.is_file():
            print(f"Error: Input file '{args.input}' not found.", file=sys.stderr)
            sys.exit(1)

        # Try reading as binary first to detect base64 robustly
        raw_bytes = input_path.read_bytes()
        decoded_content = None
        try:
             # Attempt base64 decode first
             # Remove whitespace bytes before decoding
             cleaned_bytes = bytes(filter(lambda x: not chr(x).isspace(), raw_bytes))
             if len(cleaned_bytes) % 4 != 0:
                  cleaned_bytes += b'=' * (4 - len(cleaned_bytes) % 4)
             decoded_content = base64.b64decode(cleaned_bytes, validate=True).decode('utf-8')
             print("Input file decoded as Base64.", file=sys.stderr)
        except (base64.binascii.Error, ValueError, UnicodeDecodeError):
             # If decode fails, try reading as UTF-8 text
             try:
                  decoded_content = raw_bytes.decode('utf-8')
                  print("Input file read as plaintext UTF-8.", file=sys.stderr)
             except UnicodeDecodeError:
                  print(f"Error: Input file '{args.input}' is not valid Base64 nor UTF-8 text.", file=sys.stderr)
                  sys.exit(1)

        if decoded_content:
             subscription_urls = [line.strip() for line in decoded_content.splitlines() if line.strip() and not line.startswith(("#", ";", "//"))]
        print(f"Read {len(subscription_urls)} URLs from '{args.input}'.", file=sys.stderr)

    except Exception as e:
        print(f"Error reading input file '{args.input}': {e}", file=sys.stderr)
        sys.exit(1)

    if not subscription_urls:
        print("No valid subscription URLs found. Exiting.", file=sys.stderr)
        sys.exit(0)

    # --- Fetch and Parse Subscriptions Concurrently ---
    print(f"\nFetching {len(subscription_urls)} subscriptions (Cache TTL: {args.cache_ttl}h)...")
    all_parsed_results: List[TestResult] = []
    fetch_futures = []
    try:
        progress_bar_fetch = tqdm_progress(total=len(subscription_urls), desc="Fetching Subs", unit="URL", disable=not tqdm)
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads, thread_name_prefix="Fetcher") as executor:
            for url in subscription_urls:
                if is_ctrl_c_pressed: break
                future = executor.submit(fetch_and_parse_subscription_worker, url, args.fetch_proxy, args.fetch_timeout, args.no_cache)
                fetch_futures.append(future)

            for future in concurrent.futures.as_completed(fetch_futures):
                if is_ctrl_c_pressed: break
                try:
                    results_list = future.result()
                    if results_list: all_parsed_results.extend(results_list)
                except Exception as exc: print(f'\nSubscription worker generated an exception: {exc}', file=sys.stderr)
                finally:
                    if progress_bar_fetch: progress_bar_fetch.update(1)

        if progress_bar_fetch: progress_bar_fetch.close()
        if is_ctrl_c_pressed: print("\nFetching interrupted by user.", file=sys.stderr)

    except Exception as e: print(f"\nError during subscription fetching phase: {e}", file=sys.stderr)

    print(f"Fetched a total of {len(all_parsed_results)} potential configs.")
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

    # Check if xray-knife is needed *before* starting tests
    needs_xray_knife = any(res.protocol != "wg" for res in unique_results)
    if needs_xray_knife and not xray_knife_executable:
         print("\nError: xray-knife executable is required for testing non-WG/WARP configs but was not found.", file=sys.stderr)
         print("Please ensure it's in your PATH, provide --xray-knife-path, or set XRAY_KNIFE_PATH environment variable.", file=sys.stderr)
         if geoip_reader: geoip_reader.close()
         sys.exit(1)
    elif needs_xray_knife:
         print(f"Using xray-knife for non-WG tests: {xray_knife_executable}")


    # --- Test Configs Concurrently ---
    print(f"\nStarting tests on {total_outbounds_count} unique configs...")
    # Use tqdm for testing progress
    progress_bar_test = tqdm_progress(total=total_outbounds_count, desc="Testing Configs", unit="config", disable=not tqdm or args.verbose)

    tested_results: List[TestResult] = []
    completed_outbounds_count = 0
    test_futures = []
    executor = None
    try:
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=args.threads, thread_name_prefix="Tester")
        for result_obj in unique_results:
            if is_ctrl_c_pressed: break
            # Pass xray_knife_executable (which might be None if only WG tested)
            future = executor.submit(run_test_worker, result_obj, xray_knife_executable, args)
            test_futures.append(future)

        for future in concurrent.futures.as_completed(test_futures):
            if is_ctrl_c_pressed and not future.done():
                future.cancel()
                continue
            try:
                tested_result = future.result()
                tested_results.append(tested_result)
                if args.verbose and tested_result.status != 'skipped':
                    status_line = format_result_line(tested_result, args) # Use helper
                    if progress_bar_test: progress_bar_test.write(status_line) # Write below bar
                    # else: print(status_line) # Avoid double print if no progress bar

            except concurrent.futures.CancelledError:
                 if progress_bar_test: progress_bar_test.set_postfix_str("Cancelled", refresh=False)
                 continue
            except Exception as exc: print(f'\nTester worker execution resulted in exception: {exc}', file=sys.stderr)
            finally:
                 completed_outbounds_count += 1
                 if progress_bar_test: progress_bar_test.update(1)

    except KeyboardInterrupt:
         print("\nKeyboardInterrupt caught in main testing loop. Shutting down...", file=sys.stderr)
         is_ctrl_c_pressed = True
    except Exception as e: print(f"\nError during testing phase: {type(e).__name__} - {e}", file=sys.stderr)
    finally:
         if progress_bar_test: progress_bar_test.close()
         if executor:
             print("\nWaiting for test workers to shut down...", file=sys.stderr)
             cancel_opt = hasattr(concurrent.futures, 'thread') and sys.version_info >= (3, 9)
             # Give workers a bit more time to finish UDP tests gracefully if interrupted
             shutdown_wait = not is_ctrl_c_pressed
             executor.shutdown(wait=shutdown_wait, cancel_futures=cancel_opt and is_ctrl_c_pressed)
             print("Test workers shut down.", file=sys.stderr)


    print(f"\nTesting completed. Processed {len(tested_results)} out of {total_outbounds_count} unique configs.")

    # --- Filter by Country, Rename, Limit, Save ---
    inc_countries = args.include_countries.split(',') if args.include_countries else None
    exc_countries = args.exclude_countries.split(',') if args.exclude_countries else None

    final_renamed_configs = filter_rename_limit_configs(
        tested_results,
        args.limit,
        args.name_prefix,
        include_countries=inc_countries,
        exclude_countries=exc_countries
    )
    if final_renamed_configs:
         save_configs(final_renamed_configs, args.output, args.output_format == "base64")
    else:
         print(f"\nNo working configs matched the criteria to save to '{args.output}'.")


    # --- Save Detailed Results (Optional) ---
    if args.output_csv or args.output_json:
        # Sort detailed results for consistent output (e.g., by protocol then score)
        tested_results.sort(key=lambda r: (r.protocol or "zzz", r.combined_score, r.real_delay_ms))
        print(f"\nSaving detailed test results for all {len(tested_results)} tested configs...")
        save_detailed_results(tested_results, args.output_csv, args.output_json)

    # --- Protocol Statistics (Optional) ---
    if args.protocol_stats:
        print_protocol_statistics(tested_results)

    # --- Cleanup ---
    if geoip_reader:
        try: geoip_reader.close()
        except Exception: pass
        print("\nClosed GeoIP database reader.")

    print("\nDone.")


# Helper function to format result line (used if verbose is true or no tqdm)
def format_result_line(tested_result: TestResult, args: argparse.Namespace) -> str:
    delay_str = f"{tested_result.real_delay_ms:>4.0f}ms" if tested_result.real_delay_ms != float('inf') else "----ms"
    # Show speed only if speedtest enabled AND speed > 0 AND protocol is not WG
    show_speed = args.speedtest and tested_result.protocol != "wg"
    dl_speed_str = f"DL:{tested_result.download_speed_mbps:>5.1f}" if show_speed and tested_result.download_speed_mbps > 0 else ""
    ul_speed_str = f"UL:{tested_result.upload_speed_mbps:>5.1f}" if show_speed and tested_result.upload_speed_mbps > 0 else ""

    flag_str = tested_result.flag or ("?" if args.geoip_db or args.ip_info else "") # Indicate if geo expected but missing
    loc_str = f"({tested_result.location})" if tested_result.location else ""
    geo_str = f"{flag_str}{loc_str}"

    status_color_map = {
        "passed": "\033[92m", "semi-passed": "\033[93m", "failed": "\033[91m",
        "timeout": "\033[95m", "broken": "\033[91m", "skipped": "\033[90m", "pending": "\033[37m",
    }
    status_color = status_color_map.get(tested_result.status, "\033[0m")
    reset_color = "\033[0m"

    max_len = 60 # Allow slightly longer display
    display_config = tested_result.original_config
    if len(display_config) > max_len: display_config = display_config[:max_len-3] + "..."
    reason_str = f" ({tested_result.reason})" if tested_result.reason and tested_result.status not in ['passed', 'pending'] else ""

    # Pad strings for alignment
    return (
        f"{status_color}{tested_result.status.upper():<7}{reset_color} "
        f"{delay_str:<7} {dl_speed_str:<9} {ul_speed_str:<9} {geo_str:<8} "
        f"{display_config}{reason_str}"
    )


if __name__ == "__main__":
    if tqdm is None:
        tqdm_progress = fallback_tqdm
    else:
        tqdm_progress = tqdm

    try: CACHE_DIR.mkdir(parents=True, exist_ok=True)
    except Exception as e: print(f"Warning: Could not create cache directory '{CACHE_DIR}': {e}", file=sys.stderr)

    main()
