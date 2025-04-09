#!/usr/bin/env python3
import argparse
import base64
import concurrent.futures
import socket
import asyncio # Keep asyncio import, now used for UDP tests and async workers
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
    print("Warning: 'ipaddress' module not found. IPv6/IP validation might be limited.", file=sys.stderr)

try:
    from tqdm import tqdm
except ImportError:
    tqdm = None
    print("Warning: 'tqdm' module not found. Progress bar will not be displayed.", file=sys.stderr)
    # Simple fallback progress display function if tqdm is not available
    def fallback_tqdm(iterable, total=None, desc=None, **kwargs):
        """Basic fallback progress display if tqdm is unavailable."""
        if total is None:
            try: total = len(iterable)
            except TypeError: total = '?'
        current = 0
        start_time = time.monotonic()
        if desc: print(f"{desc}: ", file=sys.stderr, end='')
        last_update_time = start_time

        for item in iterable:
            yield item
            current += 1
            now = time.monotonic()
            if now - last_update_time > 1.0 or current % 10 == 0 or current == total:
                percentage = (current / total * 100) if isinstance(total, (int, float)) and total > 0 else 0
                elapsed = now - start_time
                eta_str = '?'
                eta_total = total if isinstance(total, (int, float)) else 0
                if percentage > 0 and eta_total > 0:
                    try:
                        eta = (elapsed / percentage) * (100 - percentage)
                        if eta >= 0: eta_str = str(timedelta(seconds=int(eta)))
                    except (ZeroDivisionError, OverflowError, TypeError): eta_str = '?'
                print(f"\r{desc or ''}: [{percentage:3.0f}%] {current}/{total} | Elapsed: {timedelta(seconds=int(elapsed))}, ETA: {eta_str}   ", file=sys.stderr, end='')
                last_update_time = now
        print(file=sys.stderr) # Newline at the end

    # Use the fallback if tqdm is missing
    if tqdm is None: tqdm_progress = fallback_tqdm
    else: tqdm_progress = tqdm

try:
    import geoip2.database
    import geoip2.errors
except ImportError:
    geoip2 = None
    # Warning is conditional based on --geoip-db argument later

try:
    from dotenv import load_dotenv
    load_dotenv() # Load environment variables from .env file if it exists
    # print("Info: Loaded environment variables from .env file (if found).", file=sys.stderr)
except ImportError:
    pass # dotenv is optional

# Suppress only the InsecureRequestWarning from urllib3 needed during fetching
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- Constants ---
# Country Code to Flag Emoji Mapping (Abbreviated for brevity)
COUNTRY_FLAGS = { # Keep your full list here
    "US": "🇺🇸", "DE": "🇩🇪", "NL": "🇳🇱", "GB": "🇬🇧", "FR": "🇫🇷", "CA": "🇨🇦", "JP": "🇯🇵", "SG": "🇸🇬",
    "HK": "🇭🇰", "AU": "🇦🇺", "CH": "🇨🇭", "SE": "🇸🇪", "FI": "🇫🇮", "NO": "🇳🇴", "IE": "🇮🇪", "IT": "🇮🇹",
    "ES": "🇪🇸", "PL": "🇵🇱", "RO": "🇷🇴", "TR": "🇹🇷", "RU": "🇷🇺", "UA": "🇺🇦", "IR": "🇮🇷", "AE": "🇦🇪",
    # Add more as needed or paste your full list back
}
DEFAULT_FLAG = "🏁"

# Default Settings
DEFAULT_TEST_URL = "https://cloudflare.com/cdn-cgi/trace"
DEFAULT_TEST_METHOD = "GET"
DEFAULT_BEST_CONFIGS_LIMIT = 100
DEFAULT_FETCH_TIMEOUT = 25 # Slightly increased fetch timeout
DEFAULT_XRAY_KNIFE_TIMEOUT_MS = 8000
DEFAULT_UDP_TIMEOUT_S = 5.0 # Make float explicit
PYTHON_SUBPROCESS_TIMEOUT_BUFFER_S = 15.0 # Make float explicit
DEFAULT_SPEEDTEST_AMOUNT_KB = 10000
DEFAULT_THREADS = min(32, (os.cpu_count() or 1) * 2 + 4) # Ensure os.cpu_count() returns at least 1
CACHE_DIR = Path(".proxy_cache")
CACHE_TTL_HOURS = 6
DEFAULT_DNS_TIMEOUT_S = 5.0 # Make float explicit

# Iran Specific Test Settings
IRAN_TEST_TARGETS = [
    "https://www.irancell.ir/", "https://mci.ir/", "https://www.digikala.com/",
    "https://www.shaparak.ir/", "https://rubika.ir/", "http://www.irib.ir/",
    "https://www.snapp.ir/", "https://www.bmi.ir/", "https://www.divar.ir/"
]
IRAN_TEST_COUNT = 3
IRAN_TEST_TIMEOUT_S = 5.0 # Make float explicit
IRAN_TEST_SUCCESS_THRESHOLD = 0.60 # More explicit float

# IP/ASN Check Settings
IP_CHECK_URLS = [
    "http://ip-api.com/json/?fields=status,message,query,countryCode,isp,org,as,asname",
    "https://api.ipify.org?format=json",
    "https://ipinfo.io/json",
    "http://icanhazip.com", # Plain text fallback
    "https://api.myip.com",
]
IP_CHECK_TIMEOUT_S = 7.0 # Make float explicit
CDN_ORGANIZATIONS = {"cloudflare", "akamai", "fastly", "google cloud", "amazon", "google", "microsoft azure", "azure", "level3"}
CDN_ASNS = {"AS13335", "AS15169", "AS16509", "AS20940"} # Example ASNs

# --- Global State ---
total_outbounds_count = 0
completed_outbounds_count = 0
is_ctrl_c_pressed = False
found_xray_knife_path: Optional[str] = None
geoip_reader: Optional['geoip2.database.Reader'] = None
args: Optional[argparse.Namespace] = None

# --- Dataclass for Test Results ---
@dataclass
class TestResult:
    original_config: str
    source: Optional[str] = None
    status: str = "pending" # pending, dns-failed, passed, failed, timeout, broken, skipped, semi-passed
    reason: Optional[str] = None
    # Basic Results
    real_delay_ms: float = float('inf')
    download_speed_mbps: float = 0.0
    upload_speed_mbps: float = 0.0
    # Geo/IP
    ip: Optional[str] = None
    location: Optional[str] = None
    flag: Optional[str] = None
    # Enhanced Checks
    cdn_check_ip: Optional[str] = None
    cdn_check_org: Optional[str] = None
    cdn_check_asn: Optional[str] = None
    is_cdn_ip: Optional[bool] = None
    iran_access_targets_tested: int = 0
    iran_access_targets_passed: int = 0
    iran_access_passed: Optional[bool] = None
    iran_test_http_version: Optional[str] = None
    tls_fingerprint_type: Optional[str] = None
    # Config & Score
    protocol: Optional[str] = None
    dedup_key_details: Dict[str, Any] = field(default_factory=dict)
    resilience_score: float = 1.0
    combined_score: float = float('inf')

# --- Utility Functions ---

def signal_handler(sig, frame):
    """Handles Ctrl+C interruption."""
    global is_ctrl_c_pressed
    if not is_ctrl_c_pressed:
        print("\nCtrl+C detected. Signaling workers to stop...", file=sys.stderr)
        is_ctrl_c_pressed = True
    else:
        print("\nCtrl+C pressed again. Forcing exit...", file=sys.stderr)
        sys.exit(1)

def find_xray_knife(provided_path: Optional[str]) -> Optional[str]:
    """Finds the xray-knife executable."""
    global found_xray_knife_path # Use global state to cache result
    if found_xray_knife_path: return found_xray_knife_path

    paths_to_check = []
    env_path = os.environ.get("XRAY_KNIFE_PATH")
    if provided_path: paths_to_check.append(Path(provided_path))
    if env_path: paths_to_check.append(Path(env_path))
    executable_name = "xray-knife" + (".exe" if sys.platform == "win32" else "")
    path_env = os.environ.get("PATH", "").split(os.pathsep)
    for p_dir in path_env: paths_to_check.append(Path(p_dir) / executable_name)
    script_dir = Path(__file__).parent.resolve()
    paths_to_check.extend([script_dir/executable_name, script_dir/"bin"/executable_name, Path(".") / executable_name])

    for p in paths_to_check:
        try:
            abs_path = p.resolve()
            if abs_path.is_file() and os.access(str(abs_path), os.X_OK):
                found_xray_knife_path = str(abs_path)
                return found_xray_knife_path
        except Exception: continue
    found_in_which = shutil.which(executable_name)
    if found_in_which: found_xray_knife_path = found_in_which
    return found_xray_knife_path

def get_cache_path(url: str) -> Path:
    """Generates a cache file path based on URL hash."""
    url_hash = hashlib.sha256(url.encode('utf-8')).hexdigest()
    return CACHE_DIR / f"{url_hash}.cache"

def load_from_cache(url: str, ttl_hours: int = CACHE_TTL_HOURS) -> Optional[str]:
    """Loads content from cache if valid."""
    if not CACHE_DIR.exists(): return None
    cache_file = get_cache_path(url)
    if not cache_file.is_file(): return None
    try:
        file_mod_time = datetime.fromtimestamp(cache_file.stat().st_mtime)
        if datetime.now() - file_mod_time > timedelta(hours=ttl_hours):
             if args and args.verbose > 1: print(f"Debug: Cache expired for {url}", file=sys.stderr)
             cache_file.unlink() # Remove expired cache file
             return None
        return cache_file.read_text('utf-8')
    except Exception as e:
        print(f"Warning: Could not read cache file {cache_file}: {e}", file=sys.stderr)
        return None

def save_to_cache(url: str, content: str):
    """Saves content to the cache."""
    if not content: return
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        get_cache_path(url).write_text(content, 'utf-8')
    except Exception as e:
        print(f"Warning: Could not write cache file for {url}: {e}", file=sys.stderr)

def try_parse_ip(address: str) -> bool:
    """Helper to check if a string is likely an IP address using ipaddress module."""
    if not ipaddress or not address: return False
    try: ipaddress.ip_address(address); return True
    except ValueError: return False

def get_server_port_basic(config_line: str) -> Tuple[Optional[str], Optional[int]]:
    """Extracts server hostname and port using basic urlparse. Good for WG/WARP/DNS."""
    try:
        parsed_url = urllib.parse.urlparse(config_line)
        hostname = parsed_url.hostname
        port = parsed_url.port
        if hostname and hostname.startswith('[') and hostname.endswith(']'): hostname = hostname[1:-1]
        if not hostname or not isinstance(port, int) or not (0 < port < 65536): return None, None
        return hostname, port
    except Exception: return None, None

def format_val(val, precision=None) -> str:
    """Safely formats values for CSV/JSON output."""
    if val is None: return ''
    if isinstance(val, bool): return str(val)
    if isinstance(val, float):
        if val == float('inf') or val == float('-inf') or val != val: return '' # Handle inf/nan
        return f"{val:.{precision}f}" if precision is not None else str(val)
    return str(val).replace('\n', ' ').replace('\r', '') # Remove newlines

# --- Core Logic Functions ---

def fetch_content(url: str, proxy: Optional[str] = None, timeout: int = DEFAULT_FETCH_TIMEOUT, force_fetch: bool = False) -> Optional[str]:
    """Fetches content from a URL, using cache if enabled."""
    global args
    if not force_fetch:
        cached_content = load_from_cache(url, args.cache_ttl if args else CACHE_TTL_HOURS)
        if cached_content is not None: return cached_content

    session = requests.Session()
    proxies = {"http": proxy, "https": proxy} if proxy else None
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0"}
    try:
        response = session.get(url, timeout=timeout, proxies=proxies, verify=False, headers=headers, allow_redirects=True)
        response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
        response.encoding = response.apparent_encoding or 'utf-8'
        content = response.text
        if content: save_to_cache(url, content) # Only cache non-empty content
        return content
    except requests.exceptions.Timeout: print(f"Error fetching {url}: Timeout ({timeout}s)", file=sys.stderr)
    except requests.exceptions.ProxyError as e: print(f"Error fetching {url}: Proxy Error - {e}", file=sys.stderr)
    except requests.exceptions.SSLError as e: print(f"Error fetching {url}: SSL Error - {e}", file=sys.stderr)
    except requests.exceptions.ConnectionError as e:
         if "NameResolutionError" in str(e) or "nodename nor servname provided" in str(e).lower() or "name or service not known" in str(e).lower():
              print(f"Error fetching {url}: DNS resolution failed", file=sys.stderr)
         else: print(f"Error fetching {url}: Connection Error - {e}", file=sys.stderr)
    except requests.exceptions.HTTPError as e: # Catch 4xx/5xx errors
         print(f"Error fetching {url}: HTTP {e.response.status_code} {e.response.reason}", file=sys.stderr)
    except requests.exceptions.RequestException as e: print(f"Error fetching {url}: {type(e).__name__} - {e}", file=sys.stderr)
    except Exception as e:
        print(f"Unexpected error fetching {url}: {type(e).__name__} - {e}", file=sys.stderr)
        if args and args.verbose > 1: traceback.print_exc(file=sys.stderr)
    return None

def parse_config_content(content: str, source_url: str) -> List[TestResult]:
    """Parses subscription content (plaintext or base64) into TestResult objects."""
    global args
    outbounds = []
    if not content: return outbounds

    try:
        # --- Base64 Detection ---
        decoded_content = content; is_base64 = False
        try:
            content_no_space = ''.join(content.split())
            padding = len(content_no_space) % 4
            if padding: content_no_space += '=' * (4 - padding)
            if re.fullmatch(r'^[A-Za-z0-9+/=\s]*$', content) and len(content_no_space) % 4 == 0 and len(content_no_space) > 20:
                 potential_decoded = base64.b64decode(content_no_space, validate=True).decode('utf-8', errors='ignore')
                 if any(proto in potential_decoded for proto in ["vless://", "vmess://", "trojan://", "ss://"]) or '\n' in potential_decoded:
                      decoded_content = potential_decoded; is_base64 = True
                 elif '://' in base64.b64decode(content_no_space, validate=True).decode('latin-1', errors='ignore'):
                      decoded_content = base64.b64decode(content_no_space, validate=True).decode('latin-1', errors='ignore'); is_base64 = True
        except Exception: pass # Ignore decoding errors, assume plaintext

        # --- Line-by-line Parsing ---
        supported_prefixes = ("vless://","vmess://","ss://","ssr://","trojan://","tuic://","hysteria://","hysteria2://","hy2://","wg://","wireguard://","warp://","socks://","http://","https://")
        seen_configs_this_source = set()

        for line_num, line in enumerate(decoded_content.splitlines()):
            line = line.strip()
            if not line or line.startswith(("#", "//", ";")): continue
            matched_prefix = next((p for p in supported_prefixes if line.lower().startswith(p)), None)
            if matched_prefix:
                protocol = matched_prefix.split("://", 1)[0].lower()
                if protocol in ["wireguard", "warp", "wg"]: protocol = "wg"
                elif protocol in ["hysteria2", "hy2"]: protocol = "hysteria"
                if line not in seen_configs_this_source:
                    outbounds.append(TestResult(original_config=line, source=source_url, protocol=protocol))
                    seen_configs_this_source.add(line)
            elif is_base64 and args and args.verbose > 1: # Warn about non-proxy lines only if input was base64
                 print(f"Debug: Non-proxy line in decoded base64 content? {line[:60]}...", file=sys.stderr)

    except Exception as e:
        print(f"Error processing content from {source_url}: {type(e).__name__} - {e}", file=sys.stderr)
        if args and args.verbose > 1: traceback.print_exc(file=sys.stderr)
    return outbounds

def extract_config_details_for_dedup(config_line: str) -> Dict[str, Any]:
    """Extracts detailed config parameters. Ensures hashable values."""
    global args
    details = { "protocol": None, "address": None, "port": None, "host": None, "path": None,
                "net": None, "tls": None, "fp": None, "type": None, "plugin": None, }
    try:
        parsed_url = urllib.parse.urlparse(config_line); scheme = parsed_url.scheme.lower()
        details["protocol"] = {"wireguard":"wg","warp":"wg","wg":"wg","hysteria2":"hysteria","hy2":"hysteria"}.get(scheme, scheme)
        details["address"] = parsed_url.hostname
        details["port"] = parsed_url.port
        if details["address"] and details["address"].startswith('[') and details["address"].endswith(']'): details["address"] = details["address"][1:-1]
        query_params = urllib.parse.parse_qs(parsed_url.query)
        def get_param(keys: List[str], default: Any=None) -> Optional[str]:
            for key in keys:
                v = query_params.get(key)
                if v and v[0]: return v[0]
            return default
        details["host"] = get_param(["sni", "host"]); details["path"] = get_param(["path"]); details["net"] = get_param(["type", "network", "net"])
        details["tls"] = get_param(["security", "tls"]); details["fp"] = get_param(["fp"])

        if scheme == "vmess":
            try:
                b64 = config_line[len("vmess://"):].split("#")[0].strip().replace('-', '+').replace('_', '/')
                if len(b64)%4 != 0: b64 += '='*(4 - len(b64)%4)
                data = json.loads(base64.b64decode(b64).decode('utf-8', errors='ignore'))
                details["address"]=data.get("add", details["address"]); port_str=str(data.get("port", str(details["port"]) if details["port"] else None))
                details["port"]=int(port_str) if port_str and port_str.isdigit() else details["port"]; details["host"]=data.get("sni", data.get("host", details["host"]))
                details["path"]=data.get("path", details["path"]); details["net"]=data.get("net", details["net"]); details["tls"]=data.get("tls", details["tls"]); details["type"]=data.get("type", details["type"])
            except Exception as e: pass # Ignore VMess JSON errors, keep URL params

        elif scheme == "ss":
             at_parts=parsed_url.netloc.split('@'); hp_part=(at_parts[-1] if len(at_parts)>1 else parsed_url.netloc).split('#')[0]
             if ':' in hp_part:
                  host, port_s = hp_part.rsplit(':', 1)
                  if port_s.isdigit() and host and not re.match(r'^[a-zA-Z0-9+/=]+:[a-zA-Z0-9+/=]+$', host): details["address"]=host; details["port"]=int(port_s)
             plugin=get_param(["plugin"]); details["plugin"]=plugin
             if plugin:
                 if "v2ray-plugin" in plugin or "obfs-local" in plugin:
                     if "tls" in plugin: details["tls"]="tls";
                     if "mode=websocket" in plugin: details["net"]="ws"
                     if "obfs=http" in plugin: details["net"]="http-obfs"
                     try:
                         params=dict(i.split("=", 1) for i in plugin.split(";") if "=" in i)
                         details["host"]=params.get("host", details["host"]); details["path"]=params.get("path", details["path"])
                     except ValueError: pass

        elif scheme in ["vless", "trojan"]:
             details["net"]=get_param(["type", "network", "net"], details.get("net")); details["tls"]=get_param(["security"], details.get("tls"))
             details["host"]=get_param(["sni"], details.get("host")); details["fp"]=get_param(["fp"], details.get("fp"))
             details["path"]=get_param(["serviceName" if details["net"] == "grpc" else "path"], details.get("path"))

        # Post-processing & Normalization
        if not details["net"] and details["protocol"] in ["vless","vmess","trojan","ss","socks","http"]: details["net"]="tcp"
        if details["tls"] in ["", "none"]: details["tls"]=None
        if not details["tls"] and details["port"]==443 and details["protocol"] in ["vless","vmess","trojan"]: details["tls"]="tls"
        # Validation
        if not details["address"] or not isinstance(details["port"], int) or not (0<details["port"]<65536): return {}
        # Normalize IPv6
        addr=details["address"];
        if ipaddress and addr and ':' in addr:
             try: details["address"] = ipaddress.ip_address(addr).compressed
             except ValueError: pass
        if not details["host"]: details["host"] = details["address"]
        # Final cleanup for hashability
        final_details = {}
        for k, v in details.items():
            if isinstance(v, (str, int, type(None), bool)): final_details[k] = v if v != "" else None
            else:
                try: final_details[k] = str(v) if v is not None else None
                except: final_details[k] = None # Fallback
        return final_details
    except Exception as e:
        if args and args.verbose > 1: print(f"Debug: Detail extraction failed: {e}\n{traceback.format_exc()}", file=sys.stderr)
        return {}

def get_dedup_key(config_result: TestResult) -> Optional[tuple]:
    """Generates a hashable key for deduplication."""
    details = extract_config_details_for_dedup(config_result.original_config)
    config_result.dedup_key_details = details
    proto, addr, port = details.get("protocol"), details.get("address"), details.get("port")
    if not proto or not addr or port is None: return None
    key_parts: List[Any] = [proto, addr, port]
    if proto in ["vless","vmess","trojan","tuic","hysteria","ss"]:
        key_parts.extend([details.get(k) for k in ["net","tls","host","path","fp"]])
        if proto == "ss": key_parts.append(details.get("plugin"))
    try: hash(tuple(key_parts)); return tuple(key_parts)
    except TypeError as e:
         if args and args.verbose: print(f"Error: Dedup key generation failed - unhashable element in {key_parts}: {e}", file=sys.stderr)
         return None

def deduplicate_outbounds(outbounds: List[TestResult]) -> List[TestResult]:
    """Removes duplicate configurations."""
    dedup_dict: Dict[tuple, TestResult] = {}; skipped=0; processed=0; duplicates=0
    print("Starting deduplication...", file=sys.stderr)
    for res in outbounds:
        processed += 1; key = get_dedup_key(res)
        if key is None: skipped += 1; continue
        if key not in dedup_dict: dedup_dict[key] = res
        else: duplicates +=1
    kept=len(dedup_dict)
    print(f"Deduplication: Processed {processed}. Kept {kept} unique. Removed {duplicates} duplicates. Skipped {skipped}.", file=sys.stderr)
    return list(dedup_dict.values())

def get_geoip_location(ip_address: str, reader: Optional['geoip2.database.Reader']) -> Optional[str]:
    """Looks up country code using GeoIP DB."""
    if not reader or not ip_address or not geoip2: return None
    try: return reader.country(ip_address.strip("[]")).country.iso_code
    except (geoip2.errors.AddressNotFoundError, ValueError, TypeError, Exception): return None

# --- Regex Patterns ---
REAL_DELAY_PATTERN = re.compile(r"(?:Real Delay|Latency):\s*(\d+)\s*ms", re.IGNORECASE)
DOWNLOAD_SPEED_PATTERN = re.compile(r"Downloaded\s*[\d.]+\s*[MKG]?B\s*-\s*Speed:\s*([\d.]+)\s*([mk]?)bps", re.IGNORECASE)
UPLOAD_SPEED_PATTERN = re.compile(r"Uploaded\s*[\d.]+\s*[MKG]?B\s*-\s*Speed:\s*([\d.]+)\s*([mk]?)bps", re.IGNORECASE)
IP_INFO_PATTERN = re.compile(r"\bip=(?P<ip>[\d\.a-fA-F:]+)\b(?:.*?\bloc=(?P<loc>[A-Z]{2})\b)?", re.IGNORECASE | re.DOTALL)
XRAY_KNIFE_FAIL_REASON_PATTERN = re.compile(r"\[-\].*?(?:failed|error|timeout)[:\s]+(.*)", re.IGNORECASE)
CONTEXT_DEADLINE_PATTERN = re.compile(r"context deadline exceeded", re.IGNORECASE)
IO_TIMEOUT_PATTERN = re.compile(r"i/o timeout", re.IGNORECASE)
CONNECTION_REFUSED_PATTERN = re.compile(r"connection refused", re.IGNORECASE)
DNS_ERROR_PATTERN = re.compile(r"(?:no such host|dns query failed|could not resolve host|name resolution failed)", re.IGNORECASE)
HANDSHAKE_ERROR_PATTERN = re.compile(r"(?:handshake failed|tls handshake error|ssl handshake)", re.IGNORECASE)
HTTP_VERSION_PATTERN = re.compile(r"\bHTTP/(?P<version>[1-3](?:\.[01])?)\b", re.IGNORECASE) # Improved boundary
IP_API_JSON_PATTERN = re.compile(r'"query"\s*:\s*"(?P<ip>[\d\.a-fA-F:]+)"(?:.*?"isp"\s*:\s*"(?P<isp>[^"]*)")?(?:.*?"org"\s*:\s*"(?P<org>[^"]*)")?(?:.*?"as"\s*:\s*"(?P<as>[^"]*)")?', re.IGNORECASE | re.DOTALL)
IPIFY_JSON_PATTERN = re.compile(r'"ip"\s*:\s*"(?P<ip>[\d\.a-fA-F:]+)"', re.IGNORECASE | re.DOTALL)
IPINFO_JSON_PATTERN = re.compile(r'"ip"\s*:\s*"(?P<ip>[\d\.a-fA-F:]+)"(?:.*?"org"\s*:\s*"(?P<org>[^"]*)")?(?:.*?"asn"\s*:\s*{\s*"asn"\s*:\s*"(?P<asn>[A-Z0-9]+)"[^}]*})?', re.IGNORECASE | re.DOTALL) # ASN format more specific
MYIP_JSON_PATTERN = re.compile(r'"ip"\s*:\s*"(?P<ip>[\d\.a-fA-F:]+)".*?"country"\s*:\s*"(?P<country>[^"]*)".*?(?:"cc"\s*:\s*"(?P<cc>[A-Z]{2})")?', re.IGNORECASE | re.DOTALL)
ICANHAZIP_PATTERN = re.compile(r"^([\d\.a-fA-F:]+)$")

# --- Testing Functions ---

async def preliminary_dns_check(hostname: str, port: int, timeout: float = DEFAULT_DNS_TIMEOUT_S) -> bool:
    """Performs a non-blocking DNS lookup."""
    global args # Access global args for verbose logging
    # Skip check if it looks like an IP address or is localhost
    if not hostname or hostname == 'localhost' or try_parse_ip(hostname): return True
    try:
        loop = asyncio.get_running_loop()
        await asyncio.wait_for(loop.getaddrinfo(hostname, port, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM), timeout=timeout)
        if args and args.verbose > 1: print(f"      DNS Check OK: {hostname}", file=sys.stderr)
        return True
    except asyncio.TimeoutError:
        if args and args.verbose: print(f"    DNS Check Timeout: {hostname}", file=sys.stderr)
    except socket.gaierror as e:
        if args and args.verbose: print(f"    DNS Check Failed: {hostname} ({e})", file=sys.stderr)
    except Exception as e:
        if args and args.verbose: print(f"    DNS Check Error: {hostname} ({type(e).__name__}: {e})", file=sys.stderr)
    return False

async def _test_wg_udp_async(result_obj: TestResult, args: argparse.Namespace) -> TestResult:
    """Async core logic for UDP test (WireGuard/WARP)."""
    global is_ctrl_c_pressed, geoip_reader
    # Reset results
    result_obj.status="pending"; result_obj.reason=None; result_obj.real_delay_ms=float('inf'); result_obj.combined_score=float('inf')
    result_obj.download_speed_mbps=0.0; result_obj.upload_speed_mbps=0.0; result_obj.ip=None; result_obj.location=None; result_obj.flag=None
    result_obj.cdn_check_ip=None; result_obj.cdn_check_org=None; result_obj.cdn_check_asn=None; result_obj.is_cdn_ip=None
    result_obj.iran_access_passed=None; result_obj.iran_test_http_version=None; result_obj.tls_fingerprint_type=None; result_obj.resilience_score=1.0

    if is_ctrl_c_pressed: result_obj.status="skipped"; result_obj.reason="Interrupted"; return result_obj
    server, port = get_server_port_basic(result_obj.original_config)
    if not server or not port: result_obj.status="broken"; result_obj.reason="No server/port"; return result_obj

    # Use pre-resolved IP if available from DNS check, otherwise resolve again
    resolved_ip = result_obj.dedup_key_details.get("resolved_ip")
    family = socket.AF_INET if resolved_ip and '.' in resolved_ip else socket.AF_INET6 if resolved_ip else socket.AF_UNSPEC
    if not resolved_ip:
        try:
            loop=asyncio.get_running_loop();
            addr_info = await asyncio.wait_for(loop.getaddrinfo(server, port, type=socket.SOCK_DGRAM), timeout=args.udp_timeout)
            chosen_info = next((i for i in addr_info if i[0]==socket.AF_INET), addr_info[0])
            resolved_ip = chosen_info[4][0]; family = chosen_info[0]
            result_obj.dedup_key_details["resolved_ip"] = resolved_ip # Store resolved IP
        except (socket.gaierror, asyncio.TimeoutError, IndexError) as e:
            result_obj.status="dns-failed"; result_obj.reason=f"DNS lookup error: {e}"; return result_obj
        except Exception as e: result_obj.status="broken"; result_obj.reason=f"DNS unexpected error: {e}"; return result_obj

    # GeoIP Lookup
    if geoip_reader and resolved_ip:
        db_location = get_geoip_location(resolved_ip, geoip_reader)
        if db_location: result_obj.location=db_location; result_obj.flag=COUNTRY_FLAGS.get(db_location.upper(), DEFAULT_FLAG)
        result_obj.ip = resolved_ip

    # UDP Connection Test
    transport = None; start_time = 0
    try:
        loop=asyncio.get_running_loop(); start_time=loop.time()
        conn_future = loop.create_datagram_endpoint(lambda: asyncio.DatagramProtocol(), remote_addr=(resolved_ip, port), family=family)
        transport, _ = await asyncio.wait_for(conn_future, timeout=args.udp_timeout)
        transport.sendto(b'\x00'); await asyncio.sleep(0.05)
        delay = (loop.time() - start_time) * 1000
        result_obj.real_delay_ms = max(1.0, delay); result_obj.status="passed"; result_obj.reason="UDP connection OK"
    except asyncio.TimeoutError: result_obj.status="timeout"; result_obj.reason=f"UDP timeout ({args.udp_timeout:.1f}s)"
    except OSError as e: result_obj.status="failed"; result_obj.reason=f"OS error: {e.strerror}"
    except Exception as e: result_obj.status="broken"; result_obj.reason=f"UDP test error: {e}"
    finally:
        if transport: try: transport.close() catch Exception: pass

    # Score Calculation
    if result_obj.status == "passed":
        normalized_delay = min(result_obj.real_delay_ms / 1000.0, 1.0) # Normalize against 1 sec
        result_obj.resilience_score = 0.75 # WG is generally resilient
        result_obj.combined_score = normalized_delay * result_obj.resilience_score
        if args.speedtest: result_obj.status="semi-passed"; result_obj.reason="Passed UDP, speed N/A"
    else: result_obj.combined_score = float('inf')
    return result_obj

def test_wg_udp_sync(result_obj: TestResult, args: argparse.Namespace) -> TestResult:
    """Synchronous wrapper for the async UDP test."""
    try:
        try: loop = asyncio.get_running_loop()
        except RuntimeError: loop = None
        if loop and loop.is_running():
            print(f"Warning: UDP test cannot run nested in running event loop: {result_obj.original_config[:50]}", file=sys.stderr)
            result_obj.status="broken"; result_obj.reason="Async loop conflict"; return result_obj
        else: return asyncio.run(_test_wg_udp_async(result_obj, args))
    except Exception as e:
        print(f"Critical error in test_wg_udp_sync: {e}", file=sys.stderr)
        if args and args.verbose > 1: traceback.print_exc(file=sys.stderr)
        result_obj.status="broken"; result_obj.reason=f"Sync wrapper error: {e}"; return result_obj

def run_xray_knife_curl(
    config_link: str, target_url: str, method: str = "GET", timeout_ms: int = 5000,
    xray_knife_path: str = None, args: argparse.Namespace = None, verbose_level: int = 0,
    extra_headers: Optional[List[str]] = None
) -> Tuple[bool, str, str]:
    """Runs xray-knife net curl. Returns (success_bool, stdout, stderr)."""
    global is_ctrl_c_pressed
    if is_ctrl_c_pressed or not xray_knife_path: return False, "", "Skipped/NoKnife"

    command = [xray_knife_path, "net", "curl", "-s", "-c", config_link, "-url", target_url,
               "-m", str(timeout_ms), "-X", method.upper(), "-z", args.xray_knife_core if args else "auto", "-v"]
    if args and args.xray_knife_insecure: command.append("-e")
    if extra_headers: command.extend([f"-H \"{h}\"" for h in extra_headers]) # Quote headers

    python_timeout = (timeout_ms / 1000.0) + max(5.0, PYTHON_SUBPROCESS_TIMEOUT_BUFFER_S / 2)
    if verbose_level > 1: print(f"        Running curl: {' '.join(command)}", file=sys.stderr)

    try:
        process = subprocess.run(command, capture_output=True, text=True, encoding='utf-8', errors='replace',
                                 timeout=python_timeout, check=False, env=os.environ.copy())
        # More robust success check: RC 0 and no critical failure patterns in stderr
        stderr_lower = process.stderr.lower()
        critical_errors = ["timeout", "refused", "deadline", "resolve host", "handshake failed", "ssl"]
        success = process.returncode == 0 and not any(err in stderr_lower for err in critical_errors)

        if verbose_level > 1 and not success: print(f"        Curl failed (RC={process.returncode}): {process.stderr[:150].replace(chr(10),' ')}...", file=sys.stderr)
        elif verbose_level > 2 and success: print(f"        Curl OK (RC=0): {process.stderr[:150].replace(chr(10),' ')}...", file=sys.stderr)
        return success, process.stdout, process.stderr
    except subprocess.TimeoutExpired:
        if verbose_level > 0: print(f"      Curl timed out (> {python_timeout:.1f}s): {target_url}", file=sys.stderr)
        return False, "", f"Timeout {python_timeout:.1f}s"
    except Exception as e:
        if verbose_level > 0: print(f"      Curl error on {target_url}: {type(e).__name__}", file=sys.stderr)
        return False, "", f"Curl Subprocess error: {type(e).__name__}"

def perform_cdn_check(result_obj: TestResult, xray_knife_path: str, args: argparse.Namespace):
    """Performs IP/ASN/Org check using non-CDN URL. Updates result_obj."""
    # global is_ctrl_c_pressed, args <-- REMOVED 'args' from global
    global is_ctrl_c_pressed # <-- CORRECTED
    if is_ctrl_c_pressed: return
    if args.verbose > 0: print(f"    Performing CDN/ASN check...", file=sys.stderr)

    check_url = random.choice(IP_CHECK_URLS)
    headers = ["Accept: application/json"] if any(s in check_url for s in ["ipinfo.io", "ip-api.com", "api.myip.com"]) else None
    success, stdout, stderr = run_xray_knife_curl(result_obj.original_config, check_url, method="GET",
        timeout_ms=int(IP_CHECK_TIMEOUT_S * 1000), xray_knife_path=xray_knife_path, args=args,
        verbose_level=args.verbose, extra_headers=headers)

    ip, org, asn = None, None, None
    output = stdout if success and stdout else stderr # Parse stderr if stdout empty
    if success and output:
        try:
            if "ip-api.com" in check_url: match = IP_API_JSON_PATTERN.search(output); ip, org, asn_part = (match.group("ip"), match.group("org") or match.group("isp"), match.group("as")) if match else (None,)*3; asn = asn_part.split(" ")[0] if asn_part else None
            elif "ipinfo.io" in check_url: match = IPINFO_JSON_PATTERN.search(output); ip, org, asn = (match.group("ip"), match.group("org"), match.group("asn")) if match else (None,)*3
            elif "ipify.org" in check_url: match = IPIFY_JSON_PATTERN.search(output); ip = match.group("ip") if match else None
            elif "api.myip.com" in check_url: match = MYIP_JSON_PATTERN.search(output); ip = match.group("ip") if match else None
            elif "icanhazip.com" in check_url: match = ICANHAZIP_PATTERN.search(output.strip()); ip = match.group(1) if match else None
            # Generic JSON fallback
            if not ip and '{' in output and '}' in output:
                try:
                    data=json.loads(output); ip=data.get("ip") or data.get("query"); org=data.get("org") or data.get("isp"); asn_data=data.get("asn")
                    if isinstance(asn_data, dict): asn=asn_data.get("asn")
                    elif isinstance(asn_data, str): asn=asn_data.split(" ")[0]
                    if not asn and org and org.startswith("AS"): asn=org.split(" ")[0]
                except json.JSONDecodeError: pass
        except Exception as e:
            if args.verbose > 1: print(f"      CDN Check: Error parsing output: {e}", file=sys.stderr)

    if ip:
        result_obj.cdn_check_ip = ip.strip(); result_obj.cdn_check_org = org.strip() if org else None; result_obj.cdn_check_asn = asn.strip() if asn else None
        org_lower = result_obj.cdn_check_org.lower() if result_obj.cdn_check_org else ""
        result_obj.is_cdn_ip = any(cdn in org_lower for cdn in CDN_ORGANIZATIONS) or (result_obj.cdn_check_asn in CDN_ASNS)
        if args.verbose > 0: print(f"      CDN OK: IP={ip}, Org={org}, ASN={asn}, IsCDN={result_obj.is_cdn_ip}", file=sys.stderr)
    else:
        result_obj.is_cdn_ip = None
        if args.verbose > 0: print(f"      CDN Check Failed or No IP.", file=sys.stderr)

def perform_iran_access_test(result_obj: TestResult, xray_knife_path: str, args: argparse.Namespace):
    """Tests connectivity to Iranian targets, updates result_obj, checks HTTP version."""
    # global is_ctrl_c_pressed, args <-- REMOVED 'args' from global
    global is_ctrl_c_pressed # <-- CORRECTED
    if is_ctrl_c_pressed or not IRAN_TEST_TARGETS: return

    targets = random.sample(IRAN_TEST_TARGETS, min(len(IRAN_TEST_TARGETS), IRAN_TEST_COUNT))
    passed = 0; tested = len(targets); max_http_v = 0.0
    result_obj.iran_access_targets_tested = tested
    if args.verbose > 0: print(f"    Performing Iran access test ({tested} targets)...", file=sys.stderr)

    for target in targets:
        if is_ctrl_c_pressed: break
        success, _, stderr = run_xray_knife_curl(result_obj.original_config, target, method="HEAD",
            timeout_ms=int(IRAN_TEST_TIMEOUT_S * 1000), xray_knife_path=xray_knife_path, args=args, verbose_level=args.verbose)
        if success:
             passed += 1
             match = HTTP_VERSION_PATTERN.search(stderr)
             if match: try: max_http_v = max(max_http_v, float(match.group("version"))) except ValueError: pass
             if args.verbose > 1: print(f"      Iran Access OK: {target}", file=sys.stderr)
        elif args.verbose > 1: print(f"      Iran Access Failed: {target}", file=sys.stderr)

    result_obj.iran_access_targets_passed = passed
    if tested > 0: result_obj.iran_access_passed = (passed / tested) >= IRAN_TEST_SUCCESS_THRESHOLD
    else: result_obj.iran_access_passed = None
    if max_http_v > 0: result_obj.iran_test_http_version = f"{max_http_v:.1f}".replace(".0", "")

    if args.verbose > 0: print(f"      Iran Access Result: {passed}/{tested} passed. Pass={result_obj.iran_access_passed}. MaxHTTP={result_obj.iran_test_http_version or 'N/A'}", file=sys.stderr)

def check_tls_fingerprint_params(result_obj: TestResult):
    """Checks config parameters for TLS fingerprint settings."""
    details = result_obj.dedup_key_details; fp=details.get("fp"); tls=details.get("tls"); fp_type="unknown"
    if tls == "reality": fp_type = "reality"
    elif fp:
        fp_l = fp.lower()
        known = {"chrome","firefox","safari","ios","android","edge","random","rand"}
        matched = next((k for k in known if k in fp_l), None)
        fp_type = matched if matched else "custom"
    result_obj.tls_fingerprint_type = fp_type
    if args and args.verbose > 1: print(f"      TLS Fingerprint Check: Type={fp_type}", file=sys.stderr)

def calculate_resilience_score(result_obj: TestResult) -> float:
    """Calculates a score multiplier based on config structure. Lower=better."""
    details = result_obj.dedup_key_details; proto=details.get("protocol"); net=details.get("net"); tls=details.get("tls")
    score = 1.0; proto_scores = {"vless":0.8, "trojan":0.85, "hysteria":0.9, "tuic":0.9, "vmess":1.0, "ss":1.1, "wg":0.75, "socks":1.5, "http":1.5}
    score *= proto_scores.get(proto, 1.2) # Apply base protocol score
    if proto in ["vless", "trojan", "vmess", "ss"]:
        if tls == "reality": score *= 0.7
        elif net == "grpc" and tls == "tls": score *= 0.85
        elif net == "ws" and tls == "tls": score *= 0.9
        elif net == "tcp" and tls == "tls": score *= 0.95
        elif not tls: score *= 1.25 # Penalize lack of encryption
        if proto == "ss": # SS plugin refinement
            plugin = details.get("plugin")
            if plugin and "v2ray-plugin" in plugin and "ws" in plugin and "tls" in plugin: score *= 0.95
            elif plugin and "obfs" in plugin: score *= 1.05
    good_fps = {"reality","chrome","firefox","safari","ios","android","edge"}; random_fp = {"random", "rand"}
    if result_obj.tls_fingerprint_type in good_fps: score *= 0.9
    elif result_obj.tls_fingerprint_type in random_fp: score *= 0.95
    result_obj.resilience_score = round(max(0.1, score), 3)
    if args and args.verbose > 1: print(f"      Resilience Score: {result_obj.resilience_score}", file=sys.stderr)
    return result_obj.resilience_score

def test_config_with_xray_knife(result_obj: TestResult, xray_knife_path: str, args: argparse.Namespace) -> TestResult:
    """Performs comprehensive tests using xray-knife."""
    # global is_ctrl_c_pressed, geoip_reader, args <-- REMOVED 'args' from global
    global is_ctrl_c_pressed, geoip_reader # <-- CORRECTED
    # Reset results
    result_obj.status="pending"; result_obj.reason=None; result_obj.real_delay_ms=float('inf'); result_obj.combined_score=float('inf')
    result_obj.download_speed_mbps=0.0; result_obj.upload_speed_mbps=0.0; result_obj.ip=None; result_obj.location=None; result_obj.flag=None
    result_obj.cdn_check_ip=None; result_obj.cdn_check_org=None; result_obj.cdn_check_asn=None; result_obj.is_cdn_ip=None
    result_obj.iran_access_passed=None; result_obj.iran_access_targets_passed=0; result_obj.iran_access_targets_tested=0; result_obj.iran_test_http_version=None
    result_obj.tls_fingerprint_type=None; result_obj.resilience_score=1.0

    if is_ctrl_c_pressed: result_obj.status="skipped"; result_obj.reason="Interrupted"; return result_obj
    if not xray_knife_path: result_obj.status="broken"; result_obj.reason="xray-knife missing"; return result_obj
    # DNS check already performed in worker

    # --- Initial Connectivity & Speed Test ---
    command = [xray_knife_path, "net", "http", "-v", "-c", result_obj.original_config, "-d", str(args.xray_knife_timeout_ms),
               "--url", args.test_url, "--method", args.test_method, "-z", args.xray_knife_core]
    if args.speedtest:
        command.append("-p"); kb_amount = DEFAULT_SPEEDTEST_AMOUNT_KB
        try:
            amt=str(args.speedtest_amount).lower().strip(); num_part=re.match(r'^([\d.]+)', amt)
            if num_part: num=float(num_part.group(1)); kb_amount = int(num*1024) if 'mb' in amt else int(num) if 'kb' in amt else int(num)
            if kb_amount <= 0: raise ValueError("Amount must be > 0")
        except: kb_amount = DEFAULT_SPEEDTEST_AMOUNT_KB
        command.extend(["-a", str(kb_amount)])
    if args.ip_info: command.append("--rip")
    if args.xray_knife_insecure: command.append("-e")

    python_timeout = (args.xray_knife_timeout_ms / 1000.0) + PYTHON_SUBPROCESS_TIMEOUT_BUFFER_S
    process, out, err = None, "", ""
    try:
        if args.verbose > 0: print(f"  Testing main connectivity...", file=sys.stderr)
        process = subprocess.run(command, capture_output=True, text=True, encoding='utf-8', errors='replace',
                                 timeout=python_timeout, check=False, env=os.environ.copy())
        out, err = process.stdout, process.stderr
    except subprocess.TimeoutExpired: result_obj.status="timeout"; result_obj.reason=f"Main test timeout ({python_timeout:.1f}s)"; return result_obj
    except Exception as e: result_obj.status="broken"; result_obj.reason=f"Subprocess error: {e}"; return result_obj

    # --- Parse Initial Test Output ---
    full = out + "\n" + err
    if m := REAL_DELAY_PATTERN.search(full): try: result_obj.real_delay_ms = float(m.group(1)) except ValueError: pass
    def parse_sp(match): # Speed parsing helper
        if not match: return 0.0
        try: v=float(match.group(1)); u=match.group(2).lower(); return v/1000.0 if u=='k' else v if u=='m' else v/1000000.0
        except: return 0.0
    result_obj.download_speed_mbps=parse_sp(DOWNLOAD_SPEED_PATTERN.search(full))
    result_obj.upload_speed_mbps=parse_sp(UPLOAD_SPEED_PATTERN.search(full))
    if m := IP_INFO_PATTERN.search(out): result_obj.ip, result_obj.location = m.group("ip"), m.group("loc")
    ip_geo = result_obj.ip or result_obj.dedup_key_details.get("resolved_ip")
    if geoip_reader and ip_geo:
        db_loc = get_geoip_location(ip_geo, geoip_reader)
        if db_loc: result_obj.location = db_loc
        if not result_obj.ip: result_obj.ip = ip_geo # Store IP used for lookup
    if result_obj.location: result_obj.flag = COUNTRY_FLAGS.get(result_obj.location.upper(), DEFAULT_FLAG)

    # --- Determine Initial Status ---
    status, reason = "pending", None
    if CONTEXT_DEADLINE_PATTERN.search(full): status, reason = "timeout", f"Timeout > {args.xray_knife_timeout_ms}ms"
    elif IO_TIMEOUT_PATTERN.search(full): status, reason = "timeout", "I/O timeout"
    elif CONNECTION_REFUSED_PATTERN.search(full): status, reason = "failed", "Connection refused"
    elif DNS_ERROR_PATTERN.search(full): status, reason = "dns-failed", "DNS failed (proxy level)"
    elif HANDSHAKE_ERROR_PATTERN.search(full): status, reason = "failed", "TLS/SSL handshake failed"
    else: # Check generic fail reason
         match = next((XRAY_KNIFE_FAIL_REASON_PATTERN.search(line) for line in reversed((out+err).splitlines()) if XRAY_KNIFE_FAIL_REASON_PATTERN.search(line)), None)
         if match: r = match.group(1).strip().replace('\n',' '); status, reason = "failed", r if len(r)<100 and r not in ["null",""] else "Generic fail"
    if status == "pending":
        if process and process.returncode != 0: status, reason = "broken", f"x-knife exit {process.returncode}"
        elif result_obj.real_delay_ms <= args.xray_knife_timeout_ms:
            status = "passed"
            if args.speedtest and result_obj.download_speed_mbps==0 and result_obj.upload_speed_mbps==0 and not (DOWNLOAD_SPEED_PATTERN.search(full) or UPLOAD_SPEED_PATTERN.search(full)):
                 status, reason = "semi-passed", "Passed delay, speed N/A"
        elif result_obj.real_delay_ms > args.xray_knife_timeout_ms: status, reason = "timeout", f"Delay > {args.xray_knife_timeout_ms}ms"
        else: status, reason = "broken", "Unknown status"
    result_obj.status, result_obj.reason = status, reason

    # --- Run Enhanced Checks (if initial test passed) ---
    if result_obj.status in ["passed", "semi-passed"]:
        if args.verbose > 0: print(f"  Initial test {status.upper()} ({result_obj.real_delay_ms:.0f}ms). Running enhanced checks...", file=sys.stderr)
        check_tls_fingerprint_params(result_obj)
        calculate_resilience_score(result_obj)
        perform_cdn_check(result_obj, xray_knife_path, args)
        perform_iran_access_test(result_obj, xray_knife_path, args)

    # --- Calculate Final Score ---
    if result_obj.status in ["passed", "semi-passed"]:
         delay_norm=min(result_obj.real_delay_ms/max(100,args.xray_knife_timeout_ms), 1.0)
         speed_comp=0.0; max_sp=100.0; dl_w=0.15; ul_w=0.05
         if args.speedtest and result_obj.status=="passed": speed_comp=dl_w/(1+min(result_obj.download_speed_mbps,max_sp)) + ul_w/(1+min(result_obj.upload_speed_mbps,max_sp))
         base_score=(0.8*delay_norm + speed_comp) if speed_comp>0 else delay_norm
         score = base_score * result_obj.resilience_score # Apply resilience factor
         if result_obj.iran_access_passed is False: score += 0.8 # Penalty
         elif result_obj.is_cdn_ip is False: score += 0.2
         elif result_obj.is_cdn_ip is None and result_obj.cdn_check_ip: score += 0.1
         if result_obj.iran_access_passed is True: score -= 0.1 # Bonus
         if result_obj.is_cdn_ip is True: score -= 0.05
         if result_obj.iran_test_http_version in ["2","3"]: score -= 0.05
         result_obj.combined_score = max(0.01, score)
         if args.verbose > 1: print(f"      Score Calc -> Final={result_obj.combined_score:.4f}", file=sys.stderr)
    else: # Assign inf score and ensure reason is set for failures
         result_obj.combined_score = float('inf')
         if result_obj.status not in ["passed","semi-passed","pending","skipped"] and not result_obj.reason:
              result_obj.reason = f"{result_obj.status.capitalize()} (RC={process.returncode if process else 'N/A'})"
    return result_obj

async def run_test_worker_async(result_obj: TestResult, xray_knife_path: Optional[str], args: argparse.Namespace) -> TestResult:
    """Async wrapper for test dispatching, includes preliminary DNS."""
    global is_ctrl_c_pressed
    if is_ctrl_c_pressed:
        if result_obj.status == "pending": result_obj.status = "skipped"; result_obj.reason = "Interrupted"
        return result_obj

    details = result_obj.dedup_key_details; hostname = details.get("address"); port = details.get("port")
    # Perform DNS check only if it looks like a hostname
    if hostname and port and not try_parse_ip(hostname):
        if args.verbose > 0: print(f"  Preliminary DNS check for {hostname}...", file=sys.stderr)
        dns_ok = await preliminary_dns_check(hostname, port, DEFAULT_DNS_TIMEOUT_S)
        if not dns_ok: result_obj.status = "dns-failed"; result_obj.reason = "Preliminary DNS failed"; return result_obj
        # Resolved IP is stored in details["resolved_ip"] by preliminary_dns_check if successful

    # Dispatch to appropriate test function
    try:
        if result_obj.protocol == "wg": return await _test_wg_udp_async(result_obj, args)
        else:
            loop = asyncio.get_running_loop() # Run sync function in thread pool
            return await loop.run_in_executor(None, test_config_with_xray_knife, result_obj, xray_knife_path, args)
    except Exception as e:
         print(f"CRITICAL ERROR in worker dispatch for {result_obj.original_config[:50]}: {e}", file=sys.stderr)
         traceback.print_exc(file=sys.stderr)
         result_obj.status="broken"; result_obj.reason=f"Worker dispatch error: {e}"; return result_obj

# --- Output and Filtering Functions ---

def save_configs(outbounds: List[str], filepath: str, base64_encode: bool):
    """Saves the final list of configurations to a file."""
    if not outbounds: print(f"Warning: No final configs to save to '{filepath}'.", file=sys.stderr); return
    output_path = Path(filepath)
    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        content = "\n".join(outbounds)
        if base64_encode: content = base64.b64encode(content.encode('utf-8')).decode("utf-8")
        else: content += "\n"
        output_path.write_text(content, encoding='utf-8')
        enc = "Base64" if base64_encode else "plaintext"
        print(f"\nSuccessfully saved {len(outbounds)} final configs to '{output_path.resolve()}' ({enc}).")
    except Exception as e: print(f"\nError saving config to '{filepath}': {e}", file=sys.stderr)

def save_detailed_results(results: List[TestResult], csv_filepath: Optional[str] = None, json_filepath: Optional[str] = None):
    """Saves detailed test results to CSV and/or JSON files."""
    if not results: print("No detailed results to save."); return
    # Save CSV
    if csv_filepath:
        csv_path = Path(csv_filepath); print(f"Saving detailed CSV results to {csv_path.resolve()}...")
        try:
            csv_path.parent.mkdir(parents=True, exist_ok=True); import csv
            headers = list(TestResult.__annotations__.keys()) # Get all fields from dataclass
            # Reorder headers for better readability
            ordered_headers = ["status","reason","protocol","combined_score","resilience_score","real_delay_ms","download_speed_mbps","upload_speed_mbps","ip","location","flag","iran_access_passed","iran_targets_passed","iran_targets_tested","iran_test_http_version","is_cdn_ip","cdn_check_ip","cdn_check_org","cdn_check_asn","tls_fingerprint_type","source","original_config"]
            # Add dedup keys at the end
            dedup_keys = ["dedup_"+k for k in ["protocol","address","port","host","net","tls","path","fp","plugin"]]
            final_headers = ordered_headers + dedup_keys
            with csv_path.open('w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=final_headers, quoting=csv.QUOTE_MINIMAL, extrasaction='ignore')
                writer.writeheader()
                for res in results:
                    row = {h: format_val(getattr(res, h, None)) for h in ordered_headers}
                    row.update({"dedup_"+k: format_val(res.dedup_key_details.get(k)) for k in ["protocol","address","port","host","net","tls","path","fp","plugin"]})
                    writer.writerow(row)
            print(f"Successfully saved {len(results)} detailed results to CSV.")
        except Exception as e: print(f"Error saving detailed CSV: {e}\n{traceback.format_exc()}", file=sys.stderr)
    # Save JSON
    if json_filepath:
        json_path = Path(json_filepath); print(f"Saving detailed JSON results to {json_path.resolve()}...")
        try:
            json_path.parent.mkdir(parents=True, exist_ok=True); results_list = []
            for res in results:
                res_dict = {k: (None if v==float('inf') else v) for k,v in res.__dict__.items()}
                results_list.append(res_dict)
            with json_path.open('w', encoding='utf-8') as f:
                json.dump(results_list, f, indent=2, ensure_ascii=False, default=str)
            print(f"Successfully saved {len(results)} detailed results to JSON.")
        except Exception as e: print(f"Error saving detailed JSON: {e}\n{traceback.format_exc()}", file=sys.stderr)

def filter_rename_limit_configs(
    tested_results: List[TestResult], limit_per_protocol: int, name_prefix: str,
    include_countries: Optional[List[str]] = None, exclude_countries: Optional[List[str]] = None
) -> List[str]:
    """Filters, sorts by score, limits, and renames working configs."""
    global args
    working = [r for r in tested_results if r.status in ["passed", "semi-passed"]]
    print(f"\nFound {len(working)} working configs initially.")
    # GeoIP Filter
    if include_countries or exclude_countries:
        inc = {c.upper() for c in include_countries} if include_countries else None
        exc = {c.upper() for c in exclude_countries} if exclude_countries else None
        filtered = []; skipped = 0
        for r in working:
            loc = r.location.upper() if r.location else None; included = True
            if loc:
                if exc and loc in exc: included = False
                if inc and loc not in inc: included = False
            elif inc: included = False # Exclude unknown if include list exists
            if included: filtered.append(r)
            else: skipped += 1
        print(f"Filtered {skipped} by country rules. Kept {len(filtered)}.")
        working = filtered
    else: print("No country filters applied.")
    if not working: print("No working configs remain after filtering.", file=sys.stderr); return []

    # Group, Sort by Score, Limit, Rename
    proto_map = {"ss":"SS","ssr":"SSR","vless":"VL","vmess":"VM","trojan":"TR","tuic":"TU","hysteria":"HY","socks":"SK","http":"HT","wg":"WG"}
    renamed = []; groups: Dict[str, List[TestResult]] = {}
    for res in working: groups.setdefault(proto_map.get(res.protocol, res.protocol[:2].upper() if res.protocol else "??"), []).append(res)
    total_renamed = 0
    print(f"Renaming/limiting up to {limit_per_protocol}/protocol by combined score...")
    for abbr, group in groups.items():
        group.sort(key=lambda r: (r.combined_score, r.real_delay_ms)) # Sort by score, then delay
        limited = group[:limit_per_protocol]; total_renamed += len(limited)
        for i, res in enumerate(limited, 1):
            flag = res.flag or DEFAULT_FLAG
            ir = "✅" if res.iran_access_passed else "❌" if res.iran_access_passed is False else "?"
            cdn = "C" if res.is_cdn_ip else "c" if res.is_cdn_ip is False else "?"
            fp_map={"reality":"R","chrome":"F","firefox":"F","safari":"F","ios":"F","android":"F","edge":"F","random":"r","custom":"u"}; fp=fp_map.get(res.tls_fingerprint_type,"?") if res.tls_fingerprint_type else "?"
            http=res.iran_test_http_version or "?"
            score=f"{res.combined_score:.2f}" if res.combined_score!=float('inf') else "inf"
            tag=f"🔒{name_prefix}🦈[{abbr}][{i:02d}][{flag}][{ir}|{cdn}|{fp}|H{http}]S={score}"
            base=res.original_config.split("#", 1)[0]; renamed.append(f"{base}#{urllib.parse.quote(tag)}")
    print(f"Prepared {total_renamed} renamed configs across {len(groups)} protocols.")
    renamed.sort(key=lambda x: x.split("#", 1)[-1]) # Sort final list by tag
    return renamed

def print_protocol_statistics(tested_results: List[TestResult]):
    """Prints enhanced summary statistics per protocol."""
    global args
    if not tested_results: return
    print("\n--- Protocol Statistics (Enhanced) ---")
    stats: Dict[str, Dict[str, Any]] = {}; total_tested = len(tested_results)
    for res in tested_results:
         proto = res.protocol or "unknown"
         if proto not in stats: stats[proto] = {"tested":0,"passed":0,"semi_passed":0,"dns_failed":0,"failed":0,"timeout":0,"broken":0,"skipped":0,"delays":[],"dl_speeds":[],"ul_speeds":[],"scores":[],"locations":set(),"iran_ok":0,"cdn_ip":0,"good_fp":0,"http_v":{"1.1":0,"2":0,"3":0,"other":0}}
         s = stats[proto]; s["tested"] += 1; status_k=res.status.replace('-','_'); s[status_k] = s.get(status_k, 0) + 1
         if res.location: s["locations"].add(f"{res.flag}{res.location.upper()}")
         if res.status in ["passed","semi-passed"]:
             if res.real_delay_ms!=float('inf'): s["delays"].append(res.real_delay_ms)
             if res.download_speed_mbps>0: s["dl_speeds"].append(res.download_speed_mbps)
             if res.upload_speed_mbps>0: s["ul_speeds"].append(res.upload_speed_mbps)
             if res.combined_score!=float('inf'): s["scores"].append(res.combined_score)
             if res.iran_access_passed is True: s["iran_ok"]+=1
             if res.is_cdn_ip is True: s["cdn_ip"]+=1
             if res.tls_fingerprint_type not in ["unknown","custom","random",None]: s["good_fp"]+=1
             http_v=res.iran_test_http_version; s["http_v"][http_v if http_v in s["http_v"] else "other"] +=1 if http_v else 0

    for proto in sorted(stats.keys()):
        s = stats[proto]; total=s["tested"]; working=s.get('passed',0)+s.get('semi_passed',0); working_p=(working/total*100) if total>0 else 0
        def calc(data,prec=1): return (f"{sum(data)/len(data):.{prec}f}", f"{min(data):.{prec}f}", f"{max(data):.{prec}f}") if data else ("N/A",)*3
        avg_d,min_d,max_d=calc(s["delays"],0); avg_dl,_,max_dl=calc(s["dl_speeds"],1); avg_ul,_,max_ul=calc(s["ul_speeds"],1); avg_s,min_s,max_s=calc(s["scores"],3)
        print(f"Protocol: {proto.upper():<8} (Tested:{total}, Working:{working} [{working_p:.0f}%])")
        stat_s=", ".join(f"{k.replace('_','-')}:{v}" for k,v in s.items() if k in ["passed","semi_passed","dns_failed","failed","timeout","broken","skipped"] and v>0); print(f"  Status: {stat_s}")
        print(f"  Delay (Avg/Min/Max ms): {avg_d} / {min_d} / {max_d}")
        if args.speedtest: note=" (N/A)" if proto=="wg" else ""; print(f"  DL (Avg/Max Mbps): {avg_dl} / {max_dl}{note}"); print(f"  UL (Avg/Max Mbps): {avg_ul} / {max_ul}{note}")
        print(f"  Score (Avg/Min/Max): {avg_s} / {min_s} / {max_s}")
        if working > 0:
            iran_p=(s['iran_ok']/working*100); cdn_p=(s['cdn_ip']/working*100); fp_p=(s['good_fp']/working*100)
            http_s=", ".join(f"H{k}:{v}" for k,v in s['http_v'].items() if v>0)
            print(f"  Enhanced (Working%): IranOK:{iran_p:.0f}%, CDN IP:{cdn_p:.0f}%, Good FP:{fp_p:.0f}%")
            if http_s: print(f"  HTTP Versions (Working): {http_s}")
        if s["locations"]: print(f"  Locations: {', '.join(sorted(list(s['locations'])))}")
        print("-" * 30)
    total_w=sum(p.get('passed',0)+p.get('semi_passed',0) for p in stats.values()); total_p=(total_w/total_tested*100) if total_tested>0 else 0
    print(f"Total Tested: {total_tested}, Overall Working: {total_w} [{total_p:.1f}%]")

# --- Main Orchestration ---

async def main_async():
    """Asynchronous main function to manage fetching and testing."""
    global is_ctrl_c_pressed, total_outbounds_count, args, geoip_reader, found_xray_knife_path # Use found path directly

    # Initial Setup (Sync)
    print("\n--- Pr0xySh4rk Config Manager (Enhanced++ v2) ---")
    print(f"Test Mode: Enhanced xray-knife, UDP (WG), Prelim DNS"); print(f"Using {args.threads} workers. Limit/Proto: {args.limit}.")
    print(f"Timeouts(ms): Main={args.xray_knife_timeout_ms}, UDP={args.udp_timeout*1000:.0f}, Iran={IRAN_TEST_TIMEOUT_S*1000:.0f}, IP={IP_CHECK_TIMEOUT_S*1000:.0f}, DNS={DEFAULT_DNS_TIMEOUT_S*1000:.0f}")
    print(f"Speedtest: {'On' if args.speedtest else 'Off'}. GeoIP DB: {'On' if geoip_reader else 'Off'}. Verbose: {args.verbose}")
    print(f"Enhanced Checks: CDN/ASN, Iran Access ({IRAN_TEST_COUNT} targets, >{IRAN_TEST_SUCCESS_THRESHOLD*100:.0f}%), HTTP Ver, TLS FP, Resilience")

    # Fetch and Parse (Sync using ThreadPool)
    print(f"\nFetching {len(subscription_urls)} subscriptions (Cache TTL: {args.cache_ttl}h)...")
    all_parsed_results: List[TestResult] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads, thread_name_prefix="Fetcher") as executor:
        futures = [executor.submit(fetch_and_parse_subscription_worker, url, args.fetch_proxy, args.fetch_timeout, args.no_cache) for url in subscription_urls]
        prog = tqdm_progress(concurrent.futures.as_completed(futures), total=len(futures), desc="Fetching Subs", unit="URL", disable=args.verbose > 0)
        for f in prog:
             if is_ctrl_c_pressed: break
             try: all_parsed_results.extend(f.result())
             except Exception as e: print(f'\nFetcher error: {e}', file=sys.stderr)
    if is_ctrl_c_pressed: print("\nFetching interrupted.", file=sys.stderr); sys.exit(0)
    print(f"Fetched {len(all_parsed_results)} potential configs.")
    if not all_parsed_results: print("No configs found.", file=sys.stderr); sys.exit(0)

    # Deduplicate (Sync)
    unique_results = deduplicate_outbounds(all_parsed_results); total_outbounds_count = len(unique_results)
    if total_outbounds_count == 0: print("No unique configs.", file=sys.stderr); sys.exit(0)

    # Check Xray-Knife (Sync)
    needs_knife = any(r.protocol != "wg" for r in unique_results)
    if needs_knife and not found_xray_knife_path: print("\nError: xray-knife required but not found.", file=sys.stderr); sys.exit(1)
    if needs_knife and args.verbose: print(f"Using xray-knife: {found_xray_knife_path}")

    # Test Configs Concurrently (Async)
    print(f"\nStarting tests on {total_outbounds_count} unique configs...")
    tested_results: List[TestResult] = []; completed = 0; semaphore = asyncio.Semaphore(args.threads)
    async def bounded_worker(res): async with semaphore: return await run_test_worker_async(res, found_xray_knife_path, args)
    tasks = [bounded_worker(res) for res in unique_results]
    prog_test = tqdm_progress(asyncio.as_completed(tasks), total=total_outbounds_count, desc="Testing", unit="cfg", disable=args.verbose > 0)
    start_tm = time.monotonic()

    try:
        for future in prog_test:
             if is_ctrl_c_pressed:
                  for task in tasks: task.cancel() # Cancel pending
                  break
             try:
                 res = await future; tested_results.append(res)
                 if args.verbose > 0 and res.status != 'skipped': print(format_result_line(res, args), file=sys.stderr)
             except asyncio.CancelledError: pass
             except Exception as e: print(f'\nWorker error: {e}', file=sys.stderr); traceback.print_exc(file=sys.stderr)
             finally:
                 completed += 1
                 if args.verbose > 0 and isinstance(prog_test, fallback_tqdm): # Manual progress for fallback
                      rate = completed/(time.monotonic()-start_tm) if time.monotonic()-start_tm > 0 else 0
                      eta = (total_outbounds_count-completed)/rate if rate > 0 else 0; eta_s = f"ETA: {timedelta(seconds=int(eta))}" if rate>0 else ''
                      print(f"\rTesting: {completed}/{total_outbounds_count} | Rate: {rate:.1f}/s | {eta_s}   ", file=sys.stderr, end='')
        if args.verbose > 0 and isinstance(prog_test, fallback_tqdm): print() # Newline after fallback progress
    except KeyboardInterrupt: print("\nInterrupted during testing.", file=sys.stderr); is_ctrl_c_pressed=True; [t.cancel() for t in tasks]
    finally:
        if hasattr(prog_test, 'close'): prog_test.close()

    print(f"\nTesting finished. Processed {len(tested_results)}/{total_outbounds_count}.")
    if is_ctrl_c_pressed: print("Testing was interrupted.", file=sys.stderr)

    # --- Final Steps (Sync) ---
    inc = args.include_countries.split(',') if args.include_countries else None
    exc = args.exclude_countries.split(',') if args.exclude_countries else None
    final_configs = filter_rename_limit_configs(tested_results, args.limit, args.name_prefix, inc, exc)
    if final_configs: save_configs(final_configs, args.output, args.output_format == "base64")
    if args.output_csv or args.output_json:
        tested_results.sort(key=lambda r: (r.combined_score, r.protocol or "zzz", r.real_delay_ms))
        save_detailed_results(tested_results, args.output_csv, args.output_json)
    if args.protocol_stats: print_protocol_statistics(tested_results)
    if geoip_reader: try: geoip_reader.close(); print("\nClosed GeoIP DB.") catch Exception: pass
    print("\n--- Pr0xySh4rk Run Finished ---")

# --- Entry Point ---
if __name__ == "__main__":
    # Argument Parsing (Sync)
    parser = argparse.ArgumentParser(description="Pr0xySh4rk Config Manager (Enhanced++)", formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    io_g = parser.add_argument_group('Input/Output'); fetch_g = parser.add_argument_group('Fetching'); test_g = parser.add_argument_group('Testing (Common)')
    xray_g = parser.add_argument_group('Testing (xray-knife)'); udp_g = parser.add_argument_group('Testing (UDP)'); filter_g = parser.add_argument_group('Filtering & Output'); misc_g = parser.add_argument_group('Misc')
    io_g.add_argument("--input", "-i", required=True, help="Input file (URLs/Base64 list)."); io_g.add_argument("--output", "-o", required=True, help="Output file for best configs.")
    io_g.add_argument("--output-format", choices=["base64", "text"], default="base64", help="Output encoding."); io_g.add_argument("--output-csv", help="Optional CSV details file.")
    io_g.add_argument("--output-json", help="Optional JSON details file."); io_g.add_argument("--name-prefix", default="Pr0xySh4rk", help="Prefix for renamed configs.")
    fetch_g.add_argument("--fetch-proxy", metavar="PROXY", help="Proxy for fetching subs."); fetch_g.add_argument("--fetch-timeout", type=int, default=DEFAULT_FETCH_TIMEOUT, metavar="SEC", help="Fetch timeout/URL.")
    fetch_g.add_argument("--no-cache", action="store_true", help="Force fetch."); fetch_g.add_argument("--clear-cache", action="store_true", help="Clear cache first.")
    fetch_g.add_argument("--cache-ttl", type=int, default=CACHE_TTL_HOURS, metavar="HR", help="Cache validity (hours).")
    test_g.add_argument("--threads", "-t", type=int, default=DEFAULT_THREADS, metavar="N", help="Max concurrent test workers."); test_g.add_argument("--speedtest", "-p", action="store_true", help="Enable speed test.")
    test_g.add_argument("--ip-info", "--rip", action="store_true", help="Get IP/Loc via xray-knife --rip."); test_g.add_argument("--geoip-db", metavar="PATH", help="Path to GeoLite2-Country.mmdb.")
    xray_g.add_argument("--xray-knife-path", metavar="PATH", help="Path to xray-knife."); xray_g.add_argument("--xray-knife-core", choices=["auto", "xray", "singbox"], default="auto", help="xray-knife core.")
    xray_g.add_argument("--xray-knife-timeout-ms", type=int, default=DEFAULT_XRAY_KNIFE_TIMEOUT_MS, metavar="MS", help="Main test timeout (ms).")
    xray_g.add_argument("--xray-knife-insecure", action="store_true", help="Allow insecure TLS."); xray_g.add_argument("--test-url", default=DEFAULT_TEST_URL, metavar="URL", help="Main test URL.")
    xray_g.add_argument("--test-method", default=DEFAULT_TEST_METHOD, metavar="METH", help="Main test HTTP method."); xray_g.add_argument("--speedtest-amount", "-a", type=str, default=f"{DEFAULT_SPEEDTEST_AMOUNT_KB}kb", metavar="AMT[kb|mb]", help="Speed test data amount.")
    udp_g.add_argument("--udp-timeout", type=float, default=DEFAULT_UDP_TIMEOUT_S, metavar="SEC", help="UDP test timeout (WG).")
    filter_g.add_argument("--limit", "-l", type=int, default=DEFAULT_BEST_CONFIGS_LIMIT, metavar="N", help="Max configs/protocol."); filter_g.add_argument("--include-countries", metavar="CC", help="Include countries (comma-sep).")
    filter_g.add_argument("--exclude-countries", metavar="CC", help="Exclude countries (comma-sep).")
    misc_g.add_argument("--protocol-stats", action="store_true", help="Show summary stats."); misc_g.add_argument("--verbose", "-v", action="count", default=0, help="Verbosity (-v, -vv).")
    args = parser.parse_args()

    # Setup TQDM, Cache Dir (Sync)
    if tqdm is None: tqdm_progress = fallback_tqdm
    else: tqdm_progress = tqdm
    try: CACHE_DIR.mkdir(parents=True, exist_ok=True)
    except Exception as e: print(f"Warning: Cache dir create failed '{CACHE_DIR}': {e}", file=sys.stderr)

    # Set signal handler (Sync)
    signal.signal(signal.SIGINT, signal_handler)

    # Run main async logic (Async)
    try: asyncio.run(main_async())
    except KeyboardInterrupt: print("\nInterrupted before async run.", file=sys.stderr)
    except Exception as e: print(f"\nTop-level runtime error: {e}", file=sys.stderr); traceback.print_exc(file=sys.stderr); sys.exit(1)

# Helper function to format result line
def format_result_line(tested_result: TestResult, args: argparse.Namespace) -> str:
    """Formats a single result line for verbose output."""
    delay = f"{tested_result.real_delay_ms:>4.0f}ms" if tested_result.real_delay_ms!=float('inf') else "----ms"
    dl,ul = tested_result.download_speed_mbps, tested_result.upload_speed_mbps; spd = ""
    if args.speedtest and tested_result.protocol!="wg" and (dl>0 or ul>0): spd=f"D:{dl:>5.1f} U:{ul:>5.1f}"
    flag=tested_result.flag or ("?" if args.ip_info or args.geoip_db else ""); loc=f"({tested_result.location})" if tested_result.location else ""; geo=f"{flag}{loc}"
    ir="✅" if tested_result.iran_access_passed else "❌" if tested_result.iran_access_passed is False else "?"; cdn="C" if tested_result.is_cdn_ip else "c" if tested_result.is_cdn_ip is False else "?"; asn="A" if tested_result.cdn_check_asn else "?"
    fp_map={"reality":"R","chrome":"F","firefox":"F","safari":"F","ios":"F","android":"F","edge":"F","random":"r","custom":"u"}; fp=fp_map.get(tested_result.tls_fingerprint_type,"?") if tested_result.tls_fingerprint_type else "?"
    http=tested_result.iran_test_http_version or "?"; enh=f"[{ir}|{cdn}|{asn}|{fp}|H{http}]"
    score=f"S:{tested_result.combined_score:.2f}" if tested_result.combined_score!=float('inf') else "S:---"
    cfg=tested_result.original_config; max_l=40; cfg=cfg[:max_l-3]+"..." if len(cfg)>max_l else cfg
    colors={"passed":"92","semi-passed":"93","failed":"91","dns-failed":"91","timeout":"95","broken":"91","skipped":"90","pending":"37"}; color=colors.get(tested_result.status,"0"); stat=f"\033[{color}m{tested_result.status.upper():<7}\033[0m"
    reason=f" ({tested_result.reason})" if tested_result.reason and tested_result.status not in ['passed','pending','semi-passed'] else ""
    return f"{stat} {delay:<7} {spd:<16} {geo:<8} {enh:<13} {score:<7} {cfg}{reason}".strip()
