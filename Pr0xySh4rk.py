#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import asyncio
import base64
import json
import logging
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import time
import urllib.parse
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Any

# ==============================================================================
# OPTIONAL DEPENDENCIES
# ==============================================================================
try:
    import geoip2.database
    import geoip2.errors
    GEOIP_AVAILABLE = True
except ImportError:
    GEOIP_AVAILABLE = False

try:
    from tqdm.asyncio import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False

# ==============================================================================
# CONFIGURATION & CONSTANTS
# ==============================================================================

# Logging Setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)s | %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger("Pr0xySh4rk")

# Country Flags Map
COUNTRY_FLAGS = {
    "US": "🇺🇸", "DE": "🇩🇪", "NL": "🇳🇱", "GB": "🇬🇧", "FR": "🇫🇷", "CA": "🇨🇦", "JP": "🇯🇵",
    "SG": "🇸🇬", "HK": "🇭🇰", "AU": "🇦🇺", "CH": "🇨🇭", "SE": "🇸🇪", "FI": "🇫🇮", "NO": "🇳🇴",
    "IE": "🇮🇪", "IT": "🇮🇹", "ES": "🇪🇸", "PL": "🇵🇱", "RO": "🇷🇴", "TR": "🇹🇷", "RU": "🇷🇺",
    "UA": "🇺🇦", "IR": "🇮🇷", "AE": "🇦🇪", "CN": "🇨🇳", "IN": "🇮🇳", "BR": "🇧🇷", "ZA": "🇿🇦",
    "KR": "🇰🇷", "TW": "🇹🇼", "VN": "🇻🇳", "ID": "🇮🇩", "MY": "🇲🇾", "TH": "🇹🇭"
}
DEFAULT_FLAG = "🏳️"
UNKNOWN_FLAG = "🏴‍☠️"

# Regex Patterns for Parsing xray-knife output
RE_DELAY = re.compile(r"(?:Real Delay|Latency)\s*[:=]\s*(\d+)\s*ms", re.IGNORECASE)
RE_DOWNLOAD = re.compile(r"Downloaded.*?Speed\s*[:=]\s*([\d\.]+)\s*([KMG]?)bps", re.IGNORECASE)
RE_UPLOAD = re.compile(r"Uploaded.*?Speed\s*[:=]\s*([\d\.]+)\s*([KMG]?)bps", re.IGNORECASE)
RE_IP_LOC = re.compile(r"ip=(?P<ip>[\d\.a-fA-F:]+).*?loc=(?P<loc>[A-Z]{2})", re.IGNORECASE | re.DOTALL)
RE_ERROR = re.compile(r"(?:error|failed|timeout|refused|deadline)[:\s]+(.+)", re.IGNORECASE)

# Defaults
DEFAULT_TEST_URL = "https://cp.cloudflare.com/"  # Fast, global
DEFAULT_TIMEOUT = 5000  # ms
DEFAULT_UDP_TIMEOUT = 3.0  # seconds

# ==============================================================================
# DATA STRUCTURES
# ==============================================================================

@dataclass
class ConfigResult:
    original: str
    protocol: str
    status: str = "pending"  # pending, passed, failed, timeout
    reason: str = ""
    delay: float = float('inf')
    speed_dl: float = 0.0
    speed_ul: float = 0.0
    ip: str = ""
    country: str = ""
    flag: str = ""
    score: float = float('inf')
    
    def to_dict(self):
        return asdict(self)

# ==============================================================================
# CORE LOGIC: MANAGER
# ==============================================================================

class ConfigManager:
    def __init__(self, input_file: str):
        self.input_file = input_file
        self.configs: List[ConfigResult] = []

    def load_configs(self):
        """Reads input file, handles base64, parses protocols."""
        if not os.path.exists(self.input_file):
            logger.error(f"Input file not found: {self.input_file}")
            sys.exit(1)

        try:
            with open(self.input_file, 'r', encoding='utf-8') as f:
                content = f.read().strip()
            
            # Heuristic: Check if file is one giant Base64 string
            if "://" not in content[:100] and len(content) > 50:
                try:
                    logger.info("Input appears to be Base64 encoded. Decoding...")
                    # Fix padding
                    pad = len(content) % 4
                    if pad: content += "=" * (4 - pad)
                    content = base64.b64decode(content).decode('utf-8', errors='ignore')
                except Exception as e:
                    logger.warning(f"Base64 decode failed, proceeding as text: {e}")

            lines = content.splitlines()
            for line in lines:
                line = line.strip()
                if not line or line.startswith("#"): continue
                
                proto = self._detect_protocol(line)
                if proto:
                    self.configs.append(ConfigResult(original=line, protocol=proto))
            
            logger.info(f"Loaded {len(self.configs)} raw configs.")

        except Exception as e:
            logger.error(f"Error loading configs: {e}")
            sys.exit(1)

    def _detect_protocol(self, line: str) -> Optional[str]:
        # Order matters slightly for efficiency
        if line.startswith("vless://"): return "vless"
        if line.startswith("vmess://"): return "vmess"
        if line.startswith("trojan://"): return "trojan"
        if line.startswith("ss://"): return "ss"
        if line.startswith("ssr://"): return "ssr"
        if line.startswith(("tuic://")): return "tuic"
        if line.startswith(("hysteria://", "hysteria2://", "hy2://")): return "hysteria"
        if line.startswith(("wg://", "wireguard://", "warp://")): return "wg"
        return None

    def deduplicate(self):
        """
        Advanced deduplication based on parsed URL components.
        Prevents duplicate servers with different names.
        """
        unique_map = {}
        duplicates = 0

        for cfg in self.configs:
            try:
                # Basic parsing
                parsed = urllib.parse.urlparse(cfg.original)
                host = parsed.hostname
                port = parsed.port
                
                # If we can't parse host/port, fall back to full string
                if not host or not port:
                    key = cfg.original
                else:
                    # Deep check key: Protocol + Host + Port + Path + Query
                    # This handles cases where same server runs different configs
                    path = parsed.path
                    query = parsed.query
                    key = f"{cfg.protocol}://{host}:{port}{path}?{query}"
                
                if key not in unique_map:
                    unique_map[key] = cfg
                else:
                    duplicates += 1
            except:
                continue

        self.configs = list(unique_map.values())
        logger.info(f"Deduplication finished. Removed {duplicates}. Unique: {len(self.configs)}")

# ==============================================================================
# CORE LOGIC: TESTER
# ==============================================================================

class ProxyTester:
    def __init__(self, xray_path: str, geoip_db: str, speedtest: bool, 
                 timeout: int, insecure: bool):
        self.xray_path = xray_path
        self.geoip_reader = None
        self.speedtest = speedtest
        self.timeout = timeout
        self.insecure = insecure
        
        if GEOIP_AVAILABLE and geoip_db and os.path.exists(geoip_db):
            try:
                self.geoip_reader = geoip2.database.Reader(geoip_db)
                logger.info(f"GeoIP Database loaded: {geoip_db}")
            except Exception as e:
                logger.error(f"Failed to load GeoIP DB: {e}")

    def _get_flag(self, ip: str) -> Tuple[str, str]:
        if not self.geoip_reader or not ip:
            return "", DEFAULT_FLAG
        try:
            # Strip IPv6 brackets
            clean_ip = ip.strip("[]")
            record = self.geoip_reader.country(clean_ip)
            iso = record.country.iso_code
            if iso:
                return iso, COUNTRY_FLAGS.get(iso.upper(), DEFAULT_FLAG)
        except:
            pass
        return "", DEFAULT_FLAG

    async def test_wg_udp(self, config: ConfigResult):
        """
        Tests WireGuard/WARP/UDP protocols using native Python AsyncIO.
        Sends a dummy byte to trigger a response or ICMP unreachable.
        """
        try:
            parsed = urllib.parse.urlparse(config.original)
            host = parsed.hostname
            port = parsed.port
            
            if not host or not port:
                config.status = "failed"
                config.reason = "Invalid URL"
                return

            loop = asyncio.get_running_loop()
            
            # 1. Resolve DNS (Async)
            try:
                addr_info = await loop.getaddrinfo(host, port, type=socket.SOCK_DGRAM)
                target_ip = addr_info[0][4][0]
                family = addr_info[0][0]
            except Exception as e:
                config.status = "failed"
                config.reason = "DNS Resolution Error"
                return

            # 2. UDP Handshake / Reachability
            # We use a connected UDP socket to detect ICMP errors immediately if possible
            # and measure RTT.
            
            start_time = loop.time()
            
            # Simple One-Shot UDP Protocol
            class PingProtocol(asyncio.DatagramProtocol):
                def __init__(self):
                    self.transport = None
                    self.received = asyncio.Future()
                def connection_made(self, transport):
                    self.transport = transport
                    # Send empty packet or simple handshake
                    self.transport.sendto(b'\x00\x00\x00\x00') 
                def datagram_received(self, data, addr):
                    if not self.received.done():
                        self.received.set_result(True)
                def error_received(self, exc):
                    if not self.received.done():
                        self.received.set_exception(exc)
                def connection_lost(self, exc):
                    pass

            try:
                transport, protocol = await loop.create_datagram_endpoint(
                    lambda: PingProtocol(),
                    remote_addr=(target_ip, port),
                    family=family
                )
                
                # Wait for response with timeout
                # Note: Many WG servers won't respond to garbage, but if we don't get 
                # "Connection Refused", the port is open-ish. 
                # For strict testing, we consider no-ICMP-error as 'maybe-alive' 
                # or wait for a very short timeout.
                # Here, we assume if we send and wait 1s without error, it's alive.
                
                await asyncio.wait_for(protocol.received, timeout=1.5)
                # If we received something, great.
                
            except asyncio.TimeoutError:
                # UDP is connectionless. Timeout means no reply. 
                # For WG, no reply often means it's working (Silent Drop) but reachable.
                # We mark as "passed" but with a penalty if we can't verify handshake.
                # However, to be strict, we treat successful send without error as pass.
                pass
            except Exception:
                # Connection refused or other network error
                config.status = "failed"
                config.reason = "Unreachable"
                if transport: transport.close()
                return

            end_time = loop.time()
            if transport: transport.close()

            config.status = "passed"
            config.delay = (end_time - start_time) * 1000
            config.ip = target_ip
            
            # GeoIP lookup
            config.country, config.flag = self._get_flag(target_ip)
            
            # WireGuard doesn't have "Speed" in this simple test, use delay for score
            config.score = config.delay

        except Exception as e:
            config.status = "broken"
            config.reason = str(e)

    async def test_xray(self, config: ConfigResult):
        """
        Wraps xray-knife subprocess in asyncio.
        """
        # Build Command
        cmd = [
            self.xray_path, "net", "http",
            "-c", config.original,
            "-d", str(self.timeout),
            "--url", DEFAULT_TEST_URL,
            "-z", "auto", # core selection
            "-v"
        ]
        
        if self.speedtest:
            # -p: speedtest, -a: amount (kb)
            cmd.extend(["-p", "-a", "2000"]) 
        
        if self.insecure:
            cmd.append("-e")
            
        # Use built-in IP checking if we don't have local DB, 
        # otherwise we do it locally to save time on external requests
        if not self.geoip_reader:
            cmd.append("--rip")

        try:
            # Create subprocess
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env={**os.environ, "WSL_INTEROP": ""} # Clean env
            )

            # Wait with safety buffer
            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=(self.timeout/1000) + 5)
            except asyncio.TimeoutError:
                try: proc.kill()
                except: pass
                config.status = "timeout"
                return

            output = (stdout.decode('utf-8', errors='ignore') + 
                      stderr.decode('utf-8', errors='ignore'))

            # Parse Results
            delay_m = RE_DELAY.search(output)
            if delay_m:
                config.delay = float(delay_m.group(1))
                config.status = "passed"
            else:
                config.status = "failed"
                err_m = RE_ERROR.search(output)
                if err_m: config.reason = err_m.group(1).strip()
                return

            # Speed
            dl_m = RE_DOWNLOAD.search(output)
            if dl_m:
                val, unit = float(dl_m.group(1)), dl_m.group(2).upper()
                if unit == 'K': config.speed_dl = val / 1000
                elif unit == 'M': config.speed_dl = val
                elif unit == 'G': config.speed_dl = val * 1000
                else: config.speed_dl = val / 1000000

            # IP / Location
            ip_m = RE_IP_LOC.search(output)
            if ip_m:
                config.ip = ip_m.group('ip')
                # If xray-knife found loc, use it
                if ip_m.group('loc'):
                    config.country = ip_m.group('loc')
                    config.flag = COUNTRY_FLAGS.get(config.country.upper(), DEFAULT_FLAG)
            
            # Local GeoIP override (more reliable/standardized)
            if self.geoip_reader and config.ip:
                c, f = self._get_flag(config.ip)
                if c:
                    config.country = c
                    config.flag = f

            # Scoring: Lower is better.
            # Score = Delay / (1 + Speed)
            # High speed reduces the score significantly.
            config.score = config.delay
            if config.speed_dl > 0:
                config.score = config.delay / (1 + config.speed_dl)

        except Exception as e:
            config.status = "broken"
            config.reason = str(e)

    async def run_worker(self, config: ConfigResult, sem: asyncio.Semaphore):
        async with sem:
            if config.protocol == "wg":
                await self.test_wg_udp(config)
            else:
                await self.test_xray(config)

# ==============================================================================
# CORE LOGIC: REPORTER
# ==============================================================================

class Reporter:
    def __init__(self, prefix: str):
        self.prefix = prefix

    def rename_and_format(self, configs: List[ConfigResult], limit: int) -> List[str]:
        # Filter passed
        passed = [c for c in configs if c.status == "passed"]
        
        # Group by protocol
        grouped = {}
        for c in passed:
            if c.protocol not in grouped: grouped[c.protocol] = []
            grouped[c.protocol].append(c)
            
        final_lines = []
        
        for proto, items in grouped.items():
            # Sort by Score (ascending = better)
            items.sort(key=lambda x: x.score)
            
            # Take top N
            selected = items[:limit]
            
            for idx, res in enumerate(selected, 1):
                flag = res.flag if res.flag else UNKNOWN_FLAG
                
                # Naming Convention: 🔒Prefix🦈[PROTO][NUM][FLAG]
                alias = f"🔒{self.prefix}🦈[{proto.upper()}][{idx:02d}][{flag}]"
                
                # Add speed info to name if available
                if res.speed_dl > 0:
                    alias += f"[{res.speed_dl:.1f}M]"
                
                encoded_alias = urllib.parse.quote(alias)
                
                # Replace existing fragment or append
                if "#" in res.original:
                    base = res.original.split("#", 1)[0]
                else:
                    base = res.original
                    
                final_lines.append(f"{base}#{encoded_alias}")
                
        return final_lines

    def save_file(self, content_lines: List[str], path: str, fmt: str):
        data = "\n".join(content_lines)
        if fmt == "base64":
            data = base64.b64encode(data.encode('utf-8')).decode('utf-8')
            
        with open(path, "w", encoding='utf-8') as f:
            f.write(data)

    def save_csv(self, results: List[ConfigResult], path: str):
        import csv
        fieldnames = ["protocol", "status", "delay", "speed_dl", "ip", "country", "score", "reason", "original"]
        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
                writer.writeheader()
                for r in results:
                    writer.writerow(r.to_dict())
        except Exception as e:
            logger.error(f"Failed to save CSV: {e}")

# ==============================================================================
# MAIN EXECUTION
# ==============================================================================

def setup_args():
    parser = argparse.ArgumentParser(description="Pr0xySh4rk: Advanced Proxy Processor")
    
    group_io = parser.add_argument_group("Input/Output")
    group_io.add_argument("--input", required=True, help="Input file path")
    group_io.add_argument("--output", required=True, help="Output file path")
    group_io.add_argument("--output-format", choices=["text", "base64"], default="base64")
    group_io.add_argument("--csv", help="Optional CSV report output path")
    
    group_test = parser.add_argument_group("Testing")
    group_test.add_argument("--xray-knife-path", help="Path to xray-knife binary")
    group_test.add_argument("--geoip-db", help="Path to Country.mmdb")
    group_test.add_argument("--threads", type=int, default=30, help="Concurrency level")
    group_test.add_argument("--limit", type=int, default=50, help="Limit per protocol")
    group_test.add_argument("--speedtest", action="store_true", help="Perform speed test")
    group_test.add_argument("--insecure", action="store_true", help="Allow insecure TLS")
    
    group_meta = parser.add_argument_group("Meta")
    group_meta.add_argument("--name-prefix", default="Pr0xySh4rk", help="Prefix for config names")
    
    return parser.parse_args()

def find_binary(name: str, specific_path: str = None) -> str:
    if specific_path:
        p = Path(specific_path)
        if p.exists() and os.access(p, os.X_OK):
            return str(p.resolve())
    
    # Check env
    if os.environ.get("XRAY_KNIFE_PATH"):
         p = Path(os.environ["XRAY_KNIFE_PATH"])
         if p.exists(): return str(p)

    # Check path
    found = shutil.which(name)
    if found: return found
    
    # Check current dir
    local = Path(os.getcwd()) / name
    if local.exists() and os.access(local, os.X_OK):
        return str(local)
        
    return ""

async def async_main():
    args = setup_args()
    
    # 1. Initialize Components
    manager = ConfigManager(args.input)
    reporter = Reporter(args.name_prefix)
    
    # Locate Xray-Knife
    xray_bin = find_binary("xray-knife", args.xray_knife_path)
    if not xray_bin:
        logger.warning("xray-knife not found! Only WireGuard tests will run.")
    
    tester = ProxyTester(
        xray_path=xray_bin,
        geoip_db=args.geoip_db,
        speedtest=args.speedtest,
        timeout=DEFAULT_TIMEOUT,
        insecure=args.insecure
    )

    # 2. Load & Dedup
    logger.info("Loading configurations...")
    manager.load_configs()
    manager.deduplicate()
    
    total = len(manager.configs)
    if total == 0:
        logger.error("No valid configurations found.")
        sys.exit(0)

    # 3. Test Loop
    logger.info(f"Starting tests on {total} configs (Threads: {args.threads})...")
    
    sem = asyncio.Semaphore(args.threads)
    tasks = []
    for cfg in manager.configs:
        # Skip Xray tests if binary missing
        if cfg.protocol != "wg" and not xray_bin:
            cfg.status = "skipped"
            cfg.reason = "No xray-knife"
            continue
        tasks.append(tester.run_worker(cfg, sem))

    if TQDM_AVAILABLE:
        for f in tqdm(asyncio.as_completed(tasks), total=len(tasks), unit="cfg"):
            await f
    else:
        # Simple progress report
        done = 0
        for f in asyncio.as_completed(tasks):
            await f
            done += 1
            if done % 10 == 0:
                print(f"Progress: {done}/{total}", end='\r', file=sys.stderr)
        print("", file=sys.stderr)

    # 4. Processing Results
    passed_count = sum(1 for c in manager.configs if c.status == "passed")
    logger.info(f"Testing complete. Passed: {passed_count}/{total}")

    # 5. Formatting & Saving
    final_lines = reporter.rename_and_format(manager.configs, args.limit)
    reporter.save_file(final_lines, args.output, args.output_format)
    logger.info(f"Saved {len(final_lines)} active configs to {args.output}")

    if args.csv:
        reporter.save_csv(manager.configs, args.csv)
        logger.info(f"CSV report saved to {args.csv}")

def main():
    signal.signal(signal.SIGINT, lambda s, f: sys.exit(0))
    
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        
    try:
        asyncio.run(async_main())
    except KeyboardInterrupt:
        logger.info("Process interrupted by user.")
    except Exception as e:
        logger.exception(f"Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
