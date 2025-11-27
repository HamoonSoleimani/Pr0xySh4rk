#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import asyncio
import base64
import csv
import hashlib
import json
import logging
import os
import re
import shutil
import signal
import socket
import sys
import time
import urllib.parse
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Any

# ==============================================================================
# OPTIONAL DEPENDENCIES IMPORT
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
# CONSTANTS & CONFIGURATION
# ==============================================================================

# Configure Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)8s | %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger("Pr0xySh4rk")

# Comprehensive Flag Map
COUNTRY_FLAGS = {
    "US": "🇺🇸", "DE": "🇩🇪", "NL": "🇳🇱", "GB": "🇬🇧", "FR": "🇫🇷", "CA": "🇨🇦", "JP": "🇯🇵",
    "SG": "🇸🇬", "HK": "🇭🇰", "AU": "🇦🇺", "CH": "🇨🇭", "SE": "🇸🇪", "FI": "🇫🇮", "NO": "🇳🇴",
    "IE": "🇮🇪", "IT": "🇮🇹", "ES": "🇪🇸", "PL": "🇵🇱", "RO": "🇷🇴", "TR": "🇹🇷", "RU": "🇷🇺",
    "UA": "🇺🇦", "IR": "🇮🇷", "AE": "🇦🇪", "CN": "🇨🇳", "IN": "🇮🇳", "BR": "🇧🇷", "ZA": "🇿🇦",
    "KR": "🇰🇷", "TW": "🇹🇼", "VN": "🇻🇳", "ID": "🇮🇩", "MY": "🇲🇾", "TH": "🇹🇭", "KZ": "🇰🇿",
    "SA": "🇸🇦", "EG": "🇪🇬", "IL": "🇮🇱", "PK": "🇵🇰", "BD": "🇧🇩", "PH": "🇵🇭"
}
DEFAULT_FLAG = "🚩"

# Regex Patterns for Parsing xray-knife stdout/stderr
# Optimized to handle variations in xray-knife versions
RE_DELAY = re.compile(r"(?:Real Delay|Latency)\s*[:=]\s*(\d+)\s*ms", re.IGNORECASE)
RE_DOWNLOAD = re.compile(r"Downloaded.*?Speed\s*[:=]\s*([\d\.]+)\s*([KMG]?)bps", re.IGNORECASE)
RE_IP_LOC = re.compile(r"ip=(?P<ip>[\d\.a-fA-F:]+).*?loc=(?P<loc>[A-Z]{2})", re.IGNORECASE | re.DOTALL)
RE_CRITICAL_ERROR = re.compile(r"(?:panic|fatal error|segmentation fault)", re.IGNORECASE)

DEFAULT_TEST_URL = "https://cp.cloudflare.com/"
DEFAULT_TIMEOUT_MS = 5000

# ==============================================================================
# DATA MODELS
# ==============================================================================

@dataclass
class ProxyConfig:
    original: str
    protocol: str
    status: str = "pending"  # pending, passed, failed, timeout, skipped
    reason: str = ""
    delay: float = float('inf')
    speed_dl: float = 0.0
    ip: str = ""
    country: str = ""
    flag: str = ""
    score: float = float('inf')
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_csv_dict(self):
        d = asdict(self)
        d.pop('metadata', None)
        return d

# ==============================================================================
# MODULE: GEOIP HANDLER
# ==============================================================================

class GeoIPHandler:
    def __init__(self, db_path: Optional[str]):
        self.reader = None
        if GEOIP_AVAILABLE and db_path and os.path.exists(db_path):
            try:
                self.reader = geoip2.database.Reader(db_path)
                logger.info(f"GeoIP Database loaded: {db_path}")
            except Exception as e:
                logger.error(f"Failed to load GeoIP DB: {e}")

    def lookup(self, ip_address: str) -> Tuple[str, str]:
        if not self.reader or not ip_address:
            return "", DEFAULT_FLAG
        
        try:
            # Handle IPv6 brackets
            clean_ip = ip_address.strip("[]")
            record = self.reader.country(clean_ip)
            iso_code = record.country.iso_code
            if iso_code:
                flag = COUNTRY_FLAGS.get(iso_code.upper(), DEFAULT_FLAG)
                return iso_code, flag
        except (ValueError, geoip2.errors.AddressNotFoundError):
            pass
        except Exception:
            pass
            
        return "", DEFAULT_FLAG

    def close(self):
        if self.reader:
            self.reader.close()

# ==============================================================================
# MODULE: CONFIG LOADER & DEDUPLICATOR
# ==============================================================================

class ConfigLoader:
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.configs: List[ProxyConfig] = []

    def _normalize_content(self, content: str) -> str:
        """
        Detects if content is Base64 and decodes it.
        Also handles standard whitespace issues.
        """
        content = content.strip()
        
        # Heuristic: If it looks like one long string with no spaces/newlines
        # and doesn't start with a protocol, it's likely Base64.
        if "://" not in content[:50] and len(content) > 50 and "\n" not in content[:50]:
            try:
                logger.info("Input file appears to be Base64 encoded. Decoding...")
                # Fix padding
                pad = len(content) % 4
                if pad:
                    content += "=" * (4 - pad)
                decoded_bytes = base64.b64decode(content)
                return decoded_bytes.decode('utf-8', errors='ignore')
            except Exception as e:
                logger.warning(f"Base64 decoding failed ({e}). Treating as plain text.")
                
        return content

    def _parse_line(self, line: str) -> Optional[ProxyConfig]:
        line = line.strip()
        if not line or line.startswith("#"):
            return None
        
        # Protocol Detection
        proto = None
        lower_line = line.lower()
        if lower_line.startswith("vmess://"): proto = "vmess"
        elif lower_line.startswith("vless://"): proto = "vless"
        elif lower_line.startswith("trojan://"): proto = "trojan"
        elif lower_line.startswith("ss://"): proto = "ss"
        elif lower_line.startswith("ssr://"): proto = "ssr"
        elif lower_line.startswith("tuic://"): proto = "tuic"
        elif lower_line.startswith(("hysteria://", "hysteria2://", "hy2://")): proto = "hysteria"
        elif lower_line.startswith(("wg://", "wireguard://", "warp://")): proto = "wg"
        
        if proto:
            return ProxyConfig(original=line, protocol=proto)
        return None

    def load(self):
        if not os.path.exists(self.filepath):
            logger.critical(f"Input file not found: {self.filepath}")
            sys.exit(1)

        try:
            with open(self.filepath, 'r', encoding='utf-8') as f:
                raw_content = f.read()
            
            content = self._normalize_content(raw_content)
            
            for line in content.splitlines():
                cfg = self._parse_line(line)
                if cfg:
                    self.configs.append(cfg)
            
            logger.info(f"Loaded {len(self.configs)} raw configurations.")
            
        except Exception as e:
            logger.critical(f"Fatal error reading input file: {e}")
            sys.exit(1)

    def deduplicate(self):
        """
        Advanced Deduplication:
        Parses the URL to create a unique hash based on Protocol, Host, Port, and Path.
        This ignores fragment (#name) and other non-functional parts.
        """
        unique_map = {}
        duplicates_count = 0

        for cfg in self.configs:
            try:
                parsed = urllib.parse.urlparse(cfg.original)
                
                # Robust Key Generation
                if parsed.hostname and parsed.port:
                    # Key: proto://host:port/path?query
                    key_str = f"{cfg.protocol}://{parsed.hostname}:{parsed.port}{parsed.path}?{parsed.query}"
                else:
                    # Fallback for complex/obfuscated strings (like some ss://)
                    key_str = cfg.original

                # Generate Hash
                key_hash = hashlib.md5(key_str.encode('utf-8')).hexdigest()

                if key_hash not in unique_map:
                    unique_map[key_hash] = cfg
                else:
                    duplicates_count += 1
            except Exception:
                # If parsing fails, keep it to be safe (or discard)
                # Here we treat raw string as unique
                if cfg.original not in unique_map:
                    unique_map[cfg.original] = cfg

        self.configs = list(unique_map.values())
        logger.info(f"Deduplication complete. Removed {duplicates_count} duplicates. Active: {len(self.configs)}")

# ==============================================================================
# MODULE: ASYNC TESTER
# ==============================================================================

class AsyncTester:
    def __init__(self, xray_bin: str, geoip: GeoIPHandler, 
                 speedtest: bool, insecure: bool, timeout: int):
        self.xray_bin = xray_bin
        self.geoip = geoip
        self.speedtest = speedtest
        self.insecure = insecure
        self.timeout = timeout

    async def _test_wg_native(self, config: ProxyConfig):
        """
        Pure Python AsyncIO UDP test for WireGuard/WARP.
        Sends a dummy packet to check reachability.
        """
        try:
            parsed = urllib.parse.urlparse(config.original)
            host = parsed.hostname
            port = parsed.port
            
            if not host or not port:
                raise ValueError("Invalid WireGuard URI")

            loop = asyncio.get_running_loop()
            
            # 1. DNS Resolution (Async)
            try:
                addr_info = await loop.getaddrinfo(host, port, type=socket.SOCK_DGRAM)
                target_ip = addr_info[0][4][0]
                family = addr_info[0][0]
            except Exception:
                config.status = "failed"
                config.reason = "DNS Error"
                return

            # 2. UDP Socket Interaction
            start_time = loop.time()
            
            # Helper Protocol for asyncio
            class ProbeProtocol(asyncio.DatagramProtocol):
                def __init__(self):
                    self.transport = None
                    self.received = asyncio.Future()
                def connection_made(self, transport):
                    self.transport = transport
                    # Send a 4-byte empty packet (enough to trigger a response or error)
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
                    lambda: ProbeProtocol(),
                    remote_addr=(target_ip, port),
                    family=family
                )
                
                # Wait for response with short timeout
                # Note: WireGuard is silent. If we get NO error (ICMP Unreachable), 
                # we technically don't know if it's up or dropped.
                # However, for scanning purposes, connection refused/unreachable = fail.
                # A timeout implies the packet was sent successfully into the void (or firewall).
                await asyncio.wait_for(protocol.received, timeout=2.0)
                
            except asyncio.TimeoutError:
                # Timeout in UDP often means "Packet Sent, No ICMP Error received". 
                # For WG, this is a positive sign of life/firewall accept.
                pass 
            except Exception:
                config.status = "failed"
                config.reason = "Unreachable"
                if 'transport' in locals() and transport: transport.close()
                return

            # Cleanup
            if 'transport' in locals() and transport: transport.close()
            
            end_time = loop.time()
            config.delay = (end_time - start_time) * 1000
            config.status = "passed"
            config.ip = target_ip
            
            # GeoIP Lookup
            c, f = self.geoip.lookup(target_ip)
            config.country, config.flag = c, f
            
            # Scoring
            config.score = config.delay

        except Exception as e:
            config.status = "broken"
            config.reason = str(e)

    async def _test_xray_knife(self, config: ProxyConfig):
        """
        Wraps the xray-knife binary in an async subprocess.
        """
        # Build Command
        cmd = [
            self.xray_bin, "net", "http",
            "-c", config.original,
            "-d", str(self.timeout),
            "--url", DEFAULT_TEST_URL,
            "-z", "auto",
            "-v"
        ]
        
        if self.speedtest:
            # -p enables speedtest, -a sets amount (2000kb = 2MB)
            cmd.extend(["-p", "-a", "2000"])
            
        if self.insecure:
            cmd.append("-e")
            
        # If we don't have local GeoIP, ask xray-knife to fetch it
        if not self.geoip.reader:
            cmd.append("--rip")

        try:
            # Execute
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                # Clear WSL interop env var to prevent Windows host binary interference in WSL
                env={**os.environ, "WSL_INTEROP": ""}
            )
            
            # Wait for completion with a safety margin over the internal timeout
            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), 
                    timeout=(self.timeout / 1000) + 5
                )
            except asyncio.TimeoutError:
                try: proc.kill()
                except: pass
                config.status = "timeout"
                config.reason = "Subprocess Hung"
                return

            output = (stdout.decode('utf-8', errors='ignore') + 
                      stderr.decode('utf-8', errors='ignore'))
            
            # Parse Latency
            delay_match = RE_DELAY.search(output)
            if delay_match:
                config.delay = float(delay_match.group(1))
                config.status = "passed"
            else:
                config.status = "failed"
                # Try to find reason
                if "timeout" in output.lower():
                    config.reason = "Timeout"
                else:
                    config.reason = "Connection Failed"
                return

            # Parse Speed
            speed_match = RE_DOWNLOAD.search(output)
            if speed_match:
                val = float(speed_match.group(1))
                unit = speed_match.group(2).upper()
                multiplier = 1.0
                if unit == 'K': multiplier = 0.001
                elif unit == 'G': multiplier = 1000.0
                config.speed_dl = val * multiplier

            # Parse IP/Location
            ip_match = RE_IP_LOC.search(output)
            if ip_match:
                config.ip = ip_match.group("ip")
                if ip_match.group("loc"):
                    config.country = ip_match.group("loc")
                    config.flag = COUNTRY_FLAGS.get(config.country.upper(), DEFAULT_FLAG)
            
            # Fallback/Override with Local GeoIP
            if self.geoip.reader and config.ip:
                c, f = self.geoip.lookup(config.ip)
                if c:
                    config.country, config.flag = c, f

            # Scoring Algorithm:
            # Base Score = Latency
            # Speed Bonus = Divisor based on speed
            # Formula: Latency / (1 + SpeedMBps)
            # Example: 200ms, 0 speed = 200
            # Example: 200ms, 10MBps speed = 200 / 11 = ~18
            if config.speed_dl > 0:
                config.score = config.delay / (1.0 + config.speed_dl)
            else:
                config.score = config.delay

        except Exception as e:
            config.status = "broken"
            config.reason = str(e)

    async def worker(self, config: ProxyConfig, semaphore: asyncio.Semaphore):
        async with semaphore:
            if config.protocol == "wg":
                await self._test_wg_native(config)
            else:
                await self._test_xray_knife(config)

# ==============================================================================
# MODULE: REPORTER
# ==============================================================================

class Reporter:
    def __init__(self, prefix: str):
        self.prefix = prefix

    def generate_output(self, configs: List[ProxyConfig], limit: int) -> List[str]:
        # Filter only passed
        passed = [c for c in configs if c.status == "passed"]
        
        # Group by Protocol
        grouped = {}
        for c in passed:
            if c.protocol not in grouped:
                grouped[c.protocol] = []
            grouped[c.protocol].append(c)
        
        final_lines = []
        
        for proto, items in grouped.items():
            # Sort by Score (ascending = better)
            items.sort(key=lambda x: x.score)
            
            # Apply Limit
            selection = items[:limit]
            
            for idx, res in enumerate(selection, 1):
                flag = res.flag if res.flag else DEFAULT_FLAG
                
                # Construct Name: 🔒Prefix🦈[PROTO][ID][FLAG][SPEED?]
                alias = f"🔒{self.prefix}🦈[{proto.upper()}][{idx:02d}][{flag}]"
                if res.speed_dl > 0:
                    alias += f"[{res.speed_dl:.1f}M]"
                
                # Encode alias for URL fragment
                encoded_alias = urllib.parse.quote(alias)
                
                # Clean original config (remove existing fragment)
                base_config = res.original.split("#")[0]
                
                final_lines.append(f"{base_config}#{encoded_alias}")
        
        return final_lines

    def save_to_file(self, lines: List[str], path: str, fmt: str):
        content = "\n".join(lines)
        
        if fmt == "base64":
            content = base64.b64encode(content.encode('utf-8')).decode('utf-8')
            
        try:
            with open(path, "w", encoding='utf-8') as f:
                f.write(content)
            logger.info(f"Successfully saved {len(lines)} configs to {path} ({fmt})")
        except Exception as e:
            logger.error(f"Failed to write output file: {e}")

    def save_csv(self, configs: List[ProxyConfig], path: str):
        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                fieldnames = ["protocol", "status", "delay", "speed_dl", "ip", "country", "score", "reason", "original"]
                writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
                writer.writeheader()
                for c in configs:
                    writer.writerow(c.to_csv_dict())
            logger.info(f"CSV Report saved to {path}")
        except Exception as e:
            logger.error(f"Failed to write CSV: {e}")

# ==============================================================================
# UTILITIES & MAIN
# ==============================================================================

def find_executable(name: str, specific_path: Optional[str] = None) -> str:
    # 1. Check specific path provided by args
    if specific_path:
        p = Path(specific_path)
        if p.exists() and os.access(p, os.X_OK):
            return str(p.resolve())
    
    # 2. Check PATH
    found = shutil.which(name)
    if found:
        return found
    
    # 3. Check current directory
    local = Path(os.getcwd()) / name
    if local.exists() and os.access(local, os.X_OK):
        return str(local.resolve())
        
    return ""

def parse_cli_args():
    parser = argparse.ArgumentParser(description="Pr0xySh4rk: Advanced Proxy Config Processor")
    
    # I/O Groups
    io_group = parser.add_argument_group("Input/Output")
    io_group.add_argument("--input", required=True, help="Input file path")
    io_group.add_argument("--output", required=True, help="Output file path")
    io_group.add_argument("--output-format", choices=["text", "base64"], default="base64")
    io_group.add_argument("--csv", help="Optional path to save CSV details")
    
    # Settings Groups
    settings = parser.add_argument_group("Settings")
    settings.add_argument("--threads", type=int, default=30, help="Max concurrent checks")
    settings.add_argument("--limit", type=int, default=50, help="Max configs per protocol")
    settings.add_argument("--name-prefix", default="Pr0xySh4rk", help="Config alias prefix")
    
    # Testing Config
    testing = parser.add_argument_group("Testing")
    testing.add_argument("--xray-knife-path", help="Path to xray-knife binary")
    testing.add_argument("--geoip-db", help="Path to MaxMind DB")
    testing.add_argument("--speedtest", action="store_true", help="Enable bandwidth testing")
    
    # FIX: Explicitly handle the flag passed by GitHub Action
    testing.add_argument("--xray-knife-insecure", action="store_true", dest="insecure", 
                         help="Allow insecure TLS connections")
    
    # Compatibility arguments (to prevent crash if Action passes them)
    testing.add_argument("--speedtest-amount", help="Legacy argument (ignored)")
    
    return parser.parse_args()

async def async_main():
    args = parse_cli_args()
    
    # 1. Load Configurations
    loader = ConfigLoader(args.input)
    loader.load()
    loader.deduplicate()
    
    if not loader.configs:
        logger.warning("No valid configurations to test.")
        sys.exit(0)

    # 2. Setup Components
    geoip = GeoIPHandler(args.geoip_db)
    
    xray_bin = find_executable("xray-knife", args.xray_knife_path)
    if not xray_bin:
        logger.warning("xray-knife binary not found! Non-WireGuard protocols will fail.")
    
    tester = AsyncTester(
        xray_bin=xray_bin,
        geoip=geoip,
        speedtest=args.speedtest,
        insecure=args.insecure,
        timeout=DEFAULT_TIMEOUT_MS
    )
    
    # 3. Execution Loop
    logger.info(f"Starting async tests with {args.threads} threads...")
    
    semaphore = asyncio.Semaphore(args.threads)
    tasks = []
    
    for config in loader.configs:
        # Skip Xray protocols if binary is missing
        if config.protocol != "wg" and not xray_bin:
            config.status = "skipped"
            config.reason = "Binary missing"
            continue
            
        tasks.append(tester.worker(config, semaphore))
    
    if TQDM_AVAILABLE:
        # Nice progress bar
        for f in tqdm(asyncio.as_completed(tasks), total=len(tasks), unit="cfg", desc="Testing"):
            await f
    else:
        # Standard progress
        completed = 0
        total = len(tasks)
        for f in asyncio.as_completed(tasks):
            await f
            completed += 1
            if completed % 10 == 0 or completed == total:
                sys.stdout.write(f"\rTesting: {completed}/{total}")
                sys.stdout.flush()
        print("") # Newline

    # 4. Reporting
    reporter = Reporter(args.name_prefix)
    
    output_lines = reporter.generate_output(loader.configs, args.limit)
    reporter.save_to_file(output_lines, args.output, args.output_format)
    
    if args.csv:
        reporter.save_csv(loader.configs, args.csv)

    # Summary Log
    passed_count = len([c for c in loader.configs if c.status == "passed"])
    logger.info(f"Processing Complete. {passed_count}/{len(loader.configs)} working configs saved.")
    
    geoip.close()

def main():
    # Setup Signal Handling
    signal.signal(signal.SIGINT, lambda s, f: sys.exit(0))
    
    # Windows Selector Policy fix for Python 3.8+ on Windows
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    try:
        asyncio.run(async_main())
    except KeyboardInterrupt:
        logger.info("Interrupted by user.")
    except Exception as e:
        logger.exception(f"Unexpected runtime error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
