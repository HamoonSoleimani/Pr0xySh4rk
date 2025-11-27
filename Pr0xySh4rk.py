#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import asyncio
import base64
import csv
import hashlib
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
# CONFIGURATION
# ==============================================================================

# Logging Setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)8s | %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger("Pr0xySh4rk")

# Flags
COUNTRY_FLAGS = {
    "US": "🇺🇸", "DE": "🇩🇪", "NL": "🇳🇱", "GB": "🇬🇧", "FR": "🇫🇷", "CA": "🇨🇦", "JP": "🇯🇵",
    "SG": "🇸🇬", "HK": "🇭🇰", "AU": "🇦🇺", "CH": "🇨🇭", "SE": "🇸🇪", "FI": "🇫🇮", "NO": "🇳🇴",
    "IE": "🇮🇪", "IT": "🇮🇹", "ES": "🇪🇸", "PL": "🇵🇱", "RO": "🇷🇴", "TR": "🇹🇷", "RU": "🇷🇺",
    "UA": "🇺🇦", "IR": "🇮🇷", "AE": "🇦🇪", "CN": "🇨🇳", "IN": "🇮🇳", "BR": "🇧🇷", "ZA": "🇿🇦",
    "KR": "🇰🇷", "TW": "🇹🇼", "VN": "🇻🇳", "ID": "🇮🇩", "MY": "🇲🇾", "TH": "🇹🇭", "KZ": "🇰🇿",
    "SA": "🇸🇦", "EG": "🇪🇬", "IL": "🇮🇱", "PK": "🇵🇰", "PH": "🇵🇭"
}
DEFAULT_FLAG = "🚩"

# Regex Patterns
RE_DELAY = re.compile(r"(?:Real Delay|Latency)\s*[:=]\s*(\d+)\s*ms", re.IGNORECASE)
RE_DOWNLOAD = re.compile(r"Downloaded.*?Speed\s*[:=]\s*([\d\.]+)\s*([KMG]?)bps", re.IGNORECASE)
RE_IP_LOC = re.compile(r"ip=(?P<ip>[\d\.a-fA-F:]+).*?loc=(?P<loc>[A-Z]{2})", re.IGNORECASE | re.DOTALL)

DEFAULT_TEST_URL = "https://cp.cloudflare.com/"
DEFAULT_TIMEOUT_MS = 5000

# ==============================================================================
# DATA MODELS
# ==============================================================================

@dataclass
class ProxyConfig:
    original: str
    protocol: str
    host: str
    port: int
    status: str = "pending"
    reason: str = ""
    delay: float = float('inf')
    speed_dl: float = 0.0
    ip: str = ""
    country: str = ""
    flag: str = ""
    score: float = float('inf')  # Lower is better

    def to_csv(self):
        return {
            "protocol": self.protocol,
            "status": self.status,
            "delay": f"{self.delay:.0f}",
            "speed": f"{self.speed_dl:.2f}",
            "country": self.country,
            "score": f"{self.score:.2f}",
            "host": self.host,
            "port": self.port,
            "original": self.original
        }

# ==============================================================================
# MODULE: GEOIP
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

    def lookup(self, ip: str) -> Tuple[str, str]:
        if not self.reader or not ip:
            return "", DEFAULT_FLAG
        try:
            record = self.reader.country(ip.strip("[]"))
            iso = record.country.iso_code
            if iso:
                return iso, COUNTRY_FLAGS.get(iso.upper(), DEFAULT_FLAG)
        except:
            pass
        return "", DEFAULT_FLAG

# ==============================================================================
# MODULE: LOADER & PARSER
# ==============================================================================

class ConfigLoader:
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.configs: List[ProxyConfig] = []

    def load(self):
        if not os.path.exists(self.filepath):
            logger.critical(f"Input file not found: {self.filepath}")
            sys.exit(1)

        try:
            with open(self.filepath, 'r', encoding='utf-8') as f:
                content = f.read().strip()
            
            # Recursive Base64 Decoding
            # Sometimes we have Base64 inside Base64
            attempts = 0
            while attempts < 3:
                # If no spaces and no "://", likely base64
                if "://" not in content[:100] and len(content) > 20 and "\n" not in content:
                    try:
                        # Fix padding
                        pad = len(content) % 4
                        if pad: content += "=" * (4 - pad)
                        decoded = base64.b64decode(content).decode('utf-8', errors='ignore')
                        if decoded.isprintable():
                            content = decoded
                            attempts += 1
                            continue
                    except:
                        break
                break

            lines = content.splitlines()
            for line in lines:
                self._parse_line(line)
                
            logger.info(f"Loaded {len(self.configs)} raw configurations.")

        except Exception as e:
            logger.critical(f"Failed to load configs: {e}")
            sys.exit(1)

    def _parse_line(self, line: str):
        line = line.strip()
        if not line or line.startswith("#"): return

        proto = self._detect_protocol(line)
        if not proto: return

        try:
            # Parse URL to get Host/Port for Deduplication
            # Some protocols like ss:// might need special handling, but urlparse works for most
            parsed = urllib.parse.urlparse(line)
            host = parsed.hostname
            port = parsed.port
            
            # Fallback for complex URIs (like Vmess JSON in base64)
            if not host:
                host = "unknown"
                port = 0
            
            cfg = ProxyConfig(original=line, protocol=proto, host=host, port=port or 0)
            self.configs.append(cfg)
        except:
            pass

    def _detect_protocol(self, line: str) -> Optional[str]:
        lower = line.lower()
        if lower.startswith("vmess://"): return "vmess"
        if lower.startswith("vless://"): return "vless"
        if lower.startswith("trojan://"): return "trojan"
        if lower.startswith("ss://"): return "ss"
        if lower.startswith("ssr://"): return "ssr"
        if lower.startswith("tuic://"): return "tuic"
        if lower.startswith(("hysteria://", "hysteria2://", "hy2://")): return "hysteria"
        if lower.startswith(("wg://", "wireguard://", "warp://")): return "wg"
        return None

    def deduplicate(self):
        """
        Deduplicates based on a hash of (Protocol + Host + Port).
        This removes duplicates even if the config string (remarks) differs.
        """
        unique_map = {}
        
        for cfg in self.configs:
            # Create a robust unique key
            # We ignore the 'path' and 'query' for dedup to be aggressive against spam
            # unless it's WS/GRPC where path matters. 
            # For simplicity and robustness, strict host:port dedup is usually best.
            if cfg.host == "unknown":
                key = cfg.original # fallback
            else:
                key = f"{cfg.protocol}://{cfg.host}:{cfg.port}"
            
            key_hash = hashlib.md5(key.encode()).hexdigest()
            
            if key_hash not in unique_map:
                unique_map[key_hash] = cfg
        
        removed = len(self.configs) - len(unique_map)
        self.configs = list(unique_map.values())
        logger.info(f"Deduplication removed {removed} duplicates. Active: {len(self.configs)}")

# ==============================================================================
# MODULE: TESTER
# ==============================================================================

class Tester:
    def __init__(self, xray_bin: str, geoip: GeoIPHandler, speedtest: bool, insecure: bool, timeout: int):
        self.xray_bin = xray_bin
        self.geoip = geoip
        self.speedtest = speedtest
        self.insecure = insecure
        self.timeout = timeout

    async def test_wg_udp(self, config: ProxyConfig):
        """
        Native Python UDP Test for WireGuard.
        Checks if DNS resolves and if the UDP port accepts traffic.
        """
        try:
            if config.host == "unknown" or not config.port:
                raise ValueError("Invalid Host/Port")

            loop = asyncio.get_running_loop()
            
            # 1. DNS Resolution
            try:
                addr_info = await loop.getaddrinfo(config.host, config.port, type=socket.SOCK_DGRAM)
                target_ip = addr_info[0][4][0]
                family = addr_info[0][0]
            except Exception:
                config.status = "failed"
                config.reason = "DNS Error"
                return

            # 2. UDP Socket Probe
            start_time = loop.time()
            
            class ProbeProto(asyncio.DatagramProtocol):
                def __init__(self):
                    self.transport = None
                    self.done = asyncio.Future()
                def connection_made(self, transport):
                    self.transport = transport
                    # Send empty packet
                    self.transport.sendto(b'\x00\x00\x00\x00')
                def datagram_received(self, data, addr):
                    if not self.done.done(): self.done.set_result(True)
                def error_received(self, exc):
                    pass # ICMP unreachable might trigger this
                def connection_lost(self, exc):
                    pass

            try:
                transport, protocol = await loop.create_datagram_endpoint(
                    lambda: ProbeProto(),
                    remote_addr=(target_ip, config.port),
                    family=family
                )
                
                # WG is silent. If we don't get an ICMP error in 2 seconds, assume reachable.
                # If we DO get data back, even better.
                try:
                    await asyncio.wait_for(protocol.done, timeout=2.0)
                except asyncio.TimeoutError:
                    pass # No response is normal for WG, but no error means port isn't explicitly closed/rejected
                
            except Exception:
                config.status = "failed"
                config.reason = "Unreachable"
                if 'transport' in locals() and transport: transport.close()
                return

            if 'transport' in locals() and transport: transport.close()

            # Success
            config.status = "passed"
            config.delay = (loop.time() - start_time) * 1000
            config.ip = target_ip
            
            # GeoIP
            config.country, config.flag = self.geoip.lookup(target_ip)
            
            # Score
            config.score = config.delay

        except Exception as e:
            config.status = "broken"
            config.reason = str(e)

    async def test_xray(self, config: ProxyConfig):
        """
        Executes xray-knife in a subprocess.
        """
        cmd = [
            self.xray_bin, "net", "http",
            "-c", config.original,
            "-d", str(self.timeout),
            "--url", DEFAULT_TEST_URL,
            "-z", "auto",
            "-v"
        ]
        
        if self.speedtest:
            cmd.extend(["-p", "-a", "2000"]) # 2MB speedtest
        
        if self.insecure:
            cmd.append("-e")
            
        if not self.geoip.reader:
            cmd.append("--rip")

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                # Sanitize env for WSL/Linux compatibility
                env={**os.environ, "WSL_INTEROP": ""}
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), 
                    timeout=(self.timeout / 1000) + 5
                )
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
                # Simple reason extraction
                if "timeout" in output.lower(): config.reason = "Timeout"
                else: config.reason = "Connect Failed"
                return

            dl_m = RE_DOWNLOAD.search(output)
            if dl_m:
                val, unit = float(dl_m.group(1)), dl_m.group(2).upper()
                mult = 1.0
                if unit == 'K': mult = 0.001
                elif unit == 'G': mult = 1000.0
                config.speed_dl = val * mult

            ip_m = RE_IP_LOC.search(output)
            if ip_m:
                config.ip = ip_m.group('ip')
                if ip_m.group('loc'):
                    config.country = ip_m.group('loc')
                    config.flag = COUNTRY_FLAGS.get(config.country.upper(), DEFAULT_FLAG)
            
            # Local GeoIP Override
            if self.geoip.reader and config.ip:
                c, f = self.geoip.lookup(config.ip)
                if c: config.country, config.flag = c, f

            # Scoring: Lower is better
            if config.speed_dl > 0:
                config.score = config.delay / (1.0 + config.speed_dl)
            else:
                config.score = config.delay

        except Exception as e:
            config.status = "broken"
            config.reason = str(e)

    async def worker(self, config: ProxyConfig, sem: asyncio.Semaphore):
        async with sem:
            if config.protocol == "wg":
                await self.test_wg_udp(config)
            else:
                await self.test_xray(config)

# ==============================================================================
# MODULE: REPORTER
# ==============================================================================

class Reporter:
    def __init__(self, prefix: str):
        self.prefix = prefix

    def generate_output(self, configs: List[ProxyConfig], limit: int) -> List[str]:
        # Filter passed
        passed = [c for c in configs if c.status == "passed"]
        
        # Group by Protocol
        grouped = {}
        for c in passed:
            if c.protocol not in grouped: grouped[c.protocol] = []
            grouped[c.protocol].append(c)
        
        final_lines = []
        
        # Sort and Limit PER PROTOCOL
        for proto, items in grouped.items():
            # Sort: Low Score (Better) -> High Score
            items.sort(key=lambda x: x.score)
            
            # Apply Limit
            selected = items[:limit]
            
            logger.info(f"Protocol {proto.upper()}: Found {len(items)}, Saving top {len(selected)}")
            
            for idx, res in enumerate(selected, 1):
                flag = res.flag or DEFAULT_FLAG
                
                # Name: 🔒Prefix🦈[PROTO][ID][FLAG][SPEED]
                alias = f"🔒{self.prefix}🦈[{proto.upper()}][{idx:02d}][{flag}]"
                if res.speed_dl > 0:
                    alias += f"[{res.speed_dl:.1f}M]"
                
                # Encode alias
                encoded = urllib.parse.quote(alias)
                
                # Reconstruct config string with new fragment
                if "#" in res.original:
                    base = res.original.split("#", 1)[0]
                else:
                    base = res.original
                    
                final_lines.append(f"{base}#{encoded}")
                
        return final_lines

    def save_file(self, lines: List[str], path: str, fmt: str):
        content = "\n".join(lines)
        if fmt == "base64":
            content = base64.b64encode(content.encode('utf-8')).decode('utf-8')
        
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)
        except Exception as e:
            logger.error(f"Save failed: {e}")

    def save_csv(self, configs: List[ProxyConfig], path: str):
        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                fieldnames = ["protocol", "status", "delay", "speed", "country", "score", "original"]
                writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
                writer.writeheader()
                for c in configs:
                    writer.writerow(c.to_csv())
        except Exception as e:
            logger.error(f"CSV Save failed: {e}")

# ==============================================================================
# MAIN UTILS
# ==============================================================================

def find_binary(name: str, specific_path: str = None) -> str:
    if specific_path and os.path.exists(specific_path):
        return str(Path(specific_path).resolve())
    
    found = shutil.which(name)
    if found: return found
    
    local = Path(os.getcwd()) / name
    if local.exists(): return str(local.resolve())
    
    return ""

def parse_args():
    parser = argparse.ArgumentParser()
    
    # IO
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--output-format", choices=["text", "base64"], default="base64")
    parser.add_argument("--csv")
    
    # Testing
    parser.add_argument("--xray-knife-path")
    parser.add_argument("--geoip-db")
    parser.add_argument("--threads", type=int, default=30)
    parser.add_argument("--limit", type=int, default=50)
    parser.add_argument("--speedtest", action="store_true")
    
    # Handle the specific workflow argument that caused error previously
    parser.add_argument("--xray-knife-insecure", action="store_true", dest="insecure")
    
    # Meta
    parser.add_argument("--name-prefix", default="Pr0xySh4rk")
    
    # Ignored legacy args to prevent crashes
    parser.add_argument("--speedtest-amount")

    return parser.parse_args()

async def async_main():
    args = parse_args()
    
    # 1. Load & Dedup
    loader = ConfigLoader(args.input)
    loader.load()
    loader.deduplicate()
    
    if not loader.configs:
        logger.error("No configs to test.")
        sys.exit(0)

    # 2. Prepare Tools
    xray_bin = find_binary("xray-knife", args.xray_knife_path)
    if not xray_bin:
        logger.critical("xray-knife binary NOT FOUND.")
        # We allow running, but only WG will work.
        
    geoip = GeoIPHandler(args.geoip_db)
    
    tester = Tester(
        xray_bin=xray_bin,
        geoip=geoip,
        speedtest=args.speedtest,
        insecure=args.insecure,
        timeout=DEFAULT_TIMEOUT_MS
    )

    # 3. Queue Tasks
    tasks = []
    # Create Semaphore to limit concurrency (CRITICAL for large lists)
    sem = asyncio.Semaphore(args.threads)
    
    logger.info(f"Queueing {len(loader.configs)} tests with {args.threads} threads...")
    
    for cfg in loader.configs:
        # If protocol is NOT WireGuard, we need xray-knife.
        if cfg.protocol != "wg" and not xray_bin:
            cfg.status = "skipped"
            cfg.reason = "Binary missing"
            continue
            
        tasks.append(tester.worker(cfg, sem))

    # 4. Execute
    start_time = time.time()
    
    if TQDM_AVAILABLE:
        for f in tqdm(asyncio.as_completed(tasks), total=len(tasks), unit="cfg"):
            await f
    else:
        done = 0
        total = len(tasks)
        for f in asyncio.as_completed(tasks):
            await f
            done += 1
            if done % 50 == 0:
                sys.stdout.write(f"\rProgress: {done}/{total}")
                sys.stdout.flush()
        print("")

    duration = time.time() - start_time
    logger.info(f"Testing finished in {duration:.2f} seconds.")

    # 5. Report
    reporter = Reporter(args.name_prefix)
    final_lines = reporter.generate_output(loader.configs, args.limit)
    
    if not final_lines:
        logger.warning("No configs passed the tests.")
    else:
        logger.info(f"Saving {len(final_lines)} unique, tested configs to {args.output}")
        reporter.save_file(final_lines, args.output, args.output_format)

    if args.csv:
        reporter.save_csv(loader.configs, args.csv)
        
    geoip.close()

def main():
    signal.signal(signal.SIGINT, lambda s, f: sys.exit(0))
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    try:
        asyncio.run(async_main())
    except KeyboardInterrupt:
        logger.info("Process Interrupted.")
    except Exception as e:
        logger.exception(f"Critical Runtime Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
