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
from dataclasses import dataclass, asdict
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

# Logging
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

# Regex for Xray-Knife Output
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
    score: float = float('inf')

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

    def close(self):
        """Safely closes the database reader"""
        if self.reader:
            try:
                self.reader.close()
            except:
                pass

# ==============================================================================
# MODULE: LOADER
# ==============================================================================

class ConfigLoader:
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.configs: List[ProxyConfig] = []

    def load(self):
        if not os.path.exists(self.filepath):
            logger.critical(f"Input file missing: {self.filepath}")
            sys.exit(1)

        try:
            with open(self.filepath, 'r', encoding='utf-8') as f:
                content = f.read().strip()
            
            # Recursive Base64 Decoding
            attempts = 0
            while attempts < 3:
                if "://" not in content[:100] and len(content) > 20 and "\n" not in content:
                    try:
                        pad = len(content) % 4
                        if pad: content += "=" * (4 - pad)
                        decoded = base64.b64decode(content).decode('utf-8', errors='ignore')
                        if decoded.isprintable():
                            content = decoded
                            attempts += 1
                            continue
                    except: break
                break

            for line in content.splitlines():
                self._parse_line(line)
                
            logger.info(f"Loaded {len(self.configs)} raw configurations.")

        except Exception as e:
            logger.critical(f"Load failed: {e}")
            sys.exit(1)

    def _parse_line(self, line: str):
        line = line.strip()
        if not line or line.startswith("#"): return

        proto = self._detect_protocol(line)
        if not proto: return

        try:
            parsed = urllib.parse.urlparse(line)
            host = parsed.hostname or "unknown"
            port = parsed.port or 0
            cfg = ProxyConfig(original=line, protocol=proto, host=host, port=port)
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
        unique_map = {}
        for cfg in self.configs:
            # Dedup Key: Protocol + Host + Port
            if cfg.host == "unknown": key = cfg.original
            else: key = f"{cfg.protocol}://{cfg.host}:{cfg.port}"
            
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

    async def verify_binary(self) -> bool:
        """Runs a version check to ensure xray-knife is executable"""
        if not self.xray_bin: return False
        try:
            # Run simple command
            proc = await asyncio.create_subprocess_exec(
                self.xray_bin, "version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await proc.communicate()
            return proc.returncode == 0
        except Exception as e:
            logger.error(f"Binary verification failed: {e}")
            return False

    async def test_wg_udp(self, config: ProxyConfig):
        """Native UDP Probe for WireGuard"""
        try:
            if config.host == "unknown" or not config.port: raise ValueError("Invalid Host/Port")

            loop = asyncio.get_running_loop()
            
            # DNS
            try:
                addr_info = await loop.getaddrinfo(config.host, config.port, type=socket.SOCK_DGRAM)
                target_ip = addr_info[0][4][0]
                family = addr_info[0][0]
            except:
                config.status = "failed"; config.reason = "DNS Error"; return

            # Socket
            start_time = loop.time()
            class Probe(asyncio.DatagramProtocol):
                def __init__(self): self.done = asyncio.Future()
                def connection_made(self, t): t.sendto(b'\x00\x00\x00\x00')
                def datagram_received(self, d, a): 
                    if not self.done.done(): self.done.set_result(True)
                def error_received(self, e): pass
                def connection_lost(self, e): pass

            try:
                transport, proto = await loop.create_datagram_endpoint(lambda: Probe(), remote_addr=(target_ip, config.port), family=family)
                await asyncio.wait_for(proto.done, timeout=2.0)
            except asyncio.TimeoutError: pass # Silent success possible for WG
            except Exception:
                config.status = "failed"; config.reason = "Unreachable"; return
            finally:
                if 'transport' in locals() and transport: transport.close()

            config.status = "passed"
            config.delay = (loop.time() - start_time) * 1000
            config.ip = target_ip
            config.country, config.flag = self.geoip.lookup(target_ip)
            config.score = config.delay

        except Exception as e:
            config.status = "broken"; config.reason = str(e)

    async def test_xray(self, config: ProxyConfig):
        cmd = [self.xray_bin, "net", "http", "-c", config.original, "-d", str(self.timeout), "--url", DEFAULT_TEST_URL, "-z", "auto", "-v"]
        if self.speedtest: cmd.extend(["-p", "-a", "2000"])
        if self.insecure: cmd.append("-e")
        if not self.geoip.reader: cmd.append("--rip")

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env={**os.environ, "WSL_INTEROP": ""}
            )
            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=(self.timeout/1000)+3)
            except asyncio.TimeoutError:
                try: proc.kill()
                except: pass
                config.status = "timeout"; return

            output = (stdout.decode('utf-8', errors='ignore') + stderr.decode('utf-8', errors='ignore'))

            delay_m = RE_DELAY.search(output)
            if delay_m:
                config.delay = float(delay_m.group(1))
                config.status = "passed"
            else:
                config.status = "failed"
                config.reason = "Connection Failed"
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
                if ip_m.group('loc'): config.country, config.flag = ip_m.group('loc'), COUNTRY_FLAGS.get(ip_m.group('loc').upper(), DEFAULT_FLAG)
            
            if self.geoip.reader and config.ip:
                c, f = self.geoip.lookup(config.ip)
                if c: config.country, config.flag = c, f

            # Score Calculation
            config.score = config.delay / (1.0 + config.speed_dl) if config.speed_dl > 0 else config.delay

        except Exception as e:
            config.status = "broken"; config.reason = str(e)

    async def worker(self, config: ProxyConfig, sem: asyncio.Semaphore):
        async with sem:
            if config.protocol == "wg":
                await self.test_wg_udp(config)
            else:
                await self.test_xray(config)

# ==============================================================================
# MAIN UTILS
# ==============================================================================

def resolve_binary_path(name: str, arg_path: Optional[str]) -> str:
    """Finds binary and returns absolute path"""
    # 1. Argument Path
    if arg_path:
        p = Path(arg_path).resolve()
        if p.exists(): return str(p)
    
    # 2. Local Directory
    local = Path(os.getcwd()) / name
    if local.exists(): return str(local.resolve())

    # 3. PATH Environment
    found = shutil.which(name)
    if found: return str(Path(found).resolve())
    
    return ""

async def async_main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--output-format", choices=["text", "base64"], default="base64")
    parser.add_argument("--csv")
    parser.add_argument("--xray-knife-path")
    parser.add_argument("--geoip-db")
    parser.add_argument("--threads", type=int, default=30)
    parser.add_argument("--limit", type=int, default=50)
    parser.add_argument("--speedtest", action="store_true")
    parser.add_argument("--xray-knife-insecure", action="store_true", dest="insecure")
    parser.add_argument("--name-prefix", default="Pr0xySh4rk")
    parser.add_argument("--speedtest-amount") # Compatibility
    args = parser.parse_args()
    
    # 1. Load Data
    loader = ConfigLoader(args.input)
    loader.load()
    loader.deduplicate()
    if not loader.configs: sys.exit(0)

    # 2. Verify Binary
    xray_bin = resolve_binary_path("xray-knife", args.xray_knife_path)
    
    if not xray_bin:
        # Debugging Output
        logger.critical("xray-knife binary NOT FOUND.")
        logger.info(f"Current Directory ({os.getcwd()}):")
        for f in os.listdir("."): logger.info(f" - {f}")
        logger.critical("Cannot proceed with Xray protocols. Aborting.")
        sys.exit(1)
        
    logger.info(f"Using xray-knife at: {xray_bin}")
    os.chmod(xray_bin, 0o755) # Ensure executable

    # 3. Setup Tester
    geoip = GeoIPHandler(args.geoip_db)
    tester = Tester(xray_bin, geoip, args.speedtest, args.insecure, DEFAULT_TIMEOUT_MS)

    # 4. Pre-flight Check
    logger.info("Verifying binary execution...")
    if not await tester.verify_binary():
        logger.critical("xray-knife failed to execute (permission or bad binary).")
        sys.exit(1)
    
    # 5. Run Tests
    sem = asyncio.Semaphore(args.threads)
    tasks = [tester.worker(c, sem) for c in loader.configs]
    
    logger.info(f"Running {len(tasks)} tests with {args.threads} threads...")
    
    if TQDM_AVAILABLE:
        for f in tqdm(asyncio.as_completed(tasks), total=len(tasks), unit="cfg"): await f
    else:
        done = 0
        total = len(tasks)
        for f in asyncio.as_completed(tasks):
            await f
            done += 1
            if done % 100 == 0: sys.stdout.write(f"\rProgress: {done}/{total}"); sys.stdout.flush()
        print("")

    # 6. Report
    # Sort and filter inside generate_output
    reporter = Reporter(args.name_prefix)
    final_lines = reporter.generate_output(loader.configs, args.limit)
    
    if final_lines:
        reporter.save_to_file(final_lines, args.output, args.output_format)
        logger.info(f"Saved {len(final_lines)} configs.")
    else:
        logger.warning("No working configs found.")

    if args.csv: reporter.save_csv(loader.configs, args.csv)
    geoip.close()

# MODULE: REPORTER (Included inside)
class Reporter:
    def __init__(self, prefix: str): self.prefix = prefix
    def generate_output(self, configs: List[ProxyConfig], limit: int) -> List[str]:
        passed = [c for c in configs if c.status == "passed"]
        grouped = {}
        for c in passed: grouped.setdefault(c.protocol, []).append(c)
        
        final = []
        for proto, items in grouped.items():
            items.sort(key=lambda x: x.score)
            selection = items[:limit]
            logger.info(f"Protocol {proto.upper()}: {len(selection)}/{len(items)} saved.")
            
            for idx, res in enumerate(selection, 1):
                flag = res.flag or DEFAULT_FLAG
                alias = f"🔒{self.prefix}🦈[{proto.upper()}][{idx:02d}][{flag}]"
                if res.speed_dl > 0: alias += f"[{res.speed_dl:.1f}M]"
                encoded = urllib.parse.quote(alias)
                base = res.original.split("#")[0]
                final.append(f"{base}#{encoded}")
        return final
    def save_to_file(self, lines, path, fmt):
        c = "\n".join(lines)
        if fmt=="base64": c = base64.b64encode(c.encode('utf-8')).decode('utf-8')
        with open(path, "w", encoding='utf-8') as f: f.write(c)
    def save_csv(self, configs, path):
        try:
            import csv
            with open(path, "w", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=["protocol","status","delay","speed","country","score","host","port","original"], extrasaction='ignore')
                w.writeheader()
                for c in configs: w.writerow(c.to_csv())
        except: pass

def main():
    signal.signal(signal.SIGINT, lambda s, f: sys.exit(0))
    if sys.platform == 'win32': asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    try: asyncio.run(async_main())
    except KeyboardInterrupt: pass
    except Exception as e: logger.exception(f"Fatal: {e}"); sys.exit(1)

if __name__ == "__main__":
    main()
