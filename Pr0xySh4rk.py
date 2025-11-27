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
from typing import List, Tuple, Optional

# ==============================================================================
# DEPENDENCIES
# ==============================================================================
try:
    import geoip2.database
    GEOIP_AVAILABLE = True
except ImportError:
    GEOIP_AVAILABLE = False

try:
    from tqdm.asyncio import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False

# ==============================================================================
# CONSTANTS
# ==============================================================================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)8s | %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger("Pr0xySh4rk")

# ANSI Color Code Regex (To clean output)
RE_ANSI = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

# Result Parsing Regex
RE_DELAY = re.compile(r"(?:Real Delay|Latency|RTT)\s*[:=]\s*(\d+)\s*ms", re.IGNORECASE)
RE_DOWNLOAD = re.compile(r"Downloaded.*?Speed\s*[:=]\s*([\d\.]+)\s*([KMG]?)bps", re.IGNORECASE)
RE_IP_LOC = re.compile(r"ip=(?P<ip>[\d\.a-fA-F:]+).*?loc=(?P<loc>[A-Z]{2})", re.IGNORECASE | re.DOTALL)

COUNTRY_FLAGS = {
    "US": "🇺🇸", "DE": "🇩🇪", "NL": "🇳🇱", "GB": "🇬🇧", "FR": "🇫🇷", "CA": "🇨🇦", "JP": "🇯🇵",
    "SG": "🇸🇬", "HK": "🇭🇰", "AU": "🇦🇺", "CH": "🇨🇭", "SE": "🇸🇪", "FI": "🇫🇮", "NO": "🇳🇴",
    "IE": "🇮🇪", "IT": "🇮🇹", "ES": "🇪🇸", "PL": "🇵🇱", "RO": "🇷🇴", "TR": "🇹🇷", "RU": "🇷🇺",
    "UA": "🇺🇦", "IR": "🇮🇷", "AE": "🇦🇪", "CN": "🇨🇳", "IN": "🇮🇳", "BR": "🇧🇷", "ZA": "🇿🇦",
    "KR": "🇰🇷", "TW": "🇹🇼", "VN": "🇻🇳", "ID": "🇮🇩", "MY": "🇲🇾", "TH": "🇹🇭", "KZ": "🇰🇿",
    "SA": "🇸🇦", "EG": "🇪🇬", "IL": "🇮🇱", "PK": "🇵🇰", "PH": "🇵🇭"
}
DEFAULT_FLAG = "🚩"
DEFAULT_TEST_URL = "https://cp.cloudflare.com/"
DEFAULT_TIMEOUT_MS = 6000 # Increased slightly

# ==============================================================================
# MODELS
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
            "original": self.original
        }

# ==============================================================================
# HELPERS
# ==============================================================================
def strip_ansi(text: str) -> str:
    return RE_ANSI.sub('', text)

class GeoIPHandler:
    def __init__(self, db_path: Optional[str]):
        self.reader = None
        if GEOIP_AVAILABLE and db_path and os.path.exists(db_path):
            try:
                self.reader = geoip2.database.Reader(db_path)
            except: pass

    def lookup(self, ip: str) -> Tuple[str, str]:
        if not self.reader or not ip: return "", DEFAULT_FLAG
        try:
            r = self.reader.country(ip.strip("[]"))
            iso = r.country.iso_code
            if iso: return iso, COUNTRY_FLAGS.get(iso.upper(), DEFAULT_FLAG)
        except: pass
        return "", DEFAULT_FLAG

    def close(self):
        if self.reader:
            try: self.reader.close()
            except: pass

# ==============================================================================
# LOADER
# ==============================================================================
class ConfigLoader:
    def __init__(self, filepath: str):
        self.configs = []
        self.filepath = filepath

    def load(self):
        if not os.path.exists(self.filepath): sys.exit(1)
        with open(self.filepath, 'r', encoding='utf-8') as f: content = f.read().strip()
        
        # Base64 Recursion
        for _ in range(3):
            if "://" not in content[:100] and len(content)>20 and "\n" not in content:
                try:
                    pad = len(content)%4
                    if pad: content += "="*(4-pad)
                    decoded = base64.b64decode(content).decode('utf-8', errors='ignore')
                    if decoded.isprintable(): content = decoded
                except: break
            else: break

        for line in content.splitlines():
            self._parse(line)

    def _parse(self, line: str):
        line = line.strip()
        if not line or line.startswith("#"): return
        
        proto = None
        l = line.lower()
        if l.startswith("vmess://"): proto = "vmess"
        elif l.startswith("vless://"): proto = "vless"
        elif l.startswith("trojan://"): proto = "trojan"
        elif l.startswith("ss://"): proto = "ss"
        elif l.startswith("ssr://"): proto = "ssr"
        elif l.startswith("tuic://"): proto = "tuic"
        elif l.startswith(("hysteria://", "hysteria2://", "hy2://")): proto = "hysteria"
        elif l.startswith(("wg://", "wireguard://", "warp://")): proto = "wg"
        
        if proto:
            try:
                p = urllib.parse.urlparse(line)
                host = p.hostname or "unknown"
                port = p.port or 0
                self.configs.append(ProxyConfig(line, proto, host, port))
            except: pass

    def deduplicate(self):
        uniq = {}
        for c in self.configs:
            k = f"{c.protocol}://{c.host}:{c.port}" if c.host != "unknown" else c.original
            h = hashlib.md5(k.encode()).hexdigest()
            if h not in uniq: uniq[h] = c
        self.configs = list(uniq.values())
        logger.info(f"Loaded {len(self.configs)} unique configs.")

# ==============================================================================
# TESTER
# ==============================================================================
class Tester:
    def __init__(self, xray_bin, geoip, speedtest, insecure):
        self.xray_bin = xray_bin
        self.geoip = geoip
        self.speedtest = speedtest
        self.insecure = insecure

    async def verify_bin(self):
        if not self.xray_bin: return False
        try:
            # Check help to ensure binary runs
            p = await asyncio.create_subprocess_exec(
                self.xray_bin, "--help", 
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            await p.communicate()
            return True
        except: return False

    async def test_wg(self, c: ProxyConfig):
        # Native Python UDP test
        try:
            if c.host == "unknown": raise ValueError("No host")
            loop = asyncio.get_running_loop()
            
            # DNS
            try:
                ai = await loop.getaddrinfo(c.host, c.port, type=socket.SOCK_DGRAM)
                ip = ai[0][4][0]
                fam = ai[0][0]
            except: 
                c.status = "failed"; c.reason="DNS"; return

            # Probe
            t0 = loop.time()
            class P(asyncio.DatagramProtocol):
                def __init__(self): self.f = asyncio.Future()
                def connection_made(self, t): t.sendto(b'\x00'*4)
                def datagram_received(self, d, a): 
                    if not self.f.done(): self.f.set_result(True)
                def error_received(self, e): pass
            
            try:
                tr, pr = await loop.create_datagram_endpoint(lambda: P(), remote_addr=(ip, c.port), family=fam)
                await asyncio.wait_for(pr.f, timeout=2.0)
            except asyncio.TimeoutError: pass 
            except: 
                c.status="failed"; c.reason="Unreachable"
                if 'tr' in locals() and tr: tr.close()
                return
            
            if 'tr' in locals() and tr: tr.close()
            
            c.status = "passed"
            c.delay = (loop.time() - t0) * 1000
            c.ip = ip
            c.country, c.flag = self.geoip.lookup(ip)
            c.score = c.delay

        except Exception as e:
            c.status = "broken"; c.reason = str(e)

    async def test_xray(self, c: ProxyConfig):
        # Subprocess Xray-Knife
        cmd = [self.xray_bin, "net", "http", "-c", c.original, "-d", str(DEFAULT_TIMEOUT_MS), "--url", DEFAULT_TEST_URL, "-z", "auto", "-v"]
        if self.speedtest: cmd.extend(["-p", "-a", "2000"])
        if self.insecure: cmd.append("-e")
        if not self.geoip.reader: cmd.append("--rip")

        try:
            # Must add current dir to PATH for xray-core finding
            env = os.environ.copy()
            env["PATH"] = f"{env.get('PATH', '')}:{os.getcwd()}"
            env["WSL_INTEROP"] = ""

            proc = await asyncio.create_subprocess_exec(
                *cmd, 
                stdout=asyncio.subprocess.PIPE, 
                stderr=asyncio.subprocess.PIPE,
                env=env
            )
            
            try:
                out, err = await asyncio.wait_for(proc.communicate(), timeout=DEFAULT_TIMEOUT_MS/1000 + 5)
            except asyncio.TimeoutError:
                try: proc.kill() 
                except: pass
                c.status = "timeout"; return

            # Decode and Clean Colors
            raw_output = (out.decode('utf-8', 'ignore') + err.decode('utf-8', 'ignore'))
            clean_output = strip_ansi(raw_output)

            # Match
            dm = RE_DELAY.search(clean_output)
            if dm:
                c.delay = float(dm.group(1))
                c.status = "passed"
            else:
                c.status = "failed"
                # Debug reason
                if "timeout" in clean_output.lower(): c.reason = "Timeout"
                elif "unsupported" in clean_output.lower(): c.reason = "Proto Unsupported"
                else: c.reason = "Fail"
                return

            # Speed
            sm = RE_DOWNLOAD.search(clean_output)
            if sm:
                val, unit = float(sm.group(1)), sm.group(2).upper()
                c.speed_dl = val * (1000 if unit == 'G' else 0.001 if unit == 'K' else 1)

            # IP
            im = RE_IP_LOC.search(clean_output)
            if im:
                c.ip = im.group('ip')
                if im.group('loc'): c.country, c.flag = im.group('loc'), COUNTRY_FLAGS.get(im.group('loc').upper(), DEFAULT_FLAG)

            # Local GeoIP override
            if self.geoip.reader and c.ip:
                cc, ff = self.geoip.lookup(c.ip)
                if cc: c.country, c.flag = cc, ff

            # Scoring
            c.score = c.delay / (1 + c.speed_dl) if c.speed_dl > 0 else c.delay

        except Exception as e:
            c.status = "broken"; c.reason = str(e)

    async def worker(self, c, sem):
        async with sem:
            if c.protocol == "wg": await self.test_wg(c)
            else: await self.test_xray(c)

# ==============================================================================
# MAIN
# ==============================================================================
class Reporter:
    def __init__(self, prefix): self.prefix = prefix
    
    def report(self, configs, limit, path, fmt):
        passed = [c for c in configs if c.status == "passed"]
        grouped = {}
        for c in passed: grouped.setdefault(c.protocol, []).append(c)
        
        final = []
        for p, items in grouped.items():
            items.sort(key=lambda x: x.score)
            sel = items[:limit]
            logger.info(f"Protocol {p.upper()}: {len(sel)}/{len(items)} passed/saved.")
            for i, c in enumerate(sel, 1):
                flag = c.flag or DEFAULT_FLAG
                alias = f"🔒{self.prefix}🦈[{p.upper()}][{i:02d}][{flag}]"
                if c.speed_dl > 0: alias += f"[{c.speed_dl:.1f}M]"
                enc = urllib.parse.quote(alias)
                base = c.original.split("#")[0]
                final.append(f"{base}#{enc}")
        
        if not final:
            logger.warning("No working configs.")
            return

        data = "\n".join(final)
        if fmt == "base64": data = base64.b64encode(data.encode()).decode()
        
        with open(path, 'w', encoding='utf-8') as f: f.write(data)
        logger.info(f"Saved {len(final)} configs to {path}")

    def csv(self, configs, path):
        try:
            with open(path, 'w', newline='', encoding='utf-8') as f:
                w = csv.DictWriter(f, fieldnames=["protocol","status","delay","speed","country","score","host","original"], extrasaction='ignore')
                w.writeheader()
                for c in configs: w.writerow(c.to_csv())
        except: pass

async def async_main():
    p = argparse.ArgumentParser()
    p.add_argument("--input", required=True)
    p.add_argument("--output", required=True)
    p.add_argument("--output-format", default="base64")
    p.add_argument("--csv")
    p.add_argument("--xray-knife-path")
    p.add_argument("--geoip-db")
    p.add_argument("--threads", type=int, default=40)
    p.add_argument("--limit", type=int, default=50)
    p.add_argument("--speedtest", action="store_true")
    p.add_argument("--xray-knife-insecure", action="store_true", dest="insecure")
    p.add_argument("--name-prefix", default="Pr0xySh4rk")
    p.add_argument("--speedtest-amount")
    args = p.parse_args()

    loader = ConfigLoader(args.input)
    loader.load()
    loader.deduplicate()
    if not loader.configs: sys.exit(0)

    # Bin check
    xray_bin = ""
    if args.xray_knife_path and os.path.exists(args.xray_knife_path):
        xray_bin = str(Path(args.xray_knife_path).resolve())
    elif shutil.which("xray-knife"):
        xray_bin = shutil.which("xray-knife")
    elif os.path.exists("xray-knife"):
        xray_bin = str(Path("xray-knife").resolve())

    if not xray_bin:
        logger.critical("xray-knife not found. Exiting.")
        sys.exit(1)

    geoip = GeoIPHandler(args.geoip_db)
    tester = Tester(xray_bin, geoip, args.speedtest, args.insecure)

    if not await tester.verify_bin():
        logger.critical("Binary verification failed.")
        sys.exit(1)

    sem = asyncio.Semaphore(args.threads)
    tasks = []
    logger.info(f"Testing {len(loader.configs)} configs...")
    
    for c in loader.configs:
        if c.protocol != "wg" and not xray_bin:
            c.status = "skipped"; continue
        tasks.append(tester.worker(c, sem))

    if TQDM_AVAILABLE:
        for f in tqdm(asyncio.as_completed(tasks), total=len(tasks), unit="cfg"): await f
    else:
        done=0
        for f in asyncio.as_completed(tasks):
            await f; done+=1
            if done%100==0: sys.stdout.write(f"\r{done}/{len(tasks)}"); sys.stdout.flush()
        print("")

    rep = Reporter(args.name_prefix)
    rep.report(loader.configs, args.limit, args.output, args.output_format)
    if args.csv: rep.csv(loader.configs, args.csv)
    geoip.close()

def main():
    if sys.platform=='win32': asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    try: asyncio.run(async_main())
    except KeyboardInterrupt: pass
    except Exception as e: logger.exception(e); sys.exit(1)

if __name__ == "__main__":
    main()
