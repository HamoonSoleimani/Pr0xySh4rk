#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Pr0xySh4rk collector
=====================

Fetches raw proxy subscription sources and extracts individual
vmess / vless / trojan / ss / ssr / hysteria(2) / tuic / wireguard / ...
config links, however the source happens to package them:

  * plain text, one link per line (optionally with '#' comment header
    lines mixed in, e.g. "#profile-title: ...")
  * a single base64-encoded blob for the whole file (common for
    "sub" links meant to be pasted straight into a v2ray client)
  * individual base64-encoded lines

All configs are de-duplicated (exact string match) and written, one
per line, to the output file for the tester stage to pick up.
"""

from __future__ import annotations

import argparse
import base64
import concurrent.futures
import logging
import random
import re
import sys
import time
from typing import Iterable, Optional, Set
from urllib.parse import unquote, urldefrag

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)7s | %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("collector")

# ==============================================================================
# SOURCES
# ==============================================================================
# One subscription/config URL per line. A trailing "#name" fragment is purely
# cosmetic (fragments are never sent to the server) - it's only used here to
# print a friendlier label in the logs.
SOURCES = [
    "https://raw.githubusercontent.com/EEvanescence/4Diana/main/AllConfigsSub.txt",
    "https://raw.githubusercontent.com/ALIILAPRO/v2rayNG-Config/main/sub.txt",
    "https://raw.githubusercontent.com/AzadNetCH/Clash/main/AzadNet.txt#AzadNet",
    "https://raw.githubusercontent.com/NiREvil/vless/refs/heads/main/sub/SSTime#SHADOWSOCKS%20TIME%20%F0%9F%91%BB",
    "https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/main/output_iran/iran_top100_checked.txt",
]

# ==============================================================================
# CONFIGURATION
# ==============================================================================
TIMEOUT = 25            # seconds, per request
RETRIES = 3             # transport-level retries (connection errors / 5xx / 429)
BACKOFF_FACTOR = 0.6
MAX_WORKERS = 8         # small source list -> no need for huge concurrency

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
]

# Every scheme worth capturing. Anything the tester's engine can't actually
# run (e.g. a non-standard "warp://" identity link) is simply marked
# "broken" by the tester later and filtered out - it's harmless to collect
# it here.
PROTOCOLS = (
    "vmess", "vless", "trojan", "ss", "ssr",
    "hysteria2", "hysteria", "hy2", "tuic",
    "juicity", "wireguard", "wg", "warp", "nekoray", "dtech",
)
# Longest-first alternation so "hysteria2" matches before "hysteria" etc.
_PROTO_ALTERNATION = "|".join(sorted(set(PROTOCOLS), key=len, reverse=True))
CONFIG_RE = re.compile(rf"(?:{_PROTO_ALTERNATION})://\S+", re.IGNORECASE)

# Trailing characters that are almost never part of a real link and tend to
# get glued on when a link is embedded inside prose/markdown/JSON.
_TRAILING_JUNK = ".,;:!?)]}\"'`>\u3002\uff0c"
_B64_LINE_RE = re.compile(r"^[A-Za-z0-9+/_=-]+$")


# ==============================================================================
# EXTRACTION
# ==============================================================================
def clean_trailing(link: str) -> str:
    return link.rstrip(_TRAILING_JUNK)


def clean_base64(text: str) -> str:
    text = re.sub(r"\s+", "", text)
    pad = len(text) % 4
    if pad:
        text += "=" * (4 - pad)
    return text


def try_b64_decode(candidate: str) -> Optional[str]:
    """Best-effort strict base64 decode; returns None if it isn't valid b64."""
    cleaned = clean_base64(candidate)
    if len(cleaned) < 16:
        return None
    try:
        raw = base64.b64decode(cleaned, validate=True)
    except Exception:
        return None
    for enc in ("utf-8", "latin-1"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return None


def extract_configs(text: str) -> Set[str]:
    """Pull every proxy link out of ``text``, however it's packaged."""
    found: Set[str] = set()

    def scan(s: str) -> None:
        for m in CONFIG_RE.finditer(s):
            link = clean_trailing(m.group(0))
            if link:
                found.add(link)

    scan(text)

    # The whole payload might itself be one giant base64 blob.
    whole_decoded = try_b64_decode(text)
    if whole_decoded:
        scan(whole_decoded)

    # Or each individual line might be base64 on its own.
    if "\n" in text:
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "://" in line:
                continue
            if len(line) < 20 or not _B64_LINE_RE.match(line):
                continue
            decoded = try_b64_decode(line)
            if decoded:
                scan(decoded)

    return found


# ==============================================================================
# FETCHING
# ==============================================================================
def build_session() -> requests.Session:
    session = requests.Session()
    retry = Retry(
        total=RETRIES,
        read=RETRIES,
        connect=RETRIES,
        backoff_factor=BACKOFF_FACTOR,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=("GET",),
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


def fetch_one(session: requests.Session, source: str) -> Set[str]:
    url, fragment = urldefrag(source)
    label = unquote(fragment) if fragment else url.rsplit("/", 1)[-1]
    headers = {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/plain,*/*;q=0.8",
    }
    try:
        resp = session.get(url, headers=headers, timeout=TIMEOUT)
        resp.raise_for_status()
    except requests.RequestException as exc:
        log.warning("FAILED   %-30s %s (%s)", label, url, exc)
        return set()

    configs = extract_configs(resp.text)
    if configs:
        log.info("%5d configs   %-30s", len(configs), label)
    else:
        log.warning("%5d configs   %-30s (source returned no parseable configs)", 0, label)
    return configs


def collect(sources: Iterable[str]) -> Set[str]:
    session = build_session()
    all_configs: Set[str] = set()
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {pool.submit(fetch_one, session, src): src for src in sources}
        for fut in concurrent.futures.as_completed(futures):
            all_configs.update(fut.result())
    return all_configs


# ==============================================================================
# MAIN
# ==============================================================================
def main() -> int:
    parser = argparse.ArgumentParser(description="Pr0xySh4rk config collector")
    parser.add_argument(
        "--output", default="collected_configs.txt",
        help="Where to write the combined, de-duplicated config list (default: %(default)s)",
    )
    args = parser.parse_args()

    start = time.time()
    log.info("Collecting from %d source(s)...", len(SOURCES))
    configs = collect(SOURCES)

    if not configs:
        log.error("No configs collected from ANY source. Writing an empty file so downstream steps fail loudly.")
        open(args.output, "w", encoding="utf-8").close()
        return 1

    with open(args.output, "w", encoding="utf-8") as fh:
        for cfg in sorted(configs):
            fh.write(cfg + "\n")

    log.info("Wrote %d unique configs to %s in %.1fs", len(configs), args.output, time.time() - start)
    return 0


if __name__ == "__main__":
    sys.exit(main())
