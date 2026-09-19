#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Pr0xySh4rk tester + reporter
=============================

Takes a raw list of proxy config links (one per line, as produced by
main.py), tests every one of them for real with xray-knife's built-in
batch HTTP tester (xray-knife >= v11), and writes out only the
healthiest configs per protocol as a subscription file (plain text or
base64), renamed with a small info tag ([PROTOCOL][rank][flag][speed][delay]).

Why this shells out to `xray-knife http -f ... -x csv` instead of
driving xray-core directly, one config at a time, the way older
versions of this script did: modern xray-knife (v11+) already has a
concurrent batch tester with TCP pre-screening, speed testing, retry
handling, and structured CSV output built in - re-implementing that in
Python would just be worse and slower. This script's job is purely to
feed it a clean, de-duplicated input list and turn its CSV output into
a ranked subscription.
"""

from __future__ import annotations

import argparse
import base64
import csv
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)7s | %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("tester")

DEFAULT_TEST_URL = "https://cloudflare.com/cdn-cgi/trace"  # required for ip/location to populate
PASSED_STATUSES = {"passed"}
SEMI_PASSED_STATUSES = {"semi-passed"}


# ==============================================================================
# Small helpers
# ==============================================================================
def flag_emoji(country_code: str) -> str:
    """Turn a 2-letter ISO country code into its flag emoji algorithmically
    (regional indicator symbols), so every real ISO code renders correctly
    without needing to maintain a hand-written lookup table."""
    code = (country_code or "").strip().upper()
    if len(code) != 2 or not code.isalpha():
        return "🚩"
    return "".join(chr(0x1F1E6 + ord(ch) - ord("A")) for ch in code)


def clean_field(val: Optional[str]) -> str:
    if val is None:
        return ""
    v = val.strip()
    return "" if v.lower() == "null" else v


def to_float(val: Optional[str], default: float = 0.0) -> float:
    try:
        f = float(val)
    except (TypeError, ValueError):
        return default
    return f if f == f else default  # filter NaN


def to_int(val: Optional[str], default: int = 0) -> int:
    return int(to_float(val, default))


# ==============================================================================
# Data model
# ==============================================================================
@dataclass
class TestResult:
    link: str
    status: str
    reason: str = ""
    ip: str = ""
    delay_ms: int = -1
    download_mbps: float = 0.0
    upload_mbps: float = 0.0
    location: str = ""
    protocol: str = field(init=False)

    def __post_init__(self) -> None:
        self.protocol = self.link.split("://", 1)[0].lower() if "://" in self.link else "unknown"

    @property
    def passed(self) -> bool:
        return self.status in PASSED_STATUSES

    @property
    def score(self) -> float:
        """Lower is better. Delay alone unless a speed test measured real
        throughput, in which case faster links are pulled further ahead."""
        if self.download_mbps > 0:
            return self.delay_ms / (1.0 + self.download_mbps)
        return float(self.delay_ms)


def load_results_csv(path: Path) -> List[TestResult]:
    results: List[TestResult] = []
    with path.open(newline="", encoding="utf-8", errors="replace") as fh:
        for row in csv.DictReader(fh):
            results.append(
                TestResult(
                    link=row.get("link", "").strip(),
                    status=clean_field(row.get("status")).lower() or "unknown",
                    reason=clean_field(row.get("reason")),
                    ip=clean_field(row.get("ip")),
                    delay_ms=to_int(row.get("delay"), -1),
                    download_mbps=to_float(row.get("download")),
                    upload_mbps=to_float(row.get("upload")),
                    location=clean_field(row.get("location")),
                )
            )
    return results


# ==============================================================================
# Input loading / de-duplication
# ==============================================================================
def load_input_configs(path: Path) -> List[str]:
    if not path.exists():
        log.critical("Input file not found: %s", path)
        sys.exit(2)

    seen = set()
    configs: List[str] = []
    with path.open(encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#") or "://" not in line:
                continue
            if line in seen:
                continue
            seen.add(line)
            configs.append(line)
    return configs


# ==============================================================================
# xray-knife invocation
# ==============================================================================
def resolve_xray_knife(explicit_path: Optional[str]) -> str:
    candidates = []
    if explicit_path:
        candidates.append(explicit_path)
    which = shutil.which("xray-knife")
    if which:
        candidates.append(which)
    candidates.append(str(Path.cwd() / "xray-knife"))

    for candidate in candidates:
        p = Path(candidate)
        if p.is_file() and os.access(p, os.X_OK):
            return str(p.resolve())

    log.critical(
        "Could not find a runnable 'xray-knife' binary. Looked at: %s",
        ", ".join(candidates) or "(nothing)",
    )
    sys.exit(2)


def verify_binary(xray_knife: str) -> None:
    try:
        proc = subprocess.run(
            [xray_knife, "-V"], capture_output=True, text=True, timeout=15
        )
    except Exception as exc:
        log.critical("Failed to execute xray-knife (%s): %s", xray_knife, exc)
        sys.exit(2)
    if proc.returncode != 0:
        log.critical("xray-knife -V exited with %d: %s", proc.returncode, proc.stderr.strip())
        sys.exit(2)
    version_line = (proc.stdout or proc.stderr).strip().splitlines()[0] if (proc.stdout or proc.stderr) else "unknown"
    log.info("Using %s", version_line or xray_knife)


def run_xray_knife_batch(
    xray_knife: str,
    input_file: Path,
    csv_output: Path,
    db_path: Path,
    args: argparse.Namespace,
) -> int:
    cmd = [
        xray_knife, "http",
        "-f", str(input_file),
        "-o", str(csv_output),
        "-x", "csv",
        "-t", str(args.threads),
        "-d", str(args.max_delay),
        "-u", args.test_url,
        "--retries", str(args.retries),
        "--rip",
        "--dedup-semantic",
        "--sort",
        "--db", str(db_path),
    ]
    if args.speedtest:
        cmd += ["-S", "--amount", str(args.speedtest_amount)]
    if not args.strict_tls:
        cmd.append("-e")
    if not args.no_prescan:
        cmd += ["--prescan", "--prescan-timeout", str(args.prescan_timeout)]
    if args.max_passed:
        cmd += ["--max-passed", str(args.max_passed)]

    log.info("Running: %s", " ".join(cmd))
    log.info(
        "Testing %d configs (threads=%d, max-delay=%dms, speedtest=%s, prescan=%s)...",
        sum(1 for _ in input_file.open(encoding="utf-8", errors="replace")),
        args.threads, args.max_delay, args.speedtest, not args.no_prescan,
    )

    start = time.time()
    try:
        # Inherit stdout/stderr so the live progress bar / per-config
        # errors show up directly in the CI log instead of being buffered
        # and dumped all at once (or lost) at the end.
        proc = subprocess.run(cmd, timeout=args.overall_timeout or None)
    except subprocess.TimeoutExpired:
        log.error(
            "xray-knife did not finish within %ds - aborting this run without "
            "touching the previous output (nothing published this cycle).",
            args.overall_timeout,
        )
        return 124
    elapsed = time.time() - start
    log.info("xray-knife finished in %.1fs with exit code %d", elapsed, proc.returncode)
    return proc.returncode


# ==============================================================================
# Reporting
# ==============================================================================
def build_alias(prefix: str, protocol: str, rank: int, result: TestResult) -> str:
    flag = flag_emoji(result.location)
    parts = [f"🔒{prefix}🦈", f"[{protocol.upper()}]", f"[{rank:02d}]", f"[{flag}]"]
    if result.download_mbps > 0:
        parts.append(f"[{result.download_mbps:.1f}Mbps]")
    if result.delay_ms >= 0:
        parts.append(f"[{result.delay_ms}ms]")
    return "".join(parts)


def rank_and_select(
    results: List[TestResult], limit: int, accept_semi_passed: bool
) -> Dict[str, List[TestResult]]:
    accepted_statuses = PASSED_STATUSES | (SEMI_PASSED_STATUSES if accept_semi_passed else set())
    grouped: Dict[str, List[TestResult]] = {}
    for r in results:
        if r.status not in accepted_statuses:
            continue
        grouped.setdefault(r.protocol, []).append(r)

    for protocol, items in grouped.items():
        items.sort(key=lambda r: r.score)
        grouped[protocol] = items[:limit]
    return grouped


def write_subscription(
    grouped: Dict[str, List[TestResult]], output_path: Path, output_format: str, prefix: str
) -> int:
    lines: List[str] = []
    total = 0
    for protocol in sorted(grouped):
        for rank, result in enumerate(grouped[protocol], start=1):
            alias = build_alias(prefix, protocol, rank, result)
            base_link = result.link.split("#", 1)[0]
            lines.append(f"{base_link}#{urllib.parse.quote(alias)}")
            total += 1

    if not lines:
        return 0

    data = "\n".join(lines) + "\n"
    if output_format == "base64":
        data = base64.b64encode(data.encode("utf-8")).decode("ascii")

    output_path.write_text(data, encoding="utf-8")
    return total


def write_full_report(results: List[TestResult], report_path: Path) -> None:
    with report_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["protocol", "status", "delay_ms", "download_mbps", "upload_mbps", "location", "ip", "reason", "link"])
        for r in sorted(results, key=lambda x: (x.protocol, x.score)):
            writer.writerow([r.protocol, r.status, r.delay_ms, r.download_mbps, r.upload_mbps, r.location, r.ip, r.reason, r.link])


def log_summary(results: List[TestResult]) -> None:
    from collections import Counter

    by_status = Counter(r.status for r in results)
    log.info(
        "Results: %d total | passed=%d semi-passed=%d failed=%d broken=%d timeout=%d other=%d",
        len(results),
        by_status.get("passed", 0),
        by_status.get("semi-passed", 0),
        by_status.get("failed", 0),
        by_status.get("broken", 0),
        by_status.get("timeout", 0),
        sum(v for k, v in by_status.items() if k not in {"passed", "semi-passed", "failed", "broken", "timeout"}),
    )
    by_protocol_passed = Counter(r.protocol for r in results if r.passed)
    if by_protocol_passed:
        breakdown = ", ".join(f"{proto}={count}" for proto, count in sorted(by_protocol_passed.items()))
        log.info("Passed by protocol: %s", breakdown)


# ==============================================================================
# CLI
# ==============================================================================
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Pr0xySh4rk config tester + reporter")
    p.add_argument("--input", required=True, help="File with raw config links, one per line")
    p.add_argument("--output", required=True, help="Where to write the final subscription")
    p.add_argument("--output-format", choices=["base64", "plain"], default="base64")
    p.add_argument("--csv-report", help="Optional path to dump the full per-config test report (CSV)")

    p.add_argument("--xray-knife-path", help="Path to the xray-knife binary (default: search PATH, then ./xray-knife)")

    p.add_argument("--limit", type=int, default=50, help="Max configs to keep PER PROTOCOL (default: %(default)s)")
    p.add_argument("--threads", type=int, default=50, help="Concurrent xray-knife test workers (default: %(default)s)")
    p.add_argument("--max-delay", type=int, default=8000, help="Max allowed round-trip delay in ms (default: %(default)s)")
    p.add_argument("--test-url", default=DEFAULT_TEST_URL, help="URL each config is tested against (default: Cloudflare trace, needed for IP/location)")
    p.add_argument("--retries", type=int, default=1, help="xray-knife retries per config (default: %(default)s)")

    p.add_argument("--speedtest", action="store_true", default=True, help="Measure real throughput for configs that pass (default: on)")
    p.add_argument("--no-speedtest", dest="speedtest", action="store_false")
    p.add_argument("--speedtest-amount", type=int, default=10000, help="Speed test transfer size in KB (default: %(default)s)")

    p.add_argument("--strict-tls", action="store_true", help="Do NOT allow insecure/fake-SNI TLS (default: insecure allowed, matches how most public configs are shared)")

    p.add_argument("--no-prescan", action="store_true", help="Disable the fast TCP pre-check that drops obviously-dead endpoints first")
    p.add_argument("--prescan-timeout", type=int, default=2500, help="TCP pre-check dial timeout in ms (default: %(default)s)")

    p.add_argument("--max-passed", type=int, default=0, help="Stop early once this many configs have passed (0 = test all)")
    p.add_argument("--accept-semi-passed", action="store_true", help="Also accept 'semi-passed' results (only relevant with multi-endpoint checks)")

    p.add_argument("--name-prefix", default="Pr0xySh4rk", help="Prefix used in the renamed config remarks (default: %(default)s)")
    p.add_argument("--overall-timeout", type=int, default=0, help="Hard wall-clock limit in seconds for the whole test run (0 = no limit; rely on the CI job timeout instead)")

    return p.parse_args()


def main() -> int:
    args = parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)

    configs = load_input_configs(input_path)
    if not configs:
        log.error("No usable config links found in %s - nothing to test.", input_path)
        return 1
    log.info("Loaded %d unique config link(s) from %s", len(configs), input_path)

    xray_knife = resolve_xray_knife(args.xray_knife_path)
    verify_binary(xray_knife)

    with tempfile.TemporaryDirectory(prefix="pr0xysh4rk-") as tmpdir:
        tmp = Path(tmpdir)
        input_for_knife = tmp / "configs_to_test.txt"
        input_for_knife.write_text("\n".join(configs) + "\n", encoding="utf-8")

        raw_csv = tmp / "raw_results.csv"
        db_path = tmp / "xray-knife.db"

        rc = run_xray_knife_batch(xray_knife, input_for_knife, raw_csv, db_path, args)

        if not raw_csv.exists():
            log.error(
                "xray-knife did not produce a results file (exit code %d) - "
                "leaving the previous published output untouched.", rc,
            )
            return 1

        results = load_results_csv(raw_csv)

        # Preserve the full report before it disappears with the tempdir.
        if args.csv_report:
            write_full_report(results, Path(args.csv_report))
            log.info("Wrote full diagnostic report to %s", args.csv_report)

    log_summary(results)

    grouped = rank_and_select(results, args.limit, args.accept_semi_passed)
    total_kept = sum(len(v) for v in grouped.values())

    if total_kept == 0:
        log.warning(
            "No configs passed testing this run. Leaving the previously "
            "published %s untouched rather than publishing an empty list.",
            output_path,
        )
        return 3

    written = write_subscription(grouped, output_path, args.output_format, args.name_prefix)
    log.info("Wrote %d healthy configs to %s (%s)", written, output_path, args.output_format)
    return 0


if __name__ == "__main__":
    sys.exit(main())
