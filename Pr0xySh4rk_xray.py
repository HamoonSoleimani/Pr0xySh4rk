#!/usr/bin/env python3
import argparse
import base64
import concurrent.futures
import socket
import asyncio
import urllib.parse
import requests
import os
import signal
import sys
from typing import List, Dict, Optional, Any

# --- Configuration ---
TEST_URLS = ["https://www.pinginf.net/", "https://speedtest.ir"]
total_outbounds_count = 0
completed_outbounds_count = 0
is_ctrl_c_pressed = False

# ---------------------------
# Signal Handler for Ctrl+C
# ---------------------------
def signal_handler(sig, frame):
    global is_ctrl_c_pressed
    print("\nCtrl+C detected. Gracefully stopping...")
    is_ctrl_c_pressed = True

# ---------------------------
# Fetching content from URLs
# ---------------------------
def fetch_content(url: str, proxy: Optional[str] = None) -> Optional[str]:
    session = requests.Session()
    proxies = {"http": proxy, "https": proxy} if proxy else {"http": None, "https": None}
    print(f"Thread {os.getpid()}: Fetching {url} {'using proxy: ' + proxy if proxy else 'directly'}")
    try:
        response = session.get(url, timeout=5, proxies=proxies)
        response.raise_for_status()
        return response.text
    except requests.exceptions.RequestException as e:
        print(f"Thread {os.getpid()}: Error fetching {url}: {type(e).__name__} - {e}")
        return None

# ---------------------------
# Parsing configuration content
# ---------------------------
def parse_config_content(content: str) -> List[str]:
    outbounds = []
    try:
        try:
            decoded_content = base64.b64decode(content).decode('utf-8')
            content = decoded_content
        except Exception:
            pass

        # Allowed protocols (trojan is intentionally excluded)
        for line in content.splitlines():
            line = line.strip()
            if line and not line.startswith("#") and line.startswith((
                "vless://", "vmess://", "ss://", "tuic://",
                "hysteria://", "hysteria2://", "hy2://",
                "warp://", "wireguard://"
            )):
                print(f"Thread {os.getpid()}: Found config: {line}")
                outbounds.append(line)
    except Exception as e:
        print(f"Thread {os.getpid()}: Error processing content: {e}")
    return outbounds

# ---------------------------
# Deduplicate outbounds
# ---------------------------
def deduplicate_outbounds(outbounds: List[str]) -> List[str]:
    return list(dict.fromkeys(outbounds))

# ---------------------------
# Diversify and limit (used in testing phases if needed)
# ---------------------------
def diversify_outbounds(outbounds: List[str], limit: int = 75) -> List[str]:
    return outbounds[:limit]

# ---------------------------
# Filtering best outbounds (unused in renaming phase)
# ---------------------------
def filter_best_outbounds(outbounds: List[str]) -> List[str]:
    working = [ob for ob in outbounds if ob.get("combined_delay", float('inf')) != float('inf')]
    return diversify_outbounds(working, limit=75) if len(working) > 75 else working

# ---------------------------
# TCP test
# ---------------------------
def tcp_test_outbound_sync(ob: Dict[str, Any]) -> None:
    try:
        asyncio.run(tcp_test_outbound(ob))
    except Exception as e:
        print(f"Exception in tcp_test_outbound_sync: {ob.get('original_config')}: {e}")

async def tcp_test_outbound(ob: Dict[str, Any]) -> None:
    config_line = ob.get("original_config")
    parsed_url = urllib.parse.urlparse(config_line)
    server, port = parsed_url.hostname, parsed_url.port

    if not server or not port:
        ob["tcp_delay"] = float('inf')
        print(f"TCP Test: No server/port, delay=inf - Config: {config_line}")
        return

    loop = asyncio.get_event_loop()
    start = loop.time()
    print(f"TCP Test for {config_line} to {server}:{port} started...")

    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(server, port), timeout=1)
        delay = (loop.time() - start) * 1000
        writer.close()
        await writer.wait_closed()
        ob["tcp_delay"] = delay
        print(f"TCP Test for {config_line} finished, delay={delay:.2f} ms")
    except Exception as e:
        ob["tcp_delay"] = float('inf')
        print(f"TCP Test for {config_line} error: {e}, delay=inf")

# ---------------------------
# HTTP test
# ---------------------------
def http_delay_test_outbound_sync(ob: Dict[str, Any], proxy: Optional[str], repetitions: int) -> None:
    try:
        asyncio.run(http_delay_test_outbound(ob, proxy, repetitions))
    except Exception as e:
        print(f"Exception in http_delay_test_outbound_sync: {ob.get('original_config')}: {e}")

async def http_delay_test_outbound(ob: Dict[str, Any], proxy_for_test: Optional[str], repetitions: int) -> None:
    config_line = ob.get("original_config")
    parsed_url = urllib.parse.urlparse(config_line)
    server, port = parsed_url.hostname, parsed_url.port

    if not server or not port:
        ob["http_delay"] = float('inf')
        print(f"HTTP Test: No server/port, delay=inf - Config: {config_line}")
        return

    session = requests.Session()
    total_delays = []

    print(f"HTTP Test for {config_line} to {server}:{port} started with {repetitions} repetitions...")

    for test_url in TEST_URLS:
        times = []
        print(f"  Testing against: {test_url}")
        for i in range(repetitions):
            start = asyncio.get_event_loop().time()
            current_proxies = {'http': proxy_for_test, 'https': proxy_for_test} if proxy_for_test else None

            try:
                with session.get(test_url, timeout=1, proxies=current_proxies) as response:
                    response.raise_for_status()
                elapsed = (asyncio.get_event_loop().time() - start) * 1000
                times.append(elapsed)
                print(f"    [{config_line}] {test_url} Repetition {i+1}: {elapsed:.2f} ms")
            except requests.exceptions.RequestException as e:
                times.append(None)
                print(f"    [{config_line}] {test_url} Repetition {i+1} failed: {e}")

        successful_times = [t for t in times if t is not None]
        if successful_times:
            avg = sum(successful_times) / len(successful_times)
            total_delays.append(avg)
            print(f"  Average delay for {test_url}: {avg:.2f} ms")
        else:
            total_delays.append(float('inf'))
            print(f"  All trials failed for {test_url}, delay=inf")

    ob["http_delay"] = (sum(d for d in total_delays if d != float('inf')) /
                        sum(1 for d in total_delays if d != float('inf'))
                        if any(d != float('inf') for d in total_delays) else float('inf'))
    print(f"HTTP Test for {config_line} finished. Overall Average: {ob['http_delay']:.2f} ms")

# ---------------------------
# UDP test (for WireGuard/WARP)
# ---------------------------
def udp_test_outbound_sync(ob: Dict[str, Any]) -> None:
    try:
        asyncio.run(udp_test_outbound(ob))
    except Exception as e:
        print(f"Exception in udp_test_outbound_sync: {ob.get('original_config')}: {e}")

async def udp_test_outbound(ob: Dict[str, Any]) -> None:
    config_line = ob.get("original_config")
    parsed_url = urllib.parse.urlparse(config_line)
    server, port = parsed_url.hostname, parsed_url.port

    # If server/port are missing, but it *is* a warp/wireguard, include it with inf delay.
    if (not server or not port) and config_line.startswith(("warp://", "wireguard://")):
        ob["udp_delay"] = float('inf')
        print(f"UDP Test: No server/port, BUT IS WG/WARP, delay=inf - Config: {config_line}")
        return
    elif not server or not port:
        ob["udp_delay"] = float('inf')
        print(f"UDP Test: No server/port, delay=inf - Config: {config_line}")
        return

    try:
        ip = (await asyncio.get_event_loop().getaddrinfo(server, None, family=socket.AF_INET))[0][4][0]
    except Exception as e:
        ob["udp_delay"] = float('inf')
        print(f"UDP Test for {config_line}: getaddrinfo error: {e}, delay=inf")
        return

    loop = asyncio.get_event_loop()
    start = loop.time()
    print(f"UDP Test for {config_line} to {server}:{port} ({ip}:{port}) started...")
    try:
        transport, _ = await loop.create_datagram_endpoint(lambda: asyncio.DatagramProtocol(), remote_addr=(ip, port))
        await asyncio.sleep(0.1)
        delay = (loop.time() - start) * 1000
        transport.close()
        ob["udp_delay"] = delay
        print(f"UDP Test for {config_line} finished, delay={delay:.2f} ms")
    except Exception as e:
        ob["udp_delay"] = float('inf')
        print(f"UDP Test for {config_line} error: {e}, delay=inf")

# ---------------------------
# Single-pass test
# ---------------------------
def single_test_pass(outbounds: List[Dict[str, Any]],
                     test_type: str,
                     thread_pool_size=32,
                     proxy_for_test: Optional[str] = None,
                     repetitions: int = 5) -> None:

    global completed_outbounds_count, total_outbounds_count, is_ctrl_c_pressed
    completed_outbounds_count = 0
    total_outbounds_count = len(outbounds)

    print(f"Starting tests ({test_type}) on {total_outbounds_count} outbounds")

    with concurrent.futures.ThreadPoolExecutor(max_workers=thread_pool_size) as executor:
        futures = []
        for ob in outbounds:
            if is_ctrl_c_pressed:
                print("Ctrl+C detected, stopping tests.")
                break
            config_line = ob.get("original_config")
            protocol = config_line.split("://")[0]

            if test_type == "tcp+http":
                if protocol in ("warp", "wireguard"):
                    future = executor.submit(udp_test_outbound_sync, ob)
                    futures.append(future)
                else:
                    future_tcp = executor.submit(tcp_test_outbound_sync, ob)
                    future_http = executor.submit(http_delay_test_outbound_sync, ob, proxy_for_test, repetitions)
                    futures.append(future_tcp)
                    futures.append(future_http)
            elif test_type == "tcp":
                future = executor.submit(tcp_test_outbound_sync, ob)
                futures.append(future)
            elif test_type == "http":
                future = executor.submit(http_delay_test_outbound_sync, ob, proxy_for_test, repetitions)
                futures.append(future)
            elif test_type == "udp":
                if protocol in ("warp", "wireguard"):
                    future = executor.submit(udp_test_outbound_sync, ob)
                    futures.append(future)
                else:
                    ob["udp_delay"] = float('inf')
                    continue  # skip
            else:  # Default to HTTP
                future = executor.submit(http_delay_test_outbound_sync, ob, proxy_for_test, repetitions)
                futures.append(future)

        for future in concurrent.futures.as_completed(futures):
            if is_ctrl_c_pressed:
                break
            try:
                future.result()
            except Exception as e:
                print(f"Exception during test: {e}")
            finally:
                completed_outbounds_count += 1
                print(f"Progress: {(completed_outbounds_count / total_outbounds_count) * 100:.2f}% ({completed_outbounds_count}/{total_outbounds_count})")

    print("Testing completed.")

# ---------------------------
# Saving configuration
# ---------------------------
def save_config(outbounds: List[str], filepath: str = "merged_configs.txt", base64_encode: bool = True):
    try:
        combined = "\n".join(outbounds)
        if base64_encode:
            encoded = base64.b64encode(combined.encode()).decode("utf-8")
            with open(filepath, "w") as outfile:
                outfile.write(encoded)
            print(f"Merged configs saved to {filepath} as base64 encoded.")
        else:
            with open(filepath, "w") as outfile:
                for outbound in outbounds:
                    outfile.write(outbound + "\n")
            print(f"Merged configs saved to {filepath} as plaintext.")
    except Exception as e:
        print(f"Error saving config: {e}")

# ---------------------------
# Helper: Generate unique Pr0xySh4rk-formatted tag (provided sample, not used here)
# ---------------------------
def generate_unique_tag(all_tags: set) -> str:
    base_tag = "🔒Pr0xySh4rk🦈"
    if base_tag not in all_tags:
        all_tags.add(base_tag)
        return base_tag
    counter = 1
    new_tag = f"{base_tag}-{counter}"
    while new_tag in all_tags:
        counter += 1
        new_tag = f"{base_tag}-{counter}"
    all_tags.add(new_tag)
    return new_tag

# ---------------------------
# New Helper: Rename configs by replacing the remark (after '#') with a Pr0xySh4rk-formatted tag.
# Only the portion after the '#' is replaced. If no '#' exists, the tag is appended.
# Group by protocol and limit each group to best 75.
# ---------------------------
def rename_configs_by_protocol(configs: List[str]) -> List[str]:
    protocol_map = {
        "ss": "SS",
        "vless": "VL",
        "vmess": "VM",
        "tuic": "TU",
        "hysteria": "HY",
        "hysteria2": "HY",
        "hy2": "HY",
        "warp": "WG",
        "wireguard": "WG",
    }
    groups = {}
    for config in configs:
        proto = config.split("://")[0].lower()
        abbr = protocol_map.get(proto, proto.upper())
        groups.setdefault(abbr, []).append(config)
    
    renamed_configs = []
    for abbr, conf_list in groups.items():
        limited_list = conf_list[:75]
        for i, config in enumerate(limited_list, start=1):
            new_tag = f"🔒Pr0xySh4rk🦈{abbr}{i:02d}"
            if "#" in config:
                base_part = config.split("#")[0].rstrip()
                new_config = f"{base_part}#{new_tag}"
            else:
                new_config = f"{config}#{new_tag}"
            renamed_configs.append(new_config)
    return renamed_configs

# ---------------------------
# Fetch and parse subscription
# ---------------------------
def fetch_and_parse_subscription_thread(url: str, proxy: Optional[str] = None) -> List[Any]:
    print(f"Thread {os.getpid()}: Fetching: {url}")
    content = fetch_content(url, proxy)
    if content:
        normalized_content = content.strip().replace("\n", "").replace("\r", "").replace(" ", "")
        try:
            decoded_possible = base64.b64decode(normalized_content, validate=True).decode("utf-8")
            content = decoded_possible
        except Exception:
            pass
        outbounds_list = parse_config_content(content)
        if outbounds_list:
            print(f"Thread {os.getpid()}: Parsed {len(outbounds_list)} outbounds from {url}")
            return [{"original_config": ob, "source": url} for ob in outbounds_list]
        else:
            print(f"Thread {os.getpid()}: No outbounds parsed from {url}")
            return []
    else:
        print(f"Thread {os.getpid()}: Failed to fetch {url}")
        return []

# ---------------------------
# Main function
# ---------------------------
def main():
    global is_ctrl_c_pressed
    signal.signal(signal.SIGINT, signal_handler)

    parser = argparse.ArgumentParser(description="Pr0xySh4rk Xray Config Merger")
    parser.add_argument("--input", required=True, help="Input file (base64 or URLs)")
    parser.add_argument("--output", required=True, help="Output file")
    parser.add_argument("--proxy", help="Proxy for fetching")
    parser.add_argument("--threads", type=int, default=32, help="Threads")
    parser.add_argument("--test-proxy", help="Proxy for HTTP testing")
    parser.add_argument("-r", "--repetitions", type=int, default=5, help="HTTP test repetitions")
    parser.add_argument("--test", choices=["tcp", "udp", "http", "tcp+http"], default="http", help="Test type")
    parser.add_argument("--all-wg-warp", action="store_true", help="Save best 75 WireGuard/WARP configs")
    parser.add_argument("--no-base64", action="store_true", help="Output in plaintext instead of base64 encoding")
    args = parser.parse_args()

    original_env = {}
    proxy_vars = ['http_proxy', 'https_proxy', 'all_proxy', 'HTTP_PROXY', 'PROXY', 'ALL_PROXY']
    for var in proxy_vars:
        if var in os.environ:
            original_env[var] = os.environ[var]
            del os.environ[var]

    subscription_urls = []
    try:
        with open(args.input, "rb") as f:
            encoded_content = f.read().strip()
            try:
                decoded_content = base64.b64decode(encoded_content).decode("utf-8")
                subscription_urls = [line.strip() for line in decoded_content.splitlines() if line.strip()]
                print("URLs decoded from base64.")
            except Exception:
                print("Trying plain text.")
                with open(args.input, "r") as f2:
                    subscription_urls = [line.strip() for line in f2 if line.strip()]
    except FileNotFoundError:
        print(f"Error: {args.input} not found.")
        return

    if not subscription_urls:
        print("No URLs found. Exiting.")
        return

    parsed_outbounds_lists = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = [executor.submit(fetch_and_parse_subscription_thread, url, args.proxy) for url in subscription_urls]
        for future in concurrent.futures.as_completed(futures):
            if is_ctrl_c_pressed:
                print("Ctrl+C during fetching.")
                break
            result = future.result()
            if result:
                parsed_outbounds_lists.extend(result)
        if is_ctrl_c_pressed:
            print("Exiting early due to Ctrl+C.")
            sys.exit(0)

    all_parsed_outbounds = parsed_outbounds_lists
    print(f"Total parsed: {len(all_parsed_outbounds)}")

    deduplicated_outbounds = deduplicate_outbounds([ob["original_config"] for ob in all_parsed_outbounds])
    print(f"Unique: {len(deduplicated_outbounds)}")
    deduplicated_outbounds_dicts = [{
        "original_config": config,
        "source": next((o["source"] for o in all_parsed_outbounds if o["original_config"] == config), "unknown")
    } for config in deduplicated_outbounds]

    if args.test == "tcp+http":
        # Separate WG/WARP and non-WG/WARP configs
        wireguard_warp_configs = [ob for ob in deduplicated_outbounds_dicts if ob["original_config"].startswith(("warp://", "wireguard://"))]
        other_configs = [ob for ob in deduplicated_outbounds_dicts if not ob["original_config"].startswith(("warp://", "wireguard://"))]

        print("\n=== Testing non-WireGuard/WARP configs (TCP then HTTP) ===")
        single_test_pass(other_configs, "tcp+http", args.threads, args.test_proxy, args.repetitions)
        survivors_tcp_http = [ob for ob in other_configs if ob.get("tcp_delay", float('inf')) != float('inf') and ob.get("http_delay", float('inf')) != float('inf')]
        print(f"{len(survivors_tcp_http)} non-WG/WARP passed TCP and HTTP.")

        print("\n=== Testing WireGuard/WARP configs (UDP only) ===")
        single_test_pass(wireguard_warp_configs, "udp", args.threads)
        survivors_udp = [ob for ob in wireguard_warp_configs if ob.get("udp_delay", float('inf')) != float('inf')]
        print(f"{len(survivors_udp)} WG/WARP passed (or skipped with inf delay) UDP.")

        # Combine survivors without overall limit; limiting will be done per protocol during renaming.
        final_outbounds_other = [ob["original_config"] for ob in survivors_tcp_http]
        final_outbounds_wg_warp = [ob["original_config"] for ob in survivors_udp]
        final_outbounds = final_outbounds_other + final_outbounds_wg_warp

    else:  # For single test types (tcp, udp, http)
        single_test_pass(deduplicated_outbounds_dicts, args.test, args.threads, args.test_proxy, args.repetitions)
        if is_ctrl_c_pressed:
            print("Exiting after testing due to Ctrl+C.")
            sys.exit(0)

        if args.test == "tcp":
            tested_outbounds = [ob for ob in deduplicated_outbounds_dicts if ob.get("tcp_delay", float('inf')) != float('inf')]
        elif args.test == "udp":
            tested_outbounds = [ob for ob in deduplicated_outbounds_dicts if ob.get("udp_delay", float('inf')) != float('inf')]
        else:  # "http"
            tested_outbounds = [ob for ob in deduplicated_outbounds_dicts if ob.get("http_delay", float('inf')) != float('inf')]
        print(f"{len(tested_outbounds)} passed {args.test}.")
        if args.test != "udp":
            for ob in tested_outbounds:
                if args.test == "tcp":
                    ob["combined_delay"] = ob.get("tcp_delay", float('inf'))
                elif args.test == 'udp':
                    ob["combined_delay"] = ob.get("udp_delay", float('inf'))
                else:  # "http"
                    ob["combined_delay"] = ob.get("http_delay", float('inf'))
            tested_outbounds.sort(key=lambda x: x["combined_delay"])
        final_outbounds = [ob["original_config"] for ob in tested_outbounds]

    # Rename configs by replacing the remark (after '#') with a Pr0xySh4rk-formatted tag,
    # grouping by protocol and limiting each group to best 75.
    renamed_final_outbounds = rename_configs_by_protocol(final_outbounds)
    print("Renaming completed. Total renamed configs:", len(renamed_final_outbounds))

    save_config(renamed_final_outbounds, filepath=args.output, base64_encode=not args.no_base64)

    for var, value in original_env.items():
        os.environ[var] = value

if __name__ == "__main__":
    main()
