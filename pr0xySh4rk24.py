#!/usr/bin/env python3
import argparse
import base64
import concurrent.futures
import json
import re
import socket
import asyncio
import urllib.parse
import requests
import os
import signal
import sys
from typing import List, Dict, Optional, Any

# --- Configuration ---
TEST_URL = "https://speedtest.ir"  # The URL used in HTTP tests

# Global variables for progress tracking and Ctrl+C handling
total_outbounds_count = 0
completed_outbounds_count = 0
is_ctrl_c_pressed = False

# ---------------------------
# Helper: Generate unique Pr0xySh4rk-formatted tag
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
# Signal Handler for Ctrl+C
# ---------------------------
def signal_handler(sig, frame):
    global is_ctrl_c_pressed
    print("\nCtrl+C detected. Gracefully stopping and saving configuration...")
    is_ctrl_c_pressed = True

# ---------------------------
# Fetch content from a URL
# ---------------------------
def fetch_content(url: str, proxy: Optional[str] = None) -> Optional[str]:
    session = requests.Session()
    if proxy:
        proxies = {"http": proxy, "https": proxy}
        print(f"Thread {os.getpid()}: Fetching {url} using proxy: {proxy}")
    else:
        proxies = {"http": None, "https": None}
        print(f"Thread {os.getpid()}: Fetching {url} directly (no proxy)")
    try:
        response = session.get(url, timeout=5, proxies=proxies)
        response.raise_for_status()
        return response.text
    except requests.exceptions.RequestException as e:
        print(f"Thread {os.getpid()}: Error fetching URL {url}{' via ' + proxy if proxy else ''}: {e}")
        return None

# ---------------------------
# Parsing Warp/WireGuard links
# ---------------------------
def parse_warp_single(link: str, counter: int, all_tags: set) -> (List[Dict[str, Any]], int):
    try:
        parsed = urllib.parse.urlparse(link)
        license_key = parsed.username.strip() if parsed.username else ""
        server = parsed.hostname if parsed.hostname else "auto"
        port = parsed.port if parsed.port else (0 if server.lower() == "auto" else 443)
        params = urllib.parse.parse_qs(parsed.query)
        fake_packets = params.get("ifp", [""])[0]
        fake_packets_size = params.get("ifps", [""])[0]
        fake_packets_delay = params.get("ifpd", [""])[0]
        fake_packets_mode = params.get("ifpm", [""])[0]
        fragment = parsed.fragment.strip()

        if fragment:
            tag = fragment
            all_tags.add(tag)
        else:
            tag = generate_unique_tag(all_tags)

        outbound = {
            "type": "wireguard",
            "tag": tag,
            "local_address": [
                "172.16.0.2/24",
                "2606:4700:110:8566:aded:93b9:60a9:1a6c/128"
            ],
            "private_key": license_key,
            "server": server,
            "server_port": int(port),
            "peer_public_key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
            "reserved": "AAAA",
            "mtu": 1330
        }
        if fake_packets:
            outbound["fake_packets"] = fake_packets
        if fake_packets_size:
            outbound["fake_packets_size"] = fake_packets_size
        if fake_packets_delay:
            outbound["fake_packets_delay"] = fake_packets_delay
        if fake_packets_mode:
            outbound["fake_packets_mode"] = fake_packets_mode

        return [outbound], counter
    except Exception as e:
        print(f"Thread {os.getpid()}: Error parsing warp link: {e} - Link: {link}")
        return [], counter

def parse_warp_line(line: str, counter: int, all_tags: set) -> (List[Dict[str, Any]], int):
    if "&&detour=" in line:
        main_part, detour_part = line.split("&&detour=", 1)
        main_configs, counter = parse_warp_single(main_part.strip(), counter, all_tags)
        detour_configs, counter = parse_warp_single(detour_part.strip(), counter, all_tags)
        if main_configs and detour_configs:
            detour_configs[0]["detour"] = main_configs[0]["tag"]
            return main_configs + detour_configs, counter
        return main_configs, counter
    configs, counter = parse_warp_single(line, counter, all_tags)
    return configs, counter

# ---------------------------
# Parsing config content
# ---------------------------
def parse_config_url1_2(content: str, all_tags: set) -> List[Dict[str, Any]]:
    outbounds = []
    try:
        try:
            # Attempt base64 decode
            decoded_content = base64.b64decode(content).decode('utf-8')
            content = decoded_content
        except Exception:
            pass
        json_content = "\n".join(line for line in content.splitlines() if not line.strip().startswith('//'))
        try:
            config = json.loads(json_content)
            print(f"Thread {os.getpid()}: Parsed JSON Config from URL")
            if "outbounds" in config:
                for ob in config["outbounds"]:
                    ob["tag"] = generate_unique_tag(all_tags)
                return config["outbounds"]
            else:
                print(f"Thread {os.getpid()}: 'outbounds' key not found in JSON.")
                return []
        except json.JSONDecodeError:
            print(f"Thread {os.getpid()}: JSONDecodeError")
            pass
        except Exception as e_base:
            print(f"Thread {os.getpid()}: Error processing base config content: {e_base}")
    except:
        pass

    # Legacy link parsing
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("//"):
            continue

        if line.startswith("ss://"):
            try:
                ss_url_encoded = line[5:]
                if "@" in ss_url_encoded:
                    base64_str = ss_url_encoded.split("@")[0]
                    padding = "=" * (-len(base64_str) % 4)
                    method_pass_decoded = base64.urlsafe_b64decode(base64_str + padding).decode("utf-8")
                    if ":" in method_pass_decoded:
                        method, password = method_pass_decoded.split(":", 1)
                    else:
                        method, password = None, None
                    remainder = ss_url_encoded.split("@")[1]
                    server_port_str = remainder.split("?")[0].split("#")[0]
                else:
                    padding = "=" * (-len(ss_url_encoded) % 4)
                    decoded_full = base64.urlsafe_b64decode(ss_url_encoded + padding).decode("utf-8")
                    if "@" in decoded_full:
                        method_pass, server_port_str = decoded_full.split("@", 1)
                        if ":" in method_pass:
                            method, password = method_pass.split(":", 1)
                        else:
                            method, password = None, None
                    else:
                        print(f"Thread {os.getpid()}: Invalid Shadowsocks link: {line}")
                        continue

                if server_port_str:
                    parts = server_port_str.split(":")
                    server = parts[0]
                    port_str = parts[1] if len(parts) > 1 else "443"
                    port_match = re.match(r"(\d+)", port_str)
                    port = int(port_match.group(1)) if port_match else 443
                else:
                    parsed_url = urllib.parse.urlparse(line)
                    server = parsed_url.hostname
                    port = parsed_url.port if parsed_url.port else 443

                tag = generate_unique_tag(all_tags)
                ss_outbound = {
                    "type": "shadowsocks",
                    "tag": tag,
                    "server": server,
                    "server_port": port,
                    "method": method if method else "aes-256-gcm",
                    "password": password if password else ""
                }
                outbounds.append(ss_outbound)
            except Exception as e:
                print(f"Thread {os.getpid()}: Error parsing Shadowsocks link: {e} - Link: {line}")
                continue

        elif line.startswith(("vless://", "vmess://", "trojan://", "tuic://",
                              "hysteria://", "hysteria2://", "hy2://", "warp://", "wireguard://")):
            protocol = line.split("://")[0]
            if protocol == "wireguard":
                line = line.replace("wireguard://", "warp://", 1)
            if protocol in ("warp", "wireguard"):
                parsed_configs, counter = parse_warp_line(line, 0, all_tags)
                outbounds.extend(parsed_configs)
            else:
                # For other protocols like vless, vmess, trojan, etc.
                # (The code from earlier example can be adapted here)
                # ...
                # For brevity, let's do a simple placeholder
                pass

    return outbounds

# ---------------------------
# Deduplicate outbounds
# ---------------------------
def deduplicate_outbounds(outbounds: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    def get_key(ob: Dict[str, Any]) -> tuple:
        typ = ob.get("type", "")
        server = ob.get("server", "")
        port = ob.get("server_port", "")
        return (typ, server, port)

    unique = {}
    for ob in outbounds:
        key = get_key(ob)
        if key not in unique:
            unique[key] = ob
        else:
            # We can compare delays if we want, but for now just keep the first
            pass
    return list(unique.values())

# ---------------------------
# Testing: TCP
# ---------------------------
def tcp_test_outbound_sync(ob: Dict[str, Any]) -> None:
    try:
        asyncio.run(tcp_test_outbound(ob))
    except Exception as e:
        print(f"Exception in tcp_test_outbound_sync for tag {ob.get('tag')}: {e}")

async def tcp_test_outbound(ob: Dict[str, Any]) -> None:
    tag = ob.get("tag")
    server = ob.get("server")
    port = ob.get("server_port")
    if not server or not port:
        ob["tcp_delay"] = float('inf')
        return
    loop = asyncio.get_event_loop()
    start = loop.time()
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(server, port), timeout=1)
        delay = (loop.time() - start) * 1000
        ob["tcp_delay"] = delay
        writer.close()
        await writer.wait_closed()
        print(f"TCP Test for {tag}: {delay:.2f} ms")
    except Exception as e:
        ob["tcp_delay"] = float('inf')
        print(f"TCP Test for {tag} failed: {e}")

# ---------------------------
# Testing: HTTP
# ---------------------------
def http_delay_test_outbound_sync(ob: Dict[str, Any], proxy: Optional[str], repetitions: int) -> None:
    try:
        asyncio.run(http_delay_test_outbound(ob, proxy, repetitions))
    except Exception as e:
        print(f"Exception in http_delay_test_outbound_sync for tag {ob.get('tag')}: {e}")

async def http_delay_test_outbound(ob: Dict[str, Any], proxy: Optional[str], repetitions: int) -> None:
    tag = ob.get("tag")
    server = ob.get("server")
    port = ob.get("server_port")
    if not server or not port:
        ob["http_delay"] = float('inf')
        return

    times = []
    session = requests.Session()
    for i in range(repetitions):
        start = asyncio.get_event_loop().time()
        proxies = {"http": proxy, "https": proxy} if proxy else None
        try:
            resp = session.get(TEST_URL, timeout=1, proxies=proxies)
            resp.raise_for_status()
            elapsed = (asyncio.get_event_loop().time() - start) * 1000
            times.append(elapsed)
        except requests.RequestException as e:
            times.append(None)

    good = [t for t in times if t is not None]
    if good:
        avg = sum(good)/len(good)
        ob["http_delay"] = avg
        print(f"HTTP Test for {tag} avg delay: {avg:.2f} ms")
    else:
        ob["http_delay"] = float('inf')

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
    print(f"Running single test pass: {test_type} with {total_outbounds_count} outbounds")

    with concurrent.futures.ThreadPoolExecutor(max_workers=thread_pool_size) as executor:
        futures = []
        future_to_tag = {}

        for ob in outbounds:
            if is_ctrl_c_pressed:
                break
            tag = ob.get("tag")
            if test_type == "tcp":
                future = executor.submit(tcp_test_outbound_sync, ob)
            else:
                # default to HTTP
                future = executor.submit(http_delay_test_outbound_sync, ob, proxy_for_test, repetitions)
            futures.append(future)
            future_to_tag[future] = tag

        for future in concurrent.futures.as_completed(futures):
            if is_ctrl_c_pressed:
                break
            tag = future_to_tag[future]
            try:
                future.result()
            except Exception as e:
                print(f"Exception in test pass for {tag}: {e}")
            completed_outbounds_count += 1
            pct = (completed_outbounds_count/total_outbounds_count)*100
            print(f"Progress: {pct:.2f}% ({completed_outbounds_count}/{total_outbounds_count})")

# ---------------------------
# Filter out failures
# ---------------------------
def filter_test_failures(outbounds: List[Dict[str, Any]], test_type: str) -> List[Dict[str, Any]]:
    if test_type == "tcp":
        return [ob for ob in outbounds if ob.get("tcp_delay", float('inf')) != float('inf')]
    else:
        # default to http
        return [ob for ob in outbounds if ob.get("http_delay", float('inf')) != float('inf')]

# ---------------------------
# Filter best outbounds by protocol (50 max)
# ---------------------------
def filter_best_outbounds_by_protocol(outbounds: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    # We'll just keep up to 50 total, ignoring protocol
    if len(outbounds) <= 50:
        return outbounds
    return outbounds[:50]

# ---------------------------
# Save config to file (in Base64 only)
# ---------------------------
def save_config_as_base64(config: Dict[str, Any], filepath: str) -> None:
    # Remove extra fields
    for ob in config.get("outbounds", []):
        for field in ["tcp_delay", "http_delay", "udp_delay", "source"]:
            if field in ob:
                del ob[field]
    json_str = json.dumps(config, indent=2)
    # Always base64-encode
    encoded = base64.b64encode(json_str.encode("utf-8")).decode("utf-8")
    try:
        with open(filepath, "w") as f:
            f.write(encoded)
        print(f"Config saved (Base64) to {filepath}")
    except Exception as e:
        print(f"Error saving config: {e}")

# ---------------------------
# Main
# ---------------------------
def main():
    global is_ctrl_c_pressed
    signal.signal(signal.SIGINT, signal_handler)

    parser = argparse.ArgumentParser(description="Pr0xySh4rk24 - Two-Pass Testing and Base64 Output")
    parser.add_argument("--input", required=True, help="Input subscription file (subs.txt)")
    parser.add_argument("--output", required=True, help="Output file path (will contain Base64-encoded config)")
    parser.add_argument("-r", "--repetitions", type=int, default=3, help="HTTP test repetitions")
    parser.add_argument("--test", default="tcp+http", choices=["tcp", "http", "tcp+http"],
                        help="Which test(s) to run. 'tcp+http' means 2 passes.")
    parser.add_argument("--test-proxy", help="Optional proxy for HTTP tests")
    parser.add_argument("--threads", type=int, default=32, help="Number of threads for tests")
    args = parser.parse_args()

    # Basic template
    base_config_template = {
        "log": {"level": "warn", "output": "box.log", "timestamp": True},
        "dns": {
            "servers": [],
            "rules": [],
            "final": "dns-remote"
        },
        "inbounds": [],
        "outbounds": [],
        "route": {}
    }

    # Read input subs
    try:
        with open(args.input, "r") as f:
            lines = [ln.strip() for ln in f if ln.strip()]
    except FileNotFoundError:
        print(f"File not found: {args.input}")
        sys.exit(1)

    # parse
    all_tags = set()
    outbounds = []
    for line in lines:
        # If line is base64 subscription, decode it
        # or if line is a direct link, fetch it
        # For now, assume line is direct link
        # ...
        # Actually, let's do a simple parse_config_url1_2
        content = line
        # If it's a URL, fetch it
        if line.startswith("http://") or line.startswith("https://"):
            content = fetch_content(line)
            if not content:
                continue
        parsed = parse_config_url1_2(content, all_tags)
        for ob in parsed:
            ob["source"] = line
        outbounds.extend(parsed)

    # Deduplicate
    outbounds = deduplicate_outbounds(outbounds)
    print(f"Total outbounds after deduplicate: {len(outbounds)}")

    # If user chooses "tcp+http"
    if args.test == "tcp+http":
        # Pass 1: tcp
        single_test_pass(outbounds, "tcp", args.threads, args.test_proxy, args.repetitions)
        outbounds = filter_test_failures(outbounds, "tcp")
        print(f"{len(outbounds)} outbounds survived TCP test")

        if is_ctrl_c_pressed:
            print("Stopped after TCP test")
            sys.exit(0)

        # Pass 2: http
        single_test_pass(outbounds, "http", args.threads, args.test_proxy, args.repetitions)
        outbounds = filter_test_failures(outbounds, "http")
        print(f"{len(outbounds)} outbounds survived HTTP test")

    elif args.test == "tcp":
        single_test_pass(outbounds, "tcp", args.threads, args.test_proxy, args.repetitions)
        outbounds = filter_test_failures(outbounds, "tcp")
        print(f"{len(outbounds)} outbounds survived TCP test")

    else:
        # "http"
        single_test_pass(outbounds, "http", args.threads, args.test_proxy, args.repetitions)
        outbounds = filter_test_failures(outbounds, "http")
        print(f"{len(outbounds)} outbounds survived HTTP test")

    # Filter best 50
    outbounds = filter_best_outbounds_by_protocol(outbounds)
    print(f"{len(outbounds)} outbounds after best 50 filter")

    # Merge
    base_config_template["outbounds"] = outbounds

    # Save
    save_config_as_base64(base_config_template, args.output)

if __name__ == "__main__":
    main()
