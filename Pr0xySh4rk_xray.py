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
import json
import logging
import re
from typing import List, Dict, Optional, Any

# --- Configuration ---
# Test against these two websites: one HTTPS and one HTTP.
TEST_URLS = [
    "http://cp.cloudflare.com/",
    "http://neverssl.com",
    "http://stu.iust.ac.ir/index.rose"
]
# Gather the best 75 working configs for each protocol.
BEST_CONFIGS_LIMIT = 75
total_outbounds_count = 0
completed_outbounds_count = 0
is_ctrl_c_pressed = False

# ---------------------------
# Sanitize config string to remove extraneous junk.
# For vmess URLs, remove any trailing non-base64 characters.
# For vless URLs, fix double-bracketed IPv6 addresses.
# ---------------------------
def sanitize_config(config: str) -> str:
    if config.startswith("vmess://"):
        # Extract only valid base64 characters after "vmess://"
        m = re.match(r"^(vmess://)([A-Za-z0-9+/=]+)", config)
        if m:
            return m.group(1) + m.group(2)
        else:
            return config
    elif config.startswith("vless://"):
        # Replace any double brackets in IPv6 addresses with single brackets.
        config = config.replace("[[", "[").replace("]]", "]")
        return config
    # For other protocols, return as-is.
    return config

# ---------------------------
# Signal Handler for Ctrl+C
# ---------------------------
def signal_handler(sig, frame):
    global is_ctrl_c_pressed
    logging.info("Ctrl+C detected. Gracefully stopping...")
    is_ctrl_c_pressed = True

# ---------------------------
# Fetching content from URLs
# ---------------------------
def fetch_content(url: str, proxy: Optional[str] = None) -> Optional[str]:
    session = requests.Session()
    proxies = {"http": proxy, "https": proxy} if proxy else {"http": None, "https": None}
    logging.info(f"Thread {os.getpid()}: Fetching {url} {'using proxy: ' + proxy if proxy else 'directly'}")
    try:
        response = session.get(url, timeout=5, proxies=proxies)
        response.raise_for_status()
        return response.text
    except requests.exceptions.RequestException as e:
        logging.error(f"Thread {os.getpid()}: Error fetching {url}: {type(e).__name__} - {e}")
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

        # Allowed protocols (excluding trojan)
        for line in content.splitlines():
            line = line.strip()
            if line and not line.startswith("#") and line.startswith((
                "vless://", "vmess://", "ss://", "tuic://",
                "hysteria://", "hysteria2://", "hy2://",
                "warp://", "wireguard://"
            )):
                logging.info(f"Thread {os.getpid()}: Found config: {line}")
                outbounds.append(line)
    except Exception as e:
        logging.error(f"Thread {os.getpid()}: Error processing content: {e}")
    return outbounds

# ---------------------------
# Get deduplication key from config based on addresses/properties.
# First sanitize the config.
# ---------------------------
def get_dedup_key(config: str) -> tuple:
    config = sanitize_config(config)
    scheme_sep = "://"
    if scheme_sep not in config:
        return (config,)
    scheme = config.split(scheme_sep, 1)[0].lower()
    remainder = config.split(scheme_sep, 1)[1]
    if scheme == "vmess":
        try:
            # For vmess, decode the base64 part to extract JSON properties
            decoded = base64.b64decode(remainder).decode("utf-8")
            data = json.loads(decoded)
            address = data.get("add")
            port = data.get("port")
            return (scheme, address, port)
        except Exception:
            pass  # Fallback to urlparse if decoding fails
    if scheme == "ss":
        # For ss, try to extract address and port after '@'
        if "@" in remainder:
            try:
                creds, rest = remainder.split("@", 1)
                if ":" in rest:
                    host_part = rest.split(":", 1)
                    address = host_part[0]
                    port_str = host_part[1].split("#")[0]
                    try:
                        port = int(port_str)
                    except:
                        port = None
                    return (scheme, address, port)
            except Exception:
                pass
    try:
        parsed = urllib.parse.urlparse(config)
    except Exception as e:
        logging.error(f"Error parsing URL '{config}': {e}")
        return (config,)
    try:
        port = parsed.port
    except Exception:
        port = None
    hostname = parsed.hostname
    if hostname and hostname.startswith("[[") and hostname.endswith("]]"):
        hostname = hostname[1:-1]
    return (parsed.scheme.lower(), hostname, port)

# ---------------------------
# Deduplicate outbounds based on deduplication key (address/properties)
# ---------------------------
def deduplicate_outbounds(outbounds: List[str]) -> List[str]:
    dedup_dict = {}
    for config in outbounds:
        try:
            key = get_dedup_key(config)
        except Exception as e:
            logging.error(f"Error getting dedup key for config: {config}, error: {e}")
            continue
        if key not in dedup_dict:
            dedup_dict[key] = config
    return list(dedup_dict.values())

# ---------------------------
# TCP test
# ---------------------------
def tcp_test_outbound_sync(ob: Dict[str, Any]) -> None:
    try:
        asyncio.run(tcp_test_outbound(ob))
    except Exception as e:
        logging.error(f"Exception in tcp_test_outbound_sync: {ob.get('original_config')}: {e}")

async def tcp_test_outbound(ob: Dict[str, Any]) -> None:
    config_line = ob.get("original_config")
    parsed_url = urllib.parse.urlparse(config_line)
    server, port = parsed_url.hostname, parsed_url.port

    if not server or not port:
        ob["tcp_delay"] = float('inf')
        logging.info(f"TCP Test: No server/port, delay=inf - Config: {config_line}")
        return

    loop = asyncio.get_event_loop()
    start = loop.time()
    logging.info(f"TCP Test for {config_line} to {server}:{port} started...")

    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(server, port), timeout=1)
        delay = (loop.time() - start) * 1000
        writer.close()
        await writer.wait_closed()
        ob["tcp_delay"] = delay
        logging.info(f"TCP Test for {config_line} finished, delay={delay:.2f} ms")
    except Exception as e:
        ob["tcp_delay"] = float('inf')
        logging.error(f"TCP Test for {config_line} error: {e}, delay=inf")

# ---------------------------
# HTTP test (complete and precise for both HTTPS and HTTP URLs)
# ---------------------------
def http_delay_test_outbound_sync(ob: Dict[str, Any], proxy: Optional[str], repetitions: int) -> None:
    try:
        asyncio.run(http_delay_test_outbound(ob, proxy, repetitions))
    except Exception as e:
        logging.error(f"Exception in http_delay_test_outbound_sync: {ob.get('original_config')}: {e}")

async def http_delay_test_outbound(ob: Dict[str, Any], proxy_for_test: Optional[str], repetitions: int) -> None:
    config_line = ob.get("original_config")
    parsed_url = urllib.parse.urlparse(config_line)
    server, port = parsed_url.hostname, parsed_url.port

    if not server or not port:
        ob["http_delay"] = float('inf')
        logging.info(f"HTTP Test: No server/port, delay=inf - Config: {config_line}")
        return

    session = requests.Session()
    website_averages = []

    logging.info(f"HTTP Test for {config_line} started with {repetitions} repetitions for each test URL...")

    # Test each website defined in TEST_URLS
    for test_url in TEST_URLS:
        times = []
        logging.info(f"  Testing against: {test_url}")
        for i in range(repetitions):
            start = asyncio.get_event_loop().time()
            current_proxies = {'http': proxy_for_test, 'https': proxy_for_test} if proxy_for_test else None
            try:
                with session.get(test_url, timeout=1, proxies=current_proxies) as response:
                    response.raise_for_status()
                elapsed = (asyncio.get_event_loop().time() - start) * 1000
                times.append(elapsed)
                logging.info(f"    [{config_line}] {test_url} Repetition {i+1}: {elapsed:.2f} ms")
            except requests.exceptions.RequestException as e:
                times.append(None)
                logging.error(f"    [{config_line}] {test_url} Repetition {i+1} failed: {e}")
        successful_times = [t for t in times if t is not None]
        if successful_times:
            avg = sum(successful_times) / len(successful_times)
            website_averages.append(avg)
            logging.info(f"  Average delay for {test_url}: {avg:.2f} ms")
        else:
            website_averages.append(float('inf'))
            logging.info(f"  All trials failed for {test_url}, marking as inf delay")

    if any(avg == float('inf') for avg in website_averages):
        ob["http_delay"] = float('inf')
        logging.info(f"HTTP Test for {config_line} failed because one or more test URLs did not pass.")
    else:
        overall_avg = sum(website_averages) / len(website_averages)
        ob["http_delay"] = overall_avg
        logging.info(f"HTTP Test for {config_line} finished. Overall Average: {overall_avg:.2f} ms")

# ---------------------------
# UDP test (for WireGuard/WARP)
# ---------------------------
def udp_test_outbound_sync(ob: Dict[str, Any]) -> None:
    try:
        asyncio.run(udp_test_outbound(ob))
    except Exception as e:
        logging.error(f"Exception in udp_test_outbound_sync: {ob.get('original_config')}: {e}")

async def udp_test_outbound(ob: Dict[str, Any]) -> None:
    config_line = ob.get("original_config")
    parsed_url = urllib.parse.urlparse(config_line)
    server, port = parsed_url.hostname, parsed_url.port

    if (not server or not port) and config_line.startswith(("warp://", "wireguard://")):
        ob["udp_delay"] = float('inf')
        logging.info(f"UDP Test: No server/port (but WG/WARP), delay=inf - Config: {config_line}")
        return
    elif not server or not port:
        ob["udp_delay"] = float('inf')
        logging.info(f"UDP Test: No server/port, delay=inf - Config: {config_line}")
        return

    try:
        ip = (await asyncio.get_event_loop().getaddrinfo(server, None, family=socket.AF_INET))[0][4][0]
    except Exception as e:
        ob["udp_delay"] = float('inf')
        logging.error(f"UDP Test for {config_line}: getaddrinfo error: {e}, delay=inf")
        return

    loop = asyncio.get_event_loop()
    start = loop.time()
    logging.info(f"UDP Test for {config_line} to {server}:{port} ({ip}:{port}) started...")
    try:
        transport, _ = await loop.create_datagram_endpoint(lambda: asyncio.DatagramProtocol(), remote_addr=(ip, port))
        await asyncio.sleep(0.1)
        delay = (loop.time() - start) * 1000
        transport.close()
        ob["udp_delay"] = delay
        logging.info(f"UDP Test for {config_line} finished, delay={delay:.2f} ms")
    except Exception as e:
        ob["udp_delay"] = float('inf')
        logging.error(f"UDP Test for {config_line} error: {e}, delay=inf")

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
    processed_outbound_indices = set()

    logging.info(f"Starting tests ({test_type}) on {total_outbounds_count} outbounds")

    with concurrent.futures.ThreadPoolExecutor(max_workers=thread_pool_size) as executor:
        futures_map = {}
        for index, ob in enumerate(outbounds):
            if is_ctrl_c_pressed:
                logging.info("Ctrl+C detected, stopping tests.")
                break
            config_line = ob.get("original_config")
            protocol = config_line.split("://")[0]
            futures_list = []

            if test_type == "tcp+http":
                if protocol in ("warp", "wireguard"):
                    future = executor.submit(udp_test_outbound_sync, ob)
                    futures_list.append(future)
                else:
                    future_tcp = executor.submit(tcp_test_outbound_sync, ob)
                    future_http = executor.submit(http_delay_test_outbound_sync, ob, proxy_for_test, repetitions)
                    futures_list.extend([future_tcp, future_http])
            elif test_type == "tcp":
                future = executor.submit(tcp_test_outbound_sync, ob)
                futures_list.append(future)
            elif test_type == "http":
                future = executor.submit(http_delay_test_outbound_sync, ob, proxy_for_test, repetitions)
                futures_list.append(future)
            elif test_type == "udp":
                if protocol in ("warp", "wireguard"):
                    future = executor.submit(udp_test_outbound_sync, ob)
                    futures_list.append(future)
                else:
                    ob["udp_delay"] = float('inf')
                    continue
            else:
                future = executor.submit(http_delay_test_outbound_sync, ob, proxy_for_test, repetitions)
                futures_list.append(future)
            futures_map[index] = futures_list

        all_futures = [future for futures_list in futures_map.values() for future in futures_list]

        for future in concurrent.futures.as_completed(all_futures):
            if is_ctrl_c_pressed:
                break
            try:
                future.result()
            except Exception as e:
                logging.error(f"Exception during test: {e}")
            finally:
                for index, futures_list in futures_map.items():
                    if future in futures_list and index not in processed_outbound_indices:
                        all_done = all(f.done() for f in futures_list)
                        if all_done:
                            completed_outbounds_count += 1
                            processed_outbound_indices.add(index)
                            progress_percentage = (completed_outbounds_count / total_outbounds_count) * 100
                            logging.info(f"Progress: {progress_percentage:.2f}% ({completed_outbounds_count}/{total_outbounds_count})")
                            break

    logging.info("Testing completed.")

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
            logging.info(f"Merged configs saved to {filepath} as base64 encoded.")
        else:
            with open(filepath, "w") as outfile:
                for outbound in outbounds:
                    outfile.write(outbound + "\n")
            logging.info(f"Merged configs saved to {filepath} as plaintext.")
    except Exception as e:
        logging.error(f"Error saving config: {e}")

# ---------------------------
# Rename and limit configs by protocol.
# For each protocol, select the best {BEST_CONFIGS_LIMIT} working configs (lowest combined delay)
# and assign a Pr0xySh4rk-formatted tag.
# ---------------------------
def rename_configs_by_protocol(configs: List[Dict[str, Any]]) -> List[str]:
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
    renamed_configs = []
    protocol_groups = {}
    for config_dict in configs:
        config = config_dict["original_config"]
        proto = config.split("://")[0].lower()
        abbr = protocol_map.get(proto, proto.upper())
        protocol_groups.setdefault(abbr, []).append(config_dict)

    for abbr, conf_list in protocol_groups.items():
        valid_list = [item for item in conf_list if item.get('combined_delay', float('inf')) != float('inf')]
        valid_list.sort(key=lambda x: x.get('combined_delay', float('inf')))
        limited_list = valid_list[:BEST_CONFIGS_LIMIT]
        for i, config_dict in enumerate(limited_list, start=1):
            config = config_dict["original_config"]
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
    logging.info(f"Thread {os.getpid()}: Fetching: {url}")
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
            logging.info(f"Thread {os.getpid()}: Parsed {len(outbounds_list)} outbounds from {url}")
            return [{"original_config": ob, "source": url} for ob in outbounds_list]
        else:
            logging.info(f"Thread {os.getpid()}: No outbounds parsed from {url}")
            return []
    else:
        logging.error(f"Thread {os.getpid()}: Failed to fetch {url}")
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
    parser.add_argument("--no-base64", action="store_true", help="Output in plaintext instead of base64 encoding")
    parser.add_argument("--log", help="Log file to write logs to")
    args = parser.parse_args()

    # Set up logging to both console and file if --log is provided.
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    # Console handler
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(formatter)
    logger.addHandler(ch)
    # File handler (if provided)
    if args.log:
        fh = logging.FileHandler(args.log, mode="w")
        fh.setLevel(logging.INFO)
        fh.setFormatter(formatter)
        logger.addHandler(fh)

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
                logging.info("URLs decoded from base64.")
            except Exception:
                logging.info("Trying plain text.")
                with open(args.input, "r") as f2:
                    subscription_urls = [line.strip() for line in f2 if line.strip()]
    except FileNotFoundError:
        logging.error(f"Error: {args.input} not found.")
        return

    if not subscription_urls:
        logging.error("No URLs found. Exiting.")
        return

    parsed_outbounds_lists = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = [executor.submit(fetch_and_parse_subscription_thread, url, args.proxy) for url in subscription_urls]
        for future in concurrent.futures.as_completed(futures):
            if is_ctrl_c_pressed:
                logging.info("Ctrl+C during fetching.")
                break
            result = future.result()
            if result:
                parsed_outbounds_lists.extend(result)
        if is_ctrl_c_pressed:
            logging.info("Exiting early due to Ctrl+C.")
            sys.exit(0)

    all_parsed_outbounds = parsed_outbounds_lists
    logging.info(f"Total parsed: {len(all_parsed_outbounds)}")

    deduplicated_outbounds = deduplicate_outbounds([ob["original_config"] for ob in all_parsed_outbounds])
    logging.info(f"Unique: {len(deduplicated_outbounds)}")
    deduplicated_outbounds_dicts = [{
        "original_config": config,
        "source": next((o["source"] for o in all_parsed_outbounds if o["original_config"] == config), "unknown")
    } for config in deduplicated_outbounds]

    if args.test == "tcp+http":
        wireguard_warp_configs = [ob for ob in deduplicated_outbounds_dicts if ob["original_config"].startswith(("warp://", "wireguard://"))]
        other_configs = [ob for ob in deduplicated_outbounds_dicts if not ob["original_config"].startswith(("warp://", "wireguard://"))]

        combined_outbounds_for_test = other_configs + wireguard_warp_configs
        total_outbounds_count = len(combined_outbounds_for_test)

        logging.info("=== Testing all configs (TCP+HTTP for others, UDP for WG/WARP) ===")
        single_test_pass(combined_outbounds_for_test, "tcp+http", args.threads, args.test_proxy, args.repetitions)

        survivors_tcp_http = [ob for ob in other_configs if ob.get("tcp_delay", float('inf')) != float('inf') and ob.get("http_delay", float('inf')) != float('inf')]
        logging.info(f"{len(survivors_tcp_http)} non-WG/WARP passed TCP and HTTP tests.")
        survivors_udp = [ob for ob in wireguard_warp_configs if ob.get("udp_delay", float('inf')) != float('inf')]
        logging.info(f"{len(survivors_udp)} WG/WARP passed UDP tests.")

        tested_outbounds = survivors_tcp_http + survivors_udp

        for ob in survivors_tcp_http:
            ob["combined_delay"] = (ob.get("tcp_delay", float('inf')) + ob.get("http_delay", float('inf'))) / 2 if ob.get("tcp_delay", float('inf')) != float('inf') and ob.get("http_delay", float('inf')) != float('inf') else float('inf')
        for ob in survivors_udp:
            ob["combined_delay"] = ob.get("udp_delay", float('inf'))

    else:
        total_outbounds_count = len(deduplicated_outbounds_dicts)
        single_test_pass(deduplicated_outbounds_dicts, args.test, args.threads, args.test_proxy, args.repetitions)
        if is_ctrl_c_pressed:
            logging.info("Exiting after testing due to Ctrl+C.")
            sys.exit(0)

        if args.test == "tcp":
            tested_outbounds = [ob for ob in deduplicated_outbounds_dicts if ob.get("tcp_delay", float('inf')) != float('inf')]
        elif args.test == "udp":
            tested_outbounds = [ob for ob in deduplicated_outbounds_dicts if ob.get("udp_delay", float('inf')) != float('inf')]
        else:  # http test
            tested_outbounds = [ob for ob in deduplicated_outbounds_dicts if ob.get("http_delay", float('inf')) != float('inf')]
        logging.info(f"{len(tested_outbounds)} passed {args.test} test.")

        for ob in tested_outbounds:
            if args.test == "tcp":
                ob["combined_delay"] = ob.get("tcp_delay", float('inf'))
            elif args.test == "udp":
                ob["combined_delay"] = ob.get("udp_delay", float('inf'))
            else:
                ob["combined_delay"] = ob.get("http_delay", float('inf'))

    renamed_final_outbounds = rename_configs_by_protocol(tested_outbounds)
    logging.info("Renaming and limiting completed. Total renamed configs: " + str(len(renamed_final_outbounds)))

    save_config(renamed_final_outbounds, filepath=args.output, base64_encode=not args.no_base64)

    for var, value in original_env.items():
        os.environ[var] = value

if __name__ == "__main__":
    main()
