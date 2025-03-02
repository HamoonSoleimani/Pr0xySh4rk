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
import time
from typing import List, Dict, Optional, Any, Tuple
from urllib3.exceptions import InsecureRequestWarning

# Suppress SSL warnings for testing
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# --- Configuration ---
# Test against these websites (HTTP/HTTPS)
TEST_URLS = [
    "http://httpbin.org/get",
    "https://www.cloudflare.com/",
    "http://neverssl.com",
    "http://stu.iust.ac.ir/index.rose",
    "https://api.ipify.org/?format=json"
]
# Gather the best N working configs for each protocol
BEST_CONFIGS_LIMIT = 75
# Timeouts (in seconds)
HTTP_TIMEOUT = 5
TCP_TIMEOUT = 3
UDP_TIMEOUT = 2

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
        response = session.get(url, timeout=HTTP_TIMEOUT, proxies=proxies, verify=False)
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
        # Try to decode base64 if applicable
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
                print(f"Thread {os.getpid()}: Found config: {line}")
                outbounds.append(line)
    except Exception as e:
        print(f"Thread {os.getpid()}: Error processing content: {e}")
    return outbounds

# ---------------------------
# Parse vmess config to extract server and port
# ---------------------------
def parse_vmess_config(config_line: str) -> Tuple[Optional[str], Optional[int]]:
    try:
        # For vmess, the part after vmess:// is base64 encoded
        remainder = config_line.split("://", 1)[1]
        decoded = base64.b64decode(remainder.split("#")[0]).decode("utf-8")
        data = json.loads(decoded)
        server = data.get("add")
        port = data.get("port")
        return server, port
    except Exception as e:
        print(f"Error parsing vmess config: {e}")
        return None, None

# ---------------------------
# Parse ss config to extract server and port
# ---------------------------
def parse_ss_config(config_line: str) -> Tuple[Optional[str], Optional[int]]:
    try:
        # ss://BASE64(method:password)@server:port
        remainder = config_line.split("://", 1)[1]
        if "@" in remainder:
            server_part = remainder.split("@", 1)[1]
            if ":" in server_part:
                server = server_part.split(":", 1)[0]
                port_str = server_part.split(":", 1)[1].split("#")[0].split("?")[0]
                try:
                    port = int(port_str)
                    return server, port
                except ValueError:
                    pass
    except Exception as e:
        print(f"Error parsing ss config: {e}")
    return None, None

# ---------------------------
# Get server and port from config line
# ---------------------------
def get_server_port(config_line: str) -> Tuple[Optional[str], Optional[int]]:
    try:
        protocol = config_line.split("://", 1)[0].lower()

        if protocol == "vmess":
            return parse_vmess_config(config_line)
        elif protocol == "ss":
            return parse_ss_config(config_line)
        else:
            # For other protocols use urlparse
            parsed_url = urllib.parse.urlparse(config_line)
            return parsed_url.hostname, parsed_url.port
    except Exception as e:
        print(f"Error extracting server/port from {config_line}: {e}")
        return None, None

# ---------------------------
# Get deduplication key from config based on addresses/properties
# ---------------------------
def get_dedup_key(config: str) -> tuple:
    scheme_sep = "://"
    if scheme_sep not in config:
        return (config,)

    scheme = config.split(scheme_sep, 1)[0].lower()
    server, port = get_server_port(config)

    # Return a tuple of scheme, server, port for deduplication
    return (scheme, server, port)

# ---------------------------
# Deduplicate outbounds based on deduplication key (address/properties)
# ---------------------------
def deduplicate_outbounds(outbounds: List[str]) -> List[str]:
    dedup_dict = {}
    for config in outbounds:
        key = get_dedup_key(config)
        if key[1] is not None and key[2] is not None:  # Only include configs with valid server and port
            if key not in dedup_dict:
                dedup_dict[key] = config
    return list(dedup_dict.values())

# ---------------------------
# TCP test
# ---------------------------
async def tcp_test_outbound(ob: Dict[str, Any]) -> None:
    config_line = ob.get("original_config", "")
    server, port = get_server_port(config_line)

    if not server or not port:
        ob["tcp_delay"] = float('inf')
        print(f"TCP Test: No server/port, delay=inf - Config: {config_line}")
        return

    loop = asyncio.get_event_loop()
    start = loop.time()
    print(f"TCP Test for {server}:{port} started...")

    try:
        # Resolve IP address first to ensure accurate testing
        resolved_ip = socket.gethostbyname(server)

        # Use asyncio.wait_for to enforce a strict timeout
        conn_task = asyncio.open_connection(resolved_ip, port)
        reader, writer = await asyncio.wait_for(conn_task, timeout=TCP_TIMEOUT)

        delay = (loop.time() - start) * 1000
        writer.close()
        try:
            await writer.wait_closed()
        except:
            pass

        ob["tcp_delay"] = delay
        print(f"TCP Test for {server}:{port} finished, delay={delay:.2f} ms")
    except (socket.gaierror, socket.herror) as e:
        ob["tcp_delay"] = float('inf')
        print(f"TCP Test for {server}:{port} DNS resolution failed: {e}")
    except asyncio.TimeoutError:
        ob["tcp_delay"] = float('inf')
        print(f"TCP Test for {server}:{port} timed out after {TCP_TIMEOUT}s")
    except Exception as e:
        ob["tcp_delay"] = float('inf')
        print(f"TCP Test for {server}:{port} error: {type(e).__name__} - {e}")

def tcp_test_outbound_sync(ob: Dict[str, Any]) -> None:
    try:
        asyncio.run(tcp_test_outbound(ob))
    except Exception as e:
        print(f"Exception in tcp_test_outbound_sync: {e}")
        ob["tcp_delay"] = float('inf')

# ---------------------------
# HTTP test (for both HTTP and HTTPS URLs)
# Modified: if any one repetition for any test URL fails, the config is marked as failed.
# ---------------------------
async def http_delay_test_outbound(ob: Dict[str, Any], proxy_for_test: Optional[str], repetitions: int) -> None:
    config_line = ob.get("original_config", "")
    server, port = get_server_port(config_line)

    if not server or not port:
        ob["http_delay"] = float('inf')
        print(f"HTTP Test: No server/port, delay=inf - Config: {config_line}")
        return

    session = requests.Session()
    loop = asyncio.get_event_loop()
    total_delay = 0.0
    total_tests = 0

    current_proxies = {'http': proxy_for_test, 'https': proxy_for_test} if proxy_for_test else None

    print(f"HTTP Test for {server}:{port} started with {repetitions} repetitions for each test URL...")

    for test_url in TEST_URLS:
        for i in range(repetitions):
            if is_ctrl_c_pressed:
                print("HTTP Test interrupted by Ctrl+C")
                ob["http_delay"] = float('inf')
                return

            start_time = loop.time()
            try:
                with session.get(test_url, timeout=HTTP_TIMEOUT, proxies=current_proxies, stream=True, verify=False) as response:
                    response.raise_for_status()
                elapsed = (loop.time() - start_time) * 1000
                total_delay += elapsed
                total_tests += 1
                print(f"    [{server}:{port}] {test_url} Rep {i+1}: {elapsed:.2f} ms")
            except Exception as e:
                print(f"    [{server}:{port}] {test_url} Rep {i+1} failed: {e}")
                ob["http_delay"] = float('inf')
                return

    overall_avg = total_delay / total_tests if total_tests > 0 else float('inf')
    ob["http_delay"] = overall_avg
    print(f"HTTP Test for {server}:{port} completed. Overall Average: {overall_avg:.2f} ms")

def http_delay_test_outbound_sync(ob: Dict[str, Any], proxy: Optional[str], repetitions: int) -> None:
    try:
        asyncio.run(http_delay_test_outbound(ob, proxy, repetitions))
    except Exception as e:
        print(f"Exception in http_delay_test_outbound_sync: {e}")
        ob["http_delay"] = float('inf')

# ---------------------------
# UDP test (for WireGuard/WARP)
# ---------------------------
async def udp_test_outbound(ob: Dict[str, Any]) -> None:
    config_line = ob.get("original_config", "")
    server, port = get_server_port(config_line)

    # Special case for WireGuard/WARP protocols
    is_wireguard = config_line.startswith(("warp://", "wireguard://"))

    if not server or not port:
        if is_wireguard:
            print(f"UDP Test: No server/port for WG/WARP, checking if config is valid: {config_line}")
            try:
                if "#" in config_line:
                    ob["udp_delay"] = 100.0  # Assign a default delay for WG/WARP
                    return
            except Exception as e:
                pass
        ob["udp_delay"] = float('inf')
        print(f"UDP Test: No server/port, delay=inf - Config: {config_line}")
        return

    try:
        try:
            resolved_ip = socket.gethostbyname(server)
        except (socket.gaierror, socket.herror) as e:
            ob["udp_delay"] = float('inf')
            print(f"UDP Test for {server}:{port} DNS resolution failed: {e}")
            return

        loop = asyncio.get_event_loop()
        start = loop.time()
        print(f"UDP Test for {server}:{port} ({resolved_ip}:{port}) started...")

        # Create UDP socket and send a test packet using transport.sendto()
        transport, _ = await loop.create_datagram_endpoint(
            lambda: asyncio.DatagramProtocol(),
            remote_addr=(resolved_ip, port)
        )

        # Call transport.sendto() directly. Since remote_addr is set,
        # there is no need to specify the address.
        transport.sendto(b'\x00\x00\x00\x00')

        await asyncio.sleep(0.1)

        delay = (loop.time() - start) * 1000
        transport.close()

        ob["udp_delay"] = delay
        print(f"UDP Test for {server}:{port} finished, delay={delay:.2f} ms")
    except asyncio.TimeoutError:
        ob["udp_delay"] = float('inf')
        print(f"UDP Test for {server}:{port} timed out")
    except Exception as e:
        ob["udp_delay"] = float('inf')
        print(f"UDP Test for {server}:{port} error: {type(e).__name__} - {e}")

def udp_test_outbound_sync(ob: Dict[str, Any]) -> None:
    try:
        asyncio.run(udp_test_outbound(ob))
    except Exception as e:
        print(f"Exception in udp_test_outbound_sync: {e}")
        ob["udp_delay"] = float('inf')

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

    print(f"Starting tests ({test_type}) on {total_outbounds_count} outbounds")

    with concurrent.futures.ThreadPoolExecutor(max_workers=thread_pool_size) as executor:
        futures_map = {}
        for index, ob in enumerate(outbounds):
            if is_ctrl_c_pressed:
                print("Ctrl+C detected, stopping tests.")
                break

            config_line = ob.get("original_config", "")
            try:
                protocol = config_line.split("://")[0].lower()
            except Exception as e:
                print(f"Error parsing protocol from {config_line}: {e}")
                continue

            futures_list = []

            if test_type == "tcp+http":
                if protocol in ("warp", "wireguard"):
                    future = executor.submit(udp_test_outbound_sync, ob)
                    futures_list.append(future)
                else:
                    # Run TCP test first; then (below) we also submit the HTTP test regardless of TCP result.
                    future_tcp = executor.submit(tcp_test_outbound_sync, ob)
                    futures_list.append(future_tcp)
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

            futures_map[index] = futures_list

        if test_type == "tcp+http":
            # For non-WG protocols, submit HTTP test regardless of TCP result
            for index, futures_list in list(futures_map.items()):
                if is_ctrl_c_pressed:
                    break

                config_line = outbounds[index].get("original_config", "")
                protocol = config_line.split("://")[0].lower()

                if protocol not in ("warp", "wireguard"):
                    future_http = executor.submit(http_delay_test_outbound_sync, outbounds[index], proxy_for_test, repetitions)
                    futures_map[index].append(future_http)

        all_futures = [future for futures_list in futures_map.values() for future in futures_list]

        for future in concurrent.futures.as_completed(all_futures):
            if is_ctrl_c_pressed:
                break
            try:
                future.result()
            except Exception as e:
                print(f"Exception during test: {e}")
            finally:
                for index, futures_list in futures_map.items():
                    if future in futures_list and index not in processed_outbound_indices:
                        if all(f.done() for f in futures_list):
                            completed_outbounds_count += 1
                            processed_outbound_indices.add(index)
                            progress_percentage = (completed_outbounds_count / total_outbounds_count) * 100
                            print(f"Progress: {progress_percentage:.2f}% ({completed_outbounds_count}/{total_outbounds_count})")

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
# Rename and limit configs by protocol
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
        try:
            proto = config.split("://")[0].lower()
            abbr = protocol_map.get(proto, proto.upper())
            protocol_groups.setdefault(abbr, []).append(config_dict)
        except Exception as e:
            print(f"Error processing config {config}: {e}")
            continue

    for abbr, conf_list in protocol_groups.items():
        valid_list = [item for item in conf_list if item.get('combined_delay', float('inf')) != float('inf')]
        valid_list.sort(key=lambda x: x.get('combined_delay', float('inf')))
        limited_list = valid_list[:BEST_CONFIGS_LIMIT]

        for i, config_dict in enumerate(limited_list, start=1):
            config = config_dict["original_config"]
            new_tag = f"🔒Pr0xySh4rk🦈{abbr}{i:02d}"

            if "#" in config:
                base_part = config.split("#")[0].rstrip()
                new_config = f"{base_part}#{urllib.parse.quote(new_tag)}"
            else:
                new_config = f"{config}#{urllib.parse.quote(new_tag)}"

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
            # Try base64 decoding
            decoded_possible = base64.b64decode(normalized_content, validate=True).decode("utf-8")
            content = decoded_possible
        except Exception:
            pass

        outbounds_list = parse_config_content(content)

        if outbounds_list:
            try:
                # Deduplicate within this subscription before returning
                unique_configs = deduplicate_outbounds(outbounds_list)
                print(f"Thread {os.getpid()}: Parsed {len(unique_configs)} unique outbounds from {url}")
                return [{"original_config": ob, "source": url} for ob in unique_configs]
            except Exception as e:
                print(f"Thread {os.getpid()}: Error deduplicating outbounds from {url}: {e}")
                return []
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
    global is_ctrl_c_pressed, TCP_TIMEOUT, HTTP_TIMEOUT, UDP_TIMEOUT
    signal.signal(signal.SIGINT, signal_handler)

    parser = argparse.ArgumentParser(description="Pr0xySh4rk Xray Config Merger")
    parser.add_argument("--input", required=True, help="Input file (base64 or URLs)")
    parser.add_argument("--output", required=True, help="Output file")
    parser.add_argument("--proxy", help="Proxy for fetching")
    parser.add_argument("--threads", type=int, default=32, help="Threads")
    parser.add_argument("--test-proxy", help="Proxy for HTTP testing")
    parser.add_argument("-r", "--repetitions", type=int, default=3, help="HTTP test repetitions")
    parser.add_argument("--test", choices=["tcp", "udp", "http", "tcp+http"], default="tcp+http", help="Test type")
    parser.add_argument("--no-base64", action="store_true", help="Output in plaintext instead of base64 encoding")
    parser.add_argument("--tcp-timeout", type=float, default=TCP_TIMEOUT, help=f"TCP test timeout in seconds (default: {TCP_TIMEOUT})")
    parser.add_argument("--http-timeout", type=float, default=HTTP_TIMEOUT, help=f"HTTP test timeout in seconds (default: {HTTP_TIMEOUT})")
    parser.add_argument("--udp-timeout", type=float, default=UDP_TIMEOUT, help=f"UDP test timeout in seconds (default: {UDP_TIMEOUT})")
    args = parser.parse_args()

    # Update global timeout values
    TCP_TIMEOUT = args.tcp_timeout
    HTTP_TIMEOUT = args.http_timeout
    UDP_TIMEOUT = args.udp_timeout

    # Save and clear environment proxy variables
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
                # Try decoding as base64
                decoded_content = base64.b64decode(encoded_content).decode("utf-8")
                subscription_urls = [line.strip() for line in decoded_content.splitlines() if line.strip()]
                print("URLs decoded from base64.")
            except Exception:
                print("Trying plain text format.")
                try:
                    with open(args.input, "r") as f2:
                        subscription_urls = [line.strip() for line in f2 if line.strip()]
                except UnicodeDecodeError:
                    print("Error: Input file is neither valid base64 nor plain text.")
                    return
    except FileNotFoundError:
        print(f"Error: {args.input} not found.")
        return

    if not subscription_urls:
        print("No URLs found. Exiting.")
        return

    # Fetch and parse subscription URLs
    parsed_outbounds_lists = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = [
            executor.submit(fetch_and_parse_subscription_thread, url, args.proxy)
            for url in subscription_urls
        ]

        for future in concurrent.futures.as_completed(futures):
            if is_ctrl_c_pressed:
                print("Ctrl+C during fetching.")
                break
            try:
                result = future.result()
                if result:
                    parsed_outbounds_lists.extend(result)
            except Exception as e:
                print(f"Error processing subscription: {e}")

        if is_ctrl_c_pressed:
            print("Exiting early due to Ctrl+C.")
            sys.exit(0)

    print(f"Total parsed configurations: {len(parsed_outbounds_lists)}")

    unique_outbounds_dict = {}
    for outbound in parsed_outbounds_lists:
        try:
            key = get_dedup_key(outbound["original_config"])
            if key[1] is not None and key[2] is not None:
                if key not in unique_outbounds_dict:
                    unique_outbounds_dict[key] = outbound
        except Exception as e:
            print(f"Error deduplicating outbound: {e}")

    unique_outbounds = list(unique_outbounds_dict.values())
    print(f"Unique deduplicated configs: {len(unique_outbounds)}")

    if args.test == "tcp+http":
        wireguard_warp_configs = [
            ob for ob in unique_outbounds
            if ob["original_config"].startswith(("warp://", "wireguard://"))
        ]
        other_configs = [
            ob for ob in unique_outbounds
            if not ob["original_config"].startswith(("warp://", "wireguard://"))
        ]

        combined_outbounds_for_test = other_configs + wireguard_warp_configs
        print("\n=== Testing all configs (TCP+HTTP for regular configs, UDP for WG/WARP) ===")

        single_test_pass(
            combined_outbounds_for_test,
            "tcp+http",
            args.threads,
            args.test_proxy,
            args.repetitions
        )

        # Modified survivors selection: healthy if either TCP or HTTP test passes
        survivors_tcp_http = [
            ob for ob in other_configs
            if ob.get("tcp_delay", float('inf')) != float('inf') or ob.get("http_delay", float('inf')) != float('inf')
        ]
        survivors_udp = [
            ob for ob in wireguard_warp_configs
            if ob.get("udp_delay", float('inf')) != float('inf')
        ]
        tested_outbounds = survivors_tcp_http + survivors_udp

        for ob in survivors_tcp_http:
            tcp_delay = ob.get("tcp_delay", float('inf'))
            http_delay = ob.get("http_delay", float('inf'))
            if tcp_delay != float('inf') and http_delay != float('inf'):
                ob["combined_delay"] = (tcp_delay + http_delay) / 2
            elif tcp_delay != float('inf'):
                ob["combined_delay"] = tcp_delay
            elif http_delay != float('inf'):
                ob["combined_delay"] = http_delay
    elif args.test == "tcp":
        single_test_pass(unique_outbounds, "tcp", args.threads, args.test_proxy, args.repetitions)
        tested_outbounds = [ob for ob in unique_outbounds if ob.get("tcp_delay", float('inf')) != float('inf')]
        for ob in tested_outbounds:
            ob["combined_delay"] = ob.get("tcp_delay", float('inf'))
    elif args.test == "http":
        single_test_pass(unique_outbounds, "http", args.threads, args.test_proxy, args.repetitions)
        tested_outbounds = [ob for ob in unique_outbounds if ob.get("http_delay", float('inf')) != float('inf')]
        for ob in tested_outbounds:
            ob["combined_delay"] = ob.get("http_delay", float('inf'))
    elif args.test == "udp":
        single_test_pass(unique_outbounds, "udp", args.threads, args.test_proxy, args.repetitions)
        tested_outbounds = [ob for ob in unique_outbounds if ob.get("udp_delay", float('inf')) != float('inf')]
        for ob in tested_outbounds:
            ob["combined_delay"] = ob.get("udp_delay", float('inf'))
    else:
        tested_outbounds = []
        print(f"Error: Unknown test type: {args.test}")

    renamed_final_outbounds = rename_configs_by_protocol(tested_outbounds)
    print(f"Renamed and limited configs: {len(renamed_final_outbounds)}")
    save_config(renamed_final_outbounds, filepath=args.output, base64_encode=not args.no_base64)

    for var, value in original_env.items():
        os.environ[var] = value

if __name__ == "__main__":
    main()
