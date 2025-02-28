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
import time
import random
import hashlib
from typing import List, Dict, Optional, Any, Tuple
from urllib3.exceptions import InsecureRequestWarning

# Suppress only the single InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

#####################################
#             CONFIGURATION         #
#####################################

# Test against these websites: mix of HTTPS and HTTP sites, with different locations
TEST_URLS = [
    "https://www.google.com/",
    "http://neverssl.com",
    "https://www.cloudflare.com/",
    "http://httpbin.org/get",
    "https://api.ipify.org/?format=json"
]

# Expected responses for validation
VALIDATION_PATTERNS = {
    "https://www.google.com/": ["<html", "google"],
    "http://neverssl.com": ["<html", "neverssl"],
    "https://www.cloudflare.com/": ["<html", "cloudflare"],
    "http://httpbin.org/get": ['"url"', "httpbin"],
    "https://api.ipify.org/?format=json": ['"ip"']
}

# Gather the best configs for each protocol
BEST_CONFIGS_LIMIT = 75

# Timeouts
TCP_TIMEOUT = 3      # seconds
HTTP_TIMEOUT = 5     # seconds
UDP_TIMEOUT = 3      # seconds

# Global counters
total_outbounds_count = 0
completed_outbounds_count = 0
is_ctrl_c_pressed = False

#####################################
#        UTILITY FUNCTIONS          #
#####################################

def get_proxy_url(config: str) -> Optional[str]:
    """Convert config to usable proxy URL for requests library"""
    if config.startswith("socks://") or config.startswith("socks5://"):
        protocol = config.split("://")[0]
        remainder = config.split("://")[1]
        # Extract credentials if present
        if "@" in remainder:
            creds, remainder = remainder.split("@", 1)
            if ":" in creds:
                username, password = creds.split(":", 1)
                proxy_str = f"{protocol}://{username}:{password}@{remainder}"
            else:
                proxy_str = f"{protocol}://{remainder}"
        else:
            proxy_str = f"{protocol}://{remainder}"
        return proxy_str
    elif config.startswith("http://") or config.startswith("https://"):
        return config
    # For vmess, vless, ss, etc., need to use a local proxy bridge (not implemented here)
    return None

def sanitize_config(config: str) -> str:
    if not config:
        return config
    if config.startswith("vmess://"):
        # Extract only valid base64 characters after "vmess://"
        m = re.match(r"^(vmess://)([A-Za-z0-9+/=]+)", config)
        if m:
            return m.group(1) + m.group(2)
        else:
            return config
    elif config.startswith("vless://"):
        # Replace any double brackets in IPv6 addresses with single brackets
        config = config.replace("[[", "[").replace("]]", "]")
        return config
    # For other protocols, return as-is
    return config

def signal_handler(sig, frame):
    global is_ctrl_c_pressed
    logging.info("Ctrl+C detected. Gracefully stopping...")
    is_ctrl_c_pressed = True

def fetch_content(url: str, proxy: Optional[str] = None, validate_patterns: Optional[List[str]] = None) -> Tuple[Optional[str], float, bool]:
    session = requests.Session()
    proxies = {"http": proxy, "https": proxy} if proxy else None
    result_content = None
    is_valid = False
    delay = float('inf')
    logging.info(f"Thread {os.getpid()}: Fetching {url} {'using proxy: ' + proxy if proxy else 'directly'}")
    try:
        start_time = time.time()
        response = session.get(url, timeout=HTTP_TIMEOUT, proxies=proxies, verify=False)
        delay = (time.time() - start_time) * 1000  # Convert to ms
        
        if response.status_code == 200:
            content = response.text
            result_content = content
            
            # Validate content if patterns are provided
            if validate_patterns:
                is_valid = all(pattern.lower() in content.lower() for pattern in validate_patterns)
            else:
                is_valid = True
                
            if is_valid:
                logging.info(f"Thread {os.getpid()}: Successfully fetched {url}, delay={delay:.2f}ms, validation: PASS")
            else:
                logging.warning(f"Thread {os.getpid()}: Fetched {url} but content validation failed, delay={delay:.2f}ms")
        else:
            logging.error(f"Thread {os.getpid()}: Failed to fetch {url}, status code: {response.status_code}")
    except requests.exceptions.RequestException as e:
        logging.error(f"Thread {os.getpid()}: Error fetching {url}: {type(e).__name__} - {e}")

    return result_content, delay, is_valid

def parse_config_content(content: str) -> List[str]:
    outbounds = []
    try:
        # Try to decode base64-encoded content
        try:
            decoded_content = base64.b64decode(content).decode('utf-8')
            content = decoded_content
        except Exception:
            pass

        # Parse allowed protocols
        for line in content.splitlines():
            line = line.strip()
            if line and not line.startswith("#") and line.startswith((
                "vless://", "vmess://", "ss://", "tuic://",
                "hysteria://", "hysteria2://", "hy2://",
                "warp://", "wireguard://"
            )):
                logging.info(f"Thread {os.getpid()}: Found config: {line[:50]}...")
                outbounds.append(line)
    except Exception as e:
        logging.error(f"Thread {os.getpid()}: Error processing content: {e}")

    return outbounds

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
            id_value = data.get("id", "")
            aid = data.get("aid", "")
            net = data.get("net", "")
            return (scheme, address, port, id_value, aid, net)
        except Exception:
            pass
        
    if scheme == "vless":
        try:
            if "@" in remainder:
                user_info, server_info = remainder.split("@", 1)
                server_parts = server_info.split("?", 1)[0]
                if ":" in server_parts:
                    address, port_comment = server_parts.split(":", 1)
                    if "#" in port_comment:
                        port = port_comment.split("#", 1)[0]
                    else:
                        port = port_comment
                    # Extract query parameters for more specific fingerprinting
                    params = {}
                    if "?" in remainder:
                        query = remainder.split("?", 1)[1].split("#", 1)[0]
                        for pair in query.split("&"):
                            if "=" in pair:
                                k, v = pair.split("=", 1)
                                params[k] = v
                    return (scheme, address, port, user_info, params.get("type", ""), params.get("security", ""))
        except Exception:
            pass
        
    if scheme == "ss":
        # For Shadowsocks, try to extract address, port, and method
        if "@" in remainder:
            try:
                creds, rest = remainder.split("@", 1)
                try:
                    method_pwd = base64.b64decode(creds).decode('utf-8')
                    method = method_pwd.split(":", 1)[0]
                except:
                    method = "unknown"
                    
                if ":" in rest:
                    host_part = rest.split(":", 1)
                    address = host_part[0]
                    port_str = host_part[1].split("#")[0]
                    try:
                        port = int(port_str)
                    except:
                        port = None
                    return (scheme, address, port, method)
            except Exception:
                pass
            
    # Generic parsing for other protocols
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
        
    # Get path and parameters for more precise fingerprinting
    path = parsed.path if parsed.path else ""
    query = parsed.query if parsed.query else ""
    return (parsed.scheme.lower(), hostname, port, path, query)

def deduplicate_outbounds(outbounds: List[str]) -> List[str]:
    dedup_dict = {}
    for config in outbounds:
        try:
            key = get_dedup_key(config)
        except Exception as e:
            logging.error(f"Error getting dedup key for config: {config[:50]}..., error: {e}")
            continue
        if key not in dedup_dict:
            dedup_dict[key] = config
    return list(dedup_dict.values())

#####################################
#         TESTING FUNCTIONS         #
#####################################

def tcp_test_outbound_sync(ob: Dict[str, Any]) -> None:
    try:
        asyncio.run(tcp_test_outbound(ob))
    except Exception as e:
        logging.error(f"Exception in tcp_test_outbound_sync: {ob.get('original_config')[:50]}...: {e}")

async def tcp_test_outbound(ob: Dict[str, Any]) -> None:
    config_line = ob.get("original_config")
    parsed_url = None
    server = None
    port = None

    try:
        if config_line.startswith("vmess://"):
            base64_part = config_line.replace("vmess://", "")
            decoded = base64.b64decode(base64_part).decode("utf-8")
            data = json.loads(decoded)
            server = data.get("add")
            port = data.get("port")
        elif config_line.startswith("vless://"):
            if "@" in config_line:
                server_part = config_line.split("@")[1]
                if ":" in server_part:
                    server = server_part.split(":")[0]
                    port_part = server_part.split(":")[1]
                    if "?" in port_part:
                        port = int(port_part.split("?")[0])
                    elif "#" in port_part:
                        port = int(port_part.split("#")[0])
                    else:
                        port = int(port_part)
        elif config_line.startswith("ss://"):
            if "@" in config_line:
                server_part = config_line.split("@")[1]
                if ":" in server_part:
                    server = server_part.split(":")[0]
                    port_part = server_part.split(":")[1]
                    if "#" in port_part:
                        port = int(port_part.split("#")[0])
                    else:
                        port = int(port_part)
        else:
            parsed_url = urllib.parse.urlparse(config_line)
            server, port = parsed_url.hostname, parsed_url.port
    except Exception as e:
        logging.error(f"Error parsing config: {config_line[:50]}...: {e}")

    if not server or not port:
        ob["tcp_delay"] = float('inf')
        ob["tcp_status"] = "Error: Missing server or port"
        logging.info(f"TCP Test: No server/port, delay=inf - Config: {config_line[:50]}...")
        return

    loop = asyncio.get_event_loop()
    start = loop.time()
    logging.info(f"TCP Test for {config_line[:50]}... to {server}:{port} started...")

    try:
        # Resolve hostname first to catch DNS issues early
        try:
            addr_info = await asyncio.wait_for(
                loop.getaddrinfo(server, port, family=socket.AF_INET), 
                timeout=2
            )
            resolved_ip = addr_info[0][4][0]
            logging.info(f"Resolved {server} to {resolved_ip}")
        except Exception as dns_err:
            ob["tcp_delay"] = float('inf')
            ob["tcp_status"] = f"DNS Error: {dns_err}"
            logging.error(f"TCP Test for {config_line[:50]}... DNS error: {dns_err}")
            return

        # Establish TCP connection
        transport, writer = await asyncio.wait_for(
            asyncio.open_connection(server, port), 
            timeout=TCP_TIMEOUT
        )
        
        delay = (loop.time() - start) * 1000
        
        # Simple handshake - send a few bytes and see if connection stays open
        writer.write(b'\r\n\r\n')
        await writer.drain()
        
        # Wait a moment to see if the connection is reset
        await asyncio.sleep(0.1)
        
        writer.close()
        try:
            await writer.wait_closed()
        except:
            pass
            
        ob["tcp_delay"] = delay
        ob["tcp_status"] = "Success"
        logging.info(f"TCP Test for {config_line[:50]}... finished, delay={delay:.2f} ms")
    except asyncio.TimeoutError:
        ob["tcp_delay"] = float('inf')
        ob["tcp_status"] = "Timeout"
        logging.error(f"TCP Test for {config_line[:50]}... timed out after {TCP_TIMEOUT}s")
    except ConnectionRefusedError:
        ob["tcp_delay"] = float('inf')
        ob["tcp_status"] = "Connection Refused"
        logging.error(f"TCP Test for {config_line[:50]}... connection refused")
    except Exception as e:
        ob["tcp_delay"] = float('inf')
        ob["tcp_status"] = f"Error: {type(e).__name__}"
        logging.error(f"TCP Test for {config_line[:50]}... error: {e}")

def http_delay_test_outbound_sync(ob: Dict[str, Any], proxy: Optional[str], repetitions: int) -> None:
    try:
        asyncio.run(http_delay_test_outbound(ob, proxy, repetitions))
    except Exception as e:
        logging.error(f"Exception in http_delay_test_outbound_sync: {ob.get('original_config')[:50]}...: {e}")

async def http_delay_test_outbound(ob: Dict[str, Any], proxy_for_test: Optional[str], repetitions: int) -> None:
    config_line = ob.get("original_config")
    parsed_url = None
    server = None
    port = None

    try:
        if config_line.startswith("vmess://"):
            base64_part = config_line.replace("vmess://", "")
            decoded = base64.b64decode(base64_part).decode("utf-8")
            data = json.loads(decoded)
            server = data.get("add")
            port = data.get("port")
        else:
            parsed_url = urllib.parse.urlparse(config_line)
            server, port = parsed_url.hostname, parsed_url.port
    except:
        server = "unknown"
        port = "unknown"

    if not proxy_for_test:
        ob["http_delay"] = float('inf')
        ob["http_status"] = "No proxy bridge available"
        logging.info(f"HTTP Test: No proxy bridge, delay=inf - Config: {config_line[:50]}...")
        return

    session = requests.Session()
    website_results = []

    logging.info(f"HTTP Test for {config_line[:50]}... started with {repetitions} repetitions for each test URL...")

    # Test each website defined in TEST_URLS
    for test_url in TEST_URLS:
        times = []
        validation_results = []
        validation_patterns = VALIDATION_PATTERNS.get(test_url, [])
        
        logging.info(f"  Testing against: {test_url}")
        
        for i in range(repetitions):
            if is_ctrl_c_pressed:
                break
            
            start = asyncio.get_event_loop().time()
            current_proxies = {'http': proxy_for_test, 'https': proxy_for_test}
            
            try:
                with session.get(test_url, timeout=HTTP_TIMEOUT, proxies=current_proxies, verify=False) as response:
                    elapsed = (asyncio.get_event_loop().time() - start) * 1000
                    
                    if response.status_code == 200:
                        # Validate response content
                        content = response.text
                        is_valid = all(pattern.lower() in content.lower() for pattern in validation_patterns)
                        
                        if is_valid:
                            times.append(elapsed)
                            validation_results.append(True)
                            logging.info(f"    [{config_line[:30]}...] {test_url} Rep {i+1}: {elapsed:.2f} ms - VALID")
                        else:
                            validation_results.append(False)
                            logging.warning(f"    [{config_line[:30]}...] {test_url} Rep {i+1}: {elapsed:.2f} ms - INVALID CONTENT")
                    else:
                        logging.error(f"    [{config_line[:30]}...] {test_url} Rep {i+1}: HTTP {response.status_code}")
            except requests.exceptions.RequestException as e:
                logging.error(f"    [{config_line[:30]}...] {test_url} Rep {i+1} failed: {e}")
        
        if times:
            avg = sum(times) / len(times)
            validation_success_rate = sum(validation_results) / len(validation_results) if validation_results else 0
            website_results.append({
                "url": test_url,
                "avg_delay": avg,
                "validation_rate": validation_success_rate
            })
            logging.info(f"  Average delay for {test_url}: {avg:.2f} ms, Validation Rate: {validation_success_rate*100:.1f}%")
        else:
            website_results.append({
                "url": test_url,
                "avg_delay": float('inf'),
                "validation_rate": 0
            })
            logging.info(f"  All trials failed for {test_url}")

    # Calculate overall result
    successful_sites = [site for site in website_results if site["avg_delay"] != float('inf')]

    if not successful_sites:
        ob["http_delay"] = float('inf')
        ob["http_status"] = "All sites failed"
        logging.warning(f"HTTP Test for {config_line[:50]}... failed for all test URLs")
    else:
        total_weight = sum(site["validation_rate"] for site in successful_sites)
        if total_weight > 0:
            weighted_avg = sum(site["avg_delay"] * site["validation_rate"] for site in successful_sites) / total_weight
            overall_validation_rate = sum(site["validation_rate"] for site in website_results) / len(website_results)
            
            if overall_validation_rate >= 0.5:
                ob["http_delay"] = weighted_avg
                ob["http_status"] = f"Success ({overall_validation_rate*100:.1f}% valid)"
                logging.info(f"HTTP Test for {config_line[:50]}... succeeded. Overall Avg: {weighted_avg:.2f} ms, Validation: {overall_validation_rate*100:.1f}%")
            else:
                ob["http_delay"] = float('inf')
                ob["http_status"] = f"Low validation rate ({overall_validation_rate*100:.1f}%)"
                logging.warning(f"HTTP Test for {config_line[:50]}... failed due to low validation rate: {overall_validation_rate*100:.1f}%")
        else:
            ob["http_delay"] = float('inf')
            ob["http_status"] = "No valid responses"
            logging.warning(f"HTTP Test for {config_line[:50]}... failed: no valid responses")

def udp_test_outbound_sync(ob: Dict[str, Any]) -> None:
    try:
        asyncio.run(udp_test_outbound(ob))
    except Exception as e:
        logging.error(f"Exception in udp_test_outbound_sync: {ob.get('original_config')[:50]}...: {e}")

async def udp_test_outbound(ob: Dict[str, Any]) -> None:
    config_line = ob.get("original_config")
    server = None
    port = None

    try:
        if config_line.startswith(("warp://", "wireguard://")):
            parsed_url = urllib.parse.urlparse(config_line)
            server, port = parsed_url.hostname, parsed_url.port
            if not port and config_line.startswith(("warp://", "wireguard://")):
                port = 51820
        else:
            parsed_url = urllib.parse.urlparse(config_line)
            server, port = parsed_url.hostname, parsed_url.port
    except Exception as e:
        logging.error(f"Error parsing config for UDP test: {config_line[:50]}...: {e}")

    if not server or not port:
        ob["udp_delay"] = float('inf')
        ob["udp_status"] = "Missing server/port"
        logging.info(f"UDP Test: No server/port, delay=inf - Config: {config_line[:50]}...")
        return

    try:
        loop = asyncio.get_event_loop()
        addr_info = await asyncio.wait_for(
            loop.getaddrinfo(server, None, family=socket.AF_INET),
            timeout=2
        )
        ip = addr_info[0][4][0]
    except Exception as e:
        ob["udp_delay"] = float('inf')
        ob["udp_status"] = f"DNS Error: {e}"
        logging.error(f"UDP Test for {config_line[:50]}...: DNS error: {e}")
        return

    start = loop.time()
    logging.info(f"UDP Test for {config_line[:50]}... to {server}:{port} ({ip}:{port}) started...")

    class UDPClientProtocol(asyncio.DatagramProtocol):
        def __init__(self):
            self.transport = None
            self.received = False
            
        def connection_made(self, transport):
            self.transport = transport
            data = os.urandom(32)
            transport.sendto(data)
            
        def datagram_received(self, data, addr):
            self.received = True
            
        def error_received(self, exc):
            logging.error(f"UDP error: {exc}")
            
        def connection_lost(self, exc):
            pass

    try:
        transport, protocol = await asyncio.wait_for(
            loop.create_datagram_endpoint(
                lambda: UDPClientProtocol(),
                remote_addr=(ip, port)
            ), 
            timeout=UDP_TIMEOUT
        )
        
        await asyncio.sleep(1)
        
        delay = (loop.time() - start) * 1000
        transport.close()
        
        ob["udp_delay"] = delay
        ob["udp_status"] = "Success" if protocol.received else "No response (expected)"
        logging.info(f"UDP Test for {config_line[:50]}... finished, delay={delay:.2f} ms, response: {protocol.received}")
    except asyncio.TimeoutError:
        ob["udp_delay"] = float('inf')
        ob["udp_status"] = "Timeout"
        logging.error(f"UDP Test for {config_line[:50]}... timed out after {UDP_TIMEOUT}s")
    except ConnectionRefusedError:
        ob["udp_delay"] = float('inf')
        ob["udp_status"] = "Connection Refused"
        logging.error(f"UDP Test for {config_line[:50]}... connection refused")
    except Exception as e:
        ob["udp_delay"] = float('inf')
        ob["udp_status"] = f"Error: {type(e).__name__}"
        logging.error(f"UDP Test for {config_line[:50]}... error: {e}")

def single_test_pass(outbounds: List[Dict[str, Any]],
                     test_type: str,
                     thread_pool_size: int = 32,
                     proxy_for_test: Optional[str] = None,
                     repetitions: int = 3) -> None:
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
            protocol = config_line.split("://")[0] if "://" in config_line else ""
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
                    ob["udp_status"] = "Not applicable"
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

#####################################
#         OUTPUT FUNCTIONS          #
#####################################

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

def fetch_and_parse_subscription_thread(url: str, proxy: Optional[str] = None) -> List[Any]:
    logging.info(f"Thread {os.getpid()}: Fetching: {url}")
    content = fetch_content(url, proxy)[0]
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

#####################################
#             MAIN                  #
#####################################

def main():
    global is_ctrl_c_pressed, total_outbounds_count, completed_outbounds_count
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

    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(formatter)
    logger.addHandler(ch)
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
            if ob.get("tcp_delay", float('inf')) != float('inf') and ob.get("http_delay", float('inf')) != float('inf'):
                ob["combined_delay"] = (ob.get("tcp_delay", float('inf')) + ob.get("http_delay", float('inf'))) / 2
            else:
                ob["combined_delay"] = float('inf')
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
