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
import subprocess
import time
import tempfile
import shutil
from typing import Optional, List, Dict, Any, Tuple

from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# --- Xray_core Implementation for Precise Delay Testing ---
class XrayCore:
    def __init__(self):
        self.process = None
        self.config_file = None

    def startFromJSON(self, json_config_string: str):
        # Create a temporary JSON configuration file for Xray-core
        self.config_file = tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json")

        # Parse the JSON config string and ADD LOGGING CONFIGURATION
        try:
            config = json.loads(json_config_string)
            # Inject logging configuration
            config["log"] = {
                "loglevel": "debug",  # Use "debug" for verbose output
                "access": "/tmp/xray_access.log", # Log files
                "error": "/tmp/xray_error.log"
            }
            # Write the modified config to the file
            self.config_file.write(json.dumps(config))
            self.config_file.flush()
        except Exception as e:
            print(f"Error modifying Xray config: {e}")
            if self.config_file:
                try:
                    os.remove(self.config_file.name)
                except Exception:
                    pass
                finally:
                    self.config_file = None
            return # Exit if config modification failed
        finally:
            self.config_file.close()

        print("Starting xray-core with config file:", self.config_file.name)
        try:
            # Start the xray-core process (no -log flag)
            self.process = subprocess.Popen(
                ["xray", "run", "-config", self.config_file.name], # Use 'run' subcommand
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            # Wait for xray-core to start, with port checking
            max_wait = 10  # seconds
            start_time = time.time()
            while time.time() - start_time < max_wait:
                if self.process.poll() is not None:
                    break
                # Check if SOCKS port is listening
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    if s.connect_ex(('127.0.0.1', 1080)) == 0:
                        print("xray-core SOCKS port is open.")
                        break
                time.sleep(0.5)  # Check every 0.5 seconds

            if self.process.poll() is not None:  # Check if process exited early
                stdout, stderr = self.process.communicate()
                print("xray-core failed to start:")
                print("stdout:", stdout.decode())
                print("stderr:", stderr.decode())
                raise subprocess.SubprocessError(
                    f"xray-core exited with code: {self.process.returncode}"
                )

        except FileNotFoundError:
            print("Failed to start xray-core: 'xray' executable not found. Ensure it's in your PATH.")
            self.process = None
        except subprocess.SubprocessError as e:
            print(f"Failed to start xray-core: {e}")
            self.process = None
        except Exception as e:
            print("Failed to start xray-core:", e)
            self.process = None

    def stop(self):
        if self.process:
            print("Stopping xray-core process.")
            try:
                self.process.terminate()
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                print("xray-core did not terminate, killing...")
                self.process.kill()
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    print("Failed to kill xray-core process.")
            except Exception as e:
                print(f"Error while stopping xray-core: {e}")
            finally:
                self.process = None
        if self.config_file:
            try:
                os.remove(self.config_file.name)
            except Exception as e:
                print("Failed to remove temporary config file:", e)
            finally:
                self.config_file = None

# --- The Rest of your Pr0xySh4rk.py script remains the same ---
# --- (Paste the rest of your script code here, from "Outbound Conversion" down to "if __name__ == '__main__':")

# --- Outbound Conversion --- (From your previous code)
def convert_outbound_config(ob: Dict[str, Any]) -> Dict[str, Any]:
    protocol = ob.get("type", "").lower()
    tag = ob.get("tag", "")
    if protocol == "shadowsocks":
        new_ob = {
            "protocol": "shadowsocks",
            "tag": tag,
            "settings": {
                "servers": [
                    {
                        "address": ob.get("server", ""),
                        "port": int(ob.get("server_port", 443)),
                        "users": [
                            {
                                "password": ob.get("password", ""),
                                "method": ob.get("method", "aes-256-gcm")
                            }
                        ]
                    }
                ]
            }
        }
        if "plugin" in ob:
            new_ob["settings"]["servers"][0]["plugin"] = ob["plugin"]
        return new_ob

    elif protocol == "vless":
        new_ob = {
            "protocol": "vless",
            "tag": tag,
            "settings": {
                "vnext": [
                    {
                        "address": ob.get("server", ""),
                        "port": int(ob.get("server_port", 443)),
                        "users": [
                            {
                                "id": ob.get("uuid", ""),
                                "encryption": "none",
                                "flow": ob.get("flow", "")
                            }
                        ]
                    }
                ]
            }
        }
        if "transport" in ob:
            new_ob["streamSettings"] = ob["transport"]
        if "tls" in ob and isinstance(ob["tls"], dict):
            new_ob.setdefault("streamSettings", {})["tlsSettings"] = {"serverName": ob["tls"].get("server_name", ob.get("server", ""))}
            new_ob.setdefault("streamSettings", {})["security"] = "tls"
        return new_ob

    elif protocol == "vmess":
        new_ob = {
            "protocol": "vmess",
            "tag": tag,
            "settings": {
                "vnext": [
                    {
                        "address": ob.get("server", ""),
                        "port": int(ob.get("server_port", 443)),
                        "users": [
                            {
                                "id": ob.get("uuid", ""),
                                "alterId": int(ob.get("alter_id", 0)),
                                "security": ob.get("security", "auto")
                            }
                        ]
                    }
                ]
            }
        }
        if "transport" in ob:
            new_ob["streamSettings"] = ob["transport"]
        if "tls" in ob and isinstance(ob["tls"], dict):
            new_ob.setdefault("streamSettings", {})["tlsSettings"] = {"serverName": ob["tls"].get("server_name", ob.get("server", ""))}
            new_ob.setdefault("streamSettings", {})["security"] = "tls"
        return new_ob

    elif protocol == "tuic":
        new_ob = {
            "protocol": "tuic",
            "tag": tag,
            "settings": {
                "servers": [
                    {
                        "address": ob.get("server", ""),
                        "port": int(ob.get("server_port", 443)),
                        "users": [
                            {
                                "id": ob.get("uuid", ""),
                                "password": ob.get("password", "")
                            }
                        ]
                    }
                ]
            },
            "streamSettings": {
                "udpRelay": ob.get("udp_relay_mode", "native"),
                "allowInsecure": True,
                "serverName": ob.get("tls", {}).get("server_name", ob.get("server", ""))
            }
        }
        if "congestion_control" in ob:
            new_ob["settings"]["congestionControl"] = ob["congestion_control"]
        return new_ob

    elif protocol in ("wireguard", "warp"):
        new_ob = {
            "protocol": "wireguard",
            "tag": tag,
            "settings": {
                "addresses": ob.get("local_address", []),
                "privateKey": ob.get("private_key", ""),
                "peer": {
                    "publicKey": ob.get("peer_public_key", ""),
                    "endpoint": {
                        "address": ob.get("server", ""),
                        "port": int(ob.get("server_port", 443))
                    }
                },
                "mtu": int(ob.get("mtu", 1330))
            }
        }
        return new_ob

    elif protocol in ("hysteria", "hysteria2", "hy2"):
        new_ob = {
            "protocol": "hysteria",
            "tag": tag,
            "settings": {
                "servers": [
                    {
                        "address": ob.get("server", ""),
                        "port": int(ob.get("server_port", 443)),
                        "users": [
                            {
                                "password": ob.get("password", "")
                            }
                        ]
                    }
                ]
            },
            "streamSettings": {
                "network": "udp",
                "security": "tls",
                "tlsSettings": {
                    "serverName": ob.get("tls", {}).get("server_name", ob.get("server", "")),
                    "allowInsecure": True
                }
            }
        }
        if "obfs" in ob:
            new_ob["settings"]["obfs"] = {"type": ob.get("obfs"), "password": ob.get("obfs-password", "")}
        return new_ob

    else:
        # Fallback: simply rename key "type" to "protocol" for unknown types.
        new_ob = dict(ob)
        if "type" in new_ob:
            new_ob["protocol"] = new_ob.pop("type")
        return new_ob

# --- Helper Functions for Xray-core and proxychains ---
def create_xray_config(outbound_config: dict) -> dict:
    """
    Wrap a single outbound configuration into a full Xray-core config.
    """
    return {
        "inbounds": [
            {
                "protocol": "socks",
                "port": 1080,
                "settings": {
                    "auth": "noauth"
                },
                "tag": "socks-inbound"
            }
        ],
        "outbounds": [
            outbound_config,
            {
                "protocol": "freedom",
                "tag": "direct"
            }
        ]
    }

def create_proxychains_config(proxy: str) -> str:
    if proxy.startswith("socks5://"):
        proxy_netloc = proxy[len("socks5://"):]
        host, port = (proxy_netloc.split(":", 1) + ["1080"])[:2]  # Handle missing port
    else:
        host, port = "127.0.0.1", "1080"
    config_content = f"""strict_chain
proxy_dns
tcp_read_time_out 15000
tcp_connect_time_out 8000

[ProxyList]
socks5 {host} {port}
"""
    tmp = tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".conf")
    tmp.write(config_content)
    tmp.flush()
    tmp.close()
    return tmp.name

def measure_latency_icmp_proxychains(target_host: str = "www.google.com",
                                     proxy: str = "socks5://127.0.0.1:1080",
                                     count: int = 5,
                                     timeout: int = 20) -> float:
    config_path = create_proxychains_config(proxy)
    command = ["proxychains4", "-f", config_path, "fping", "-c", str(count), target_host]
    try:
        process_output = subprocess.check_output(command, stderr=subprocess.STDOUT, text=True, timeout=timeout)
        match = re.search(r"min/avg/max = ([\d\.]+)/([\d\.]+)/([\d\.]+)", process_output)
        if match:
            _, avg_rtt, _ = map(float, match.groups())
            return avg_rtt
        else:
            # Fallback to HTTP test if ICMP parsing fails but command succeeded
            print("ICMP parse failed, falling back to HTTP test")
            return measure_xray_latency_http(proxy, timeout=timeout)
    except (subprocess.TimeoutExpired, subprocess.CalledProcessError) as e:
        print(f"ICMP Latency measurement error: {e}")
        return measure_xray_latency_http(proxy, timeout=timeout)
    finally:
        try:
            os.remove(config_path)
        except OSError:
            pass

def measure_xray_latency_http(proxy: str, timeout: int = 5) -> float:
    """
    Measures HTTP latency using a diverse set of URLs with concurrent requests and retries.
    Uses a robust requests session with a retry strategy.
    """
    test_urls = [
        "https://www.cloudflare.com/cdn-cgi/trace",
        "https://checkip.amazonaws.com",
        "https://ipleak.net/json",
        "https://ipinfo.io/ip",
        "http://httpbin.org/get",
        "http://neverssl.com",
    ]
    session = requests.Session()
    if proxy:
        session.proxies = {'http': proxy, 'https': proxy}
    retry_strategy = Retry(
        total=3,
        allowed_methods=["GET"],
        backoff_factor=0.5,
        status_forcelist=[429, 500, 502, 503, 504]
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    def fetch_url(url: str) -> Tuple[Optional[float], str]:
        try:
            start_time = time.time()
            response = session.get(url, timeout=timeout)
            response.raise_for_status()
            latency = (time.time() - start_time) * 1000
            print(f"HTTP test for {url} succeeded: {latency:.2f} ms")
            return latency, url
        except Exception as e:
            print(f"HTTP test for {url} failed: {e}")
            return None, url

    latencies = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(test_urls)) as executor:
        futures = {executor.submit(fetch_url, url): url for url in test_urls}
        for future in concurrent.futures.as_completed(futures):
            latency, url = future.result()
            if latency is not None:
                latencies.append(latency)
    if latencies:
        best_latency = min(latencies)
        print(f"Best HTTP latency: {best_latency:.2f} ms from {len(latencies)} successful tests.")
        return best_latency
    else:
        print("All HTTP latency test attempts failed.")
        return float('inf')

def measure_latency_precise(proxy: str,
                            target_host: str = "www.google.com",
                            count: int = 5,
                            timeout: int = 20) -> float:
    # First try ICMP through Xray's SOCKS proxy
    try:
        return measure_latency_icmp_proxychains(target_host, proxy, count, timeout)
    except Exception as e:
        print(f"Precise ICMP test failed ({e}), falling back to direct HTTP")
        return measure_xray_latency_http(proxy, timeout=timeout)

def real_delay_test_outbound(outbound_config: dict) -> float:
    converted = convert_outbound_config(outbound_config)
    config = create_xray_config(converted)
    json_config_str = json.dumps(config)  # This will be modified by startFromJSON
    xr = XrayCore()
    try:
        xr.startFromJSON(json_config_str)
        time.sleep(2)  # Allow xray-core to start (though we have better checks now)
        proxy = "socks5://127.0.0.1:1080"
        latency = measure_latency_precise(proxy, target_host="www.google.com", count=5, timeout=20)
        # FIX: update the outbound config with xray delay for proper filtering.
        outbound_config["xray_delay"] = latency
        print(f"Real delay test for {converted.get('tag')}: {latency:.2f} ms")
        return latency
    except Exception as e:
        print(f"Error during real delay test for {converted.get('tag')}: {e}")
        outbound_config["xray_delay"] = float('inf')
        return float('inf')
    finally:
        xr.stop()

# --- Normalization ---
def normalize_config(config: Dict[str, Any]) -> Dict[str, Any]:
    if "inbounds" in config:
        for inbound in config["inbounds"]:
            if "type" in inbound:
                inbound["protocol"] = inbound.pop("type")
    if "outbounds" in config:
        for outbound in config["outbounds"]:
            if "type" in outbound:
                outbound["protocol"] = outbound.pop("type")
            if "detour" in outbound:
                outbound.pop("detour")  # Remove detour
    return config

# --- Signal Handling ---
total_outbounds_count = 0
completed_outbounds_count = 0
is_ctrl_c_pressed = False

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

def signal_handler(sig, frame):
    global is_ctrl_c_pressed
    print("\nCtrl+C detected. Gracefully stopping...")
    is_ctrl_c_pressed = True

# --- Fetching, Parsing, Deduplication ---
def fetch_content(url: str, proxy: Optional[str] = None) -> Optional[str]:
    session = requests.Session()
    proxies = {"http": proxy, "https": proxy} if proxy else None

    if proxies:
        print(f"Thread {os.getpid()}: Fetching {url} using proxy: {proxy}")
    else:
        print(f"Thread {os.getpid()}: Fetching {url} directly (no proxy)")

    try:
        # Clear proxy environment variables
        orig_env = {}
        for env_var in ['http_proxy', 'https_proxy', 'HTTP_PROXY', 'HTTPS_PROXY', 'all_proxy', 'ALL_PROXY']:
            if env_var in os.environ:
                orig_env[env_var] = os.environ[env_var]
                del os.environ[env_var]

        response = session.get(url, timeout=10, proxies=proxies)

        # Restore environment variables
        for env_var, value in orig_env.items():
            os.environ[env_var] = value

        response.raise_for_status()
        return response.text
    except requests.exceptions.RequestException as e:
        print(f"Thread {os.getpid()}: Error fetching URL {url}{' via proxy ' + proxy if proxy else ''}: {e}")
        # Restore potentially removed environment variables
        for env_var, value in orig_env.items():
            os.environ[env_var] = value

        # Retry with system proxies if direct connection failed and no proxy was used initially
        if not proxies and not any(var in os.environ for var in ['http_proxy', 'https_proxy', 'HTTP_PROXY', 'HTTPS_PROXY']):
            try:
                print(f"Thread {os.getpid()}: Retrying {url} with system proxy settings...")
                response = requests.get(url, timeout=10)
                response.raise_for_status()
                return response.text
            except requests.exceptions.RequestException as e2:
                print(f"Thread {os.getpid()}: System proxy retry also failed for {url}: {e2}")
        return None

def parse_warp_single(link: str, counter: int, all_tags: set) -> Tuple[List[Dict[str, Any]], int]:
    try:
        parsed = urllib.parse.urlparse(link)
        if parsed.scheme not in ("warp", "wireguard"):
            raise ValueError("Invalid scheme")
        license_key = parsed.username.strip() if parsed.username else ""
        server = parsed.hostname if parsed.hostname else "auto"
        port = parsed.port if parsed.port else (0 if server.lower() == "auto" else 443)  # Handle "auto"
        params = urllib.parse.parse_qs(parsed.query)
        fragment = parsed.fragment.strip()
        tag = fragment if fragment else generate_unique_tag(all_tags)  # Use fragment or generate
        if fragment:
            all_tags.add(tag)  # add tag if exists

        outbound: Dict[str, Any] = {
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
            "mtu": 1330,
            "fake_packets": params.get("ifp", [""])[0],
            "fake_packets_size": params.get("ifps", [""])[0],
            "fake_packets_delay": params.get("ifpd", [""])[0],
            "fake_packets_mode": params.get("ifpm", [""])[0],
        }
        return [outbound], counter
    except Exception as e:
        print(f"Thread {os.getpid()}: Error parsing warp link: {e} - Link: {link}")
        return [], counter

def parse_warp_line(line: str, counter: int, all_tags: set) -> Tuple[List[Dict[str, Any]], int]:
    if "&&detour=" in line:
        main_part, detour_part = line.split("&&detour=", 1)
        main_configs, counter = parse_warp_single(main_part.strip(), counter, all_tags)
        detour_configs, counter = parse_warp_single(detour_part.strip(), counter, all_tags)
        if main_configs and detour_configs:
            detour_configs[0].pop("detour", None)  # Remove "detour"
            return main_configs + detour_configs, counter
        return main_configs, counter  # Return main even if detour fails
    return parse_warp_single(line, counter, all_tags)

def parse_config_url1_2(content: str, all_tags: set) -> List[Dict[str, Any]]:
    outbounds = []
    try:
        try:
            decoded_content = base64.b64decode(content, validate=True).decode('utf-8')
            content = decoded_content
        except Exception:
            pass
        json_content = "\n".join(line for line in content.splitlines() if not line.strip().startswith('//'))
        try:
            config = json.loads(json_content)
            print(f"Thread {os.getpid()}: Parsed JSON Config from URL")
            if "outbounds" in config:
                for ob in config["outbounds"]:
                    ob["tag"] = generate_unique_tag(all_tags)  # Ensure unique tag
                return config["outbounds"]
            else:
                print(f"Thread {os.getpid()}: Warning: 'outbounds' key not found in JSON config.")
                return []
        except json.JSONDecodeError:
            pass  # Not valid JSON, proceed to line-by-line parsing
    except Exception as e_base:
        print(f"Thread {os.getpid()}: Error processing base config content: {e_base}")
        return []

    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "//")):
            continue

        if line.startswith("ss://"):
            try:
                ss_url_encoded = line[5:]
                if "#" in ss_url_encoded:
                    ss_url_encoded, frag = ss_url_encoded.split("#", 1)
                if "@" in ss_url_encoded:
                    base64_str = ss_url_encoded.split("@")[0]
                    padding = "=" * (-len(base64_str) % 4)  # Correct padding
                    method_pass_decoded = base64.urlsafe_b64decode(base64_str + padding).decode("utf-8")
                    method, password = (method_pass_decoded.split(":", 1) + [None])[:2]  # Handle missing password
                    remainder = ss_url_encoded.split("@")[1]
                    server_port_str = remainder.split("?")[0].split("#")[0]
                else:
                    padding = "=" * (-len(ss_url_encoded) % 4)
                    decoded_full = base64.urlsafe_b64decode(ss_url_encoded + padding).decode("utf-8")
                    if "@" in decoded_full:
                        method_pass, server_port_str = decoded_full.split("@", 1)
                        method, password = (method_pass.split(":", 1) + [None])[:2]
                    else:
                        continue  # Skip invalid

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

                tag = generate_unique_tag(all_tags)  # Generate unique tag
                ss_outbound = {
                    "type": "shadowsocks",
                    "tag": tag,
                    "server": server,
                    "server_port": int(port),
                    "method": method or "aes-256-gcm",  # Default method
                    "password": password or ""  # Default password
                }
                outbounds.append(ss_outbound)

            except Exception as e:
                print(f"Thread {os.getpid()}: Error parsing Shadowsocks link: {e} - Link: {line}")
                continue

        elif line.startswith(("vless://", "vmess://", "tuic://",
                              "hysteria://", "hysteria2://", "hy2://", "warp://", "wireguard://")):
            protocol = line.split("://")[0]

            if protocol == "vless":
                try:
                    parsed_url = urllib.parse.urlparse(line)
                    userinfo = parsed_url.username
                    netloc = parsed_url.netloc
                    server_port_str = netloc.split("@")[-1] if "@" in netloc else netloc

                    if "[" in server_port_str and "]" in server_port_str:
                        server_ipv6 = server_port_str[server_port_str.find("[") + 1:server_port_str.find("]")]
                        server = server_ipv6
                        port_str = server_port_str.split("]")[-1].strip(":")
                        port = int(port_str) if port_str.isdigit() else 443
                    else:
                        server = server_port_str.split(":")[0]
                        port = int(server_port_str.split(":")[1]) if ":" in server_port_str and server_port_str.split(":")[1].isdigit() else 443

                    params = urllib.parse.parse_qs(parsed_url.query)
                    tag = generate_unique_tag(all_tags)  # Generate unique tag
                    uuid = userinfo
                    vless_outbound = {
                        "type": "vless",
                        "tag": tag,
                        "server": server,
                        "server_port": int(port),
                        "uuid": uuid,
                        "flow": params.get("flow", [""])[0],
                        "packet_encoding": params.get("packet_encoding", [""])[0],
                    }

                    transport_type = params.get("type", [""])[0]
                    if transport_type == "ws":
                        vless_outbound["transport"] = {
                            "type": "ws",
                            "path": params.get("path", ["/"])[0],
                            "headers": {"Host": params.get("host", [""])[0]}
                        }

                    if params.get("security", [""])[0] == "reality":
                        vless_outbound["tls"] = {
                            "enabled": True,
                            "server_name": params.get("sni", [server])[0],
                            "reality": {
                                "enabled": True,
                                "public_key": params.get("pbk", [""])[0],
                                "short_id": params.get("sid", [""])[0]
                            },
                            "utls": {
                                "enabled": True,
                                "fingerprint": params.get("fp", [""])[0] or "chrome"
                            }
                        }
                    elif params.get("security", [""])[0] == "tls":
                        vless_outbound["tls"] = {
                            "enabled": True,
                            "server_name": params.get("sni", [server])[0]
                        }
                    outbounds.append(vless_outbound)

                except Exception as e:
                    print(f"Thread {os.getpid()}: Error parsing vless link: {e} - Link: {line}")
                    continue

            elif protocol == "vmess":
                try:
                    base64_config = line.split("vmess://")[1]
                    config_str = base64_config.split("#")[0] if "#" in base64_config else base64_config
                    padding = "=" * (-len(config_str) % 4)
                    decoded_bytes = base64.b64decode(config_str + padding)
                    config_json = json.loads(decoded_bytes.decode("utf-8"))
                    tag = generate_unique_tag(all_tags)
                    vmess_outbound = {
                        "type": "vmess",
                        "tag": tag,
                        "server": config_json.get("add"),
                        "server_port": int(config_json.get("port", 443)),
                        "uuid": config_json.get("id"),
                        "security": config_json.get("scy", "auto"),
                        "alter_id": int(config_json.get("aid", 0))
                    }

                    transport_type = config_json.get("net")
                    if transport_type == "ws":
                        vmess_outbound["transport"] = {
                            "type": "ws",
                            "path": config_json.get("path", "/"),
                            "headers": {"Host": config_json.get("host", "")}
                        }
                    if config_json.get("tls") == "tls":
                        vmess_outbound["tls"] = {
                            "enabled": True,
                            "server_name": config_json.get("sni", config_json.get("add"))
                        }
                    outbounds.append(vmess_outbound)

                except Exception as e:
                    print(f"Thread {os.getpid()}: Error parsing vmess link: {e} - Link: {line}")
                    continue

            elif protocol == "tuic":
                try:
                    parsed_url = urllib.parse.urlparse(line)
                    uuid = parsed_url.username
                    netloc = parsed_url.netloc
                    server_port_str = netloc.split("@")[-1] if "@" in netloc else netloc

                    if "[" in server_port_str and "]" in server_port_str:
                        server_ipv6 = server_port_str[server_port_str.find("[") + 1:server_port_str.find("]")]
                        server = server_ipv6
                        port_str = server_port_str.split("]")[-1].strip(":")
                        port = int(port_str) if port_str.isdigit() else 443
                    else:
                        server = server_port_str.split(":")[0]
                        port = int(server_port_str.split(":")[1]) if ":" in server_port_str and server_port_str.split(":")[1].isdigit() else 443

                    params = urllib.parse.parse_qs(parsed_url.query)
                    tag = generate_unique_tag(all_tags)
                    tuic_outbound = {
                        "type": "tuic",
                        "tag": tag,
                        "server": server,
                        "server_port": int(port),
                        "uuid": uuid,
                        "password": params.get("password", [""])[0],
                        "congestion_control": params.get("congestion_control", ["bbr"])[0] or "bbr",
                        "udp_relay_mode": params.get("udp_relay_mode", ["native"])[0] or "native",
                        "tls": {"enabled": True, "server_name": params.get("sni", [server])[0], "insecure": True}
                    }
                    outbounds.append(tuic_outbound)
                except Exception as e:
                    print(f"Thread {os.getpid()}: Error parsing tuic link: {e} - Link: {line}")
                    continue

            elif protocol in ("warp", "wireguard"):
                if protocol == "wireguard":
                    line = line.replace("wireguard://", "warp://", 1)  # Correct replacement
                parsed_configs, _ = parse_warp_line(line, 0, all_tags)
                outbounds.extend(parsed_configs)
            elif protocol in ("hysteria", "hysteria2", "hy2"):
                try:
                    parsed_url = urllib.parse.urlparse(line)
                    password = parsed_url.username
                    netloc = parsed_url.netloc
                    server_port_str = netloc.split("@")[-1] if "@" in netloc else netloc

                    if "[" in server_port_str and "]" in server_port_str:
                        server_ipv6 = server_port_str[server_port_str.find("[") + 1:server_port_str.find("]")]
                        server = server_ipv6
                        port_str = server_port_str.split("]")[-1].strip(":")
                        port = int(port_str) if port_str.isdigit() else 443
                    else:
                        server = server_port_str.split(":")[0]
                        port = int(server_port_str.split(":")[1]) if ":" in server_port_str and server_port_str.split(":")[1].isdigit() else 443

                    params = urllib.parse.parse_qs(parsed_url.query)
                    tag = generate_unique_tag(all_tags)
                    hysteria_outbound = {
                        "type": "hysteria2",
                        "tag": tag,
                        "server": server,
                        "server_port": int(port),
                        "password": password,
                        "tls": {"enabled": True, "server_name": params.get("sni", [server])[0], "insecure": True}
                    }
                    obfs = params.get("obfs", [""])[0]
                    if obfs:
                        hysteria_outbound["obfs"] = {
                            "type": obfs,
                            "password": params.get("obfs-password", [""])[0]
                        }
                    outbounds.append(hysteria_outbound)
                except Exception as e:
                    print(f"Thread {os.getpid()}: Error parsing hysteria link: {e} - Link: {line}")
                    continue
            elif protocol == "reality":
                continue  # Skip reality for now

    return outbounds

def deduplicate_outbounds(outbounds: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    def get_key(ob: Dict[str, Any]) -> Tuple[Any, ...]:
        typ = ob.get("type", "")
        server = ob.get("server", "")
        port = ob.get("server_port", "")
        if typ == "shadowsocks":
            return (typ, server, port, ob.get("method", ""), ob.get("password", ""), ob.get("plugin", ""))
        elif typ in ("vless", "vmess"):
            return (typ, server, port, ob.get("uuid", ""))
        elif typ in ("tuic", "reality"):
            return (typ, server, port, ob.get("uuid", ""), ob.get("password", ""))
        elif typ in ("wireguard", "warp"):
            return (typ, server, port, ob.get("private_key", ""))
        elif typ in ("hysteria", "hysteria2", "hy2"):
            return (typ, server, port, ob.get("password", ""))
        else:
            return (typ, server, port)

    unique: Dict[Tuple[Any, ...], Dict[str, Any]] = {}
    for ob in outbounds:
        key = get_key(ob)
        if key not in unique:
            unique[key] = ob
        else:
            # Prioritize based on available delay info (tcp, then http, then xray)
            existing = unique[key]
            existing_delay = existing.get("tcp_delay", existing.get("http_delay", existing.get("xray_delay", float('inf'))))
            new_delay = ob.get("tcp_delay", ob.get("http_delay", ob.get("xray_delay", float('inf'))))
            if new_delay < existing_delay:
                unique[key] = ob
    return list(unique.values())

def diversify_outbounds_by_protocol(protocol_outbounds: List[Dict[str, Any]], limit: int = 75) -> List[Dict[str, Any]]:
    groups = {}
    for ob in protocol_outbounds:
        src = ob.get("source", "unknown")
        groups.setdefault(src, []).append(ob)

    for src in groups:
        def combined_delay(o: Dict[str, Any]) -> float:
            return o.get("tcp_delay", float('inf')) + o.get("http_delay", float('inf')) + o.get("xray_delay", float('inf'))
        groups[src].sort(key=combined_delay)

    diversified = []
    while len(diversified) < limit:
        added_this_round = False
        for src, lst in groups.items():
            if lst:
                diversified.append(lst.pop(0))
                added_this_round = True
                if len(diversified) == limit:
                    break
        if not added_this_round:
            break
    return diversified

def filter_best_outbounds_by_protocol(outbounds: List[Dict[str, Any]], tests_run: List[str]) -> List[Dict[str, Any]]:
    protocols: Dict[str, List[Dict[str, Any]]] = {}
    for ob in outbounds:
        typ = ob.get("type")
        if typ:
            protocols.setdefault(typ, []).append(ob)

    filtered = []
    for typ, obs in protocols.items():
        working = []
        for ob in obs:
            passed = True
            if ob.get("type") in ("wireguard", "warp"):
                # For WireGuard/Warp, only require UDP and REAL delays.
                if ob.get("udp_delay", float('inf')) == float('inf'):
                    passed = False
                if 'real' in tests_run and ob.get("xray_delay", float('inf')) == float('inf'):
                    passed = False
            else:
                if 'tcp' in tests_run and ob.get("tcp_delay", float('inf')) == float('inf'):
                    passed = False
                if 'http' in tests_run and ob.get("http_delay", float('inf')) == float('inf'):
                    passed = False
                if 'real' in tests_run and ob.get("xray_delay", float('inf')) == float('inf'):
                    passed = False

            if passed:
                working.append(ob)

        if len(working) <= 75:
            filtered.extend(working)
        else:
            diversified = diversify_outbounds_by_protocol(working, limit=75)
            filtered.extend(diversified)
    return filtered

def replace_existing_outbounds(base_config: Dict[str, Any], new_outbounds: List[Dict]) -> Dict:
    existing_selector_outbounds = []
    existing_urltest_outbounds = []

    for outbound in base_config.get("outbounds", []):
        if outbound.get("protocol") == "selector":
            existing_selector_outbounds = outbound.get("outbounds", [])
        elif outbound.get("protocol") == "urltest":
            existing_urltest_outbounds = outbound.get("outbounds", [])

    new_selector_outbounds = []
    new_urltest_outbounds = []
    new_tags = {ob["tag"] for ob in new_outbounds}

    for ob in new_outbounds:
        new_selector_outbounds.append(ob["tag"])
        new_urltest_outbounds.append(ob["tag"])

    for tag in existing_selector_outbounds:
        if tag not in new_tags:
            new_selector_outbounds.append(tag)
    for tag in existing_urltest_outbounds:
        if tag not in new_tags:
            new_urltest_outbounds.append(tag)

    final_outbounds = [
        ob for ob in base_config.get("outbounds", [])
        if ob.get("protocol") not in ("selector", "urltest") and ob.get("tag") != "Hiddify Warp"
    ]
    final_outbounds.extend(new_outbounds)

    selector_exists = False
    urltest_exists = False

    for ob in base_config.get("outbounds", []):
        if ob.get("protocol") == "selector":
            ob["outbounds"] = new_selector_outbounds
            final_outbounds.append(ob)
            selector_exists = True
        elif ob.get("protocol") == "urltest":
            ob["outbounds"] = new_urltest_outbounds
            final_outbounds.append(ob)
            urltest_exists = True
    if not selector_exists:
        final_outbounds.append({
            "protocol": "selector",
            "tag": "select",
            "outbounds": new_selector_outbounds,
            "default": "auto"
        })
    if not urltest_exists:
        final_outbounds.append({
            "protocol": "urltest",
            "tag": "auto",
            "outbounds": new_urltest_outbounds,
            "url": "https://clients3.google.com/generate_204",
            "interval": "10m0s"
        })
    base_config["outbounds"] = final_outbounds
    return base_config

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
        print(f"TCP Test for {tag}: No server or port, delay=inf")
        return

    loop = asyncio.get_running_loop()
    start = loop.time()
    print(f"TCP Test for {tag} to {server}:{port} started...")
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(server, port), timeout=3)
        delay = (loop.time() - start) * 1000
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        ob["tcp_delay"] = delay
        print(f"TCP Test for {tag} finished, delay={delay:.2f} ms")
    except (asyncio.TimeoutError, OSError) as e:
        ob["tcp_delay"] = float('inf')
        print(f"TCP Test for {tag} error: {e}, delay=inf")

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
        print(f"HTTP Test for {tag}: No server or port, delay=inf")
        return

    test_urls = [
        "https://www.cloudflare.com/cdn-cgi/trace",
        "https://checkip.amazonaws.com",
        "https://ipleak.net/json",
        "https://ipinfo.io/ip",
        "http://httpbin.org/get",
        "http://neverssl.com",
    ]

    session = requests.Session()
    times = []
    print(f"HTTP Test for {tag} to {server}:{port} started with {repetitions} repetitions...")

    # Clear proxy environment variables temporarily for this test
    orig_env = {}
    for env_var in ['http_proxy', 'https_proxy', 'HTTP_PROXY', 'HTTPS_PROXY', 'all_proxy', 'ALL_PROXY']:
        if env_var in os.environ:
            orig_env[env_var] = os.environ[env_var]
            del os.environ[env_var]

    for i in range(repetitions):
        start = time.time()
        current_proxies = {'http': proxy, 'https': proxy} if proxy else None
        success = False

        for test_url in test_urls:
            try:
                with session.get(test_url, timeout=3, proxies=current_proxies) as response:
                    response.raise_for_status()
                elapsed = (time.time() - start) * 1000
                times.append(elapsed)
                print(f"[{tag}] HTTP Repetition {i+1} using {test_url}: {elapsed:.2f} ms")
                success = True
                break
            except requests.exceptions.RequestException as e:
                print(f"[{tag}] HTTP Repetition {i+1} failed with {test_url}: {e}")

        if not success:
            times.append(float('inf'))
            print(f"[{tag}] HTTP Repetition {i+1} failed with all URLs")

    for env_var, value in orig_env.items():
        os.environ[env_var] = value

    successful_times = [t for t in times if t != float('inf')]
    if successful_times:
        avg = sum(successful_times) / len(successful_times)
        ob["http_delay"] = avg
        print(f"HTTP Test for {tag} finished: Average delay = {avg:.2f} ms over {len(successful_times)} successes")
    else:
        ob["http_delay"] = float('inf')
        print(f"HTTP Test for {tag} finished: All {repetitions} trials failed, delay=inf")

def udp_test_outbound_sync(ob: Dict[str, Any]) -> None:
    try:
        asyncio.run(udp_test_outbound(ob))
    except Exception as e:
        print(f"Exception in udp_test_outbound_sync for tag {ob.get('tag')}: {e}")

async def udp_test_outbound(ob: Dict[str, Any]) -> None:
    tag = ob.get("tag")
    server = ob.get("server")
    port = ob.get("server_port")
    if not server or not port:
        ob["udp_delay"] = float('inf')
        print(f"UDP Test for {tag}: No server or port, delay=inf")
        return
    try:
        infos = []
        try:
            infos = await asyncio.get_running_loop().getaddrinfo(server, None, family=socket.AF_INET)
        except Exception as e4:
            print(f"UDP Test for {tag}: IPv4 getaddrinfo error: {e4}, trying IPv6")
            try:
                infos = await asyncio.get_running_loop().getaddrinfo(server, None, family=socket.AF_INET6)
            except Exception as e6:
                print(f"UDP Test for {tag}: IPv6 getaddrinfo also failed: {e6}")
                raise

        if not infos:
            raise RuntimeError(f"No address info found for {server}")

        ip = infos[0][4][0]
    except Exception as e:
        ob["udp_delay"] = float('inf')
        print(f"UDP Test for {tag}: getaddrinfo error: {e}, delay=inf")
        return

    loop = asyncio.get_running_loop()
    start = loop.time()
    print(f"UDP Test for {tag} to {server}:{port} ({ip}:{port}) started...")
    try:
        transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
            lambda: asyncio.DatagramProtocol(), remote_addr=(ip, port)
        )
        transport.sendto(b"PING")
        await asyncio.sleep(0.2)
        delay = (loop.time() - start) * 1000
        transport.close()
        ob["udp_delay"] = delay
        print(f"UDP Test for {tag} finished, delay={delay:.2f} ms")
    except (asyncio.TimeoutError, OSError) as e:
        ob["udp_delay"] = float('inf')
        print(f"UDP Test for {tag} error: {e}, delay=inf")

def single_test_pass(outbounds: List[Dict[str, Any]],
                     test_type: str,
                     thread_pool_size=32,
                     proxy_for_test: Optional[str] = None,
                     repetitions: int = 5) -> None:
    global completed_outbounds_count, total_outbounds_count, is_ctrl_c_pressed
    completed_outbounds_count = 0
    total_outbounds_count = len(outbounds)
    print(f"Starting single_test_pass with {total_outbounds_count} outbounds (Test type: {test_type})")

    orig_env = {}
    for env_var in ['http_proxy', 'https_proxy', 'HTTP_PROXY', 'HTTPS_PROXY', 'all_proxy', 'ALL_PROXY']:
        if env_var in os.environ:
            orig_env[env_var] = os.environ[env_var]
            del os.environ[env_var]

    with concurrent.futures.ThreadPoolExecutor(max_workers=thread_pool_size) as executor:
        futures = []
        future_to_tag = {}
        for ob in outbounds:
            if is_ctrl_c_pressed:
                print("Ctrl+C detected, stopping outbound testing.")
                break
            tag = ob.get("tag")
            if test_type == "tcp":
                future = executor.submit(tcp_test_outbound_sync, ob)
            elif test_type == "http":
                future = executor.submit(http_delay_test_outbound_sync, ob, proxy_for_test, repetitions)
            elif test_type == "udp":
                future = executor.submit(udp_test_outbound_sync, ob)
            elif test_type == "real":
                future = executor.submit(real_delay_test_outbound, ob)
            else:  # should not be reachable, added safety.
                print(f"Invalid test type in single_test_pass: {test_type}")
                continue

            futures.append(future)
            future_to_tag[future] = tag

        print("Waiting for all test futures to complete...")
        for future in concurrent.futures.as_completed(futures):
            if is_ctrl_c_pressed:
                print("Ctrl+C detected, stopping wait for remaining tests.")
                break
            tag = future_to_tag[future]
            try:
                future.result()
            except Exception as e:
                print(f"Exception during test for tag {tag}: {e}")
            finally:
                completed_outbounds_count += 1
                percentage_completed = (completed_outbounds_count / total_outbounds_count) * 100
                print(f"Progress: {percentage_completed:.2f}% ({completed_outbounds_count}/{total_outbounds_count} tests completed)")
        print("All test futures completed or Ctrl+C abort.")

    for env_var, value in orig_env.items():
        os.environ[env_var] = value

    print("Exiting single_test_pass")

def preprocess_outbounds_for_hiddify(config: Dict[str, Any]) -> Dict[str, Any]:
    return config

def convert_outbound_to_string(ob: Dict[str, Any]) -> Optional[str]:
    protocol = ob.get("type")
    if protocol == "shadowsocks":
        server = ob.get("server")
        port = ob.get("server_port")
        method = ob.get("method")
        password = ob.get("password")
        tag = ob.get("tag")
        userinfo = base64.urlsafe_b64encode(f"{method}:{password}".encode()).decode().rstrip("=")
        return f"ss://{userinfo}@{server}:{port}#{urllib.parse.quote(tag)}"

    elif protocol == "vless":
        server = ob.get("server")
        port = ob.get("server_port")
        uuid = ob.get("uuid")
        tag = ob.get("tag")
        query_params = {}
        if ob.get("flow"):
            query_params["flow"] = ob.get("flow")
        if ob.get("packet_encoding"):
            query_params["packet_encoding"] = ob.get("packet_encoding")
        if ob.get("tls"):
            query_params["security"] = "tls"
            tls_settings = ob.get("tls")
            if tls_settings.get("server_name"):
                query_params["sni"] = tls_settings.get("server_name")
            if tls_settings.get("reality"):
                query_params["security"] = "reality"
                query_params["pbk"] = tls_settings["reality"].get("public_key")
                query_params["sid"] = tls_settings["reality"].get("short_id")
                query_params["fp"] = tls_settings["utls"].get("fingerprint", "chrome")

        if ob.get("transport"):
            transport_settings = ob.get("transport")
            query_params["type"] = transport_settings.get("type")
            if query_params["type"] == "ws":
                query_params["path"] = transport_settings.get("path", "/")
                if transport_settings.get("headers") and transport_settings["headers"].get("Host"):
                    query_params["host"] = transport_settings["headers"].get("Host")

        query_str = urllib.parse.urlencode(query_params)
        return f"vless://{uuid}@{server}:{port}?{query_str}#{urllib.parse.quote(tag)}" if query_str else f"vless://{uuid}@{server}:{port}#{urllib.parse.quote(tag)}"

    elif protocol == "vmess":
        server = ob.get("server")
        port = ob.get("server_port")
        uuid = ob.get("uuid")
        alter_id = ob.get("alterId", 0)
        security = ob.get("security", "auto")
        tag = ob.get("tag")

        config_json = {
            "v": "2",
            "ps": tag,
            "add": server,
            "port": str(port),
            "id": uuid,
            "aid": str(alter_id),
            "scy": security,
            "net": "tcp",
            "type": "none",
            "host": "",
            "path": "/",
            "tls": ""
        }
        if ob.get("transport"):
            transport_settings = ob.get("transport")
            transport_type = transport_settings.get("type")
            if transport_type == "ws":
                config_json["net"] = "ws"
                config_json["path"] = transport_settings.get("path", "/")
                if transport_settings.get("headers") and transport_settings["headers"].get("Host"):
                    config_json["host"] = transport_settings["headers"].get("Host")
        if ob.get("tls") and ob["tls"].get("enabled"):
            config_json["tls"] = "tls"
            if ob["tls"].get("server_name"):
                config_json["sni"] = ob["tls"].get("server_name")

        config_b64 = base64.b64encode(json.dumps(config_json).encode()).decode()
        return f"vmess://{config_b64}#{urllib.parse.quote(tag)}"

    elif protocol == "tuic":
        server = ob.get("server")
        port = ob.get("server_port")
        uuid = ob.get("uuid")
        password = ob.get("password")
        tag = ob.get("tag")
        query_params = {}
        query_params["password"] = password
        if ob.get("congestion_control"):
            query_params["congestion_control"] = ob.get("congestion_control")
        if ob.get("udp_relay_mode"):
            query_params["udp_relay_mode"] = ob.get("udp_relay_mode")
        if ob.get("tls") and ob["tls"].get("server_name"):
            query_params["sni"] = ob["tls"]["server_name"]

        query_str = urllib.parse.urlencode(query_params)
        return f"tuic://{uuid}@{server}:{port}?{query_str}#{urllib.parse.quote(tag)}" if query_str else f"tuic://{uuid}@{server}:{port}#{urllib.parse.quote(tag)}"
    elif protocol in ("wireguard", "warp"):
        server = ob.get("server")
        port = ob.get("server_port")
        private_key = ob.get("private_key")
        tag = ob.get("tag")
        query_params = {
            "address": ",".join(ob.get("local_address", [])),
            "publickey": ob.get("peer")["publicKey"] if ob.get("peer") and ob.get("peer").get("publicKey") else "",
            "mtu": str(ob.get("mtu")),
        }
        reserved_raw = ob.get("reserved")
        if reserved_raw:
            query_params["reserved"] = ",".join(str(ord(c)) for c in reserved_raw)
        query_str = urllib.parse.urlencode(query_params)
        return f"wireguard://{private_key}@{server}:{port}?{query_str}#{urllib.parse.quote(tag)}"

    elif protocol in ("hysteria", "hysteria2", "hy2"):
        server = ob.get("server")
        port = ob.get("server_port")
        password = ob.get("password")
        tag = ob.get("tag")
        query_params = {}
        tls_settings = ob.get("tls", {})
        if tls_settings.get("server_name"):
            query_params["sni"] = tls_settings.get("server_name")
        if tls_settings.get("insecure"):
            query_params["insecure"] = "1"
        obfs_settings = ob.get("obfs",{})
        if obfs_settings.get("type"):
            query_params["obfs"] = obfs_settings.get("type")
            if obfs_settings.get("password"):
                query_params["obfs-password"] = obfs_settings.get("password")

        query_str = urllib.parse.urlencode(query_params)
        return f"hy2://{password}@{server}:{port}?{query_str}#{urllib.parse.quote(tag)}"

    return None

def save_config(outbounds: List[Dict[str, Any]], filepath: str = "merged_config.txt", base64_output: bool = True):
    try:
        output_lines = []
        for ob in outbounds:
            config_string = convert_outbound_to_string(ob)
            if config_string:
                output_lines.append(config_string)
        output_str = "\n".join(output_lines)
        if base64_output:
            output_str = base64.b64encode(output_str.encode()).decode()
        with open(filepath, "w") as outfile:
            outfile.write(output_str)
        if base64_output:
            print(f"Merged configs saved to {filepath} in single-line format (base64 encoded).")
        else:
            print(f"Merged configs saved to {filepath} in single-line plaintext format.")
    except Exception as e:
        print(f"Error saving config to {filepath}: {e}")

def rename_outbound_tags(configs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    protocol_abbr = {
        "shadowsocks": "SS",
        "vless": "VL",
        "vmess": "VM",
        "tuic": "TU",
        "wireguard": "WG",
        "warp": "WG",
        "hysteria": "HY",
        "hysteria2": "HY",
        "hy2": "HY",
        "reality": "RT"
    }
    renamed_configs = []
    protocol_counts: Dict[str, int] = {}
    for config in configs:
        protocol = config.get("type")
        if protocol not in protocol_abbr:
            print(f"Skipping unknown protocol: {protocol}")
            continue

        abbr = protocol_abbr.get(protocol, "XX")
        protocol_counts[abbr] = protocol_counts.get(abbr, 0) + 1
        count = protocol_counts[abbr]

        if count > 75:
            continue

        new_tag = f"🔒Pr0xySh4rk🦈{abbr}{count:02d}"
        config["tag"] = new_tag
        renamed_configs.append(config)

    return renamed_configs

def check_connectivity(url="https://www.google.com", timeout=5):
    print(f"Testing internet connectivity to {url}...")
    try:
        orig_env = {}
        for env_var in ['http_proxy', 'https_proxy', 'HTTP_PROXY', 'HTTPS_PROXY', 'all_proxy', 'ALL_PROXY']:
            if env_var in os.environ:
                orig_env[env_var] = os.environ[env_var]
                del os.environ[env_var]

        response = requests.get(url, timeout=timeout)
        response.raise_for_status()

        for env_var, value in orig_env.items():
            os.environ[env_var] = value

        print(f"✅ Internet connectivity test passed! Response status: {response.status_code}")
        return True
    except requests.exceptions.RequestException as e:
        for env_var, value in orig_env.items():
            os.environ[env_var] = value
        print(f"❌ Internet connectivity test failed: {e}")
        return False

def fetch_and_parse_subscription_thread(url: str, proxy: Optional[str] = None, all_tags: Optional[set] = None) -> List[Dict[str, Any]]:
    if all_tags is None:
        all_tags = set()
    content = fetch_content(url, proxy)
    if content:
        normalized_content = content.strip().replace("\n", "").replace("\r", "").replace(" ", "")
        try:
            decoded_possible = base64.b64decode(normalized_content, validate=True).decode("utf-8")
            content = decoded_possible
        except Exception:
            pass

        outbounds_list = parse_config_url1_2(content, all_tags)
        for outbound in outbounds_list:
            outbound["source"] = url
        if outbounds_list:
            print(f"Thread {os.getpid()}: Parsed {len(outbounds_list)} outbounds from {url}")
            return outbounds_list
        else:
            print(f"Thread {os.getpid()}: No outbounds parsed from {url}")
            return []
    else:
        print(f"Thread {os.getpid()}: Failed to fetch content from {url}, skipping.")
        return []

def main():
    global is_ctrl_c_pressed
    signal.signal(signal.SIGINT, signal_handler)

    parser = argparse.ArgumentParser(description="Pr0xySh4rk Hiddify Config Merger - Multi-threaded")
    parser.add_argument("--input", required=True, help="Input subscription file (base64 or plain text with URLs)")
    parser.add_argument("--output", required=True, help="Output configuration file path")
    parser.add_argument("--proxy", help="Optional proxy for fetching subscription URLs (e.g., 'http://127.0.0.1:1080')")
    parser.add_argument("--threads", type=int, default=32, help="Number of threads (default: 32)")
    parser.add_argument("--test-proxy", help="Optional proxy for HTTP testing (e.g., 'http://127.0.0.1:1080')")
    parser.add_argument("-r", "--repetitions", type=int, default=5, help="HTTP test repetitions (default: 5)")
    parser.add_argument("--test", choices=["tcp", "udp", "http", "tcp+http", "real", "http+real", "tcp+real", "tcp+http+real"],
                        default="http", help="Test type(s).  Combined tests run sequentially.")
    parser.add_argument("--no-base64", action="store_true", dest="no_base64_output",
                        help="Output in plaintext (not base64 encoded)")
    parser.set_defaults(no_base64_output=False)
    args = parser.parse_args()

    if not check_connectivity():
        print("Exiting due to failed internet connectivity test.")
        return

    base_config_template = {
       "log": {"level": "warn"}, "dns": {}, "inbounds": [], "outbounds": [], "route": {}, "experimental": {}
    }

    subscription_urls: List[str] = []
    try:
        with open(args.input, "rb") as f:
            encoded_content = f.read().strip()
        try:
            # Attempt base64 decoding, strict validation
            decoded_content = base64.b64decode(encoded_content, validate=True).decode("utf-8")
            subscription_urls = [line.strip() for line in decoded_content.splitlines() if line.strip()]
            print("Subscription URLs decoded from base64 input file.")
        except (ValueError, UnicodeDecodeError) as e:  # Catch specific errors
            print(f"Base64 decoding failed: {e}. Trying plain text with multiple encodings.")
            # Try multiple encodings, starting with the most likely
            encodings = ["utf-8", "latin-1", "cp1252"]
            decoded_content = None
            for enc in encodings:
                try:
                    with open(args.input, "r", encoding=enc) as f2:
                        decoded_content = f2.read()
                        break # If successful, exit encoding loop
                except UnicodeDecodeError:
                    continue  # Try the next encoding
            if decoded_content is not None:
              subscription_urls = [line.strip() for line in decoded_content.splitlines() if line.strip()]
            else:
              print("Error: could not read input file as text.")
              sys.exit(1) # Exit with error.


    except FileNotFoundError:
        print(f"Error: {args.input} not found.")
        return

    if not subscription_urls:
        print("No subscription URLs found.")
        save_config([], filepath=args.output, base64_output=(not args.no_base64_output))
        return

    all_tags: set = set()
    parsed_outbounds_lists: List[List[Dict[str, Any]]] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = [executor.submit(fetch_and_parse_subscription_thread, url, args.proxy, all_tags)
                   for url in subscription_urls]
        for future in concurrent.futures.as_completed(futures):
            if is_ctrl_c_pressed:
                print("Ctrl+C detected during subscription fetching.")
                break
            result = future.result()
            if result:
                parsed_outbounds_lists.append(result)
        if is_ctrl_c_pressed:
            print("Exiting early due to Ctrl+C after fetching.")
            save_config([], filepath=args.output, base64_output=(not args.no_base64_output))
            sys.exit(0)

    all_parsed_outbounds = [ob for sublist in parsed_outbounds_lists for ob in sublist]
    print(f"Total parsed outbounds before deduplication: {len(all_parsed_outbounds)}")
    all_parsed_outbounds = deduplicate_outbounds(all_parsed_outbounds)
    print(f"Total unique outbounds after deduplication: {len(all_parsed_outbounds)}")

    test_type = args.test
    tested_outbounds: List[Dict[str, Any]] = []
    tests_to_run = []

    if test_type == "tcp+http":
        group_udp = [ob for ob in all_parsed_outbounds if ob.get("type") in ("wireguard", "warp", "hysteria", "hysteria2", "hy2")]
        group_tcp_http = [ob for ob in all_parsed_outbounds if ob.get("type") not in ("wireguard", "warp", "hysteria", "hysteria2", "hy2")]

        print("\n=== Testing non-WireGuard/Warp/Hysteria (TCP+HTTP) outbounds ===")
        single_test_pass(group_tcp_http, "tcp", args.threads, args.test_proxy, args.repetitions)
        survivors_tcp = [ob for ob in group_tcp_http if ob.get("tcp_delay", float('inf')) != float('inf')]
        print(f"{len(survivors_tcp)} outbounds passed the TCP test (non-WG/Warp/Hysteria).")

        if is_ctrl_c_pressed:
            print("Exiting early due to Ctrl+C after TCP testing.")
            save_config([], filepath=args.output, base64_output=(not args.no_base64_output))
            sys.exit(0)

        print("\n=== Running HTTP test for non-WireGuard/Warp/Hysteria outbounds ===")
        single_test_pass(survivors_tcp, "http", args.threads, args.test_proxy, args.repetitions)
        survivors_http = [ob for ob in survivors_tcp if ob.get("http_delay", float('inf')) != float('inf')]
        print(f"{len(survivors_http)} outbounds passed both TCP and HTTP tests (non-WG/Warp/Hysteria).")

        print("\n=== Testing WireGuard/Warp/Hysteria (UDP) outbounds ===")
        single_test_pass(group_udp, "udp", args.threads, args.test_proxy, args.repetitions)
        survivors_udp = [ob for ob in group_udp if ob.get("udp_delay", float('inf')) != float('inf')]
        print(f"{len(survivors_udp)} outbounds passed the UDP test for WG/Warp/Hysteria.")

        tested_outbounds = survivors_http + survivors_udp
        print(f"Total outbounds passed all tests: {len(tested_outbounds)}")
        tests_to_run = test_type.split('+')

    elif test_type in ("http+real", "tcp+real", "tcp+http+real"):
        group_udp = [ob for ob in all_parsed_outbounds if ob.get("type") in ("wireguard", "warp")]
        group_tcp_http = [ob for ob in all_parsed_outbounds if ob.get("type") not in ("wireguard", "warp")]

        tests_to_run = test_type.split('+')
        for ob in all_parsed_outbounds:
            ob["tcp_delay"] = float('inf')
            ob["http_delay"] = float('inf')
            ob["xray_delay"] = float('inf')
            ob["udp_delay"] = float('inf')

        temp_tested_outbounds_tcp_http = group_tcp_http[:]
        temp_tested_outbounds_udp = group_udp[:]

        if test_type == "tcp+http+real":
            for test in ["tcp", "http", "real"]:
                print(f"\n=== Starting {test.upper()} test pass for non-WG/Warp ===")
                single_test_pass(temp_tested_outbounds_tcp_http, test, args.threads, args.test_proxy, args.repetitions)

                if test == "tcp":
                    temp_tested_outbounds_tcp_http = [ob for ob in temp_tested_outbounds_tcp_http if ob.get("tcp_delay", float('inf')) != float('inf')]
                elif test == "http":
                    temp_tested_outbounds_tcp_http = [ob for ob in temp_tested_outbounds_tcp_http if ob.get("http_delay", float('inf')) != float('inf')]
                elif test == "real":
                    temp_tested_outbounds_tcp_http = [ob for ob in temp_tested_outbounds_tcp_http if ob.get("xray_delay", float('inf')) != float('inf')]

            print(f"\n=== Starting UDP test pass for WG/Warp ===")
            single_test_pass(temp_tested_outbounds_udp, "udp", args.threads, args.test_proxy, args.repetitions)
            temp_tested_outbounds_udp = [ob for ob in temp_tested_outbounds_udp if ob.get("udp_delay", float('inf')) != float('inf')]
            print(f"\n=== Starting REAL test pass for WG/Warp ===")
            single_test_pass(temp_tested_outbounds_udp, "real", args.threads, args.test_proxy, args.repetitions)
            temp_tested_outbounds_udp = [ob for ob in temp_tested_outbounds_udp if ob.get("xray_delay", float('inf')) != float('inf')]

            tested_outbounds = temp_tested_outbounds_tcp_http + temp_tested_outbounds_udp
            tested_outbounds = filter_best_outbounds_by_protocol(tested_outbounds, tests_to_run)

        else:
            for test in tests_to_run:
                print(f"\n=== Starting {test.upper()} test pass ===")
                if test in ("tcp", "http", "real"):
                    single_test_pass(temp_tested_outbounds_tcp_http, test, args.threads, args.test_proxy, args.repetitions)
                elif test == "udp":
                    single_test_pass(temp_tested_outbounds_udp, test, args.threads, args.test_proxy, args.repetitions)

                if test == "tcp":
                    temp_tested_outbounds_tcp_http = [ob for ob in temp_tested_outbounds_tcp_http if ob.get("tcp_delay", float('inf')) != float('inf')]
                elif test == "http":
                    temp_tested_outbounds_tcp_http = [ob for ob in temp_tested_outbounds_tcp_http if ob.get("http_delay", float('inf')) != float('inf')]
                elif test == "real":
                    temp_tested_outbounds_tcp_http = [ob for ob in temp_tested_outbounds_tcp_http if ob.get("xray_delay", float('inf')) != float('inf')]
                elif test == 'udp':
                    temp_tested_outbounds_udp = [ob for ob in temp_tested_outbounds_udp if ob.get("udp_delay", float('inf')) != float('inf')]
            tested_outbounds = temp_tested_outbounds_tcp_http + temp_tested_outbounds_udp
            tested_outbounds = filter_best_outbounds_by_protocol(tested_outbounds, tests_to_run)

    elif test_type == "real":
        print("\n=== Real Delay Test using xray_core for each outbound ===")
        for ob in all_parsed_outbounds:
            ob["xray_delay"] = float('inf')
        single_test_pass(all_parsed_outbounds, "real", args.threads, args.test_proxy, args.repetitions)
        tested_outbounds = [ob for ob in all_parsed_outbounds if ob.get("xray_delay", float('inf')) != float('inf')]
        tests_to_run = [test_type]

    else:
        if test_type == "udp":
            print("\n=== UDP Test (primarily for WireGuard/Warp) ===")
            for ob in all_parsed_outbounds:
                ob["udp_delay"] = float('inf')
            single_test_pass(all_parsed_outbounds, args.test, args.threads, args.test_proxy, args.repetitions)
            tested_outbounds = [ob for ob in all_parsed_outbounds if ob.get("udp_delay", float('inf')) != float('inf')]
            tests_to_run = [test_type]
        else:
            single_test_pass(all_parsed_outbounds, args.test, args.threads, args.test_proxy, args.repetitions)
            if args.test == "tcp":
                tested_outbounds = [ob for ob in all_parsed_outbounds if ob.get("tcp_delay", float('inf')) != float('inf')]
            elif args.test == "http":
                tested_outbounds = [ob for ob in all_parsed_outbounds if ob.get("http_delay", float('inf')) != float('inf')]
            print(f"{len(tested_outbounds)} outbounds passed the {args.test} test.")
            tests_to_run = [test_type]

    if is_ctrl_c_pressed:
        print("Exiting early due to Ctrl+C after testing.")
        save_config([], filepath=args.output, base64_output=(not args.no_base64_output))
        sys.exit(0)

    tested_outbounds = filter_best_outbounds_by_protocol(tested_outbounds, tests_to_run)
    print(f"Total outbounds after filtering best per protocol: {len(tested_outbounds)}")

    renamed_outbounds = rename_outbound_tags(tested_outbounds)
    save_config(renamed_outbounds, filepath=args.output, base64_output=(not args.no_base64_output))

if __name__ == "__main__":
    main()
