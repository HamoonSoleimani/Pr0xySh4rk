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
TEST_URL = "https://google.com"  # Define test URL here for easy changing

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
# Fetching content from URLs (Thread-safe)
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
        error_type = type(e).__name__
        error_message = str(e)
        print(f"Thread {os.getpid()}: Error fetching URL {url}{' via proxy ' + proxy if proxy else ''}: {error_type} - {error_message}")
        return None

# ---------------------------
# Parsing Warp/WireGuard links (Thread-safe)
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
# Parsing configuration content (Thread-safe)
# ---------------------------
def parse_config_url1_2(content: str, all_tags: set) -> List[Dict[str, Any]]:
    outbounds = []
    try:
        try:
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
                print(f"Thread {os.getpid()}: Warning: 'outbounds' key not found in JSON config.")
                return []
        except json.JSONDecodeError:
            print(f"Thread {os.getpid()}: JSONDecodeError")
            pass
        except Exception as e_base:
            print(f"Thread {os.getpid()}: Error processing base config content: {e_base}")
    except:
        pass

    # Legacy link parsing follows:
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("//"):
            continue

        if line.startswith("ss://"):
            print(f"Thread {os.getpid()}: Found Shadowsocks link: {line}")
            try:
                ss_url_encoded = line[5:]
                if "#" in ss_url_encoded:
                    ss_url_encoded, frag = ss_url_encoded.split("#", 1)
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
                        print(f"Thread {os.getpid()}: Invalid Shadowsocks link (missing '@'): {line}")
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
            print(f"Thread {os.getpid()}: Protocol detected: {protocol}")
            if protocol == "vless":
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
                    port = int(server_port_str.split(":")[1]) if (":" in server_port_str and server_port_str.split(":")[1].isdigit()) else 443
                params = urllib.parse.parse_qs(parsed_url.query)
                tag = generate_unique_tag(all_tags)
                uuid = userinfo
                vless_outbound = {
                    "type": "vless",
                    "tag": tag,
                    "server": server,
                    "server_port": port,
                    "uuid": uuid,
                    "flow": params.get("flow", [""])[0],
                    "packet_encoding": params.get("packet_encoding", [""])[0]
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

            elif protocol == "vmess":
                base64_config = line.split("vmess://")[1]
                try:
                    config_str = base64_config.split("#")[0] if "#" in base64_config else base64_config
                    padding = "=" * (-len(config_str) % 4)
                    decoded_bytes = base64.b64decode(config_str + padding)
                    config_json = json.loads(decoded_bytes.decode("utf-8"))
                    tag = generate_unique_tag(all_tags)
                    vmess_outbound = {
                        "type": "vmess",
                        "tag": tag,
                        "server": config_json.get("add"),
                        "server_port": int(config_json.get("port")),
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

            elif protocol == "trojan":
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
                    port = int(server_port_str.split(":")[1]) if (":" in server_port_str and server_port_str.split(":")[1].isdigit()) else 443
                params = urllib.parse.parse_qs(parsed_url.query)
                tag = generate_unique_tag(all_tags)
                trojan_outbound = {
                    "type": "trojan",
                    "tag": tag,
                    "server": server,
                    "server_port": port,
                    "password": password,
                }
                if params.get("security", [""])[0] == "tls":
                    trojan_outbound["tls"] = {
                        "enabled": True,
                        "server_name": params.get("sni", [server])[0],
                        "alpn": params.get("alpn", [])
                    }
                outbounds.append(trojan_outbound)

            elif protocol == "tuic":
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
                    port = int(server_port_str.split(":")[1]) if (":" in server_port_str and server_port_str.split(":")[1].isdigit()) else 443
                params = urllib.parse.parse_qs(parsed_url.query)
                tag = generate_unique_tag(all_tags)
                tuic_outbound = {
                    "type": "tuic",
                    "tag": tag,
                    "server": server,
                    "server_port": port,
                    "uuid": uuid,
                    "password": params.get("password", [""])[0],
                    "congestion_control": params.get("congestion_control", [""])[0] or "bbr",
                    "udp_relay_mode": params.get("udp_relay_mode", [""])[0] or "native",
                    "tls": {"enabled": True, "server_name": params.get("sni", [server])[0], "insecure": True}
                }
                outbounds.append(tuic_outbound)

            elif protocol in ("warp", "wireguard"):
                if protocol == "wireguard":
                    line = line.replace("wireguard://", "warp://", 1)
                parsed_configs, counter = parse_warp_line(line, 0, all_tags)
                outbounds.extend(parsed_configs)

            elif protocol in ("hysteria", "hysteria2", "hy2"):
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
                    port = int(server_port_str.split(":")[1]) if (":" in server_port_str and server_port_str.split(":")[1].isdigit()) else 443
                params = urllib.parse.parse_qs(parsed_url.query)
                tag = generate_unique_tag(all_tags)
                hysteria_outbound = {
                    "type": "hysteria2",
                    "tag": tag,
                    "server": server,
                    "server_port": port,
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
            elif protocol == "reality":
                tag = generate_unique_tag(all_tags)
                reality_outbound = {
                    "type": "reality",
                    "tag": tag,
                    "server": "",
                    "server_port": 443,
                    "password": "",
                    "tls": {"enabled": True}
                }
                outbounds.append(reality_outbound)
    return outbounds

# ---------------------------
# Deduplicate outbounds to avoid testing the same config multiple times
# ---------------------------
def deduplicate_outbounds(outbounds: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    def get_key(ob: Dict[str, Any]) -> tuple:
        typ = ob.get("type", "")
        server = ob.get("server", "")
        port = ob.get("server_port", "")
        if typ == "shadowsocks":
            method = ob.get("method", "")
            password = ob.get("password", "")
            plugin = ob.get("plugin", "")
            return (typ, server, port, method, password, plugin)
        elif typ in ("vless", "vmess"):
            uuid = ob.get("uuid", "")
            return (typ, server, port, uuid)
        elif typ in ("trojan", "tuic", "reality"):
            pwd = ob.get("password", "")
            if typ == "tuic":
                uuid = ob.get("uuid", "")
                return (typ, server, port, uuid, pwd)
            return (typ, server, port, pwd)
        elif typ in ("wireguard", "warp"):
            key = ob.get("private_key", "")
            return (typ, server, port, key)
        elif typ in ("hysteria", "hysteria2", "hy2"):
            pwd = ob.get("password", "")
            return (typ, server, port, pwd)
        else:
            return (typ, server, port)
    unique = {}
    for ob in outbounds:
        key = get_key(ob)
        if key not in unique:
            unique[key] = ob
        else:
            old_tcp = unique[key].get("tcp_delay", float('inf'))
            new_tcp = ob.get("tcp_delay", float('inf'))
            old_http = unique[key].get("http_delay", float('inf'))
            new_http = ob.get("http_delay", float('inf'))
            if (new_tcp + new_http) < (old_tcp + old_http):
                unique[key] = ob
    return list(unique.values())

# ---------------------------
# Diversify outbounds if there are more than 50 for a protocol
# ---------------------------
def diversify_outbounds_by_protocol(protocol_outbounds: List[Dict[str, Any]], limit: int = 50) -> List[Dict[str, Any]]:
    groups = {}
    for ob in protocol_outbounds:
        src = ob.get("source", "unknown")
        groups.setdefault(src, []).append(ob)
    for src in groups:
        def combined_delay(o: Dict[str, Any]) -> float:
            td = o.get("tcp_delay", float('inf'))
            hd = o.get("http_delay", float('inf'))
            return td + hd
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

# ---------------------------
# Filtering best outbounds: Limit to 50 best working per protocol.
# ---------------------------
def filter_best_outbounds_by_protocol(outbounds: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    protocols = {}
    for ob in outbounds:
        typ = ob.get("type")
        protocols.setdefault(typ, []).append(ob)
    filtered = []
    for typ, obs in protocols.items():
        working = [
            ob for ob in obs
            if ob.get("tcp_delay", 0) != float('inf') and ob.get("http_delay", 0) != float('inf')
        ]
        if len(working) <= 50:
            filtered.extend(working)
        else:
            diversified = diversify_outbounds_by_protocol(working, limit=50)
            filtered.extend(diversified)
    return filtered

# ---------------------------
# Merging and renaming outbounds (Thread-safe)
# ---------------------------
def merge_configs(base_config: Dict[str, Any], outbound_lists: List[List[Dict[str, Any]]], all_tags: set) -> Dict[str, Any]:
    merged_outbounds: List[Dict[str, Any]] = base_config.get("outbounds", [])
    selector_outbounds: List[str] = []
    urltest_outbounds: List[str] = []
    for ob in merged_outbounds:
        if "tag" in ob:
            all_tags.add(ob["tag"])
        if ob.get("type") == "selector":
            selector_outbounds = ob.get("outbounds", [])
            all_tags.update(selector_outbounds)
        elif ob.get("type") == "urltest":
            urltest_outbounds = ob.get("outbounds", [])

    for outbound_list in outbound_lists:
        for outbound in outbound_list:
            merged_outbounds.append(outbound)
            selector_outbounds.append(outbound["tag"])
            urltest_outbounds.append(outbound["tag"])

    for ob in merged_outbounds:
        if ob.get("type") == "selector":
            ob["outbounds"] = selector_outbounds
        elif ob.get("type") == "urltest":
            ob["outbounds"] = urltest_outbounds

    base_config["outbounds"] = merged_outbounds

    if any("detour" in ob and ob["detour"] == "Hiddify Warp" for ob_list in outbound_lists for ob in ob_list):
        hiddify_warp_exists = any(ob.get("tag") == "Hiddify Warp" for ob in base_config["outbounds"])
        if not hiddify_warp_exists:
            hiddify_warp_outbound = {
                "type": "direct",
                "tag": "Hiddify Warp",
            }
            base_config["outbounds"].append(hiddify_warp_outbound)
            print("Added a placeholder 'Hiddify Warp' outbound (type: direct).")
    return base_config

def replace_existing_outbounds(base_config: Dict[str, Any], new_outbounds: List[Dict]) -> Dict:
    existing_selector_outbounds = []
    existing_urltest_outbounds = []
    for outbound in base_config.get("outbounds", []):
        if outbound.get("type") == "selector":
            existing_selector_outbounds = outbound.get("outbounds", [])
        elif outbound.get("type") == "urltest":
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
        if ob.get("type") not in ("selector", "urltest") and ob.get("tag") != "Hiddify Warp"
    ]
    final_outbounds.extend(new_outbounds)

    selector_exists = False
    urltest_exists = False
    for ob in base_config.get("outbounds", []):
        if ob.get("type") == "selector":
            ob["outbounds"] = new_selector_outbounds
            final_outbounds.append(ob)
            selector_exists = True
        elif ob.get("type") == "urltest":
            ob["outbounds"] = new_urltest_outbounds
            final_outbounds.append(ob)
            urltest_exists = True

    if not selector_exists:
        final_outbounds.append({
            "type": "selector",
            "tag": "select",
            "outbounds": new_selector_outbounds,
            "default": "auto"
        })
    if not urltest_exists:
        final_outbounds.append({
            "type": "urltest",
            "tag": "auto",
            "outbounds": new_urltest_outbounds,
            "url": "https://clients3.google.com/generate_204",
            "interval": "10m0s"
        })

    base_config["outbounds"] = final_outbounds
    return base_config

# ---------------------------
# TCP test (stores results in ob["tcp_delay"])
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
        print(f"TCP Test for {tag}: No server or port, delay=inf")
        return
    loop = asyncio.get_event_loop()
    start = loop.time()
    print(f"TCP Test for {tag} to {server}:{port} started...")
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(server, port), timeout=1)
        delay = (loop.time() - start) * 1000
        writer.close()
        try:
            await writer.wait_closed()
        except:
            pass
        ob["tcp_delay"] = delay
        print(f"TCP Test for {tag} finished, delay={delay:.2f} ms")
    except Exception as e:
        ob["tcp_delay"] = float('inf')
        print(f"TCP Test for {tag} error: {e}, delay=inf")

# ---------------------------
# HTTP test (stores results in ob["http_delay"])
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
        print(f"HTTP Test for {tag}: No server or port, delay=inf")
        return
    test_url = TEST_URL
    session = requests.Session()
    times = []
    print(f"HTTP Test for {tag} to {server}:{port} using {test_url} started with {repetitions} repetitions...")
    for i in range(repetitions):
        start = asyncio.get_event_loop().time()
        current_proxies = {'http': proxy, 'https': proxy} if proxy else None
        try:
            with session.get(test_url, timeout=1, proxies=current_proxies) as response:
                response.raise_for_status()
            elapsed = (asyncio.get_event_loop().time() - start) * 1000
            times.append(elapsed)
            print(f"[{tag}] HTTP Repetition {i+1}: {elapsed:.2f} ms")
        except requests.exceptions.RequestException as e:
            times.append(None)
            print(f"[{tag}] HTTP Repetition {i+1} failed: {e}")
    successful = [t for t in times if t is not None]
    if successful:
        avg = sum(successful) / len(successful)
        ob["http_delay"] = avg
        print(f"HTTP Test for {tag} finished: Average delay = {avg:.2f} ms over {len(successful)} successes")
    else:
        ob["http_delay"] = float('inf')
        print(f"HTTP Test for {tag} finished: All {repetitions} trials failed, delay=inf")

# ---------------------------
# UDP test (stores results in ob["udp_delay"])
# ---------------------------
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
        infos = await asyncio.get_event_loop().getaddrinfo(server, None, family=socket.AF_INET)
        ip = infos[0][4][0]
    except Exception as e:
        ob["udp_delay"] = float('inf')
        print(f"UDP Test for {tag}: getaddrinfo error: {e}, delay=inf")
        return
    loop = asyncio.get_event_loop()
    start = loop.time()
    print(f"UDP Test for {tag} to {server}:{port} ({ip}:{port}) started...")
    try:
        transport, protocol = await asyncio.get_event_loop().create_datagram_endpoint(
            lambda: asyncio.DatagramProtocol(), remote_addr=(ip, port)
        )
        await asyncio.sleep(0.1)
        delay = (loop.time() - start) * 1000
        transport.close()
        ob["udp_delay"] = delay
        print(f"UDP Test for {tag} finished, delay={delay:.2f} ms")
    except Exception as e:
        ob["udp_delay"] = float('inf')
        print(f"UDP Test for {tag} error: {e}, delay=inf")

# ---------------------------
# Single-pass test on outbounds (Threaded).
# This function runs the chosen test (tcp, http, or udp) on all outbounds.
# ---------------------------
def single_test_pass(outbounds: List[Dict[str, Any]],
                     test_type: str,
                     thread_pool_size=32,
                     proxy_for_test: Optional[str] = None,
                     repetitions: int = 5) -> None:
    global completed_outbounds_count, total_outbounds_count, is_ctrl_c_pressed
    completed_outbounds_count = 0
    total_outbounds_count = len(outbounds)
    print(f"Starting single_test_pass with {total_outbounds_count} outbounds (Test type: {test_type})")
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
            else:
                future = executor.submit(http_delay_test_outbound_sync, ob, proxy_for_test, repetitions)
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
    print("Exiting single_test_pass")

# ---------------------------
# Saving configuration as Base64-encoded output (Thread-safe)
# ---------------------------
def save_config(config: Dict[str, Any], filepath: str = "merge_config.json"):
    try:
        # Remove testing and source metadata.
        for outbound in config.get("outbounds", []):
            if "udp_delay" in outbound:
                del outbound["udp_delay"]
            if "tcp_delay" in outbound:
                del outbound["tcp_delay"]
            if "http_delay" in outbound:
                del outbound["http_delay"]
            if "source" in outbound:
                del outbound["source"]
        final_json_str = json.dumps(config, indent=2)
        final_encoded = base64.b64encode(final_json_str.encode("utf-8")).decode("utf-8")
        with open(filepath, "w") as outfile:
            outfile.write(final_encoded)
        print(f"Merged config saved to {filepath} (base64 encoded)")
    except Exception as e:
        print(f"Error saving config to {filepath}: {e}")

# ---------------------------
# Fetch and parse subscription URLs in Threads.
# Each outbound is annotated with its source URL.
# ---------------------------
def fetch_and_parse_subscription_thread(url: str, proxy: Optional[str] = None, all_tags: set = None) -> List[Dict[str, Any]]:
    print(f"Thread {os.getpid()}: Fetching and parsing: {url}")
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

# ---------------------------
# Main function
# ---------------------------
def main():
    global is_ctrl_c_pressed
    signal.signal(signal.SIGINT, signal_handler)
    parser = argparse.ArgumentParser(description="Pr0xySh4rk Hiddify Config Merger - Multi-threaded (Base64 encoded output only)")
    parser.add_argument("--input", required=True, help="Input subscription file (base64 or plain text with URLs)")
    parser.add_argument("--output", required=True, help="Output configuration file path (will contain Base64 encoded config)")
    parser.add_argument("--proxy", help="Optional proxy for fetching subscription URLs (e.g., 'http://127.0.0.1:1080')")
    parser.add_argument("--threads", type=int, default=32, help="Number of threads to use for fetching/testing (default: 32)")
    parser.add_argument("--test-proxy", help="Optional proxy to use for HTTP testing outbounds (e.g., 'http://127.0.0.1:1080')")
    parser.add_argument("-r", "--repetitions", type=int, default=5, help="Number of test repetitions (HTTP) per outbound (default: 5)")
    parser.add_argument("--test", choices=["tcp", "udp", "http", "tcp+http"], default="http",
                        help="Specify which test(s) to run. 'tcp+http' runs a two-pass test (TCP then HTTP).")
    args = parser.parse_args()

    # Remove environment proxy settings
    original_env = {}
    proxy_vars = ['http_proxy', 'https_proxy', 'all_proxy', 'HTTP_PROXY', 'PROXY', 'ALL_PROXY']
    for var in proxy_vars:
        if var in os.environ:
            original_env[var] = os.environ[var]
            del os.environ[var]

    base_config_template = {
        "log": {"level": "warn", "output": "box.log", "timestamp": True},
        "dns": {
            "servers": [
                {"tag": "dns-remote", "address": "tcp://185.228.168.9", "address_resolver": "dns-direct"},
                {"tag": "dns-trick-direct", "address": "https://sky.rethinkdns.com/", "detour": "direct-fragment"},
                {"tag": "dns-direct", "address": "tcp://8.8.4.4", "address_resolver": "dns-local", "detour": "direct"},
                {"tag": "dns-local", "address": "local", "detour": "direct"},
                {"tag": "dns-block", "address": "rcode://success"}
            ],
            "rules": [
                {"domain_suffix": ".ir", "geosite": "ir", "server": "dns-direct"},
                {"domain": "clients3.google.com", "server": "dns-remote", "rewrite_ttl": 3000}
            ],
            "final": "dns-remote",
            "static_ips": {
                "sky.rethinkdns.com": [
                    "188.114.96.3",
                    "188.114.97.3",
                    "2a06:98c1:3121::3",
                    "2a06:98c1:3120::3"
                ]
            },
            "independent_cache": True
        },
        "inbounds": [
            {
                "type": "tun",
                "tag": "tun-in",
                "mtu": 9000,
                "inet4_address": "172.19.0.1/28",
                "inet6_address": "fdfe:dcba:9876::1/126",
                "auto_route": True,
                "strict_route": True,
                "endpoint_independent_nat": True,
                "sniff": True,
                "sniff_override_destination": True
            },
            {
                "type": "mixed",
                "tag": "mixed-in",
                "listen": "127.0.0.1",
                "listen_port": 12334,
                "sniff": True,
                "sniff_override_destination": True
            },
            {
                "type": "direct",
                "tag": "dns-in",
                "listen": "127.0.0.1",
                "listen_port": 16440,
                "override_address": "1.1.1.1",
                "override_port": 53
            }
        ],
        "outbounds": [
            {
                "type": "selector",
                "tag": "select",
                "outbounds": [
                    "direct",
                    "bypass",
                    "block"
                ],
                "default": "auto"
            },
            {
                "type": "urltest",
                "tag": "auto",
                "outbounds": [],
                "url": "https://clients3.google.com/generate_204",
                "interval": "10m0s"
            },
            {"type": "dns", "tag": "dns-out"},
            {"type": "direct", "tag": "direct"},
            {
                "type": "direct",
                "tag": "direct-fragment",
                "tls_fragment": {
                    "enabled": True,
                    "size": "10-30",
                    "sleep": "1-2"
                }
            },
            {"type": "direct", "tag": "bypass"},
            {"type": "block", "tag": "block"}
        ],
        "route": {
            "geoip": {"path": "geo-assets/chocolate4u-iran-sing-box-rules-geoip.db"},
            "geosite": {"path": "geo-assets/chocolate4u-iran-sing-box-rules-geosite.db"},
            "rules": [
                {"inbound": "dns-in", "outbound": "dns-out"},
                {"port": 53, "outbound": "dns-out"},
                {"clash_mode": "Direct", "outbound": "direct"},
                {"clash_mode": "Global", "outbound": "select"},
                {"domain_suffix": ".ir", "geosite": "ir", "geoip": "ir", "outbound": "bypass"}
            ],
            "auto_detect_interface": True,
            "override_android_vpn": True
        },
        "experimental": {
            "clash_api": {"external_controller": "127.0.0.1:6756"}
        }
    }

    subscription_urls = []
    try:
        with open(args.input, "rb") as f:
            encoded_content = f.read().strip()
        try:
            decoded_content = base64.b64decode(encoded_content).decode("utf-8")
            subscription_urls = [line.strip() for line in decoded_content.splitlines() if line.strip()]
            print("Subscription URLs decoded from base64 input file.")
        except Exception as e:
            print(f"Base64 decoding failed: {e}. Trying plain text.")
            with open(args.input, "r") as f2:
                subscription_urls = [line.strip() for line in f2 if line.strip()]
    except FileNotFoundError:
        print(f"Error: {args.input} not found.")
        return

    if not subscription_urls:
        print("No subscription URLs found.")
        save_config(base_config_template, filepath=args.output)
        return

    all_tags = set()
    parsed_outbounds_lists = []
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
            save_config(base_config_template, filepath=args.output)
            sys.exit(0)

    all_parsed_outbounds = [ob for sublist in parsed_outbounds_lists for ob in sublist]
    print(f"Total parsed outbounds before deduplication: {len(all_parsed_outbounds)}")

    all_parsed_outbounds = deduplicate_outbounds(all_parsed_outbounds)
    print(f"Total unique outbounds after deduplication: {len(all_parsed_outbounds)}")

    # If test mode is tcp+http, perform a two-pass test:
    if args.test == "tcp+http":
        print("\n=== First pass: TCP test ===")
        single_test_pass(all_parsed_outbounds, "tcp", args.threads, args.test_proxy, args.repetitions)
        survivors_tcp = [ob for ob in all_parsed_outbounds if ob.get("tcp_delay", float('inf')) != float('inf')]
        print(f"{len(survivors_tcp)} outbounds passed the TCP test. Proceeding to HTTP test...")

        if is_ctrl_c_pressed:
            print("Exiting early due to Ctrl+C after first pass.")
            save_config(base_config_template, filepath=args.output)
            sys.exit(0)

        print("\n=== Second pass: HTTP test ===")
        single_test_pass(survivors_tcp, "http", args.threads, args.test_proxy, args.repetitions)
        survivors_http = [ob for ob in survivors_tcp if ob.get("http_delay", float('inf')) != float('inf')]
        print(f"{len(survivors_http)} outbounds passed both TCP and HTTP tests.")

        if is_ctrl_c_pressed:
            print("Exiting early due to Ctrl+C after second pass.")
            save_config(base_config_template, filepath=args.output)
            sys.exit(0)

        all_parsed_outbounds = filter_best_outbounds_by_protocol(survivors_http)
        print(f"Total outbounds after filtering best per protocol: {len(all_parsed_outbounds)}")

    else:
        # Single-pass test mode: tcp, udp, or http.
        single_test_pass(all_parsed_outbounds, args.test, args.threads, args.test_proxy, args.repetitions)
        if is_ctrl_c_pressed:
            print("Exiting early due to Ctrl+C after testing.")
            save_config(base_config_template, filepath=args.output)
            sys.exit(0)
        if args.test == "tcp":
            all_parsed_outbounds = [ob for ob in all_parsed_outbounds if ob.get("tcp_delay", float('inf')) != float('inf')]
        elif args.test == "udp":
            all_parsed_outbounds = [ob for ob in all_parsed_outbounds if ob.get("udp_delay", float('inf')) != float('inf')]
        else:
            all_parsed_outbounds = [ob for ob in all_parsed_outbounds if ob.get("http_delay", float('inf')) != float('inf')]
        print(f"{len(all_parsed_outbounds)} outbounds passed the {args.test} test.")
        all_parsed_outbounds = filter_best_outbounds_by_protocol(all_parsed_outbounds)
        print(f"Total outbounds after filtering best per protocol: {len(all_parsed_outbounds)}")

    merged_config = replace_existing_outbounds(base_config_template.copy(), all_parsed_outbounds)
    try:
        save_config(merged_config, filepath=args.output)
    except Exception as e:
        print(f"Error writing to output file: {e}")

    for var, value in original_env.items():
        os.environ[var] = value

if __name__ == "__main__":
    main()
