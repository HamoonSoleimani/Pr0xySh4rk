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
import threading # Added for get_ident
from typing import Optional, List, Dict, Any, Tuple

# Import exceptions for newer requests/urllib3 if needed
try:
    from urllib3.exceptions import InsecureRequestWarning
    # Suppress only the single InsecureRequestWarning from urllib3 needed for self-signed certificates
    requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
except ImportError:
    # Fallback for older versions
    try:
        import requests.packages.urllib3
        requests.packages.urllib3.disable_warnings()
    except:
        pass

# Added imports for Retry/HTTPAdapter
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# --- Configuration from Second Script (for UDP test logic) ---
# Test against these websites (HTTP/HTTPS) - Keep original first script's HTTP targets
# TEST_URLS = [...] # Keep original first script's test URLs in measure_xray_latency_http
# Gather the best N working configs for each protocol
BEST_CONFIGS_LIMIT = 75
# Default Timeouts (in seconds) - Can be overridden by args
DEFAULT_TCP_TIMEOUT = 5
DEFAULT_HTTP_TIMEOUT = 8
DEFAULT_UDP_TIMEOUT = 3
# Protocol-specific timeouts (merged concept, used by get_protocol_timeout)
PROTOCOL_TIMEOUTS = {
    "ss": {"tcp": 6, "http": 10},       # Shadowsocks often needs more time
    "vless": {"tcp": 6, "http": 10},    # VLESS might need more time
    "vmess": {"tcp": 5, "http": 8},     # VMess standard timeout
    "tuic": {"tcp": 5, "http": 8},      # TUIC standard timeout
    "hysteria": {"tcp": 5, "http": 8},  # Hysteria standard timeout
    "hysteria2": {"tcp": 5, "http": 8}, # Hysteria2 standard timeout
    "hy2": {"tcp": 5, "http": 8},       # Hy2 standard timeout
    "warp": {"udp": 3},                 # WireGuard/WARP UDP timeout
    "wireguard": {"udp": 3}             # WireGuard UDP timeout
}


# --- Requirements ---
# Ensure you have a requirements.txt file with at least:
# requests
# urllib3
# PySocks

# --- Global Variables ---
total_outbounds_count = 0
completed_outbounds_count = 0
is_ctrl_c_pressed = False
# Global timeout variables to be set by args
TCP_TIMEOUT = DEFAULT_TCP_TIMEOUT
HTTP_TIMEOUT = DEFAULT_HTTP_TIMEOUT
UDP_TIMEOUT = DEFAULT_UDP_TIMEOUT

# --- Xray_core Implementation for Precise Delay Testing (Unchanged except minor log tweaks) ---
class XrayCore:
    def __init__(self):
        self.process = None
        self.config_file = None
        self.log_file = None  # Added for xray logs
        self.last_stderr = ""  # Store last stderr output

    def startFromJSON(self, json_config_string: str):
        # Create a temporary JSON configuration file for Xray-core
        self.config_file = tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json")
        # Create a temporary log file for Xray's stderr
        self.log_file = tempfile.NamedTemporaryFile(mode="r", delete=False, suffix=".log")
        try:
            # --- Add basic logging to the Xray config ---
            try:
                config_dict = json.loads(json_config_string)
                # Set log level - 'warning' is usually good, 'debug' for extreme detail
                config_dict.setdefault("log", {})["loglevel"] = "warning"
                json_config_string = json.dumps(config_dict)
            except json.JSONDecodeError:
                print("Warning: Could not parse JSON to inject log settings.")
            # --- End log config injection ---
            self.config_file.write(json_config_string)
            self.config_file.flush()
        finally:
            self.config_file.close()
        # Close the read handle for the log file so Popen can write to it
        self.log_file.close()
        print(f"Starting xray-core with config: {self.config_file.name}, logging stderr to: {self.log_file.name}")
        stderr_handle = None  # Initialize handle
        try:
            # Start the xray-core process, redirecting stderr to the log file
            stderr_handle = open(self.log_file.name, "w")
            self.process = subprocess.Popen(
                ["xray", "-config", self.config_file.name],
                stdout=subprocess.PIPE,  # Keep stdout if needed, or redirect too
                stderr=stderr_handle,    # Redirect stderr to our file
                preexec_fn=os.setsid if sys.platform != "win32" else None,
                bufsize=1,
                universal_newlines=True
            )
            # Wait a bit longer for xray-core to initialize properly
            time.sleep(3)
            if self.process.poll() is not None:
                stderr_handle.close()
                self._read_and_store_stderr()
                raise subprocess.SubprocessError(
                    f"xray-core exited immediately with code: {self.process.returncode}. Stderr:\n{self.last_stderr}"
                )
            print(f"xray-core started successfully (PID: {self.process.pid}).")
        except FileNotFoundError:
            print("Failed to start xray-core: 'xray' executable not found. Ensure it's in your PATH.")
            self.process = None
            if stderr_handle:
                stderr_handle.close()
        except subprocess.SubprocessError as e:
            print(f"Failed to start xray-core: {e}")
            self.process = None
            if stderr_handle and not stderr_handle.closed:
                stderr_handle.close()
        except Exception as e:
            print(f"Failed to start xray-core: {type(e).__name__}: {e}")
            self.process = None
            if stderr_handle and not stderr_handle.closed:
                stderr_handle.close()

    def _read_and_store_stderr(self):
        """Reads the content of the stderr log file."""
        if self.log_file and os.path.exists(self.log_file.name):
            try:
                with open(self.log_file.name, "r") as f:
                    self.last_stderr = f.read().strip()
                if self.last_stderr:
                    # Avoid printing excessive logs, just confirm length
                    print(f"--- Xray Log Content ({os.path.basename(self.log_file.name)}) stored (length: {len(self.last_stderr)}) ---")
                    # log_preview = self.last_stderr[:1000] + ('...' if len(self.last_stderr) > 1000 else '')
                    # print(f"--- Preview: {log_preview} ---") # Optional: uncomment for short preview
                else:
                    print(f"--- Xray Log ({os.path.basename(self.log_file.name)}) was empty ---")
            except Exception as e:
                print(f"Error reading xray log file {self.log_file.name}: {e}")
                self.last_stderr = f"Error reading log: {e}"
        else:
            # print(f"--- Xray Log file {self.log_file.name if self.log_file else 'N/A'} not found or inaccessible ---") # Reduced verbosity
            self.last_stderr = ""

    def stop(self):
        if self.process:
            # Close std err/out if needed
            #if self.process.stderr and not self.process.stderr.closed:
            #    self.process.stderr.close()
            #if self.process.stdout and not self.process.stdout.closed:
            #    self.process.stdout.close()

            print(f"Stopping xray-core process (PID: {self.process.pid}).")
            killed = False
            pgid = None
            try:
                # Attempt to get process group ID (works on Unix-like systems)
                if sys.platform != "win32":
                    pgid = os.getpgid(self.process.pid)
                    print(f"Sending SIGTERM to process group {pgid}...")
                    os.killpg(pgid, signal.SIGTERM)
                else:
                    # Fallback for Windows: use terminate()
                    print("Sending SIGTERM (terminate) to process...")
                    self.process.terminate()

                self.process.wait(timeout=5) # Wait for termination
                print("xray-core terminated gracefully.")
            except ProcessLookupError:
                print("xray-core process already exited.")
            except subprocess.TimeoutExpired:
                print("xray-core did not terminate gracefully after SIGTERM, sending SIGKILL...")
                killed = True
                try:
                    if pgid is not None and sys.platform != "win32":
                        os.killpg(pgid, signal.SIGKILL)
                    else: # Fallback for Windows or if getpgid failed
                         self.process.kill()

                    self.process.wait(timeout=5)
                    print(f"xray-core process {'group ' if pgid else ''}killed.")

                except ProcessLookupError:
                     print("xray-core process exited between SIGTERM and SIGKILL.")
                except subprocess.TimeoutExpired:
                    print(f"::error::Failed to confirm kill for xray-core process {'group ' if pgid else ''}after SIGKILL.")
                except Exception as ke:
                    print(f"::warning::Error during SIGKILL: {ke}")
            except AttributeError:
                # This might catch cases where getpgid is not available but wasn't Windows
                print("Process group termination attribute error, using terminate/kill fallback...")
                try:
                    self.process.terminate()
                    self.process.wait(timeout=5)
                    print("xray-core terminated.")
                except subprocess.TimeoutExpired:
                    print("xray-core did not terminate, killing...")
                    killed = True
                    self.process.kill()
                    try:
                        self.process.wait(timeout=5)
                        print("xray-core killed.")
                    except subprocess.TimeoutExpired:
                        print("::error::Failed to confirm kill for xray-core process.")
                    except Exception as ke2:
                        print(f"::warning::Error during fallback kill: {ke2}")
                except Exception as te:
                    print(f"Error during fallback terminate: {te}")
            except Exception as e:
                print(f"::warning::Error while stopping xray-core process: {type(e).__name__}: {e}")
            finally:
                self.process = None # Mark process as stopped

        # Read logs AFTER stopping attempts
        print("Reading final Xray logs...")
        self._read_and_store_stderr()

        # Cleanup temporary files
        if self.config_file:
            config_file_name = self.config_file.name
            try:
                if os.path.exists(config_file_name):
                    os.remove(config_file_name)
                    print(f"Removed temporary config file: {config_file_name}")
            except Exception as e:
                print(f"::warning::Failed to remove temporary config file {config_file_name}: {e}")
            finally:
                self.config_file = None
        if self.log_file:
            log_file_name = self.log_file.name
            try:
                # Ensure the file handle is closed before trying to remove
                if os.path.exists(log_file_name):
                    # Attempt to close handle if it's still open (shouldn't be, but defensively)
                    try:
                        if hasattr(self.log_file, 'close') and not self.log_file.closed:
                            self.log_file.close()
                    except: pass # Ignore errors closing
                    os.remove(log_file_name)
                    print(f"Removed temporary log file: {log_file_name}")
            except Exception as e:
                print(f"::warning::Failed to remove temporary log file {log_file_name}: {e}")
            finally:
                self.log_file = None


# --- Outbound Conversion (Revised for WireGuard/WARP to match needed fields for UDP test) ---
def convert_outbound_config(ob: Dict[str, Any]) -> Dict[str, Any]:
    protocol = ob.get("type", "").lower() # Handle original 'type' field
    if not protocol and "protocol" in ob:
        protocol = ob["protocol"].lower() # Handle potential existing 'protocol' field

    tag = ob.get("tag", "")
    # Ensure 'protocol' field exists in the output dictionary
    ob['protocol'] = protocol

    # --- VLESS ---
    if protocol == "vless":
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
                                "encryption": "none", # VLESS encryption is usually handled by TLS/Reality
                                "flow": ob.get("flow", "") # Include flow control if present
                            }
                        ]
                    }
                ]
            }
        }
        # Handle stream settings (transport)
        if "transport" in ob and isinstance(ob["transport"], dict):
            new_ob["streamSettings"] = ob["transport"]
        # Handle TLS/Reality settings
        if "tls" in ob and isinstance(ob["tls"], dict) and ob["tls"].get("enabled"):
            new_ob.setdefault("streamSettings", {})["security"] = "tls"
            tls_settings = {
                "serverName": ob["tls"].get("server_name", ob.get("server", "")),
                "allowInsecure": ob["tls"].get("insecure", False) # Default to secure
            }
            if ob["tls"].get("alpn"):
                 tls_settings["alpn"] = ob["tls"]["alpn"]

            # Handle Reality
            if ob["tls"].get("reality", {}).get("enabled"):
                 new_ob["streamSettings"]["security"] = "reality"
                 reality_settings = {
                     "serverName": tls_settings["serverName"], # Reality uses serverName from tlsSettings
                     "publicKey": ob["tls"]["reality"].get("public_key", ""),
                     "shortId": ob["tls"]["reality"].get("short_id", ""),
                 }
                 # Handle UTLS/Fingerprint within Reality
                 if ob["tls"].get("utls", {}).get("enabled"):
                     reality_settings["fingerprint"] = ob["tls"]["utls"].get("fingerprint", "chrome")
                 new_ob["streamSettings"]["realitySettings"] = reality_settings
                 # Xray docs suggest keeping serverName in tlsSettings too, even for Reality
                 new_ob.setdefault("streamSettings", {}).setdefault("tlsSettings", {})["serverName"] = tls_settings["serverName"]
                 # Add allowInsecure to tlsSettings if needed, Reality usually ignores it server-side?
                 new_ob.setdefault("streamSettings", {}).setdefault("tlsSettings", {})["allowInsecure"] = tls_settings["allowInsecure"]

            else: # Just regular TLS
                 new_ob.setdefault("streamSettings", {})["tlsSettings"] = tls_settings

        return new_ob

    # --- VMESS ---
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
                                "security": ob.get("security", "auto") # security inside users is cipher
                            }
                        ]
                    }
                ]
            }
        }
        if "transport" in ob and isinstance(ob["transport"], dict):
            new_ob["streamSettings"] = ob["transport"]
        if "tls" in ob and isinstance(ob["tls"], dict) and ob["tls"].get("enabled"):
            new_ob.setdefault("streamSettings", {})["security"] = "tls"
            tls_settings = {
                "serverName": ob["tls"].get("server_name", ob.get("server", "")),
                "allowInsecure": ob["tls"].get("insecure", False) # Default to secure
            }
            if ob["tls"].get("alpn"):
                 tls_settings["alpn"] = ob["tls"]["alpn"]
            new_ob.setdefault("streamSettings", {})["tlsSettings"] = tls_settings
        return new_ob

    # --- SHADOWSOCKS ---
    elif protocol == "shadowsocks":
        new_ob = {
            "protocol": "shadowsocks",
            "tag": tag,
            "settings": {
                "servers": [
                    {
                        "address": ob.get("server", ""),
                        "port": int(ob.get("server_port", 443)),
                        "method": ob.get("method", "aes-256-gcm"),
                        "password": ob.get("password", "")
                        # Xray structure puts method/password here, not in a 'users' list for SS server
                    }
                ]
            }
        }
        # Handle SS Plugin (obfs, v2ray-plugin)
        if "plugin" in ob:
             plugin_opts_str = ""
             if "plugin_opts" in ob and isinstance(ob["plugin_opts"], dict):
                  # Format options based on plugin type if needed, otherwise join
                  opts = ob["plugin_opts"]
                  plugin_opts_parts = []
                  for k, v in opts.items():
                       # Handle boolean flags for v2ray-plugin (like 'tls')
                       if ob["plugin"] == "v2ray-plugin" and isinstance(v, bool):
                            if v: plugin_opts_parts.append(k) # Add key only if true
                       else:
                            plugin_opts_parts.append(f"{k}={v}")
                  plugin_opts_str = ";".join(plugin_opts_parts)


             new_ob["settings"]["servers"][0]["plugin"] = ob["plugin"]
             if plugin_opts_str:
                  # Use 'pluginOpts' key for Xray
                  new_ob["settings"]["servers"][0]["pluginOpts"] = plugin_opts_str
        return new_ob

    # --- TUIC ---
    elif protocol == "tuic":
        new_ob = {
            "protocol": "tuic", # Use tuic v5 protocol name for newer Xray
            "tag": tag,
            "settings": {
                "server": ob.get("server", ""),
                "port": int(ob.get("server_port", 443)),
                "uuid": ob.get("uuid", ""),
                "password": ob.get("password", ""),
                "congestion_control": ob.get("congestion_control", "bbr"),
                "udp_relay_mode": ob.get("udp_relay_mode", "native"), # or "quic"
                "alpn": ob.get("tls", {}).get("alpn", ["h3"]) # ALPN is usually needed for TUIC
            },
             "streamSettings": {
                 "network": "udp", # TUIC is UDP based
                 "security": "tls", # TUIC requires TLS
                 "tlsSettings": {
                     "serverName": ob.get("tls", {}).get("server_name", ob.get("server", "")),
                     "allowInsecure": ob.get("tls", {}).get("insecure", True) # TUIC often used with self-signed/insecure
                     # Fingerprint/UTLS not typically used with TUIC directly in Xray config?
                 }
             }
        }
        return new_ob

    # --- HYSTERIA/HYSTERIA2/HY2 ---
    elif protocol in ("hysteria", "hysteria2", "hy2"):
        # Consolidate to "hysteria2" as it's the current protocol name in Xray
        new_ob = {
            "protocol": "hysteria2",
            "tag": tag,
            "settings": {
                "server": ob.get("server", ""),
                "port": int(ob.get("server_port", 443)),
                "password": ob.get("password", ""),
                # Add other Hy2 specific settings if parsed (up_mbps, down_mbps etc.) - assuming basic for now
            },
            "streamSettings": {
                "network": "udp", # Hysteria2 is UDP based
                "security": "tls", # Hysteria2 requires TLS for auth (unless insecure mode)
                "tlsSettings": {
                    "serverName": ob.get("tls", {}).get("server_name", ob.get("server", "")),
                    "allowInsecure": ob.get("tls", {}).get("insecure", True), # Often used with self-signed/insecure
                    "alpn": ob.get("tls", {}).get("alpn", ["h3"]) # Typically uses h3 ALPN
                    # Fingerprint/UTLS not typically used with Hy2 directly in Xray config?
                }
            }
        }
        # Handle OBFS for Hysteria2
        if "obfs" in ob and isinstance(ob["obfs"], dict):
             # Ensure type and password exist before adding
             obfs_type = ob["obfs"].get("type")
             obfs_password = ob["obfs"].get("password")
             if obfs_type and obfs_password is not None: # Password can be empty string
                 new_ob["settings"]["obfs"] = {
                     "type": obfs_type, # e.g., "salamander"
                     "password": obfs_password
                 }
        return new_ob

    # --- WIRE GUARD / WARP (Revised for UDP test needs, NO Xray conversion) ---
    elif protocol in ("wireguard", "warp"):
        # This conversion is now primarily to hold data for the UDP test,
        # NOT for generating an Xray outbound config section for WG.
        new_ob = {
            "protocol": "wireguard", # Use consistent protocol name
            "tag": tag,
            "server": ob.get("server", ""),
            "server_port": int(ob.get("server_port", 0)), # Port is crucial
            # Include fields needed by udp_test_outbound_first_script or for identification
            "private_key": ob.get("private_key", ""), # Keep for potential future use / identification
            "peer_public_key": ob.get("peer_public_key", ""), # Keep for potential future use / identification
            "address": ob.get("local_address", ()), # Keep as tuple for potential future use / identification
            "mtu": ob.get("mtu"), # Keep for potential future use / identification
            "reserved": ob.get("reserved", ()), # Keep as tuple for potential future use / identification
            "original_config": ob.get("original_config", "") # Store the original link if available
            # DO NOT add 'settings' or 'streamSettings' in Xray format
        }
        return new_ob

    # --- Other/Unknown Protocols ---
    else:
        print(f"Warning: Passing through unknown/unhandled protocol type '{protocol}' with minimal conversion for tag '{tag}'.")
        # Create a basic structure, ensuring 'protocol' and 'tag' are present
        new_ob = dict(ob) # Make a copy
        new_ob["protocol"] = protocol # Ensure 'protocol' field
        new_ob["tag"] = tag # Ensure 'tag' field
        if "type" in new_ob:
            del new_ob["type"] # Remove old 'type' field if it exists
        return new_ob

# --- Helper Functions for Xray-core and proxychains (Unchanged) ---
def create_xray_config(outbound_config: dict) -> dict:
    # This function is used for NON-WireGuard protocols
    return {
        "log": {
            "loglevel": "warning" # Default log level
        },
        "dns": {
            "servers": [
                "1.1.1.1", # Cloudflare DNS
                "8.8.8.8", # Google DNS
                "localhost" # Use system resolver as fallback
            ]
        },
        "inbounds": [
            {
                "protocol": "socks",
                "port": 1080, # Standard SOCKS port
                "listen": "127.0.0.1", # Listen only on localhost
                "settings": {
                    "auth": "noauth", # No authentication
                    "udp": True,      # Enable UDP forwarding
                    "ip": "127.0.0.1" # Respond with localhost IP
                },
                "tag": "socks-in" # Tag for routing rules
            }
        ],
        "outbounds": [
            outbound_config, # The actual outbound proxy being tested
            {
                "protocol": "freedom", # Direct connection outbound
                "tag": "direct"
            },
            {
                "protocol": "blackhole", # Block connection outbound
                "tag": "block"
            }
        ],
        "routing": {
            "rules": [
                {
                    "type": "field",
                    "inboundTag": ["socks-in"], # Apply to traffic from our SOCKS inbound
                    "outboundTag": outbound_config.get("tag", "proxy") # Route to the primary outbound
                },
                 # Optional: Add rules for DNS, private IPs, etc. if needed
                 #{
                 #    "type": "field",
                 #    "port": 53,
                 #    "outboundTag": "direct" # Route DNS directly
                 #},
                 #{
                 #    "type": "field",
                 #    "ip": ["geoip:private"],
                 #    "outboundTag": "direct" # Route private IPs directly
                 #}
            ]
        }
    }

def create_proxychains_config(proxy: str) -> Optional[str]: # Added Optional return type
    # Parses proxy string and creates a temporary proxychains config file
    host = None
    port = None
    proxy_type = None
    try:
        if proxy.startswith("socks5://"):
            proxy_netloc = proxy[len("socks5://"):]
            host, port_str = (proxy_netloc.split(":", 1) + ["1080"])[:2]
            port = int(port_str)
            proxy_type = "socks5"
        elif proxy.startswith("socks4://"):
            proxy_netloc = proxy[len("socks4://"):]
            host, port_str = (proxy_netloc.split(":", 1) + ["1080"])[:2]
            port = int(port_str)
            proxy_type = "socks4"
        elif proxy.startswith("http://") or proxy.startswith("https://"):
             parsed_p = urllib.parse.urlparse(proxy)
             host = parsed_p.hostname
             port = parsed_p.port or (443 if parsed_p.scheme == 'https' else 80)
             proxy_type = "http" # Assuming http, proxychains handles HTTPS via CONNECT
        else:
            # Default to SOCKS5 on localhost:1080 if format is unrecognized
            host, port = "127.0.0.1", 1080
            proxy_type = "socks5"
            print(f"Warning: Unrecognized proxy format '{proxy}', defaulting to {proxy_type}://{host}:{port}.")
    except ValueError:
        print(f"Warning: Invalid port in proxy string '{proxy}', defaulting to socks5://127.0.0.1:1080.")
        host, port, proxy_type = "127.0.0.1", 1080, "socks5"
    except Exception as e:
        print(f"Error parsing proxy string '{proxy}': {e}. Defaulting to socks5://127.0.0.1:1080.")
        host, port, proxy_type = "127.0.0.1", 1080, "socks5"


    # Basic proxychains configuration
    config_content = f"""strict_chain
proxy_dns
remote_dns_subnet 224
tcp_read_time_out 15000
tcp_connect_time_out 10000 # Slightly increased connect timeout

[ProxyList]
# type host port [user pass]
{proxy_type} {host} {port}
"""
    # Create a temporary file for the config
    try:
        # Use 'with' statement for automatic closing
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".conf") as tmp:
            tmp.write(config_content)
            tmp.flush()
            return tmp.name # Return the path of the created file
    except Exception as e:
        print(f"::error::Failed to create temporary proxychains config: {e}")
        return None # Return None on failure


def measure_latency_icmp_proxychains(target_host: str = "www.google.com",
                                     proxy: str = "socks5://127.0.0.1:1080",
                                     count: int = 3,
                                     timeout: int = 15) -> float:
    # Measures ICMP latency using fping through proxychains
    config_path = create_proxychains_config(proxy)
    if not config_path: # Handle case where config creation failed
         print("ICMP Test Error: Failed to create proxychains config file.")
         return float('inf')

    # Calculate per-packet timeout for fping, ensure minimum 500ms
    per_packet_timeout_ms = max(500, int((timeout * 1000) / count)) if count > 0 else 5000
    # Construct the fping command with sudo
    command = ["proxychains4", "-f", config_path, "sudo", "fping",
               "-c", str(count), # Number of pings
               "-t", str(per_packet_timeout_ms), # Per-packet timeout in ms
               "-q", # Quiet mode (only summary and errors to stderr)
               "-A", # Show address, not hostname
               target_host]
    print(f"Attempting ICMP test: {' '.join(command)}")
    try:
        # Set a total process timeout slightly longer than the expected fping duration
        process_timeout = timeout + 10 # Add buffer for proxychains/sudo overhead
        result = subprocess.run(command, capture_output=True, text=True,
                                  timeout=process_timeout, check=False) # Don't check=True, handle errors manually

        # Check stderr first for password prompts or proxychains errors
        stderr_lower = result.stderr.lower()
        if "sudo: a password is required" in stderr_lower or "authentication failure" in stderr_lower:
             print("ICMP Test Error: sudo requires a password or authentication failed.")
             return float('inf')
        if "[proxychains] preloading" not in stderr_lower and result.returncode != 0:
             # If proxychains didn't even load, it's likely a setup issue
             print(f"ICMP Test Error: proxychains preloading failed? Stderr: {result.stderr.strip()[:200]}...")
             return float('inf')


        # fping returns non-zero if packets are lost or host is unreachable
        if result.returncode != 0:
             print(f"ICMP Latency measurement command failed/timed out (exit code {result.returncode}). Timeout={process_timeout}s")
             if result.stderr:
                 # Look for specific errors, but avoid flooding logs
                 stderr_summary = result.stderr.strip()
                 if len(stderr_summary) > 500: stderr_summary = stderr_summary[:500] + "..."
                 print(f"stderr summary:\n{stderr_summary}")
             return float('inf')

        # fping -q summary is usually on stderr
        process_output = result.stderr
        # Regex to find the min/avg/max line
        match = re.search(r"min/avg/max = ([\d\.]+)/([\d\.]+)/([\d\.]+)", process_output)
        if match:
            min_rtt, avg_rtt, max_rtt = map(float, match.groups())
            print(f"ICMP test successful: min={min_rtt:.2f}ms, avg={avg_rtt:.2f} ms, max={max_rtt:.2f}ms")
            return avg_rtt # Return average latency
        else:
            # Fallback check if summary format changes or is mixed with stdout
            match_stdout = re.search(r"min/avg/max = ([\d\.]+)/([\d\.]+)/([\d\.]+)", result.stdout)
            if match_stdout:
                 min_rtt, avg_rtt, max_rtt = map(float, match_stdout.groups())
                 print(f"ICMP test successful (parsed from stdout): avg={avg_rtt:.2f} ms")
                 return avg_rtt

            print(f"Failed to parse fping summary output from stderr/stdout.")
            if process_output: print(f"(stderr: {process_output.strip()[:200]}...)")
            if result.stdout: print(f"(stdout: {result.stdout.strip()[:200]}...)")
            return float('inf')

    except subprocess.TimeoutExpired:
        print(f"ICMP Latency measurement process timed out after {process_timeout}s.")
        return float('inf')
    except FileNotFoundError as e:
         print(f"ICMP Latency measurement error: Command not found ({e.filename}). Ensure proxychains4, sudo, fping are installed and in PATH.")
         return float('inf')
    except Exception as e:
        print(f"ICMP Latency measurement unexpected error: {type(e).__name__}: {e}")
        return float('inf')
    finally:
        # Clean up the temporary proxychains config file
        try:
            if config_path and os.path.exists(config_path):
                os.remove(config_path)
        except OSError as e:
            print(f"::warning:: Failed to remove proxychains config {config_path}: {e}")

def measure_xray_latency_http(proxy: str, timeout: int = 15) -> float:
    # Measures HTTP(S) latency through the provided SOCKS proxy (assumed to be Xray)
    test_urls = [
        "http://detectportal.firefox.com/success.txt", # Lightweight HTTP
        "http://neverssl.com", # Plain HTTP, no redirects expected
        "https://www.google.com/generate_204", # Google HTTPS 204
        "https://www.cloudflare.com/cdn-cgi/trace", # Cloudflare HTTPS trace
    ]
    session = requests.Session()
    if proxy:
        session.proxies = {'http': proxy, 'https': proxy}
    session.trust_env = False # Ignore environment proxies

    # Configure retries for robustness (using imported Retry class)
    retries = Retry(total=2, backoff_factor=0.1, status_forcelist=[500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retries)
    session.mount('http://', adapter)
    session.mount('https://', adapter)


    def fetch_url(url: str) -> Tuple[Optional[float], str]:
        # Fetches a single URL and returns latency or None
        try:
            start_time = time.time()
            # Use stream=False and read content to ensure connection is fully tested
            response = session.get(url, timeout=timeout, allow_redirects=True, stream=False, verify=False) # verify=False for potential proxy MITM
            response.raise_for_status() # Check for HTTP errors (4xx, 5xx)
            _ = response.content # Read content to ensure data transfer
            latency = (time.time() - start_time) * 1000
            return latency, url
        # Specific exceptions first
        except requests.exceptions.SSLError as e:
            print(f"HTTP Fail: {url} via {proxy} - SSL Error: {e}")
        except requests.exceptions.ProxyError as e:
            print(f"HTTP Fail: {url} via {proxy} - Proxy Error: {e}")
        except requests.exceptions.ConnectTimeout as e:
             print(f"HTTP Fail: {url} via {proxy} - Connect Timeout: {e}")
        except requests.exceptions.ReadTimeout as e:
             print(f"HTTP Fail: {url} via {proxy} - Read Timeout: {e}")
        except requests.exceptions.ConnectionError as e:
             print(f"HTTP Fail: {url} via {proxy} - Connection Error: {e}")
        except requests.exceptions.HTTPError as e:
             print(f"HTTP Fail: {url} via {proxy} - HTTP Error Status: {e.response.status_code}")
        # General request exception
        except requests.exceptions.RequestException as e:
            print(f"HTTP Fail: {url} via {proxy} - General Request Error: {type(e).__name__}: {e}")
        # Other unexpected errors
        except Exception as e:
            print(f"HTTP Fail: {url} via {proxy} - Unexpected Error: {type(e).__name__}: {e}")

        return None, url # Return None on failure

    latencies = []
    # Use ThreadPoolExecutor for concurrent requests
    # Adjust num_workers based on number of URLs, max 4 seems reasonable
    num_workers = min(max(1, len(test_urls)), 4)
    with concurrent.futures.ThreadPoolExecutor(max_workers=num_workers) as executor:
        # Submit all fetch tasks
        futures = {executor.submit(fetch_url, url): url for url in test_urls}
        results = []
        try:
            # Collect results as they complete
            for future in concurrent.futures.as_completed(futures):
                results.append(future.result())
        except Exception as e:
             print(f"Error processing HTTP test futures for {proxy}: {e}") # Should not happen with proper future handling

    # Process results
    for latency, url in results:
         if latency is not None:
             latencies.append(latency)

    if latencies:
        best_latency = min(latencies)
        avg_latency = sum(latencies) / len(latencies)
        success_rate = (len(latencies) / len(test_urls)) * 100
        print(f"HTTP Result for {proxy}: Best={best_latency:.0f}ms, Avg={avg_latency:.0f}ms ({len(latencies)}/{len(test_urls)} OK ~ {success_rate:.0f}%)")
        return best_latency # Return the best latency achieved
    else:
        print(f"HTTP Result for {proxy}: All {len(test_urls)} test attempts failed.")
        return float('inf')

def measure_latency_precise(proxy: str,
                            target_host: str = "www.google.com",
                            count: int = 3,
                            timeout: int = 15) -> float:
    # Tries ICMP ping via proxychains first, falls back to HTTP test
    has_proxychains = shutil.which("proxychains4")
    has_fping = shutil.which("fping")
    has_sudo = shutil.which("sudo")

    # Check if dependencies for ICMP test are met
    if has_proxychains and has_fping and has_sudo:
        print("Dependencies found (proxychains4, fping, sudo). Attempting ICMP test via sudo...")
        latency = measure_latency_icmp_proxychains(target_host, proxy, count, timeout)
        if latency != float('inf'):
            return latency # Return ICMP latency if successful
        else:
            print("ICMP latency measurement failed or timed out, falling back to HTTP test.")
    else:
        # Log which dependencies are missing
        missing = [dep for dep, present in [("proxychains4", has_proxychains), ("fping", has_fping), ("sudo", has_sudo)] if not present]
        print(f"Skipping ICMP test, missing dependencies: {', '.join(missing)}. Falling back to HTTP test.")

    # Fallback to HTTP test
    print("Performing HTTP latency test...")
    # Use the HTTP timeout value set globally/by args
    global HTTP_TIMEOUT
    return measure_xray_latency_http(proxy, timeout=int(HTTP_TIMEOUT)) # Ensure timeout is int


# --- Protocol Timeout Helper ---
def get_protocol_timeout(protocol: str, test_type: str, default_timeout: float) -> float:
    """Gets the timeout for a specific protocol and test type, or returns the default."""
    protocol = protocol.lower()
    test_type = test_type.lower()
    if protocol in PROTOCOL_TIMEOUTS and test_type in PROTOCOL_TIMEOUTS[protocol]:
        return float(PROTOCOL_TIMEOUTS[protocol][test_type])
    return float(default_timeout)


# --- Revised: WireGuard/WARP UDP Testing Procedure (Adapted from Second Script) ---
async def udp_test_outbound_first_script(ob: Dict[str, Any]) -> None:
    """
    Performs a basic UDP test suitable for WireGuard/WARP, storing result in ob['udp_delay'].
    Adapted from the second script's logic.
    """
    tag = ob.get("tag", "unknown_tag")
    server = ob.get("server")
    port = ob.get("server_port")
    protocol = ob.get("protocol", "unknown")
    result_key = "udp_delay"
    ob[result_key] = float('inf') # Default to failure

    # Get protocol-specific timeout using global UDP_TIMEOUT as default
    timeout = get_protocol_timeout(protocol, "udp", UDP_TIMEOUT)

    # --- Special Handling from Second Script ---
    is_wireguard_protocol = protocol in ("wireguard", "warp")
    if not server or not port:
        if is_wireguard_protocol:
            # Check if it's a potentially valid config despite missing server/port
            # Use the presence of a tag and private key as a proxy for validity.
            if tag != "unknown_tag" and ob.get("private_key"):
                 print(f"UDP Test ({tag}): WG/WARP config seems valid but missing server/port. Assigning default delay 100.0 ms.")
                 ob[result_key] = 100.0 # Assign default delay as per second script's logic
                 return # Exit successfully with default delay
            else:
                 print(f"UDP Test ({tag}): Invalid WG/WARP config (missing server/port/key?). Setting delay=inf.")
                 return # Exit, already set to inf
        else:
             print(f"UDP Test ({tag}): Missing server or port. Setting delay=inf.")
             return # Exit, already set to inf
    # --- End Special Handling ---

    # Ensure port is an integer
    try:
        port = int(port)
    except (ValueError, TypeError):
        print(f"UDP Test ({tag}): Invalid port value '{port}'. Setting delay=inf.")
        return

    # Resolve hostname to IP address
    resolved_ip = None
    try:
        loop = asyncio.get_running_loop()
        # Use loop.getaddrinfo for async DNS resolution
        addr_info = await loop.getaddrinfo(server, port, proto=socket.IPPROTO_UDP)
        if not addr_info:
            raise socket.gaierror(f"No address info found for {server}")
        resolved_ip = addr_info[0][4][0] # Get the IP address from the first result
    except socket.gaierror as e:
        print(f"UDP Test ({tag}): DNS resolution failed for {server}: {e}")
        return # Exit, delay is inf
    except Exception as e:
        print(f"UDP Test ({tag}): Unexpected error during DNS resolution: {type(e).__name__}: {e}")
        return # Exit, delay is inf

    # Perform UDP send test
    transport = None
    start_time = loop.time()
    try:
        print(f"UDP Test ({tag}): Starting UDP test for {server}:{port} ({resolved_ip}) with timeout {timeout:.1f}s")
        # Create datagram endpoint - this establishes the socket
        connect_future = loop.create_datagram_endpoint(
            lambda: asyncio.DatagramProtocol(), remote_addr=(resolved_ip, port)
        )
        # Wait for the endpoint creation with timeout
        transport, protocol_instance = await asyncio.wait_for(connect_future, timeout=timeout)

        # Send a small UDP packet
        transport.sendto(b'\x00\x00\x00\x00') # Send 4 null bytes

        # Wait briefly - This doesn't confirm receipt, just that send didn't fail immediately.
        # This matches the heuristic used in both original scripts.
        await asyncio.sleep(0.1)

        # Calculate delay based on successful send attempt
        delay = (loop.time() - start_time) * 1000
        ob[result_key] = delay
        print(f"UDP Test ({tag}): Success (send initiated), measured delay = {delay:.2f} ms")

    except asyncio.TimeoutError:
        print(f"UDP Test ({tag}): Timed out after {timeout:.1f}s during endpoint creation or send.")
        ob[result_key] = float('inf')
    except OSError as e:
         # Handle potential OS errors like Network Unreachable, Permission Denied
         print(f"UDP Test ({tag}): OS Error connecting/sending to {resolved_ip}:{port} - {e}")
         ob[result_key] = float('inf')
    except Exception as e:
        print(f"UDP Test ({tag}): Error during UDP operation: {type(e).__name__}: {e}")
        ob[result_key] = float('inf')
    finally:
        # Ensure the transport is closed
        if transport:
            try:
                transport.close()
            except Exception as e_close:
                 print(f"UDP Test ({tag}): Error closing transport: {e_close}")

# Sync wrapper for the UDP test
def udp_test_outbound_first_script_sync(ob: Dict[str, Any]) -> None:
    """Synchronous wrapper for the async UDP test."""
    global is_ctrl_c_pressed
    if is_ctrl_c_pressed:
         ob["udp_delay"] = float('inf')
         return
    try:
        # Run the async function in a new event loop
        asyncio.run(udp_test_outbound_first_script(ob))
    except RuntimeError as e:
        # Handle potential event loop issues (e.g., running inside another loop)
        if "cannot run event loop while another loop is running" in str(e):
             print(f"UDP Test ({ob.get('tag', 'unknown')}): Error - cannot run nested event loops. Skipping test.")
        else:
             print(f"UDP Test ({ob.get('tag', 'unknown')}): Runtime Error - {e}")
        ob["udp_delay"] = float('inf')
    except Exception as e:
        print(f"UDP Test ({ob.get('tag', 'unknown')}): Exception in sync wrapper - {type(e).__name__}: {e}")
        ob["udp_delay"] = float('inf')


# --- Revised real_delay_test_outbound ---
def real_delay_test_outbound(outbound_config: dict) -> float:
    """
    Performs the 'real' delay test using XrayCore for supported protocols.
    For WireGuard/WARP, this function now does nothing, as the test is handled
    by udp_test_outbound_first_script_sync triggered from single_test_pass.
    """
    tag = outbound_config.get("tag", "unknown_tag")
    protocol = outbound_config.get("protocol", "").lower()

    # --- MODIFICATION: Skip Xray for WireGuard/WARP ---
    if protocol in ("wireguard", "warp"):
        print(f"--- Real delay test for tag: {tag} ({protocol}) ---")
        print(f"Protocol {protocol} uses UDP test procedure, skipping XrayCore setup.")
        # Ensure xray_delay remains infinite or unset for filtering logic.
        outbound_config["xray_delay"] = float('inf')
        print(f"--- Finished real delay test (skipped Xray) for tag: {tag} ---")
        return float('inf') # Return inf as Xray test wasn't performed
    # --- END MODIFICATION ---

    # --- Original Xray logic for other protocols ---
    converted = None
    config = None
    json_config_str = None
    xr = None
    latency = float('inf')
    error_message = ""
    xray_stderr_log = ""

    try:
        print(f"--- Starting real delay test for tag: {tag} ({protocol}) ---")
        converted = convert_outbound_config(outbound_config)
        if not converted or not converted.get("protocol"):
            raise ValueError("Failed to convert outbound config or protocol missing.")

        # Ensure the tag from the original config is used in the converted one
        converted["tag"] = tag

        # Start XrayCore instance
        xr = XrayCore()
        config = create_xray_config(converted)
        try:
            json_config_str = json.dumps(config)
        except TypeError as e:
             raise ValueError(f"Failed to serialize Xray config to JSON: {e}. Config: {config}") from e

        xr.startFromJSON(json_config_str)

        if xr.process is None:
            # Get stderr from XrayCore instance if available
            xray_stderr_log = xr.last_stderr
            raise RuntimeError(f"XrayCore failed to start for tag {tag}.")

        # Perform latency test through the Xray SOCKS proxy
        proxy = "socks5://127.0.0.1:1080"
        # Use global timeouts set by args
        global TCP_TIMEOUT, HTTP_TIMEOUT
        combined_timeout = max(TCP_TIMEOUT, HTTP_TIMEOUT, 15) # Use a reasonable combined timeout
        latency = measure_latency_precise(proxy, target_host="www.google.com", count=3, timeout=int(combined_timeout))

        if latency == float('inf'):
            error_message = f"Latency test failed for tag {tag}."
            print(error_message)
        else:
            print(f"+++ Real delay test for {tag} SUCCEEDED: {latency:.2f} ms +++")

    except Exception as e:
        error_message = f"Error during real delay test for {tag}: {type(e).__name__}: {e}"
        print(f"::error:: {error_message}") # Print as error
        # Print traceback for unexpected errors during testing phase
        # import traceback
        # traceback.print_exc()
        latency = float('inf')
    finally:
        if xr is not None:
            print(f"--- Stopping xray-core for tag: {tag} ---")
            xr.stop()
            xray_stderr_log = xr.last_stderr # Capture logs after stopping
            if latency == float('inf'):
                print(f"--- Real delay test for tag: {tag} FAILED ---")
                if error_message and "XrayCore failed to start" not in error_message: # Avoid duplicate message
                    print(f"Failure reason: {error_message}")
                # Avoid printing huge logs automatically, maybe just length
                if xray_stderr_log:
                     print(f"Captured Xray stderr log (length: {len(xray_stderr_log)}). Check logs for details.")
                     # print(f"Captured Xray stderr log:\n{xray_stderr_log[:1000]}{'...' if len(xray_stderr_log)>1000 else ''}")


        # Store the latency result in the original outbound_config dict
        # Use 'xray_delay' key consistent with original script's intent for this function
        outbound_config["xray_delay"] = latency
        print(f"--- Finished real delay test for tag: {tag} ---")
        # Return the measured latency (or inf)
        return latency


# --- Normalization (Unchanged) ---
def normalize_config(config: Dict[str, Any]) -> Dict[str, Any]:
    """Ensure consistent 'protocol' key instead of 'type'."""
    if "inbounds" in config and isinstance(config["inbounds"], list):
        for inbound in config["inbounds"]:
            if isinstance(inbound, dict) and "type" in inbound:
                inbound["protocol"] = inbound.pop("type")
    if "outbounds" in config and isinstance(config["outbounds"], list):
        for outbound in config["outbounds"]:
            if isinstance(outbound, dict):
                if "type" in outbound:
                    outbound["protocol"] = outbound.pop("type")
                # Remove deprecated 'detour' field if present
                if "detour" in outbound:
                    outbound.pop("detour")
    return config

# --- Signal Handling (Unchanged) ---
def signal_handler(sig, frame):
    """Handles Ctrl+C interrupts gracefully."""
    global is_ctrl_c_pressed
    if not is_ctrl_c_pressed:
        print("\nCtrl+C detected. Requesting graceful stop... (Press again to force exit)")
        is_ctrl_c_pressed = True
        # Note: Further actions to stop threads might be needed depending on implementation
    else:
        print("Forcing exit due to repeated Ctrl+C.")
        # Terminate potentially hanging child processes (like xray) before exiting
        # This is complex to do robustly here, better handled in main cleanup
        sys.exit(1) # Force exit

# --- Tag Generation (Unchanged) ---
def generate_unique_tag(all_tags: set) -> str:
    """Generates a unique tag string."""
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


# --- Fetching, Parsing, Deduplication (Largely Unchanged, minor logging tweaks) ---
def fetch_content(url: str, proxy: Optional[str] = None) -> Optional[str]:
    """Fetches content from a URL, optionally using a proxy."""
    session = requests.Session()
    proxies = {"http": proxy, "https": proxy} if proxy else None
    session.trust_env = False # Ignore environment proxies for consistency
    # Corrected thread ID fetching
    thread_id = threading.get_ident() # Get thread ID using threading module

    if proxies:
        print(f"Thread {thread_id}: Fetching {url} using proxy: {proxy}")
    else:
        print(f"Thread {thread_id}: Fetching {url} directly")

    fetched = False
    content = None
    try:
        # Use global HTTP timeout
        global HTTP_TIMEOUT
        response = session.get(url, timeout=HTTP_TIMEOUT, proxies=proxies, allow_redirects=True, verify=False) # verify=False common for subs
        response.raise_for_status() # Check for HTTP errors
        # Attempt to decode content, trying common encodings
        try:
            content = response.content.decode('utf-8')
        except UnicodeDecodeError:
            try:
                 content = response.content.decode('latin-1')
                 print(f"Thread {thread_id}: Decoded content from {url} using latin-1.")
            except UnicodeDecodeError:
                 print(f"Thread {thread_id}: Failed to decode content from {url} using utf-8 or latin-1.")
                 content = None # Fail if decoding doesn't work
        if content is not None:
             fetched = True
    except requests.exceptions.Timeout:
         print(f"Thread {thread_id}: Timeout fetching URL {url} after {HTTP_TIMEOUT}s")
    except requests.exceptions.RequestException as e:
        print(f"Thread {thread_id}: Error fetching URL {url}{' via proxy ' + proxy if proxy else ''}: {type(e).__name__}: {e}")
    except Exception as e:
         print(f"Thread {thread_id}: Unexpected error fetching URL {url}: {type(e).__name__}: {e}")
    finally:
        # Clean up session? Not strictly necessary here.
        session.close()

    return content

# Note: parse_warp_single and parse_warp_line are NOT needed as WG/WARP conversion is simplified
# The primary parsing happens in parse_config_url1_2

def parse_config_url1_2(content: str, all_tags: set) -> List[Dict[str, Any]]:
    """Parses various config formats (Base64, JSON, line-by-line URIs)."""
    outbounds = []
    # Corrected thread ID fetching
    thread_id = threading.get_ident() # Get thread ID using threading module

    # 1. Try Base64 decoding first
    is_base64 = False
    try:
        # Basic check: might be base64 if it's long and contains valid chars
        if len(content) > 20 and re.match(r'^[a-zA-Z0-9+/=\s\r\n]*$', content.strip()):
             # More robust check: try decoding
             stripped_content = content.strip().replace('\n', '').replace('\r', '').replace(' ', '')
             missing_padding = len(stripped_content) % 4
             if missing_padding:
                 stripped_content += '=' * (4 - missing_padding)
             decoded_bytes = base64.urlsafe_b64decode(stripped_content) # Use urlsafe_b64decode
             decoded_content = decoded_bytes.decode('utf-8')
             # If decoding succeeds and result looks like multiple lines, assume it was base64
             if '\n' in decoded_content or decoded_content.startswith(('ss://', 'vmess://', 'vless://')):
                 print(f"Thread {thread_id}: Content appears to be base64 encoded, decoded.")
                 content = decoded_content # Replace original content with decoded version
                 is_base64 = True
    except (ValueError, UnicodeDecodeError, base64.binascii.Error):
        # Not valid base64 or failed decode, proceed as plain text
        pass
    except Exception as e_b64:
        # Log unexpected errors during base64 decode attempt, but continue
        print(f"Thread {thread_id}: Unexpected error during base64 decode attempt: {type(e_b64).__name__}: {e_b64}")
        pass

    # 2. Try parsing as a full JSON configuration
    # Remove comments first (lines starting with // or #)
    json_content_lines = [line for line in content.splitlines() if not line.strip().startswith( ('//', '#') )]
    json_content_str = "\n".join(json_content_lines)
    # Check if it looks like a JSON object
    if json_content_str.strip().startswith('{') and json_content_str.strip().endswith('}'):
        try:
            config = json.loads(json_content_str)
            # Check if it has the expected structure (e.g., 'outbounds' list)
            if isinstance(config, dict) and "outbounds" in config and isinstance(config["outbounds"], list):
                print(f"Thread {thread_id}: Parsed as full JSON config with {len(config['outbounds'])} outbounds.")
                parsed_count = 0
                for i, ob in enumerate(config["outbounds"]):
                    if not isinstance(ob, dict): continue # Skip non-dictionary items

                    # Ensure unique tag
                    original_tag = ob.get("tag", f"json_ob_{i+1}")
                    final_tag = original_tag
                    if original_tag in all_tags:
                         final_tag = generate_unique_tag(all_tags)
                    ob["tag"] = final_tag
                    all_tags.add(final_tag)

                    # Normalize 'type' to 'protocol'
                    if "type" in ob and "protocol" not in ob:
                         ob["protocol"] = ob.pop("type")

                    # Basic validation: check if protocol exists
                    if ob.get("protocol"):
                        # Add source URL info
                        # ob["source"] = source_url # This needs to be passed into the function
                        outbounds.append(ob)
                        parsed_count += 1
                    else:
                        print(f"Thread {thread_id}: Skipping outbound in JSON due to missing protocol: {ob.get('tag')}")

                print(f"Thread {thread_id}: Added {parsed_count} valid outbounds from JSON structure.")
                # If successfully parsed as JSON, return the results
                return outbounds
            else:
                 # Looks like JSON but structure is wrong (e.g., missing 'outbounds')
                 print(f"Thread {thread_id}: Content looked like JSON, but structure was invalid ('outbounds' list missing or not a list). Proceeding line-by-line.")
        except json.JSONDecodeError:
             # Failed to parse as JSON, proceed to line-by-line parsing
             print(f"Thread {thread_id}: Content not valid JSON, proceeding with line-by-line parsing.")
             pass # Continue to line-by-line parsing
        except Exception as e_json:
             print(f"Thread {thread_id}: Unexpected error during JSON parsing: {type(e_json).__name__}. Proceeding line-by-line.")
             pass # Continue to line-by-line parsing


    # 3. Parse line by line (assuming URI format)
    print(f"Thread {thread_id}: Parsing content line by line...")
    lines_processed = 0
    protocols_found = {}
    for line_num, line in enumerate(content.splitlines()):
        line = line.strip()
        if not line or line.startswith(("#", "//")):
            continue # Skip empty lines and comments

        lines_processed += 1
        parsed_ob: Optional[Dict[str, Any]] = None
        protocol_scheme = ""

        try:
            # --- ShadowSocks (ss://) ---
            if line.startswith("ss://"):
                protocol_scheme = "shadowsocks"
                parsed_ob = {}
                frag = "" # Fragment part for the tag

                # Extract base64/userinfo part and server part
                link_part = line[len("ss://"):]
                if "#" in link_part:
                    link_part, frag = link_part.split("#", 1)

                user_info = ""
                server_part = ""
                if "@" in link_part:
                    user_info_encoded, server_part = link_part.split("@", 1)
                    try:
                         # Decode user info (method:password)
                         padding = "=" * (-len(user_info_encoded) % 4)
                         user_info = base64.urlsafe_b64decode(user_info_encoded + padding).decode("utf-8")
                    except Exception as e_user:
                         print(f"Thread {thread_id} Line {line_num+1}: SS UserInfo decode error: {e_user} - Info: {user_info_encoded}")
                         continue # Skip this line
                else:
                    # Handle format where user info might be part of the base64 string before '@' is missing
                    server_part = link_part # Assume the whole part is server or combined base64

                # Extract method and password
                method, password = (user_info.split(":", 1) + [None])[:2] if user_info else (None, None)

                # Fallback if user info wasn't directly after ss://
                if not method or password is None:
                     try:
                          # Try decoding the whole link part before server specifier '?' or '#'
                          potential_b64 = link_part.split("?")[0].split("#")[0]
                          # Check if '@' is present AFTER decoding
                          full_decoded_b64 = base64.urlsafe_b64decode(potential_b64 + "=" * (-len(potential_b64) % 4)).decode("utf-8")
                          if "@" in full_decoded_b64:
                              user_info_decoded, server_part_decoded = full_decoded_b64.split("@", 1)
                              method, password = (user_info_decoded.split(":", 1) + [None])[:2]
                              # Reconstruct server_part if it was part of the base64
                              server_part = server_part_decoded # Assume server_part follows decoded user info
                          else:
                              # If still no user info, cannot parse reliably
                              print(f"Thread {thread_id} Line {line_num+1}: Skipping SS link with undecipherable format (no user info): {line[:80]}...")
                              continue
                     except Exception:
                          # Decoding failed or format is wrong
                          print(f"Thread {thread_id} Line {line_num+1}: Skipping SS link, failed to parse user/server: {line[:80]}...")
                          continue

                # Extract server and port
                server = ""
                port = 443 # Default port
                # Server part might contain plugin options after '?'
                server_address_part = server_part.split("?")[0]
                # Handle IPv6 addresses in brackets and port
                match_ipv6 = re.match(r"\[([a-fA-F0-9:]+)\]:(\d+)", server_address_part)
                match_host_port = re.match(r"([^:]+):(\d+)", server_address_part)

                if match_ipv6:
                    server = match_ipv6.group(1)
                    port = int(match_ipv6.group(2))
                elif ":" in server_address_part and not server_address_part.startswith("["): # Basic IPv4:port check
                    try:
                        maybe_host, maybe_port = server_address_part.rsplit(":", 1)
                        port_num = int(maybe_port)
                        server = maybe_host
                        port = port_num
                    except ValueError: # Port wasn't an int, assume host only
                        server = server_address_part
                else:
                    # Assume only hostname/IP, use default port
                    server = server_address_part
                    # print(f"Warning: Port not found for SS server '{server}', using default {port}.")

                if not server:
                    print(f"Thread {thread_id} Line {line_num+1}: Skipping SS link, could not determine server address: {line[:80]}...")
                    continue

                # Get tag from fragment
                tag_name = urllib.parse.unquote(frag).strip() if frag else generate_unique_tag(all_tags)
                final_tag = tag_name
                if tag_name in all_tags: final_tag = generate_unique_tag(all_tags)
                all_tags.add(final_tag)

                parsed_ob = {
                    "protocol": "shadowsocks",
                    "tag": final_tag,
                    "server": server,
                    "server_port": port,
                    "method": method or "aes-256-gcm", # Default method if missing
                    "password": password or ""
                }

                # Extract plugin info if present
                plugin_match = re.search(r"\?(.*)", server_part)
                if plugin_match:
                    plugin_query = plugin_match.group(1)
                    plugin_params = urllib.parse.parse_qs(plugin_query)
                    if "plugin" in plugin_params:
                         plugin_full_def = plugin_params["plugin"][0]
                         parts = plugin_full_def.split(';')
                         plugin_name = parts[0]
                         # Common plugins: obfs-local (simple-obfs), v2ray-plugin
                         if plugin_name in ("obfs-local", "simple-obfs", "v2ray-plugin"):
                              parsed_ob["plugin"] = plugin_name
                              plugin_opts = {}
                              for part in parts[1:]:
                                   if '=' in part:
                                        key, val = part.split('=', 1)
                                        plugin_opts[key.strip()] = val.strip()
                              if plugin_opts:
                                   parsed_ob["plugin_opts"] = plugin_opts
                         else:
                              print(f"Thread {thread_id} Line {line_num+1}: Unsupported SS plugin '{plugin_name}' found.")

            # --- VLESS (vless://) ---
            elif line.startswith("vless://"):
                protocol_scheme = "vless"
                parsed_url = urllib.parse.urlparse(line)
                uuid = parsed_url.username
                if not uuid: raise ValueError("UUID missing")

                # Extract server and port (handle IPv6)
                server = parsed_url.hostname
                port = parsed_url.port or 443 # Default port if missing
                if not server: raise ValueError("Server address missing")

                # Parse query parameters
                params = urllib.parse.parse_qs(parsed_url.query)

                # Get tag from fragment
                frag = parsed_url.fragment
                tag_name = urllib.parse.unquote(frag).strip() if frag else generate_unique_tag(all_tags)
                final_tag = tag_name
                if tag_name in all_tags: final_tag = generate_unique_tag(all_tags)
                all_tags.add(final_tag)

                parsed_ob = {
                    "protocol": "vless",
                    "tag": final_tag,
                    "server": server,
                    "server_port": port,
                    "uuid": uuid,
                    "flow": params.get("flow", [""])[0],
                    # Packet encoding not standard in Xray config, skip? params.get("packetEncoding", [""])[0]
                }

                # Transport settings
                transport_type = params.get("type", [""])[0] # ws, grpc, httpupgrade, etc.
                if transport_type:
                     transport_settings: Dict[str, Any] = {"type": transport_type}
                     if transport_type == "ws":
                         transport_settings["path"] = params.get("path", ["/"])[0]
                         # Host header might be in 'host' param or SNI
                         ws_host = params.get("host", [params.get("sni", [server])[0]])[0]
                         transport_settings["headers"] = {"Host": ws_host}
                     elif transport_type == "grpc":
                         transport_settings["serviceName"] = params.get("serviceName", [""])[0]
                         # Add 'multiMode' if needed? Typically default 'gun' is used
                     # Add other transport types if needed (e.g., httpupgrade)
                     parsed_ob["transport"] = transport_settings

                # Security settings (TLS / Reality)
                security = params.get("security", ["none"])[0]
                if security in ("tls", "reality"):
                     parsed_ob["tls"] = {"enabled": True}
                     # SNI is crucial, default to host param or server address
                     sni = params.get("sni", [params.get("host", [server])[0]])[0]
                     parsed_ob["tls"]["server_name"] = sni
                     # Allow insecure? Default false
                     allow_insecure = params.get("allowInsecure", ["0"])[0] in ("1", "true")
                     parsed_ob["tls"]["insecure"] = allow_insecure
                     # ALPN
                     alpn_list = [a for a in params.get("alpn", [""])[0].split(',') if a]
                     if alpn_list:
                          parsed_ob["tls"]["alpn"] = alpn_list

                     if security == "reality":
                         parsed_ob["tls"]["reality"] = {
                             "enabled": True,
                             "public_key": params.get("pbk", [""])[0],
                             "short_id": params.get("sid", [""])[0]
                             # spiderX / fingerprint is handled under utls
                         }
                         # UTLS / Fingerprint (often used with Reality)
                         fp = params.get("fp", [""])[0]
                         if fp and fp != "none":
                              parsed_ob["tls"]["utls"] = {"enabled": True, "fingerprint": fp}
                     # else: just TLS settings apply

            # --- VMESS (vmess://) ---
            elif line.startswith("vmess://"):
                protocol_scheme = "vmess"
                encoded_part = line[len("vmess://"):].strip()
                # Sometimes URL encoded, sometimes not, try decoding just in case
                try:
                    maybe_decoded = urllib.parse.unquote(encoded_part)
                    encoded_part = maybe_decoded
                except Exception:
                     pass # Ignore if unquoting fails

                try:
                    # Decode the base64 part
                    padding = "=" * (-len(encoded_part) % 4)
                    decoded_json = base64.b64decode(encoded_part + padding).decode("utf-8")
                    vmess_data = json.loads(decoded_json)
                except Exception as e_vmess_b64:
                     print(f"Thread {thread_id} Line {line_num+1}: VMess Base64 decode/JSON parse error: {e_vmess_b64} - Data: {encoded_part[:80]}...")
                     continue # Skip this line

                # Extract fields from the decoded JSON
                tag_name = vmess_data.get("ps", "").strip() or generate_unique_tag(all_tags) # 'ps' is the tag/remark
                final_tag = tag_name
                if tag_name in all_tags: final_tag = generate_unique_tag(all_tags)
                all_tags.add(final_tag)

                server_addr = vmess_data.get("add", "")
                server_port = int(vmess_data.get("port", 443))
                user_id = vmess_data.get("id", "")
                alter_id = int(vmess_data.get("aid", 0))
                # Security (cipher method) - use 'scy' if present, else 'security'
                vmess_security = vmess_data.get("scy", vmess_data.get("security", "auto"))

                if not server_addr or not user_id:
                     raise ValueError("Missing server address or UUID in VMess JSON")

                parsed_ob = {
                    "protocol": "vmess",
                    "tag": final_tag,
                    "server": server_addr,
                    "server_port": server_port,
                    "uuid": user_id,
                    "alter_id": alter_id,
                    "security": vmess_security,
                }

                # Network type (net) and associated settings
                net_type = vmess_data.get("net", "tcp") # tcp, ws, grpc, etc.
                host = vmess_data.get("host", server_addr) # Host header or SNI target
                path = vmess_data.get("path", "/") # Path for ws, serviceName for grpc
                if net_type != "tcp":
                    transport_settings: Dict[str, Any] = {"type": net_type}
                    if net_type == "ws":
                        transport_settings["path"] = path
                        transport_settings["headers"] = {"Host": host}
                    elif net_type == "grpc":
                        # gRPC mode (gun/multi) - default 'gun' usually works
                        # grpc_mode = vmess_data.get("mode", "gun") # Could be 'multi'
                        transport_settings["serviceName"] = vmess_data.get("serviceName", path if path != "/" else "")
                        # transport_settings["multiMode"] = (grpc_mode == "multi") # Xray uses bool? check docs
                    # Add other network types if needed
                    parsed_ob["transport"] = transport_settings

                # TLS settings ('tls' field: "tls" or empty/none)
                tls_type = vmess_data.get("tls", "")
                if tls_type == "tls":
                     tls_settings = {
                         "enabled": True,
                         "server_name": vmess_data.get("sni", host), # Use 'sni' if present, else 'host'
                         # allowInsecure: vmess often uses 'verify_certificate' boolean? Or 'skip-cert-verify'? Assume 'allowInsecure' mapping
                         "insecure": vmess_data.get("allowInsecure", vmess_data.get("skip-cert-verify", False)) # Default secure
                     }
                     # ALPN
                     alpn_list = [a for a in vmess_data.get("alpn", "").split(',') if a]
                     if alpn_list:
                          tls_settings["alpn"] = alpn_list
                     parsed_ob["tls"] = tls_settings

            # --- TUIC (tuic://) ---
            elif line.startswith("tuic://"):
                protocol_scheme = "tuic"
                parsed_url = urllib.parse.urlparse(line)
                user_pass = parsed_url.username or "" # UUID:PASSWORD
                if ':' not in user_pass: raise ValueError("Missing UUID:PASSWORD")
                uuid, password = user_pass.split(":", 1)

                server = parsed_url.hostname
                port = parsed_url.port or 443
                if not server: raise ValueError("Server address missing")

                params = urllib.parse.parse_qs(parsed_url.query)
                frag = parsed_url.fragment
                tag_name = urllib.parse.unquote(frag).strip() if frag else generate_unique_tag(all_tags)
                final_tag = tag_name
                if tag_name in all_tags: final_tag = generate_unique_tag(all_tags)
                all_tags.add(final_tag)

                # TUIC v5 uses 'protocol: tuic'
                parsed_ob = {
                    "protocol": "tuic",
                    "tag": final_tag,
                    "server": server,
                    "server_port": port,
                    "uuid": uuid,
                    "password": password,
                    "congestion_control": params.get("congestion_control", ["bbr"])[0],
                    "udp_relay_mode": params.get("udp_relay_mode", ["native"])[0],
                    "tls": { # TUIC requires TLS, parse related params
                        "enabled": True,
                        "server_name": params.get("sni", [server])[0],
                        "insecure": params.get("allow_insecure", ["1"])[0] in ("1", "true"), # Default insecure=True common
                        "alpn": [a for a in params.get("alpn", ["h3"])[0].split(',') if a] # Default 'h3'
                    }
                }

            # --- WireGuard/WARP (wireguard://, warp://) ---
            elif line.startswith(("wireguard://", "warp://")):
                protocol_scheme = "wireguard" # Treat both as wireguard
                parsed_url = urllib.parse.urlparse(line)

                # Server and Port are crucial for the UDP test
                server = parsed_url.hostname
                port = parsed_url.port
                # WARP often uses 'engage.cloudflareclient.com:2408' implicitly
                # Use default only if server/port is truly missing from URL
                if not server and "warp://" in line: server = "engage.cloudflareclient.com" # Default WARP endpoint
                if not port and "warp://" in line: port = 2408 # Default WARP port

                if not server or not port:
                     print(f"Thread {thread_id} Line {line_num+1}: Skipping WG/WARP link - missing server or port: {line[:80]}")
                     continue # Cannot test without server/port

                # Extract parameters from query string
                params = urllib.parse.parse_qs(parsed_url.query)

                # Get tag from fragment
                frag = parsed_url.fragment
                tag_name = urllib.parse.unquote(frag).strip() if frag else generate_unique_tag(all_tags)
                final_tag = tag_name
                if tag_name in all_tags: final_tag = generate_unique_tag(all_tags)
                all_tags.add(final_tag)

                # Extract key info (private key is often in userinfo for warp://)
                private_key = parsed_url.username or params.get("secret", [""])[0] # Check userinfo and 'secret' param
                public_key = params.get("publickey", params.get("pk", [""])[0])
                peer_public_key = params.get("peer_public_key", [public_key])[0] # Use 'publickey' or 'pk' as peer key

                # Local address(es) - Corrected parsing
                addr_param_list = params.get("address", params.get("ip", [])) # Get the list for 'address' or 'ip'
                local_address_list = []
                if addr_param_list: # Check if the list is not empty
                    addr_string = addr_param_list[0] # Get the first string element
                    if isinstance(addr_string, str): # Make sure it's a string before splitting
                         local_address_list = [addr.strip() for addr in addr_string.split(',') if addr.strip()]

                # Reserved field
                reserved_str = params.get("reserved", [""])[0]
                reserved_list = []
                if reserved_str:
                    try:
                         # Assuming comma-separated list of numbers
                         reserved_list = [int(r.strip()) for r in reserved_str.split(',') if r.strip().isdigit()]
                    except Exception:
                         print(f"Thread {thread_id} Line {line_num+1}: Failed to parse WG reserved field: {reserved_str}")
                         reserved_list = []

                # MTU
                mtu = None
                try:
                    mtu_str = params.get("mtu", ["0"])[0]
                    mtu_val = int(mtu_str)
                    if mtu_val > 0: mtu = mtu_val
                except ValueError:
                     pass # Ignore invalid MTU

                # Create the dictionary, converting lists to tuples for hashability
                parsed_ob = {
                    "protocol": "wireguard",
                    "tag": final_tag,
                    "server": server,
                    "server_port": port,
                    "private_key": private_key,
                    "peer_public_key": peer_public_key,
                    "local_address": tuple(local_address_list) if local_address_list else (), # Store as tuple
                    "reserved": tuple(reserved_list) if reserved_list else (), # Store as tuple
                    "mtu": mtu,
                    "original_config": line # Store original link
                }


            # --- Hysteria / Hysteria2 / Hy2 (hysteria://, hysteria2://, hy2://) ---
            elif line.startswith(("hysteria://", "hysteria2://", "hy2://")):
                protocol_scheme = "hysteria2" # Treat all as Hysteria 2
                parsed_url = urllib.parse.urlparse(line)
                params = urllib.parse.parse_qs(parsed_url.query) # Parse params early

                # Auth is typically password (in userinfo) or auth_str param
                password = parsed_url.username if parsed_url.username is not None else params.get("auth", [""])[0] # Use username or 'auth' param

                server = parsed_url.hostname
                port = parsed_url.port or 443
                if not server: raise ValueError("Server address missing")

                frag = parsed_url.fragment
                tag_name = urllib.parse.unquote(frag).strip() if frag else generate_unique_tag(all_tags)
                final_tag = tag_name
                if tag_name in all_tags: final_tag = generate_unique_tag(all_tags)
                all_tags.add(final_tag)

                parsed_ob = {
                    "protocol": "hysteria2",
                    "tag": final_tag,
                    "server": server,
                    "server_port": port,
                    "password": password,
                    # Speed params (optional)
                    #"up_mbps": int(params.get("upmbps", ["10"])[0]),
                    #"down_mbps": int(params.get("downmbps", ["50"])[0]),
                    "tls": { # Hysteria requires TLS settings
                        "enabled": True,
                        "server_name": params.get("sni", [server])[0],
                        "insecure": params.get("insecure", ["1"])[0] in ("1", "true"), # Default insecure=True common
                        "alpn": [a for a in params.get("alpn", ["h3"])[0].split(',') if a] # Default 'h3'
                    }
                }

                # OBFS (obfs type and password)
                obfs_type = params.get("obfs", [""])[0]
                if obfs_type:
                      obfs_password = params.get("obfs-password", params.get("obfs_password", [""])[0])
                      parsed_ob["obfs"] = {
                          "type": obfs_type,
                          "password": obfs_password
                      }

            # --- End of Protocol Parsing ---

            # If an outbound was successfully parsed
            if parsed_ob and isinstance(parsed_ob, dict) and parsed_ob.get("protocol"):
                 protocol = parsed_ob["protocol"]
                 protocols_found[protocol] = protocols_found.get(protocol, 0) + 1
                 # Add source_url here if needed
                 outbounds.append(parsed_ob)

        except Exception as e:
            print(f"Thread {thread_id} Line {line_num+1}: Error parsing link ({protocol_scheme or 'unknown'}): {type(e).__name__}: {e} - Link: {line[:100]}...")
            # Optionally add traceback here for debugging
            # import traceback
            # traceback.print_exc()
            parsed_ob = None # Ensure failed parse doesn't add anything

    # --- Post-parsing summary ---
    print(f"Thread {thread_id}: Finished line-by-line parsing. Processed {lines_processed} lines.")
    if protocols_found:
         print(f"Thread {thread_id}: Protocols found: {protocols_found}")
    else:
         print(f"Thread {thread_id}: No known proxy protocols found in line-by-line parse.")

    return outbounds


def deduplicate_outbounds(outbounds: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Deduplicates outbounds based on protocol, server, port, and primary ID/key."""
    unique: Dict[Tuple[Any, ...], Dict[str, Any]] = {}
    duplicates_found = 0

    def get_key(ob: Dict[str, Any]) -> Optional[Tuple[Any, ...]]:
        # Generates a tuple key for deduplication
        typ = ob.get("protocol", "").lower()
        server = str(ob.get("server", "")).lower().strip()
        port = ob.get("server_port", "")

        # Basic check: need protocol, server, and port for meaningful comparison
        if not typ or not server or not port:
            return ("nokey", id(ob))

        try:
            port = int(port)
        except (ValueError, TypeError):
            return ("badport", id(ob))

        key_base = (typ, server, port)

        # Add protocol-specific identifiers to the key
        try:
            if typ == "shadowsocks":
                plugin = ob.get("plugin", "")
                plugin_opts_str = str(sorted(ob.get("plugin_opts", {}).items())) if ob.get("plugin_opts") else ""
                return key_base + (ob.get("method", ""), ob.get("password", ""), plugin, plugin_opts_str)
            elif typ == "vless":
                 return key_base + (ob.get("uuid", ""),)
            elif typ == "vmess":
                 return key_base + (ob.get("uuid", ""),)
            elif typ == "tuic":
                 return key_base + (ob.get("uuid", ""),)
            elif typ == "hysteria2":
                 return key_base + (ob.get("password", ""),)

            # Robust WireGuard Key Handling
            elif typ == "wireguard":
                peer_key = ob.get("peer_public_key", "")
                private_key = ob.get("private_key", "")
                identifier_val = peer_key if peer_key else private_key

                if identifier_val is None or isinstance(identifier_val, (list, dict)):
                    # print(f"Warning: Invalid WG key identifier type ({type(identifier_val)}) for tag '{ob.get('tag', 'N/A')}'. Using object ID.")
                    return ("wg_nokey", id(ob))
                else:
                    identifier_str = str(identifier_val).strip() # Convert to string and strip whitespace
                    if not identifier_str:
                        # print(f"Warning: Empty WG key identifier for tag '{ob.get('tag', 'N/A')}'. Using object ID.")
                        return ("wg_nokey_empty", id(ob))
                    else:
                        return key_base + (identifier_str,) # Add the guaranteed non-empty string identifier

            else: # Unknown protocols
                return key_base
        except Exception as e:
             print(f"Warning: Error generating dedupe key for tag '{ob.get('tag', 'N/A')}': {e}. Treating as unique.")
             return ("key_error", id(ob))

    # Iterate through outbounds and add to dict based on key
    processed_count = 0
    for ob in outbounds:
        key = get_key(ob)
        processed_count += 1
        if key is None: # Should not happen with current get_key logic
             unique[("unkeyed", id(ob))] = ob
             continue

        if key not in unique:
            unique[key] = ob
        else:
            duplicates_found += 1
            pass

    if duplicates_found > 0:
        print(f"Deduplication removed {duplicates_found} duplicate configurations (out of {processed_count} processed).")
    else:
        print(f"No duplicate configurations found based on key criteria (processed {processed_count}).")

    return list(unique.values())

# --- Sorting and Filtering Functions (Revised for WG/WARP UDP delay) ---

def get_sort_key(o: Dict[str, Any], tests_run_list: List[str]) -> float:
    """
    Calculates a sort key (delay) for an outbound configuration,
    prioritizing test results based on tests run and protocol.
    Lower is better. Handles WireGuard/WARP specifically.
    """
    proto = o.get("protocol", "").lower()
    delay = float('inf') # Default to infinite delay (worst)

    # --- WireGuard/WARP Specific Logic ---
    if proto in ("wireguard", "warp"):
        # Primary delay source for WG/WARP is the UDP test result
        udp_d = o.get("udp_delay", float('inf'))
        if udp_d != float('inf'):
            delay = udp_d
        # Fallback (less likely if UDP test runs): check xray_delay (which should be inf)
        else:
            xray_d = o.get("xray_delay", float('inf'))
            if xray_d != float('inf'):
                 delay = xray_d + 10000 # Penalize if UDP failed but Xray somehow worked (error case)

    # --- Logic for Other Protocols ---
    else:
        # Get delays from all relevant tests
        real_d = o.get("xray_delay", float('inf'))
        http_d = o.get("http_delay", float('inf'))
        tcp_d = o.get("tcp_delay", float('inf'))

        # Prioritize based on the tests that were run
        if 'real' in tests_run_list and real_d != float('inf'):
            delay = real_d
        elif 'http' in tests_run_list and http_d != float('inf'):
            delay = http_d
        elif 'tcp' in tests_run_list and tcp_d != float('inf'):
            delay = tcp_d

        # Penalize if 'real' test was run but failed, yet a fallback test succeeded
        if 'real' in tests_run_list and real_d == float('inf') and delay != float('inf'):
            delay += 5000 # Add significant penalty (5 seconds)

    # Ensure delay is always float
    return float(delay)


def diversify_outbounds_by_protocol(protocol_outbounds: List[Dict[str, Any]],
                                     tests_run: List[str],
                                     limit: int = BEST_CONFIGS_LIMIT) -> List[Dict[str, Any]]:
    """
    Selects up to 'limit' outbounds for a specific protocol, attempting to
    diversify based on source URL while prioritizing lower delays.
    """
    if len(protocol_outbounds) <= limit:
        return protocol_outbounds

    groups: Dict[str, List[Dict[str, Any]]] = {}
    for ob in protocol_outbounds:
        src = ob.get("source", "unknown_source")
        groups.setdefault(src, []).append(ob)

    for src in groups:
        groups[src].sort(key=lambda o: get_sort_key(o, tests_run))

    diversified: List[Dict[str, Any]] = []
    source_keys = list(groups.keys())
    current_source_index = 0
    processed_in_round = True

    while len(diversified) < limit and processed_in_round:
        processed_in_round = False
        processed_sources_this_round = 0

        while processed_sources_this_round < len(source_keys) and len(diversified) < limit:
             source_key = source_keys[current_source_index]
             if groups[source_key]:
                 diversified.append(groups[source_key].pop(0))
                 processed_in_round = True
             current_source_index = (current_source_index + 1) % len(source_keys)
             processed_sources_this_round += 1

        if not processed_in_round:
            break

    print(f"Diversified protocol group: Selected {len(diversified)} outbounds from {len(protocol_outbounds)} based on source diversity and delay.")
    return diversified

def filter_best_outbounds_by_protocol(outbounds: List[Dict[str, Any]], tests_run: List[str]) -> List[Dict[str, Any]]:
    """
    Filters outbounds that passed the required tests, then groups them by protocol,
    sorts by delay, and applies diversification and limits.
    """
    protocols: Dict[str, List[Dict[str, Any]]] = {}
    total_passed_initial_filter = 0

    print(f"Filtering best outbounds based on tests run: {tests_run}")

    for ob in outbounds:
        typ = ob.get("protocol", "").lower()
        if not typ: continue

        passed = True
        # Determine which tests *should* have run for this protocol based on tests_run
        required_tests_passed = True
        if typ in ("wireguard", "warp"):
            wg_test_ran = any(t in tests_run for t in ['udp', 'real', 'tcp+http', 'udp+real', 'http+real', 'tcp+real', 'tcp+http+real'])
            if wg_test_ran and ob.get("udp_delay", float('inf')) == float('inf'):
                required_tests_passed = False
        else: # Other protocols
            if 'tcp' in tests_run and ob.get("tcp_delay", float('inf')) == float('inf'):
                required_tests_passed = False
            if 'http' in tests_run and ob.get("http_delay", float('inf')) == float('inf'):
                required_tests_passed = False
            if 'real' in tests_run and ob.get("xray_delay", float('inf')) == float('inf'):
                required_tests_passed = False

        if required_tests_passed:
            protocols.setdefault(typ, []).append(ob)
            total_passed_initial_filter += 1

    print(f"Total outbounds passed initial test filter: {total_passed_initial_filter}")

    final_filtered: List[Dict[str, Any]] = []
    # Use a consistent sorting approach across all protocols before diversification
    all_passed_outbounds_sorted = []
    for typ, obs_list in protocols.items():
        all_passed_outbounds_sorted.extend(obs_list)

    # Sort ALL passed outbounds globally first
    all_passed_outbounds_sorted.sort(key=lambda o: get_sort_key(o, tests_run))

    # Re-group after global sort
    sorted_protocols: Dict[str, List[Dict[str, Any]]] = {}
    for ob in all_passed_outbounds_sorted:
         typ = ob.get("protocol", "").lower()
         sorted_protocols.setdefault(typ, []).append(ob)


    # Now apply diversification and limit per protocol group
    for typ, obs_list in sorted_protocols.items():
        print(f"Processing protocol: {typ} ({len(obs_list)} passed initial filter)")
        if not obs_list: continue

        # Apply diversification and limit to the globally sorted list for this protocol
        diversified_limited = diversify_outbounds_by_protocol(obs_list, tests_run, limit=BEST_CONFIGS_LIMIT)
        final_filtered.extend(diversified_limited)
        print(f" -> Selected {len(diversified_limited)} for protocol {typ} after diversification/limit.")

    # Final sort of the combined diversified list
    final_filtered.sort(key=lambda o: get_sort_key(o, tests_run))

    return final_filtered


# --- Config Replacement Logic (Largely Unchanged from Original First Script) ---
def replace_existing_outbounds(base_config: Dict[str, Any], new_outbounds: List[Dict]) -> Dict:
    """Replaces outbounds in a base Xray config JSON, updating selectors."""
    existing_selector_outbounds = []
    existing_urltest_outbounds = []
    preserved_outbounds = []

    selector_tag = "select"
    urltest_tag = "auto"

    essential_tags = {"direct", "block"}

    for outbound in base_config.get("outbounds", []):
        tag = outbound.get("tag")
        protocol = outbound.get("protocol")

        if protocol == "selector":
            selector_tag = tag
            existing_selector_outbounds = outbound.get("outbounds", [])
            preserved_outbounds.append(outbound)
        elif protocol == "urltest":
            urltest_tag = tag
            existing_urltest_outbounds = outbound.get("outbounds", [])
            preserved_outbounds.append(outbound)
        elif tag in essential_tags:
             preserved_outbounds.append(outbound)

    new_tags = {ob["tag"] for ob in new_outbounds}

    final_outbounds = []
    final_outbounds.extend(new_outbounds)

    preserved_tags_added = set()
    for po in preserved_outbounds:
         p_tag = po.get("tag")
         if p_tag not in new_tags and p_tag not in preserved_tags_added:
              final_outbounds.append(po)
              preserved_tags_added.add(p_tag)


    updated_proxy_list = sorted(list(new_tags))
    updated_selector_options = sorted(list(new_tags))
    updated_urltest_options = sorted(list(new_tags))

    if any(ob.get("tag") == urltest_tag for ob in final_outbounds):
         if urltest_tag not in updated_selector_options:
              updated_selector_options.insert(0, urltest_tag)

    if "direct" not in updated_selector_options:
         updated_selector_options.append("direct")

    selector_found = False
    urltest_found = False

    for ob in final_outbounds:
         tag = ob.get("tag")
         protocol = ob.get("protocol")

         if tag == selector_tag and protocol == "selector":
             ob["outbounds"] = updated_selector_options
             ob["default"] = urltest_tag if urltest_tag in updated_selector_options else \
                             (updated_proxy_list[0] if updated_proxy_list else "direct")
             selector_found = True
         elif tag == urltest_tag and protocol == "urltest":
              ob["outbounds"] = updated_urltest_options
              ob["url"] = ob.get("url", "https://clients3.google.com/generate_204")
              ob["interval"] = ob.get("interval", "10m0s")
              urltest_found = True

    if not selector_found:
        print(f"Adding default selector outbound with tag '{selector_tag}'.")
        final_outbounds.append({
            "protocol": "selector",
            "tag": selector_tag,
            "outbounds": updated_selector_options,
            "default": urltest_tag if urltest_found else (updated_proxy_list[0] if updated_proxy_list else "direct")
        })

    if not urltest_found and updated_urltest_options:
        print(f"Adding default urltest outbound with tag '{urltest_tag}'.")
        final_outbounds.append({
            "protocol": "urltest",
            "tag": urltest_tag,
            "outbounds": updated_urltest_options,
            "url": "https://clients3.google.com/generate_204",
            "interval": "10m0s"
        })

    base_config["outbounds"] = final_outbounds
    return base_config

# --- Basic Delay Tests (TCP, HTTP) - Kept from Original First Script (UDP handled separately) ---
async def tcp_test_outbound(ob: Dict[str, Any]) -> None:
    """Performs a basic TCP connection test to the outbound's server:port."""
    tag = ob.get("tag", "unknown_tag")
    server = ob.get("server")
    port = ob.get("server_port")
    protocol = ob.get("protocol", "unknown")
    result_key = "tcp_delay"
    ob[result_key] = float('inf') # Default to failure

    if not server or not port:
        return

    timeout = get_protocol_timeout(protocol, "tcp", TCP_TIMEOUT)

    loop = asyncio.get_running_loop()
    start_time = loop.time()
    writer = None
    resolved_ip = None
    try:
        try:
            addr_info = await loop.getaddrinfo(server, port, proto=socket.IPPROTO_TCP)
            if not addr_info: raise socket.gaierror(f"No address info found for {server}")
            resolved_ip = addr_info[0][4][0]
            target_port = addr_info[0][4][1]
        except socket.gaierror as dns_error:
             return

        conn_future = asyncio.open_connection(resolved_ip, target_port)
        reader, writer = await asyncio.wait_for(conn_future, timeout=timeout)

        delay = (loop.time() - start_time) * 1000
        ob[result_key] = delay

    except asyncio.TimeoutError:
        pass
    except OSError as e:
        pass
    except Exception as e:
         print(f"TCP Test ({tag}): Unexpected Error - {type(e).__name__}: {e}")
         pass
    finally:
        if writer:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

async def http_delay_test_outbound(ob: Dict[str, Any], proxy_for_http_test: Optional[str], repetitions: int) -> None:
    """
    Performs basic HTTP/S latency tests DIRECTLY to target URLs (or via test proxy if provided).
    """
    tag = ob.get("tag", "unknown_tag")
    server = ob.get("server")
    port = ob.get("server_port")
    protocol = ob.get("protocol", "unknown")
    result_key = "http_delay"
    ob[result_key] = float('inf')

    test_urls = [
        "http://detectportal.firefox.com/success.txt",
        "http://neverssl.com",
        "https://www.google.com/generate_204",
    ]

    timeout = get_protocol_timeout(protocol, "http", HTTP_TIMEOUT)

    session = requests.Session()
    session.trust_env = False
    if proxy_for_http_test:
         session.proxies = {'http': proxy_for_http_test, 'https': proxy_for_http_test}

    successful_latencies = []
    loop = asyncio.get_running_loop()

    async def fetch_http(url: str) -> Optional[float]:
        """Async helper to fetch a single URL using requests in executor."""
        start_time = time.time()
        try:
            response = await loop.run_in_executor(
                None,
                lambda: session.get(url, timeout=timeout, allow_redirects=False, verify=False, stream=False)
            )
            response.raise_for_status()
            _ = response.content
            elapsed = (time.time() - start_time) * 1000
            return elapsed
        except requests.exceptions.RequestException as e:
            return None
        except Exception as e:
            print(f"HTTP Test ({tag}): Error during request for {url} - {type(e).__name__}: {e}")
            return None

    all_results: List[Optional[float]] = []
    total_attempts = 0
    for _ in range(repetitions):
        if is_ctrl_c_pressed: break
        tasks = [fetch_http(url) for url in test_urls]
        results_this_rep = await asyncio.gather(*tasks, return_exceptions=False)
        all_results.extend(results_this_rep)
        total_attempts += len(test_urls)

    session.close()

    successful_latencies = [t for t in all_results if t is not None]

    if successful_latencies:
        avg_latency = sum(successful_latencies) / len(successful_latencies)
        ob[result_key] = avg_latency


# Sync wrappers for the basic tests
def run_async_test(test_func, ob, *args):
    """Runs an async test function within a synchronous context."""
    global is_ctrl_c_pressed
    if is_ctrl_c_pressed:
         fail_key = {tcp_test_outbound: "tcp_delay",
                     http_delay_test_outbound: "http_delay",
                     udp_test_outbound_first_script: "udp_delay"}.get(test_func, "unknown_delay")
         ob[fail_key] = float('inf')
         return

    tag = ob.get('tag', 'unknown')
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(test_func(ob, *args))
        loop.close()
    except RuntimeError as e:
         if "cannot schedule new futures after shutdown" in str(e) or \
            "cannot run event loop while another loop is running" in str(e):
              print(f"Warning: Event loop issue during test for {tag} (likely shutdown/nested): {e}")
         else:
              print(f"RuntimeError during async test for {tag} ({test_func.__name__}): {e}")
         fail_key = {tcp_test_outbound: "tcp_delay",
                     http_delay_test_outbound: "http_delay",
                     udp_test_outbound_first_script: "udp_delay"}.get(test_func, "unknown_delay")
         ob[fail_key] = float('inf')
    except Exception as e:
        print(f"Exception in run_async_test for tag {tag} ({test_func.__name__}): {type(e).__name__}: {e}")
        fail_key = {tcp_test_outbound: "tcp_delay",
                    http_delay_test_outbound: "http_delay",
                    udp_test_outbound_first_script: "udp_delay"}.get(test_func, "unknown_delay")
        ob[fail_key] = float('inf')


# --- Revised Test Pass Function ---
def single_test_pass(outbounds: List[Dict[str, Any]],
                     test_type: str, # e.g., "tcp", "http", "udp", "real", "tcp+http" etc.
                     thread_pool_size: int = 32,
                     proxy_for_http_test: Optional[str] = None, # Proxy for basic HTTP test
                     http_repetitions: int = 3) -> None:
    """
    Runs a specific test pass ('tcp', 'http', 'udp', 'real') on the given outbounds
    using a thread pool. Handles WG/WARP specifically based on test_type.
    """
    global completed_outbounds_count, total_outbounds_count, is_ctrl_c_pressed
    completed_outbounds_count = 0
    # Reset total count for this pass
    current_pass_outbounds = [ob for ob in outbounds if not is_ctrl_c_pressed] # Filter out any potential Nones if list modified during run
    total_outbounds_count = len(current_pass_outbounds)


    if total_outbounds_count == 0:
         print(f"Skipping test pass '{test_type}': No outbounds to test.")
         return

    print(f"\n=== Starting Test Pass: {test_type.upper()} ({total_outbounds_count} outbounds) ===")
    start_time_pass = time.time()

    with concurrent.futures.ThreadPoolExecutor(max_workers=thread_pool_size, thread_name_prefix=f'Test_{test_type}') as executor:
        futures = []
        future_to_tag: Dict[concurrent.futures.Future, str] = {}

        for ob in current_pass_outbounds: # Use the filtered list for this pass
            if is_ctrl_c_pressed:
                print(f"Ctrl+C detected during submission for '{test_type}' pass. No more tests will be scheduled.")
                break

            tag = ob.get("tag", "unknown_tag")
            protocol = ob.get("protocol", "").lower()
            future = None

            # --- Test Submission Logic ---
            if test_type == "tcp":
                 future = executor.submit(run_async_test, tcp_test_outbound, ob)
            elif test_type == "http":
                 future = executor.submit(run_async_test, http_delay_test_outbound, ob, proxy_for_http_test, http_repetitions)
            elif test_type == "udp":
                 if protocol in ("wireguard", "warp"):
                      future = executor.submit(udp_test_outbound_first_script_sync, ob)
                 else:
                      ob["udp_delay"] = float('inf')
                      continue
            elif test_type == "real":
                 if protocol in ("wireguard", "warp"):
                      future = executor.submit(udp_test_outbound_first_script_sync, ob)
                 else:
                      future = executor.submit(real_delay_test_outbound, ob)
            elif test_type == "tcp+http":
                 if protocol in ("wireguard", "warp"):
                      future = executor.submit(udp_test_outbound_first_script_sync, ob)
                 else:
                      f_tcp = executor.submit(run_async_test, tcp_test_outbound, ob)
                      futures.append(f_tcp)
                      future_to_tag[f_tcp] = tag + "_tcp"
                      f_http = executor.submit(run_async_test, http_delay_test_outbound, ob, proxy_for_http_test, http_repetitions)
                      futures.append(f_http)
                      future_to_tag[f_http] = tag + "_http"
                      continue
            # Add other combined test logic as needed (e.g., udp+real)
            elif test_type == "udp+real":
                if protocol in ("wireguard", "warp"):
                    future = executor.submit(udp_test_outbound_first_script_sync, ob)
                else:
                    future = executor.submit(real_delay_test_outbound, ob)
            else:
                 print(f"::error:: Invalid test type '{test_type}' in single_test_pass.")
                 continue
            # --- End Test Submission Logic ---

            if future:
                futures.append(future)
                future_to_tag[future] = tag

        print(f"Submitted {len(futures)} {test_type} tests to thread pool. Waiting for completion...")

        # --- Result Collection and Progress ---
        processed_tags_in_pass = set()
        completed_tasks_count = 0 # Count completed tasks, not unique tags
        try:
            for future in concurrent.futures.as_completed(futures):
                completed_tasks_count += 1 # Increment task counter

                if is_ctrl_c_pressed and completed_tasks_count % 10 == 0:
                     print(f"Stop requested, waiting for currently running {test_type} tests...")

                full_tag_marker = future_to_tag.get(future, "unknown_future")
                tag = full_tag_marker.split('_')[0] if '_' in full_tag_marker and full_tag_marker.split('_')[-1] in ('tcp','http') else full_tag_marker


                try:
                    future.result()
                except Exception as e:
                    print(f"::warning:: Task for {test_type} test of tag {tag} failed internally: {type(e).__name__}: {e}")
                finally:
                     # Update overall completed count based on unique tags processed
                     if tag not in processed_tags_in_pass and tag != "unknown_future":
                          processed_tags_in_pass.add(tag)
                          completed_outbounds_count = len(processed_tags_in_pass) # Update global count

                     # Print progress based on completed tasks vs total submitted futures
                     if total_outbounds_count > 0 : # Avoid division by zero if no tests submitted
                         print_interval = max(1, len(futures) // 20) if len(futures) > 0 else 1
                         if completed_tasks_count % print_interval == 0 or completed_tasks_count == len(futures):
                             # Use completed_outbounds_count (unique tags) for percentage of total
                             percentage_completed = (completed_outbounds_count / total_outbounds_count) * 100
                             elapsed_time = time.time() - start_time_pass
                             print(f"Progress ({test_type}): {percentage_completed:.1f}% ({completed_outbounds_count}/{total_outbounds_count}) | Elapsed: {elapsed_time:.1f}s", end='\r' if sys.stdout.isatty() else '\n')

        except KeyboardInterrupt:
             print(f"\nCtrl+C caught during {test_type} test completion. Cancelling remaining...")
             is_ctrl_c_pressed = True
             cancelled_count = 0
             for f in futures:
                 if not f.done():
                     if f.cancel():
                          cancelled_count += 1
             print(f"Requested cancellation for {cancelled_count} pending {test_type} futures.")

    if sys.stdout.isatty(): print()

    end_time_pass = time.time()
    # Use the accurate count of unique tags completed for the summary
    final_completed_count = len(processed_tags_in_pass)
    print(f"=== Finished Test Pass: {test_type.upper()} ({final_completed_count}/{total_outbounds_count} completed) in {end_time_pass - start_time_pass:.2f}s ===")


# --- Output Conversion (Revised for WG/WARP) ---
def convert_outbound_to_string(ob: Dict[str, Any]) -> Optional[str]:
    """Converts a parsed outbound dictionary back into a URI string format."""
    protocol = ob.get("protocol", "").lower()
    tag = ob.get("tag", "")
    server = ob.get("server")
    port = ob.get("server_port")

    try:
        if not protocol or not server or not port:
            if protocol == "wireguard" and (ob.get("private_key") or ob.get("peer_public_key")):
                 print(f"Warning: Converting WG tag '{tag}' without server/port (keys found).")
                 server = server or "unknown.server"
                 port = port or 2408
            else:
                 # print(f"Warning: Skipping conversion for tag '{tag}', missing protocol/server/port.") # Reduced verbosity
                 return None

        try:
            port = int(port)
        except (ValueError, TypeError):
            # print(f"Warning: Invalid port '{port}' for tag '{tag}' during conversion.") # Reduced verbosity
            return None

        # --- ShadowSocks ---
        if protocol == "shadowsocks":
            method = ob.get("method")
            password = ob.get("password")
            if method is None or password is None: return None
            userinfo = base64.urlsafe_b64encode(f"{method}:{password}".encode()).decode().rstrip("=")
            link = f"ss://{userinfo}@{server}:{port}"
            if ob.get("plugin") and ob.get("plugin_opts"):
                opts_str = ";".join([f"{k}={v}" for k,v in ob["plugin_opts"].items()])
                plugin_str = f"plugin={urllib.parse.quote(ob['plugin'] + ';' + opts_str)}"
                link += f"?{plugin_str}"
            link += f"#{urllib.parse.quote(tag)}"
            return link

        # --- VLESS ---
        elif protocol == "vless":
            uuid = ob.get("uuid")
            if not uuid: return None
            query_params: Dict[str, str] = {}
            security_type = "none"
            tls_settings = ob.get("tls", {})
            if tls_settings.get("enabled"):
                 security_type = "tls"
                 if tls_settings.get("reality", {}).get("enabled"):
                      security_type = "reality"
            if security_type != "none": query_params["security"] = security_type
            if ob.get("flow"): query_params["flow"] = ob["flow"]
            transport = ob.get("transport", {})
            transport_type = transport.get("type")
            if transport_type:
                 query_params["type"] = transport_type
                 if transport_type == "ws":
                      if transport.get("path"): query_params["path"] = transport["path"]
                      if transport.get("headers", {}).get("Host"): query_params["host"] = transport["headers"]["Host"]
                 elif transport_type == "grpc":
                      if transport.get("serviceName"): query_params["serviceName"] = transport["serviceName"]
            if security_type == "tls" or security_type == "reality":
                 if tls_settings.get("server_name"): query_params["sni"] = tls_settings["server_name"]
                 if tls_settings.get("insecure"): query_params["allowInsecure"] = "1"
                 if tls_settings.get("alpn"): query_params["alpn"] = ",".join(tls_settings["alpn"])
                 if security_type == "reality":
                      reality_settings = tls_settings.get("reality", {})
                      if reality_settings.get("public_key"): query_params["pbk"] = reality_settings["public_key"]
                      if reality_settings.get("short_id"): query_params["sid"] = reality_settings["short_id"]
                      utls_settings = tls_settings.get("utls", {})
                      if utls_settings.get("enabled") and utls_settings.get("fingerprint"):
                           query_params["fp"] = utls_settings["fingerprint"]
            query_str = urllib.parse.urlencode(query_params) if query_params else ""
            host_part = f"[{server}]" if ':' in server else server # Handle IPv6
            link = f"vless://{uuid}@{host_part}:{port}"
            if query_str: link += f"?{query_str}"
            link += f"#{urllib.parse.quote(tag)}"
            return link

        # --- VMESS ---
        elif protocol == "vmess":
            uuid = ob.get("uuid")
            if not uuid: return None
            vmess_json = {
                "v": "2", "ps": tag, "add": server, "port": str(port),
                "id": uuid, "aid": str(ob.get("alter_id", 0)), "scy": ob.get("security", "auto"),
                "net": "tcp", "type": "none", "host": "", "path": "",
                "tls": "", "sni": "", "alpn": ""
            }
            transport = ob.get("transport", {})
            net_type = transport.get("type")
            if net_type:
                 vmess_json["net"] = net_type
                 if net_type == "ws":
                      vmess_json["path"] = transport.get("path", "/")
                      vmess_json["host"] = transport.get("headers", {}).get("Host", server)
                 elif net_type == "grpc":
                      vmess_json["path"] = transport.get("serviceName", "")
            tls = ob.get("tls", {})
            if tls.get("enabled"):
                 vmess_json["tls"] = "tls"
                 vmess_json["sni"] = tls.get("server_name", vmess_json["host"])
                 if tls.get("alpn"): vmess_json["alpn"] = ",".join(tls["alpn"])
            config_str = json.dumps(vmess_json, separators=(',', ':'))
            config_b64 = base64.b64encode(config_str.encode()).decode().rstrip("=")
            return f"vmess://{config_b64}"

        # --- TUIC ---
        elif protocol == "tuic":
            uuid = ob.get("uuid")
            password = ob.get("password")
            if uuid is None or password is None: return None
            query_params = {
                 "congestion_control": ob.get("congestion_control", "bbr"),
                 "udp_relay_mode": ob.get("udp_relay_mode", "native"),
            }
            tls = ob.get("tls", {})
            if tls.get("enabled"):
                 if tls.get("server_name"): query_params["sni"] = tls["server_name"]
                 if tls.get("insecure"): query_params["allow_insecure"] = "1"
                 if tls.get("alpn"): query_params["alpn"] = ",".join(tls["alpn"])
            else:
                 query_params["disable_sni"] = "1"
            query_str = urllib.parse.urlencode(query_params)
            host_part = f"[{server}]" if ':' in server else server # Handle IPv6
            link = f"tuic://{uuid}:{password}@{host_part}:{port}"
            if query_str: link += f"?{query_str}"
            link += f"#{urllib.parse.quote(tag)}"
            return link

        # --- WireGuard/WARP ---
        elif protocol == "wireguard":
            private_key = ob.get("private_key")
            if not private_key:
                # print(f"Warning: Skipping WG conversion for tag '{tag}', missing private key.") # Reduced verbosity
                return None

            query_params = {}
            query_params["secret"] = private_key
            peer_key = ob.get("peer_public_key")
            if peer_key: query_params["publickey"] = peer_key

            local_addr_tuple = ob.get("local_address", ob.get("address", ())) # Handle both keys, expect tuple
            if local_addr_tuple and isinstance(local_addr_tuple, tuple):
                 query_params["ip"] = ",".join(local_addr_tuple)

            reserved_tuple = ob.get("reserved", ())
            if reserved_tuple and isinstance(reserved_tuple, tuple):
                 query_params["reserved"] = ",".join(map(str, reserved_tuple))

            if ob.get("mtu"): query_params["mtu"] = str(ob["mtu"])

            query_str = urllib.parse.urlencode(query_params)
            host_part = f"[{server}]" if ':' in server else server
            link = f"wireguard://{host_part}:{port}"
            if query_str: link += f"?{query_str}"
            link += f"#{urllib.parse.quote(tag)}"
            return link

        # --- Hysteria / Hysteria2 / Hy2 ---
        elif protocol == "hysteria2":
            password = ob.get("password", "")
            query_params = {}
            tls = ob.get("tls", {})
            if tls.get("enabled"):
                 if tls.get("server_name"): query_params["sni"] = tls["server_name"]
                 if tls.get("insecure"): query_params["insecure"] = "1"
                 if tls.get("alpn"): query_params["alpn"] = ",".join(tls["alpn"])
            obfs = ob.get("obfs")
            if obfs and isinstance(obfs, dict) and obfs.get("type"):
                 query_params["obfs"] = obfs["type"]
                 if obfs.get("password"): query_params["obfs-password"] = obfs["password"]
            query_str = urllib.parse.urlencode(query_params)
            host_part = f"[{server}]" if ':' in server else server # Handle IPv6
            link = f"hy2://{urllib.parse.quote(password)}@{host_part}:{port}" # URL-encode password if needed
            if query_str: link += f"?{query_str}"
            link += f"#{urllib.parse.quote(tag)}"
            return link

        else:
            # print(f"Warning: Cannot convert unknown protocol '{protocol}' for tag '{tag}' to string link.") # Reduced verbosity
            return None

    except Exception as e:
        print(f"::error:: Error converting outbound {tag} (protocol: {protocol}) to string: {type(e).__name__}: {e}")
        return None

def save_config(outbounds: List[Dict[str, Any]], filepath: str = "merged_config.txt", base64_output: bool = True):
    """Saves the final list of outbound dictionaries to a file."""
    if not outbounds:
        print("No valid outbounds to save.")
        try:
            with open(filepath, "w") as outfile:
                outfile.write("")
            print(f"Saved empty output file to {filepath}")
        except Exception as e:
            print(f"::error:: Error saving empty config to {filepath}: {e}")
        return

    try:
        output_lines = []
        conversion_failures = 0
        for ob in outbounds:
            config_string = convert_outbound_to_string(ob)
            if config_string:
                output_lines.append(config_string)
            else:
                 conversion_failures += 1

        if conversion_failures > 0:
             print(f"::warning:: Could not convert {conversion_failures} outbounds back to string format.")

        if not output_lines:
             print("::warning:: No outbounds could be converted to string format. Saving empty file.")
             output_str = ""
        else:
            output_str = "\n".join(output_lines)

        if base64_output:
            try:
                output_str = base64.b64encode(output_str.encode('utf-8')).decode('ascii')
                save_format = "single-line base64 encoded"
            except Exception as e_b64:
                 print(f"::error:: Failed to base64 encode the output: {e}. Saving as plaintext instead.")
                 output_str = "\n".join(output_lines)
                 save_format = "multi-line plaintext (base64 failed)"
                 base64_output = False
        else:
            save_format = "multi-line plaintext"

        with open(filepath, "w", encoding='utf-8' if not base64_output else 'ascii') as outfile:
            outfile.write(output_str)

        print(f"Merged {len(output_lines)} configs saved to {filepath} in {save_format} format.")

    except Exception as e:
        print(f"::error:: Error saving config to {filepath}: {type(e).__name__}: {e}")


def rename_outbound_tags(configs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Renames tags based on protocol and order after sorting/filtering."""
    protocol_abbr = {
        "shadowsocks": "SS", "vless": "VL", "vmess": "VM",
        "tuic": "TU", "wireguard": "WG", "warp": "WG",
        "hysteria": "HY", "hysteria2": "HY", "hy2": "HY",
        "trojan": "TJ", "snell": "SN",
    }
    renamed_configs = []
    protocol_counts: Dict[str, int] = {}
    unknown_count = 0

    print(f"Renaming tags for {len(configs)} configurations...")

    for config in configs:
        protocol = config.get("protocol", "unknown").lower()
        abbr = protocol_abbr.get(protocol, "XX")

        protocol_counts[abbr] = protocol_counts.get(abbr, 0) + 1
        count = protocol_counts[abbr]

        new_tag = f"🔒Pr0xySh4rk🦈{abbr}{count:02d}"

        if abbr == "XX":
             print(f"Warning: Unknown protocol '{protocol}' for original tag '{config.get('tag')}'. Using 'XX' prefix: {new_tag}")

        config["tag"] = new_tag
        renamed_configs.append(config)

    print("Tag renaming complete.")
    return renamed_configs

def check_connectivity(url="https://www.google.com", timeout=10):
    """Checks basic internet connectivity."""
    print(f"Testing direct internet connectivity to {url}...")
    try:
        session = requests.Session()
        session.trust_env = False
        response = session.get(url, timeout=timeout, allow_redirects=True, verify=True)
        response.raise_for_status()
        print(f"✅ Direct internet connectivity test passed! (Status: {response.status_code})")
        return True
    except requests.exceptions.RequestException as e:
        print(f"❌ Direct internet connectivity test failed: {type(e).__name__}: {e}")
        try:
            print("Attempting fallback connectivity check to http://neverssl.com...")
            session = requests.Session()
            session.trust_env = False
            global HTTP_TIMEOUT
            fallback_timeout = max(5, int(HTTP_TIMEOUT))
            response = session.get("http://neverssl.com", timeout=fallback_timeout)
            response.raise_for_status()
            print(f"✅ Fallback connectivity check passed! (Status: {response.status_code})")
            return True
        except requests.exceptions.RequestException as e2:
            print(f"❌ Fallback connectivity check also failed: {type(e2).__name__}: {e2}")
            return False
        except Exception as e_fb:
             print(f"❌ Unexpected error during fallback connectivity check: {e_fb}")
             return False
    except Exception as e:
         print(f"❌ Unexpected error during connectivity check: {e}")
         return False

def fetch_and_parse_subscription_thread(url: str, proxy: Optional[str], all_tags: set) -> List[Dict[str, Any]]:
    """Worker function for fetching and parsing a single subscription URL."""
    global is_ctrl_c_pressed
    if is_ctrl_c_pressed: return []

    # Corrected thread ID fetching
    thread_id = threading.get_ident() # Get thread ID using threading module
    print(f"Thread {thread_id}: Processing subscription URL: {url}")

    content = fetch_content(url, proxy)
    if is_ctrl_c_pressed: return []

    if content:
        try:
             outbounds_list = parse_config_url1_2(content, all_tags)
        except Exception as e_parse:
             print(f"::error:: Thread {thread_id}: Unhandled error parsing content from {url}: {type(e_parse).__name__}")
             outbounds_list = []

        if outbounds_list:
            for outbound in outbounds_list:
                outbound["source"] = url
            print(f"Thread {thread_id}: Parsed {len(outbounds_list)} outbounds from {url}")
            return outbounds_list
        else:
            # print(f"Thread {thread_id}: No outbounds parsed from {url}") # Reduced verbosity
            return []
    else:
        # print(f"Thread {thread_id}: Failed to fetch content from {url}, skipping.") # Reduced verbosity
        return []


# --- Main Execution Logic ---
def main():
    global is_ctrl_c_pressed, total_outbounds_count, completed_outbounds_count
    global TCP_TIMEOUT, HTTP_TIMEOUT, UDP_TIMEOUT

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    parser = argparse.ArgumentParser(description="Pr0xySh4rk Config Merger & Tester - Multi-threaded")
    parser.add_argument("--input", required=True, help="Input subscription file (URLs, one per line, plain text or base64 encoded list)")
    parser.add_argument("--output", required=True, help="Output file path for the final merged links")
    parser.add_argument("--proxy", help="Optional SOCKS or HTTP proxy for fetching subscription URLs (e.g., 'socks5://127.0.0.1:1080')")
    parser.add_argument("--threads", type=int, default=max(4, os.cpu_count() * 2), help=f"Number of threads for fetching and testing (default: {max(4, os.cpu_count() * 2)})") # Ensure minimum threads
    parser.add_argument("--http-reps", type=int, default=3, help="Basic HTTP test repetitions (default: 3)")
    parser.add_argument("--test", choices=["tcp", "udp", "http", "tcp+http", "real", "http+real", "tcp+real", "tcp+http+real", "udp+real"],
                        default="real", help="Test type(s) to run. 'real' uses Xray (except WG)/UDP. Combined tests run sequentially. (default: real)")
    parser.add_argument("--no-base64", action="store_true", dest="no_base64_output",
                        help="Output links as multi-line plaintext instead of single-line base64")
    parser.add_argument("--tcp-timeout", type=float, default=DEFAULT_TCP_TIMEOUT, help=f"TCP test timeout (seconds, default: {DEFAULT_TCP_TIMEOUT})")
    parser.add_argument("--http-timeout", type=float, default=DEFAULT_HTTP_TIMEOUT, help=f"HTTP test timeout (seconds, default: {DEFAULT_HTTP_TIMEOUT})")
    parser.add_argument("--udp-timeout", type=float, default=DEFAULT_UDP_TIMEOUT, help=f"UDP test timeout (seconds, default: {DEFAULT_UDP_TIMEOUT})")

    parser.set_defaults(no_base64_output=False)
    args = parser.parse_args()

    TCP_TIMEOUT = args.tcp_timeout
    HTTP_TIMEOUT = args.http_timeout
    UDP_TIMEOUT = args.udp_timeout

    start_time_main = time.time()
    print("--- Pr0xySh4rk Initializing ---")
    print(f"Input File: {args.input}")
    print(f"Output File: {args.output}")
    print(f"Fetch Proxy: {args.proxy or 'None'}")
    print(f"Max Threads: {args.threads}")
    print(f"Tests to Run: {args.test}")
    print(f"Output Format: {'Plaintext' if args.no_base64_output else 'Base64'}")
    print(f"Timeouts (TCP/HTTP/UDP): {TCP_TIMEOUT:.1f}s / {HTTP_TIMEOUT:.1f}s / {UDP_TIMEOUT:.1f}s")

    if not check_connectivity(timeout=max(5, int(HTTP_TIMEOUT))):
        print("::error::Exiting due to failed internet connectivity test.")
        sys.exit(1)

    subscription_urls: List[str] = []
    try:
        with open(args.input, "rb") as f:
            raw_content = f.read()
        try:
             decoded_content = raw_content.decode("utf-8").strip()
        except UnicodeDecodeError:
             print("Warning: Input file is not valid UTF-8, trying latin-1.")
             try:
                  decoded_content = raw_content.decode("latin-1").strip()
             except UnicodeDecodeError:
                  print(f"::error::Input file '{args.input}' is not valid UTF-8 or Latin-1.")
                  sys.exit(1)

        is_likely_base64 = False
        if len(decoded_content) > 50 and re.match(r"^[a-zA-Z0-9+/=\s\r\n]*$", decoded_content):
             try:
                  temp_decoded = base64.b64decode(decoded_content.replace("\n", "").replace("\r", "").replace(" ",""), validate=True).decode("utf-8")
                  if '\n' in temp_decoded or temp_decoded.strip().startswith(('http://', 'https://', 'ss://', 'vmess://')):
                       is_likely_base64 = True
             except Exception:
                  is_likely_base64 = False

        if is_likely_base64:
             print("Input content looks like base64, attempting decode...")
             try:
                  decoded_list_str = base64.b64decode(decoded_content.replace("\n", "").replace("\r", "").replace(" ",""), validate=True).decode("utf-8")
                  subscription_urls = [line.strip() for line in decoded_list_str.splitlines() if line.strip() and not line.strip().startswith(("#", "//"))]
                  print(f"Decoded {len(subscription_urls)} URLs from base64 input.")
             except Exception as e:
                  print(f"::error::Failed to decode base64 input content: {e}. Please provide plain text URLs or a valid base64 encoded list.")
                  sys.exit(1)
        else:
             subscription_urls = [line.strip() for line in decoded_content.splitlines() if line.strip() and not line.strip().startswith(("#", "//"))]
             print(f"Read {len(subscription_urls)} URLs from plain text input.")

    except FileNotFoundError:
        print(f"::error::Input file '{args.input}' not found.")
        sys.exit(1)
    except Exception as e:
        print(f"::error::Error reading input file '{args.input}': {e}")
        sys.exit(1)

    if not subscription_urls:
        print("::warning::No valid subscription URLs found in the input file. Saving empty output.")
        save_config([], filepath=args.output, base64_output=(not args.no_base64_output))
        sys.exit(0)

    print(f"\n--- Fetching and Parsing {len(subscription_urls)} Subscriptions ---")
    all_tags: set = set()
    parsed_outbounds_lists: List[List[Dict[str, Any]]] = []
    fetch_start_time = time.time()

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads, thread_name_prefix='Fetcher') as executor:
        futures = {executor.submit(fetch_and_parse_subscription_thread, url, args.proxy, all_tags): url
                   for url in subscription_urls}
        try:
            for future in concurrent.futures.as_completed(futures):
                url = futures[future]
                if is_ctrl_c_pressed:
                    print("Stop requested during subscription fetching/parsing.")
                    break
                try:
                    result = future.result()
                    if result:
                        parsed_outbounds_lists.append(result)
                except Exception as e:
                     print(f"::error::Error processing subscription future for {url}: {type(e).__name__}: {e}")
        except KeyboardInterrupt:
             print("\nCtrl+C caught during fetching. Stopping...")
             is_ctrl_c_pressed = True
             cancelled_count = 0
             for f in futures:
                 if not f.done():
                     if f.cancel():
                          cancelled_count += 1
             print(f"Requested cancellation for {cancelled_count} pending fetch futures.")


    fetch_end_time = time.time()
    print(f"Subscription fetching/parsing completed in {fetch_end_time - fetch_start_time:.2f}s.")

    if is_ctrl_c_pressed:
        print("Exiting early due to stop request during fetch/parse.")
        save_config([], filepath=args.output, base64_output=(not args.no_base64_output))
        sys.exit(0)

    all_parsed_outbounds = [ob for sublist in parsed_outbounds_lists for ob in sublist]
    print(f"\nTotal parsed outbounds before deduplication: {len(all_parsed_outbounds)}")

    if not all_parsed_outbounds:
         print("::warning::No outbounds were parsed from any subscription. Saving empty output.")
         save_config([], filepath=args.output, base64_output=(not args.no_base64_output))
         sys.exit(0)

    all_parsed_outbounds = deduplicate_outbounds(all_parsed_outbounds)
    print(f"Total unique outbounds after deduplication: {len(all_parsed_outbounds)}")

    if not all_parsed_outbounds:
         print("::warning::No unique outbounds remaining after deduplication. Saving empty output.")
         save_config([], filepath=args.output, base64_output=(not args.no_base64_output))
         sys.exit(0)


    tests_to_run = args.test.split('+')
    print(f"\n--- Running Test Sequence: {' -> '.join(t.upper() for t in tests_to_run)} ---")

    current_outbounds = all_parsed_outbounds
    for ob in current_outbounds:
         ob.pop("tcp_delay", None); ob.pop("http_delay", None); ob.pop("udp_delay", None); ob.pop("xray_delay", None); ob.pop("combined_delay", None)


    for test_name in tests_to_run:
        if is_ctrl_c_pressed:
            print(f"Stop requested before running '{test_name}' test.")
            break
        if not current_outbounds:
            print(f"Skipping '{test_name}' test as no outbounds remain.")
            break

        single_test_pass(current_outbounds, test_name, args.threads, None, args.http_reps)

        survivors = []
        if test_name == "tcp":
            survivors = [ob for ob in current_outbounds if ob.get("tcp_delay", float('inf')) != float('inf')]
        elif test_name == "http":
            survivors = [ob for ob in current_outbounds if ob.get("http_delay", float('inf')) != float('inf')]
        elif test_name == "udp":
            survivors = [ob for ob in current_outbounds if ob.get("udp_delay", float('inf')) != float('inf')]
        elif test_name == "real":
            survivors = [ob for ob in current_outbounds if
                         (ob.get("protocol","").lower() in ("wireguard", "warp") and ob.get("udp_delay", float('inf')) != float('inf')) or \
                         (ob.get("protocol","").lower() not in ("wireguard", "warp") and ob.get("xray_delay", float('inf')) != float('inf')) ]
        elif test_name == "tcp+http":
            survivors = [ob for ob in current_outbounds if
                         (ob.get("protocol","").lower() in ("wireguard", "warp") and ob.get("udp_delay", float('inf')) != float('inf')) or \
                         (ob.get("protocol","").lower() not in ("wireguard", "warp") and ob.get("tcp_delay", float('inf')) != float('inf') and ob.get("http_delay", float('inf')) != float('inf')) ]
        else:
             print(f"::error::Unknown test type '{test_name}' encountered during filtering.")
             survivors = current_outbounds

        print(f"-> {len(survivors)} outbounds remaining after {test_name.upper()} test.")
        current_outbounds = survivors

        if not current_outbounds:
             print(f"::warning::No outbounds passed the '{test_name}' test. Stopping test sequence.")
             break

    tested_outbounds = current_outbounds

    if is_ctrl_c_pressed:
        print("Exiting early due to stop request during testing.")
        print("Saving potentially partial results...")
    elif not tested_outbounds:
         print("::warning::No outbounds passed the required tests. Saving empty output file.")
         save_config([], filepath=args.output, base64_output=(not args.no_base64_output))
         sys.exit(0)


    print("\n--- Filtering and Diversifying Results ---")
    final_outbounds = filter_best_outbounds_by_protocol(tested_outbounds, tests_to_run)
    print(f"Total outbounds after final filtering/diversification: {len(final_outbounds)}")

    if not final_outbounds:
         print("::warning::No outbounds remaining after final filtering. Saving empty output file.")
         save_config([], filepath=args.output, base64_output=(not args.no_base64_output))
         sys.exit(0)

    print("\n--- Renaming Tags ---")
    renamed_outbounds = rename_outbound_tags(final_outbounds)

    print("\n--- Saving Final Configuration ---")
    save_config(renamed_outbounds, filepath=args.output, base64_output=(not args.no_base64_output))

    end_time_main = time.time()
    print(f"\n--- Pr0xySh4rk Finished in {end_time_main - start_time_main:.2f} seconds ---")

# --- Entry Point ---
if __name__ == "__main__":
    if sys.platform == "win32":
         try:
              asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
         except:
              print("Note: Could not set WindowsSelectorEventLoopPolicy (might be using Proactor).")
    try:
        main()
    except Exception as main_err:
         print(f"\n::error:: An unexpected error occurred in main execution: {type(main_err).__name__}: {main_err}")
         # import traceback # Uncomment for full traceback
         # traceback.print_exc()
         sys.exit(1)
