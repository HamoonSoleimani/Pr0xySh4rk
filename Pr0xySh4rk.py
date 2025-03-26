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

# --- Requirements ---
# Ensure you have a requirements.txt file with at least:
# requests
# urllib3
# PySocks

# --- Xray_core Implementation for Precise Delay Testing ---
class XrayCore:
    def __init__(self):
        self.process = None
        self.config_file = None
        self.log_file = None # Added for xray logs
        self.last_stderr = "" # Store last stderr output

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
                # Log path setting in config isn't strictly needed when redirecting stderr,
                # but might be useful if stderr redirection fails for some reason.
                # config_dict["log"]["logpath"] = self.log_file.name.replace(".log", ".xray-internal.log")
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
        stderr_handle = None # Initialize handle
        try:
            # Start the xray-core process, redirecting stderr to the log file
            stderr_handle = open(self.log_file.name, "w")
            self.process = subprocess.Popen(
                ["xray", "-config", self.config_file.name],
                stdout=subprocess.PIPE, # Keep stdout if needed, or redirect too
                stderr=stderr_handle,   # Redirect stderr to our file
                # Use preexec_fn to ensure the child process group is killed cleanly later (Linux/macOS)
                preexec_fn=os.setsid if sys.platform != "win32" else None,
                # Set buffer size to prevent potential blocking on stderr/stdout
                bufsize=1,
                universal_newlines=True # Decode stdout/stderr as text if reading directly
            )
            # Wait a bit longer for xray-core to initialize properly
            time.sleep(3) # Increased wait time

            if self.process.poll() is not None:
                stderr_handle.close() # Close handle before reading
                self._read_and_store_stderr() # Read logs even if it exits early
                raise subprocess.SubprocessError(
                    f"xray-core exited immediately with code: {self.process.returncode}. Stderr:\n{self.last_stderr}"
                )
            print(f"xray-core started successfully (PID: {self.process.pid}).")

        except FileNotFoundError:
            print("Failed to start xray-core: 'xray' executable not found. Ensure it's in your PATH.")
            self.process = None
            if stderr_handle: stderr_handle.close()
        except subprocess.SubprocessError as e:
            print(f"Failed to start xray-core: {e}") # Error message now includes stderr from immediate exit
            self.process = None
            # Ensure handle is closed if it was opened
            if stderr_handle and not stderr_handle.closed: stderr_handle.close()
        except Exception as e:
            print(f"Failed to start xray-core: {e}")
            self.process = None
            # Ensure handle is closed if it was opened
            if stderr_handle and not stderr_handle.closed: stderr_handle.close()
        # Note: We don't close stderr_handle here if successful, stop() will handle it via the process object.


    def _read_and_store_stderr(self):
        """Reads the content of the stderr log file."""
        if self.log_file and os.path.exists(self.log_file.name):
            try:
                with open(self.log_file.name, "r") as f:
                    self.last_stderr = f.read().strip()
                if self.last_stderr:
                    # Keep track of the log file name for context
                    print(f"--- Xray Log Content ({os.path.basename(self.log_file.name)}) ---")
                    # Limit printing very long logs to console during normal operation
                    log_preview = self.last_stderr[:1000] + ('...' if len(self.last_stderr) > 1000 else '')
                    # print(log_preview) # Commented out for less verbose normal runs
                    # Full log will be printed explicitly on failure in real_delay_test_outbound
                    print(f"--- (Log content stored, length: {len(self.last_stderr)}) ---")
                else:
                    print(f"--- Xray Log ({os.path.basename(self.log_file.name)}) was empty ---")
            except Exception as e:
                print(f"Error reading xray log file {self.log_file.name}: {e}")
                self.last_stderr = f"Error reading log: {e}"
        else:
            # Handle case where log file might not have been created or was already deleted
            print(f"--- Xray Log file {self.log_file.name if self.log_file else 'N/A'} not found or inaccessible ---")
            self.last_stderr = ""


    def stop(self):
        # Close process handles (stderr, stdout) before terminating
        if self.process:
            if self.process.stderr and not self.process.stderr.closed:
                self.process.stderr.close()
            if self.process.stdout and not self.process.stdout.closed:
                self.process.stdout.close()

            print(f"Stopping xray-core process (PID: {self.process.pid}).")
            killed = False
            try:
                 # Use process group ID to kill xray and potentially child processes (like plugins) more reliably
                 # This requires the setsid in Popen
                pgid = os.getpgid(self.process.pid)
                print(f"Sending SIGTERM to process group {pgid}...")
                os.killpg(pgid, signal.SIGTERM)
                self.process.wait(timeout=5) # Wait for graceful termination
                print("xray-core terminated gracefully.")
            except ProcessLookupError: # Process already exited
                print("xray-core process already exited.")
                pass
            except subprocess.TimeoutExpired:
                print("xray-core did not terminate gracefully after SIGTERM, sending SIGKILL to group...")
                killed = True
                try:
                    os.killpg(pgid, signal.SIGKILL)
                    self.process.wait(timeout=5) # Wait for kill confirmation
                    print("xray-core process group killed.")
                except ProcessLookupError:
                     print("xray-core process exited between SIGTERM and SIGKILL.")
                     pass # Process exited between TERM and KILL
                except subprocess.TimeoutExpired:
                    print("::error::Failed to confirm kill for xray-core process group.")
                except Exception as ke:
                     print(f"::warning::Error during SIGKILL killpg: {ke}")
            except AttributeError:
                 # Fallback for non-POSIX systems where getpgid/killpg might not exist
                 print("Process group termination not available, using terminate/kill fallback...")
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
                print(f"::warning::Error while stopping xray-core process group: {e}")
            finally:
                # Ensure process is marked as None
                self.process = None

        # Read log file *after* trying to stop the process, ensuring all output is captured
        print("Reading final Xray logs...")
        self._read_and_store_stderr()

        # Clean up temporary files
        if self.config_file:
            config_file_name = self.config_file.name # Store name before setting to None
            try:
                if os.path.exists(config_file_name):
                    os.remove(config_file_name)
                    print(f"Removed temporary config file: {config_file_name}")
            except Exception as e:
                print(f"::warning::Failed to remove temporary config file {config_file_name}: {e}")
            finally:
                self.config_file = None
        if self.log_file:
            log_file_name = self.log_file.name # Store name before setting to None
            try:
                # Check path exists before removing, file handle was closed earlier
                if os.path.exists(log_file_name):
                    os.remove(log_file_name)
                    print(f"Removed temporary log file: {log_file_name}")
            except Exception as e:
                print(f"::warning::Failed to remove temporary log file {log_file_name}: {e}")
            finally:
                self.log_file = None


# --- Outbound Conversion (Unchanged from original) ---
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
             # Handle reality specific fields if present
            if ob["tls"].get("reality", {}).get("enabled"):
                 new_ob["streamSettings"]["realitySettings"] = {
                     "publicKey": ob["tls"]["reality"].get("public_key", ""),
                     "shortId": ob["tls"]["reality"].get("short_id", ""),
                     "serverName": new_ob["streamSettings"]["tlsSettings"]["serverName"], # Reuse SNI
                     # 'fingerprint' might be under utls in original, map to realitySettings if needed by xray
                     # "fingerprint": ob["tls"].get("utls", {}).get("fingerprint", "chrome")
                 }
                 # If reality is used, tlsSettings might need allowInsecure depending on xray version/config needs
                 # new_ob["streamSettings"]["tlsSettings"]["allowInsecure"] = True
                 new_ob["streamSettings"]["security"] = "reality" # Override security to reality
                 # Handle UTLS fingerprint if present
                 if ob["tls"].get("utls", {}).get("enabled"):
                     new_ob["streamSettings"]["realitySettings"]["fingerprint"] = ob["tls"]["utls"].get("fingerprint", "chrome")


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
                                "security": ob.get("security", "auto") # This is vmess security (encryption), not TLS
                            }
                        ]
                    }
                ]
            }
        }
        if "transport" in ob:
            new_ob["streamSettings"] = ob["transport"]
        if "tls" in ob and isinstance(ob["tls"], dict) and ob["tls"].get("enabled"):
            new_ob.setdefault("streamSettings", {})["security"] = "tls"
            new_ob.setdefault("streamSettings", {}).setdefault("tlsSettings", {})["serverName"] = ob["tls"].get("server_name", ob.get("server", ""))
            # Add allowInsecure if needed, common for self-signed or certain setups
            # new_ob["streamSettings"]["tlsSettings"]["allowInsecure"] = ob["tls"].get("insecure", False)
        return new_ob

    elif protocol == "tuic":
         # Note: TUIC v5 support in Xray might differ. This structure assumes a common pattern.
         # Check Xray documentation for the exact TUIC outbound structure it expects.
        new_ob = {
            "protocol": "tuic", # Protocol name might need adjustment based on Xray version (e.g., tuic_v5)
            "tag": tag,
            "settings": {
                "server": ob.get("server", ""),
                "port": int(ob.get("server_port", 443)),
                "uuid": ob.get("uuid", ""),
                "password": ob.get("password", ""),
                # Map parameters - check Xray docs for exact names
                "congestion_control": ob.get("congestion_control", "bbr"),
                "udp_relay_mode": ob.get("udp_relay_mode", "native"),
                # TUIC's internal TLS handling might be configured differently
                # "disable_sni": not ob.get("tls", {}).get("server_name"),
                # "sni": ob.get("tls", {}).get("server_name", ob.get("server", "")),
                # "insecure_skip_verify": ob.get("tls", {}).get("insecure", True),
                # "alpn": ["h3"] # Common ALPN for TUIC, adjust if needed
            },
             # Stream settings might not be used or structured differently for TUIC
             "streamSettings": {
                 "network": "udp", # TUIC is UDP based
                 # TLS settings might be within the main 'settings' block for TUIC in Xray
                 "security": "tls", # Assuming Xray handles TUIC TLS via streamSettings
                 "tlsSettings": {
                     "serverName": ob.get("tls", {}).get("server_name", ob.get("server", "")),
                     "allowInsecure": ob.get("tls", {}).get("insecure", True)
                 }
             }
        }
        return new_ob

    elif protocol in ("wireguard", "warp"):
        # This structure seems generally correct for Xray's WireGuard outbound
        new_ob = {
            "protocol": "wireguard",
            "tag": tag,
            "settings": {
                "secretKey": ob.get("private_key", ""), # Use secretKey for private key
                "address": ob.get("local_address", []),
                "peers": [ # Use peers list
                    {
                        "publicKey": ob.get("peer_public_key", ob.get("peer", {}).get("publicKey", "")), # Allow fallback from 'peer' obj
                        "endpoint": f"{ob.get('server', '')}:{int(ob.get('server_port', 443))}",
                        # Wireguard 'reserved' bytes if provided
                        "reserved": [int(x) for x in ob.get("reserved", "").split(',')] if ob.get("reserved") else []
                    }
                ],
                "mtu": int(ob.get("mtu", 1330)),
                # Other potential WireGuard settings if needed: workers, connIdle, etc.
            }
        }
        return new_ob

    elif protocol in ("hysteria", "hysteria2", "hy2"):
        # Hysteria/Hysteria2 might have different protocol names in Xray depending on version
        # Check Xray documentation. Assuming "hysteria2" is the modern one.
        new_ob = {
            "protocol": "hysteria2",
            "tag": tag,
            "settings": {
                "server": ob.get("server", ""),
                "port": int(ob.get("server_port", 443)),
                "password": ob.get("password", ""),
                 # Map obfs if present - check Xray Hysteria2 docs for exact structure
                 # "obfs": {
                 #     "type": ob.get("obfs", {}).get("type"),
                 #     "password": ob.get("obfs", {}).get("password")
                 # } if ob.get("obfs") else None
            },
            "streamSettings": {
                "network": "udp", # Hysteria is UDP based
                "security": "tls", # Assuming TLS is handled via streamSettings
                "tlsSettings": {
                    "serverName": ob.get("tls", {}).get("server_name", ob.get("server", "")),
                    "allowInsecure": ob.get("tls", {}).get("insecure", True),
                    # ALPN might be needed for Hysteria
                    # "alpn": ["h3"] # Or specific ALPN used by the server
                }
            }
        }
        # Handle OBFS conversion based on Xray's expected structure
        if ob.get("obfs"):
            new_ob["settings"]["obfs"] = ob.get("obfs") # Simple mapping, adjust if needed

        return new_ob

    else:
        # Fallback: simply rename key "type" to "protocol" for unknown types.
        print(f"Warning: Passing through unknown protocol type '{protocol}' with minimal conversion for tag '{tag}'.")
        new_ob = dict(ob)
        if "type" in new_ob:
            new_ob["protocol"] = new_ob.pop("type")
        return new_ob


# --- Helper Functions for Xray-core and proxychains ---
def create_xray_config(outbound_config: dict) -> dict:
    """
    Wrap a single outbound configuration into a full Xray-core config
    with a SOCKS inbound.
    """
    return {
        # Add log section (will be potentially overridden by XrayCore class)
        "log": {
            "loglevel": "warning"
        },
        # Add DNS section - important for reliable lookups through the proxy
        "dns": {
            "servers": [
                "1.1.1.1", # Primary DNS
                "8.8.8.8", # Secondary DNS
                "localhost" # Allow resolving local names if needed
            ]
        },
        "inbounds": [
            {
                "protocol": "socks",
                "port": 1080, # Standard SOCKS port
                "listen": "127.0.0.1", # Listen only locally
                "settings": {
                    "auth": "noauth", # No authentication needed for local testing
                    "udp": True, # Enable UDP forwarding for tests that need it (like fping DNS)
                    "ip": "127.0.0.1" # Bind UDP response locally
                },
                "tag": "socks-in"
            }
        ],
        "outbounds": [
            outbound_config, # The main outbound to test
            {
                "protocol": "freedom", # Direct connection
                "tag": "direct"
            },
             {
                "protocol": "blackhole", # Block connection
                "tag": "block"
            }
        ],
        # Basic routing - send everything through the tagged outbound by default
        "routing": {
            "rules": [
                # Example: Route DNS queries directly if needed (can sometimes help)
                # {
                #     "type": "field",
                #     "port": 53,
                #     "network": "udp",
                #     "outboundTag": "direct"
                # },
                {
                    "type": "field",
                    "inboundTag": ["socks-in"], # Apply to traffic from our SOCKS inbound
                    "outboundTag": outbound_config.get("tag", "proxy") # Route to the outbound being tested
                }
            ]
        }
    }

def create_proxychains_config(proxy: str) -> str:
    """Creates a temporary proxychains4 configuration file."""
    if proxy.startswith("socks5://"):
        proxy_netloc = proxy[len("socks5://"):]
        host, port = (proxy_netloc.split(":", 1) + ["1080"])[:2] # Handle missing port
        proxy_type = "socks5"
    elif proxy.startswith("socks4://"):
        proxy_netloc = proxy[len("socks4://"):]
        host, port = (proxy_netloc.split(":", 1) + ["1080"])[:2]
        proxy_type = "socks4"
    else:
        # Default to SOCKS5 localhost if format is unrecognized
        host, port = "127.0.0.1", "1080"
        proxy_type = "socks5"

    # Ensure proxychains uses DNS through the proxy
    config_content = f"""strict_chain
proxy_dns
tcp_read_time_out 15000
tcp_connect_time_out 10000 # Slightly increased connect timeout

[ProxyList]
# type host port [user pass]
{proxy_type} {host} {port}
"""
    tmp = tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".conf")
    tmp.write(config_content)
    tmp.flush()
    tmp.close()
    # print(f"Created proxychains config {tmp.name} for {proxy_type} {host}:{port}")
    return tmp.name

def measure_latency_icmp_proxychains(target_host: str = "www.google.com",
                                     proxy: str = "socks5://127.0.0.1:1080",
                                     count: int = 3, # Reduced default count
                                     timeout: int = 15) -> float: # Adjusted default timeout
    """Measures ICMP latency using fping through proxychains, attempting sudo."""
    config_path = create_proxychains_config(proxy)
    # Calculate per-packet timeout for fping (in milliseconds)
    # Ensure it's at least 500ms, prevent division by zero
    per_packet_timeout_ms = max(500, int((timeout * 1000) / count)) if count > 0 else 5000

    # --- Added sudo before fping ---
    command = ["proxychains4", "-f", config_path, "sudo", "fping",
               "-c", str(count),     # Number of pings
               "-t", str(per_packet_timeout_ms), # Timeout per packet (ms)
               "-q",                 # Quiet mode (only summary)
               target_host]

    print(f"Attempting ICMP test: {' '.join(command)}")
    try:
        # Use subprocess.run for better error capture and timeout handling
        # Allow extra time beyond the calculated ping timeouts for sudo/process overhead
        process_timeout = timeout + 10
        result = subprocess.run(command, capture_output=True, text=True,
                                timeout=process_timeout, check=False) # check=False to handle non-zero exits manually

        # --- Check results ---
        if result.returncode != 0:
             print(f"ICMP Latency measurement command failed (exit code {result.returncode}). Timeout={process_timeout}s")
             # Log stderr which might contain sudo errors, fping errors, or proxychains errors
             if result.stderr:
                 print(f"stderr:\n{result.stderr.strip()}")
             if result.stdout: # Log stdout too, fping might print errors there in some modes
                 print(f"stdout:\n{result.stdout.strip()}")
             return float('inf')

        # --- Process successful output (stderr is used by fping -q for summary) ---
        process_output = result.stderr # fping -q prints summary to stderr
        # Example fping -q output: "www.google.com : 10.5 11.2 10.8" (min/avg/max) - No, wait, -q is different.
        # fping -q stderr: "google.com : xmt/rcv/%loss = 3/3/0%, min/avg/max = 9.43/9.57/9.76"
        match = re.search(r"min/avg/max = ([\d\.]+)/([\d\.]+)/([\d\.]+)", process_output)
        if match:
            _, avg_rtt, _ = map(float, match.groups())
            print(f"ICMP test successful: avg={avg_rtt:.2f} ms")
            return avg_rtt
        else:
            # Fallback parsing if -q format is different or missing summary line
            print(f"Failed to parse fping summary output from stderr:\n{process_output}")
            # Try parsing stdout just in case fping version behaves differently
            if result.stdout:
                 print(f"(Checking stdout: {result.stdout.strip()})")
            return float('inf')

    except subprocess.TimeoutExpired:
        print(f"ICMP Latency measurement command timed out after {process_timeout}s.")
        return float('inf')
    except Exception as e: # Catch other potential errors like FileNotFoundError if sudo/fping aren't there
        print(f"ICMP Latency measurement error: {type(e).__name__}: {e}")
        return float('inf')
    finally:
        try:
            if config_path and os.path.exists(config_path):
                os.remove(config_path)
                # print(f"Removed proxychains config: {config_path}")
        except OSError as e:
            print(f"::warning:: Failed to remove proxychains config {config_path}: {e}")


def measure_xray_latency_http(proxy: str, timeout: int = 15) -> float: # Increased default timeout
    """
    Measures HTTP latency using a diverse set of URLs with concurrent requests.
    Uses a requests session with PySocks support. Retries are less useful for fundamental proxy errors.
    """
    test_urls = [
        "https://www.cloudflare.com/cdn-cgi/trace", # Good CDN edge test
        "https://checkip.amazonaws.com",           # Reliable IP check
        "http://neverssl.com",                     # Simple HTTP test
        "http://detectportal.firefox.com/success.txt", # Another simple HTTP target
        "https://google.com/generate_204",          # Commonly used connectivity check (HTTPS)
        "https://ipinfo.io/ip",                    # Another IP check service (HTTPS)
    ]
    session = requests.Session()
    if proxy:
        session.proxies = {'http': proxy, 'https': proxy}
    # Disable environment proxy usage for this specific session to avoid interference
    session.trust_env = False

    # Optional: Configure retries, but they might mask underlying permanent proxy issues
    # retry_strategy = Retry(total=1, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504])
    # adapter = HTTPAdapter(max_retries=retry_strategy)
    # session.mount("http://", adapter)
    # session.mount("https://", adapter)

    def fetch_url(url: str) -> Tuple[Optional[float], str]:
        try:
            start_time = time.time()
            # verify=False can sometimes bypass certain TLS issues originating *after* the proxy,
            # but usually the SSLError comes *from* the proxy connection itself.
            # Let's keep verify=True for better security and error detection.
            response = session.get(url, timeout=timeout, allow_redirects=True, stream=False) # stream=False ensures content is downloaded
            response.raise_for_status() # Check for HTTP 4xx/5xx errors AFTER connection
            latency = (time.time() - start_time) * 1000
            # Short success message to reduce log noise
            # print(f"HTTP OK: {url} via {proxy} ({latency:.0f}ms)")
            return latency, url
        # --- More Specific Error Handling ---
        except requests.exceptions.SSLError as e:
            # Often indicates issues with the proxy's handling of TLS or the target cert
            print(f"HTTP Fail: {url} via {proxy} - SSL Error: {e}")
            return None, url
        except requests.exceptions.ProxyError as e:
            # Error specifically related to connecting TO the proxy server
            print(f"HTTP Fail: {url} via {proxy} - Proxy Error: {e}")
            return None, url
        except requests.exceptions.ConnectTimeout as e:
             # Timeout trying to establish connection (TCP handshake)
             print(f"HTTP Fail: {url} via {proxy} - Connect Timeout: {e}")
             return None, url
        except requests.exceptions.ReadTimeout as e:
             # Timeout waiting for data after connection established
             print(f"HTTP Fail: {url} via {proxy} - Read Timeout: {e}")
             return None, url
        except requests.exceptions.ConnectionError as e:
             # More general connection error (DNS issues, refused connections not caught by ProxyError)
             print(f"HTTP Fail: {url} via {proxy} - Connection Error: {e}")
             return None, url
        except requests.exceptions.HTTPError as e:
             # Handle HTTP errors (4xx, 5xx) after successful connection
             print(f"HTTP Fail: {url} via {proxy} - HTTP Error Status: {e.response.status_code}")
             return None, url
        except requests.exceptions.RequestException as e:
            # Catch-all for other requests issues (like TooManyRedirects)
            print(f"HTTP Fail: {url} via {proxy} - General Request Error: {e}")
            return None, url
        except Exception as e:
            # Catch unexpected errors within the test function
            print(f"HTTP Fail: {url} via {proxy} - Unexpected Error: {type(e).__name__}: {e}")
            return None, url

    latencies = []
    # Limit concurrency slightly - might be gentler on Xray instance / runner resources
    # Adjust max_workers based on observation. Too high might overload Xray/network.
    num_workers = max(2, len(test_urls) // 2)
    # print(f"Starting HTTP tests for {proxy} with {num_workers} workers...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=num_workers) as executor:
        # Shuffle URLs slightly? Might not matter much.
        # random.shuffle(test_urls)
        futures = {executor.submit(fetch_url, url): url for url in test_urls}
        results = []
        try:
            # Wait for all futures to complete
            for future in concurrent.futures.as_completed(futures):
                results.append(future.result())
        except Exception as e: # Should not happen with proper handling in fetch_url
             print(f"Error processing HTTP test futures for {proxy}: {e}")

    # Process results after all threads are done
    for latency, url in results:
         if latency is not None:
             latencies.append(latency)

    if latencies:
        best_latency = min(latencies)
        # Calculate average and success rate for more info
        avg_latency = sum(latencies) / len(latencies)
        success_rate = (len(latencies) / len(test_urls)) * 100
        print(f"HTTP Result for {proxy}: Best={best_latency:.0f}ms, Avg={avg_latency:.0f}ms ({len(latencies)}/{len(test_urls)} OK ~ {success_rate:.0f}%)")
        return best_latency
    else:
        print(f"HTTP Result for {proxy}: All {len(test_urls)} test attempts failed.")
        return float('inf')


def measure_latency_precise(proxy: str,
                            target_host: str = "www.google.com",
                            count: int = 3,
                            timeout: int = 15) -> float:
    """
    Attempts ICMP latency test via proxychains/sudo/fping first.
    Falls back to HTTP latency test if ICMP fails or dependencies are missing.
    """
    # Check for dependencies once
    has_proxychains = shutil.which("proxychains4")
    has_fping = shutil.which("fping")
    has_sudo = shutil.which("sudo") # Check for sudo command

    if has_proxychains and has_fping and has_sudo:
        print("Dependencies found (proxychains4, fping, sudo). Attempting ICMP test via sudo...")
        latency = measure_latency_icmp_proxychains(target_host, proxy, count, timeout)
        if latency != float('inf'):
            return latency # Return successful ICMP result
        else:
            # ICMP failed, log message already printed by measure_latency_icmp_proxychains
            print("ICMP latency measurement failed, falling back to HTTP test.")
            # Proceed to HTTP test
    else:
        missing = [dep for dep, present in [("proxychains4", has_proxychains), ("fping", has_fping), ("sudo", has_sudo)] if not present]
        # This is common, don't make it a warning unless debugging
        print(f"Skipping ICMP test, missing dependencies: {', '.join(missing)}. Falling back to HTTP test.")

    # Fallback to HTTP test
    print("Performing HTTP latency test...")
    return measure_xray_latency_http(proxy, timeout=timeout) # Use the same timeout


def real_delay_test_outbound(outbound_config: dict) -> float:
    """
    Performs a realistic delay test for a single outbound config using XrayCore.
    Starts Xray, runs latency tests (ICMP with HTTP fallback), stops Xray,
    and captures Xray logs on failure.
    """
    converted = None
    config = None
    json_config_str = None
    xr = XrayCore() # Instantiate XrayCore
    latency = float('inf')
    error_message = ""
    xray_stderr_log = ""
    tag = outbound_config.get("tag", "unknown_tag") # Get tag early for logging

    try:
        print(f"--- Starting real delay test for tag: {tag} ---")
        converted = convert_outbound_config(outbound_config)
        if not converted or not converted.get("protocol"):
             raise ValueError("Failed to convert outbound config or protocol missing.")
        # Ensure the converted config has the same tag for routing purposes
        converted["tag"] = tag
        config = create_xray_config(converted)
        json_config_str = json.dumps(config)

        # Start XrayCore instance
        xr.startFromJSON(json_config_str)
        if xr.process is None: # Check if start failed inside XrayCore
             # Error message already printed by startFromJSON
             raise RuntimeError(f"XrayCore failed to start for tag {tag}.")

        # Xray is running, perform the latency test
        proxy = "socks5://127.0.0.1:1080"
        # Call the combined ICMP/HTTP test function
        latency = measure_latency_precise(proxy, target_host="www.google.com", count=3, timeout=15)

        if latency == float('inf'):
            error_message = f"All latency test methods (ICMP/HTTP) failed for tag {tag}."
            # Log might be printed later in finally block
        else:
            # Success case
            print(f"+++ Real delay test for {tag} SUCCEEDED: {latency:.2f} ms +++")

    except Exception as e:
        # Catch errors during conversion, config creation, or latency measurement itself
        error_message = f"Error during real delay test setup or execution for {tag}: {type(e).__name__}: {e}"
        import traceback
        print(error_message)
        print(traceback.format_exc()) # Print stack trace for debugging
        latency = float('inf')
    finally:
        # --- Stop Xray and Capture Logs ---
        # This should always run, even if tests succeeded, to clean up
        print(f"--- Stopping XrayCore for tag: {tag} ---")
        xr.stop() # stop() now reads and stores stderr internally
        xray_stderr_log = xr.last_stderr # Get logs captured by stop()

        # --- Analyze and Log Results ---
        if latency == float('inf'):
            print(f"--- Real delay test for tag: {tag} FAILED (Latency: inf) ---")
            # Print the specific Python error if one occurred
            if error_message:
                 print(f"Failure reason (Python Level): {error_message}")
            # Print the captured Xray stderr log if the test failed, as it's highly relevant
            if xray_stderr_log:
                 print(f"--- Captured Xray stderr log for failed tag {tag} ({os.path.basename(xr.log_file.name if xr.log_file else 'N/A')}): ---")
                 # Print the full log now
                 print(xray_stderr_log)
                 print("--- End of Xray stderr log ---")
            elif not error_message:
                 # If no specific Python error and no Xray log, give a generic message
                 print(f"Test failed for tag {tag}, but no specific Python error or Xray log was captured.")

        # Update the original outbound config dictionary with the result
        # This happens regardless of success or failure
        outbound_config["xray_delay"] = latency
        # Optionally, add error context to the config (might make it too verbose)
        # if latency == float('inf'):
        #     outbound_config["xray_test_error"] = error_message or "Test failed, check logs"
        #     outbound_config["xray_test_log_snippet"] = xray_stderr_log[:200] + "..." if xray_stderr_log else ""

        print(f"--- Finished real delay test for tag: {tag} ---")
        # Return the measured latency (inf on failure)
        return latency

# --- Normalization (Unchanged) ---
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

# --- Signal Handling (Unchanged) ---
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
    if not is_ctrl_c_pressed: # Only print the first time
        print("\nCtrl+C detected. Requesting graceful stop... (Press again to force exit)")
        is_ctrl_c_pressed = True
    else:
        print("Forcing exit due to repeated Ctrl+C.")
        sys.exit(1)


# --- Fetching, Parsing, Deduplication (Largely Unchanged, minor logging tweaks) ---
def fetch_content(url: str, proxy: Optional[str] = None) -> Optional[str]:
    session = requests.Session()
    proxies = {"http": proxy, "https": proxy} if proxy else None
    # Disable environment proxies for fetching subscriptions unless explicitly provided
    session.trust_env = False

    pid = os.getpid() # Get pid once

    if proxies:
        print(f"Thread {pid}: Fetching {url} using proxy: {proxy}")
    else:
        # Reduced noise for direct fetches
        # print(f"Thread {pid}: Fetching {url} directly")
        pass

    orig_env = {} # To handle temporary removal of system proxies if needed (less common now with trust_env=False)
    fetched = False
    content = None

    try:
        # --- Attempt 1: Direct or via specified proxy ---
        response = session.get(url, timeout=15, proxies=proxies, allow_redirects=True) # Increased timeout
        response.raise_for_status()
        content = response.text
        fetched = True
        # print(f"Thread {pid}: Successfully fetched {url}")

    except requests.exceptions.RequestException as e:
        print(f"Thread {pid}: Error fetching URL {url}{' via proxy ' + proxy if proxy else ''}: {e}")
        # --- Attempt 2: If direct failed, maybe try with system proxies? (Less common use case) ---
        # This logic might be removed if system proxies are not desired for subscription fetching.
        # if not proxies and ('http_proxy' in os.environ or 'https_proxy' in os.environ):
        #     try:
        #         print(f"Thread {pid}: Retrying {url} with system proxy settings...")
        #         # Create a new session that *does* trust env
        #         system_proxy_session = requests.Session()
        #         system_proxy_session.trust_env = True
        #         response = system_proxy_session.get(url, timeout=15, allow_redirects=True)
        #         response.raise_for_status()
        #         content = response.text
        #         fetched = True
        #         print(f"Thread {pid}: Successfully fetched {url} using system proxy.")
        #     except requests.exceptions.RequestException as e2:
        #         print(f"Thread {pid}: System proxy retry also failed for {url}: {e2}")

    finally:
        # Restore environment variables if they were modified (less likely needed now)
        # for env_var, value in orig_env.items():
        #     os.environ[env_var] = value
        pass

    return content

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
        if fragment and tag not in all_tags: # Ensure existing tag is added
            all_tags.add(tag)

        # Extract peer public key from params if available
        peer_public_key = params.get("publickey", ["bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="])[0]
        # Extract reserved bytes from params if available
        reserved_str = params.get("reserved", [""])[0]
        # reserved_bytes = bytes([int(x) for x in reserved_str.split(',')]) if reserved_str else b"" # Convert back to bytes if needed by specific parser/xray

        outbound: Dict[str, Any] = {
            "type": "wireguard", # Standardize to wireguard
            "tag": tag,
            # Default WARP IPs, might need adjustment based on source
            "local_address": params.get("address", [
                "172.16.0.2/32", # Use /32 for single address assignment
                "2606:4700:110:8566:aded:93b9:60a9:1a6c/128"
            ])[0].split(','), # Split if multiple addresses are comma-separated
            "private_key": license_key,
            "server": server,
            "server_port": int(port),
            "peer_public_key": peer_public_key,
            "reserved": reserved_str, # Store as string as parsed
            "mtu": int(params.get("mtu", ["1280"])[0]), # Default MTU for WARP is often 1280
            # Include fake packets parameters if present (might not be used by Xray directly)
            "fake_packets": params.get("ifp", [""])[0],
            "fake_packets_size": params.get("ifps", [""])[0],
            "fake_packets_delay": params.get("ifpd", [""])[0],
            "fake_packets_mode": params.get("ifpm", [""])[0],
        }
        return [outbound], counter
    except Exception as e:
        pid = os.getpid()
        print(f"Thread {pid}: Error parsing warp/wireguard link: {e} - Link: {link}")
        return [], counter

def parse_warp_line(line: str, counter: int, all_tags: set) -> Tuple[List[Dict[str, Any]], int]:
    if "&&detour=" in line:
        main_part, detour_part = line.split("&&detour=", 1)
        main_configs, counter = parse_warp_single(main_part.strip(), counter, all_tags)
        # Detours are usually not standard WG links, might need different parsing or ignored
        # For now, let's just parse the main part.
        # detour_configs, counter = parse_warp_single(detour_part.strip(), counter, all_tags)
        # if main_configs and detour_configs:
        #    # How to handle detour? Add as separate outbound? Ignore?
        #    return main_configs + detour_configs, counter
        return main_configs, counter
    return parse_warp_single(line, counter, all_tags)

def parse_config_url1_2(content: str, all_tags: set) -> List[Dict[str, Any]]:
    """Parses various proxy formats (SS, Vless, Vmess, TUIC, WG, Hysteria) from text content."""
    outbounds = []
    pid = os.getpid() # Get thread/process ID

    # --- 1. Attempt Base64 Decode (Common for subscription links) ---
    try:
        # Be more lenient with base64 padding and variations
        missing_padding = len(content) % 4
        if missing_padding:
            content += '=' * (4 - missing_padding)
        decoded_content = base64.urlsafe_b64decode(content).decode('utf-8')
        # If decoding works, assume the *decoded* content is the list of links
        content = decoded_content
        print(f"Thread {pid}: Content appears to be base64 encoded, decoded.")
    except (ValueError, UnicodeDecodeError, base64.binascii.Error):
        # Failed decoding, assume content is already plain text links
        # print(f"Thread {pid}: Content not valid base64, processing as plain text.")
        pass
    except Exception as e_b64:
        print(f"Thread {pid}: Unexpected error during base64 decode attempt: {e_b64}")
        # Continue assuming plain text


    # --- 2. Attempt Full JSON Config Parse ---
    # Remove comment lines for JSON parsing
    json_content_lines = [line for line in content.splitlines() if not line.strip().startswith( ('//', '#') )]
    json_content_str = "\n".join(json_content_lines)
    if json_content_str.strip().startswith('{') and json_content_str.strip().endswith('}'):
        try:
            config = json.loads(json_content_str)
            if isinstance(config, dict) and "outbounds" in config and isinstance(config["outbounds"], list):
                print(f"Thread {pid}: Parsed as full JSON config with {len(config['outbounds'])} outbounds.")
                parsed_count = 0
                for i, ob in enumerate(config["outbounds"]):
                    if not isinstance(ob, dict): continue
                    # Ensure unique tag - use original if possible, generate if missing/duplicate
                    original_tag = ob.get("tag", f"json_ob_{i+1}")
                    if original_tag in all_tags:
                         ob["tag"] = generate_unique_tag(all_tags)
                    else:
                         ob["tag"] = original_tag # Use original
                         all_tags.add(original_tag)
                    # Basic validation/normalization
                    if "type" in ob and "protocol" not in ob:
                         ob["protocol"] = ob.pop("type")
                    if ob.get("protocol"): # Only add if protocol seems present
                        outbounds.append(ob)
                        parsed_count += 1
                print(f"Thread {pid}: Added {parsed_count} valid outbounds from JSON structure.")
                # If successfully parsed as JSON, return early
                return outbounds
            else:
                print(f"Thread {pid}: Content looked like JSON, but structure was invalid ('outbounds' list missing).")
        except json.JSONDecodeError:
            # Not valid JSON, proceed to line-by-line parsing
             print(f"Thread {pid}: Content not valid JSON, proceeding with line-by-line parsing.")
             pass # Continue to line-by-line

    # --- 3. Line-by-line Parsing (SS, VLESS, VMESS, etc.) ---
    print(f"Thread {pid}: Parsing content line by line...")
    lines_processed = 0
    protocols_found = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "//")):
            continue
        lines_processed += 1

        parsed_ob = None # Store result of parsing attempt for this line

        # --- Shadowsocks (ss://) ---
        if line.startswith("ss://"):
            try:
                parsed_ob = {} # Start fresh dict
                frag = ""
                link_part = line[len("ss://"):]
                if "#" in link_part:
                    link_part, frag = link_part.split("#", 1)

                # Decode userinfo (method:password)
                user_info = ""
                server_part = ""
                if "@" in link_part:
                    user_info_encoded, server_part = link_part.split("@", 1)
                    try:
                         padding = "=" * (-len(user_info_encoded) % 4)
                         user_info = base64.urlsafe_b64decode(user_info_encoded + padding).decode("utf-8")
                    except Exception as e_user:
                         print(f"Thread {pid}: SS UserInfo decode error: {e_user} - Info: {user_info_encoded}")
                         continue # Skip this invalid SS link
                else:
                    # Handle format ss://BASE64_METHOD_PASS_SERVER_PORT#TAG ? (Less common)
                    # Assume the whole part before '#' is the server if no '@'
                    server_part = link_part


                method, password = (user_info.split(":", 1) + [None])[:2] if user_info else (None, None)
                if not method or password is None:
                     # Try parsing the non-@ part as base64(method:pass@server:port) - older format?
                     try:
                          full_decoded_b64 = base64.urlsafe_b64decode(link_part + "=" * (-len(link_part) % 4)).decode("utf-8")
                          if "@" in full_decoded_b64:
                              user_info, server_part = full_decoded_b64.split("@", 1)
                              method, password = (user_info.split(":", 1) + [None])[:2]
                          else: # If still no @ after decode, format is unknown
                              print(f"Thread {pid}: Skipping SS link with undecipherable format: {line[:50]}...")
                              continue
                     except Exception:
                          print(f"Thread {pid}: Skipping SS link, failed to parse user/server: {line[:50]}...")
                          continue # Skip if parsing fails badly


                # Parse server:port
                server = ""
                port = 443 # Default port
                # Remove plugin info if present in server_part
                server_port_str = server_part.split("?")[0]
                if ":" in server_port_str:
                     host_maybe_ipv6, port_str = server_port_str.rsplit(":", 1)
                     # Check for IPv6
                     if host_maybe_ipv6.startswith("[") and host_maybe_ipv6.endswith("]"):
                          server = host_maybe_ipv6[1:-1]
                     else:
                          server = host_maybe_ipv6
                     try:
                          port = int(port_str)
                     except ValueError:
                          print(f"Thread {pid}: Invalid port for SS: {port_str}")
                          continue # Skip
                else: # No port specified
                     server = server_port_str

                if not server:
                    print(f"Thread {pid}: Skipping SS link, could not determine server address: {line[:50]}...")
                    continue

                tag_name = urllib.parse.unquote(frag).strip() if frag else generate_unique_tag(all_tags)
                if tag_name not in all_tags: all_tags.add(tag_name)

                parsed_ob = {
                    "type": "shadowsocks",
                    "tag": tag_name,
                    "server": server,
                    "server_port": port,
                    "method": method or "aes-256-gcm", # Default method if missing
                    "password": password or ""
                }

                # Handle plugin options
                plugin_match = re.search(r"\?(.*)", server_part)
                if plugin_match:
                    plugin_str = plugin_match.group(1)
                    if plugin_str.startswith("plugin="):
                         plugin_def = urllib.parse.unquote(plugin_str[len("plugin="):])
                         parts = plugin_def.split(';')
                         plugin_name = parts[0]
                         plugin_opts = {}
                         if plugin_name in ("obfs-local", "simple-obfs", "v2ray-plugin"): # Known plugins
                              parsed_ob["plugin"] = plugin_name
                              # Very basic option parsing, may need enhancement
                              for part in parts[1:]:
                                   if '=' in part:
                                        key, val = part.split('=', 1)
                                        plugin_opts[key] = val
                              if plugin_opts:
                                   parsed_ob["plugin_opts"] = plugin_opts # Store raw opts

            except Exception as e:
                print(f"Thread {pid}: Error parsing Shadowsocks link: {e} - Link: {line[:80]}...")
                parsed_ob = None # Ensure it's None on error

        # --- VLESS (vless://) ---
        elif line.startswith("vless://"):
            try:
                parsed_url = urllib.parse.urlparse(line)
                uuid = parsed_url.username
                if not uuid: raise ValueError("UUID missing")

                server_part = parsed_url.netloc.split('@')[-1] # Handle potential user@host:port format

                if ":" in server_part: # Check for explicit port
                    host_maybe_ipv6, port_str = server_part.rsplit(":", 1)
                    if host_maybe_ipv6.startswith("[") and host_maybe_ipv6.endswith("]"):
                        server = host_maybe_ipv6[1:-1] # IPv6
                    else:
                        server = host_maybe_ipv6 # IPv4 or domain
                    try:
                        port = int(port_str)
                    except ValueError: raise ValueError(f"Invalid port: {port_str}")
                else: # No port specified
                    server = server_part
                    port = 443 # Default for VLESS often TLS

                if not server: raise ValueError("Server address missing")

                params = urllib.parse.parse_qs(parsed_url.query)
                frag = parsed_url.fragment
                tag_name = urllib.parse.unquote(frag).strip() if frag else generate_unique_tag(all_tags)
                if tag_name not in all_tags: all_tags.add(tag_name)

                parsed_ob = {
                    "type": "vless",
                    "tag": tag_name,
                    "server": server,
                    "server_port": port,
                    "uuid": uuid,
                    "flow": params.get("flow", [""])[0], # Optional flow control
                    "packet_encoding": params.get("packetEncoding", params.get("packet_encoding", [""])[0]), # Optional packet encoding
                }

                # Transport Settings
                transport_type = params.get("type", [""])[0] # ws, grpc, http, etc.
                if transport_type == "ws":
                    parsed_ob["transport"] = {
                        "type": "ws",
                        "path": params.get("path", ["/"])[0],
                        "headers": {"Host": params.get("host", [server])[0]} # Use server if host header missing
                    }
                elif transport_type == "grpc":
                     parsed_ob["transport"] = {
                         "type": "grpc",
                         "serviceName": params.get("serviceName", [""])[0],
                         # Add 'multi' mode if indicated?
                         # "multiMode": params.get("mode", [""])[0] == "multi"
                     }
                # Add other transport types (h2, http) if needed

                # TLS / Security Settings
                security = params.get("security", ["none"])[0]
                if security == "tls" or security == "reality":
                     parsed_ob["tls"] = {"enabled": True}
                     # SNI (Server Name Indication)
                     sni = params.get("sni", [params.get("host", [server])[0]])[0] # Use host header or server if SNI missing
                     parsed_ob["tls"]["server_name"] = sni

                     if security == "reality":
                         parsed_ob["tls"]["reality"] = {
                             "enabled": True,
                             "public_key": params.get("pbk", [""])[0],
                             "short_id": params.get("sid", [""])[0]
                         }
                         # Fingerprint (uTLS) often used with Reality
                         fp = params.get("fp", ["chrome"])[0] # Default to chrome
                         if fp and fp != "none":
                              parsed_ob["tls"]["utls"] = {"enabled": True, "fingerprint": fp}
                     else: # Plain TLS
                         # ALPN (Application-Layer Protocol Negotiation)
                         alpn_list = [a for a in params.get("alpn", [""])[0].split(',') if a]
                         if alpn_list:
                              parsed_ob["tls"]["alpn"] = alpn_list
                         # Allow insecure? (Usually false for standard TLS)
                         parsed_ob["tls"]["insecure"] = params.get("allowInsecure", ["0"])[0] == "1"

            except Exception as e:
                print(f"Thread {pid}: Error parsing VLESS link: {e} - Link: {line[:80]}...")
                parsed_ob = None

        # --- VMess (vmess://) ---
        elif line.startswith("vmess://"):
            try:
                encoded_part = line[len("vmess://"):].strip()
                # Handle potential URL encoding before base64
                encoded_part = urllib.parse.unquote(encoded_part)

                try:
                    # Decode the base64 part
                    padding = "=" * (-len(encoded_part) % 4)
                    decoded_json = base64.b64decode(encoded_part + padding).decode("utf-8")
                    vmess_data = json.loads(decoded_json)
                except Exception as e_vmess_b64:
                     print(f"Thread {pid}: VMess Base64 decode/JSON parse error: {e_vmess_b64} - Data: {encoded_part[:50]}...")
                     continue # Skip this invalid VMess link

                # Extract data from the decoded JSON
                tag_name = vmess_data.get("ps", "").strip() or generate_unique_tag(all_tags)
                if tag_name not in all_tags: all_tags.add(tag_name)

                parsed_ob = {
                    "type": "vmess",
                    "tag": tag_name,
                    "server": vmess_data.get("add", ""),
                    "server_port": int(vmess_data.get("port", 443)),
                    "uuid": vmess_data.get("id", ""),
                    "alter_id": int(vmess_data.get("aid", 0)),
                    "security": vmess_data.get("scy", vmess_data.get("security", "auto")), # VMess encryption type
                }
                if not parsed_ob["server"] or not parsed_ob["uuid"]:
                     raise ValueError("Missing server address or UUID in VMess JSON")

                # Transport Settings
                net_type = vmess_data.get("net", "tcp")
                host = vmess_data.get("host", parsed_ob["server"]) # Use server if host missing
                path = vmess_data.get("path", "/")
                if net_type == "ws":
                    parsed_ob["transport"] = {"type": "ws", "path": path, "headers": {"Host": host}}
                elif net_type == "grpc":
                    # serviceName might be in 'path' or a separate field depending on client
                    serviceName = vmess_data.get("serviceName", path if path != "/" else "")
                    grpc_mode = vmess_data.get("mode", "gun") # Default to gun mode for grpc
                    parsed_ob["transport"] = {"type": "grpc", "serviceName": serviceName}
                    # Xray might expect multiMode: true instead of mode:"multi"
                    # if grpc_mode == "multi": parsed_ob["transport"]["multiMode"] = True
                # Add other network types (tcp, kcp, h2, quic) if needed

                # TLS Settings
                tls_type = vmess_data.get("tls", "none")
                if tls_type == "tls":
                     parsed_ob["tls"] = {
                         "enabled": True,
                         "server_name": vmess_data.get("sni", host), # Use host if SNI missing
                         # VMess JSON might have 'allowInsecure' or similar field
                         "insecure": vmess_data.get("allowInsecure", vmess_data.get("verify", True) is False)
                     }
                     # ALPN? Usually specified in 'alpn' field if needed
                     alpn_list = [a for a in vmess_data.get("alpn", "").split(',') if a]
                     if alpn_list:
                          parsed_ob["tls"]["alpn"] = alpn_list

            except Exception as e:
                print(f"Thread {pid}: Error parsing VMess link: {e} - Link: {line[:80]}...")
                parsed_ob = None

        # --- TUIC (tuic://) ---
        elif line.startswith("tuic://"):
            try:
                # TUIC v5 format: tuic://UUID:PASSWORD@SERVER:PORT?params...#TAG
                parsed_url = urllib.parse.urlparse(line)
                user_pass = parsed_url.username
                if not user_pass or ':' not in user_pass: raise ValueError("Missing UUID:PASSWORD")
                uuid, password = user_pass.split(":", 1)

                server_part = parsed_url.netloc.split('@')[-1]
                if ":" in server_part:
                    host_maybe_ipv6, port_str = server_part.rsplit(":", 1)
                    if host_maybe_ipv6.startswith("[") and host_maybe_ipv6.endswith("]"): server = host_maybe_ipv6[1:-1]
                    else: server = host_maybe_ipv6
                    try: port = int(port_str)
                    except ValueError: raise ValueError(f"Invalid port: {port_str}")
                else:
                    server = server_part
                    port = 443 # Common default

                if not server: raise ValueError("Server address missing")

                params = urllib.parse.parse_qs(parsed_url.query)
                frag = parsed_url.fragment
                tag_name = urllib.parse.unquote(frag).strip() if frag else generate_unique_tag(all_tags)
                if tag_name not in all_tags: all_tags.add(tag_name)

                parsed_ob = {
                    "type": "tuic", # Or tuic_v5 depending on parser/Xray version
                    "tag": tag_name,
                    "server": server,
                    "server_port": port,
                    "uuid": uuid,
                    "password": password,
                    "congestion_control": params.get("congestion_control", ["bbr"])[0],
                    "udp_relay_mode": params.get("udp_relay_mode", ["native"])[0], # native or quic
                    "tls": { # TUIC often implies TLS
                        "enabled": True,
                        # SNI is crucial for TUIC
                        "server_name": params.get("sni", [server])[0],
                        "insecure": params.get("allow_insecure", ["1"])[0] == "1", # Use allow_insecure=1
                        # ALPN usually h3 or specific values needed by server
                        "alpn": [a for a in params.get("alpn", ["h3"])[0].split(',') if a]
                    }
                }

            except Exception as e:
                print(f"Thread {pid}: Error parsing TUIC link: {e} - Link: {line[:80]}...")
                parsed_ob = None

        # --- WireGuard/WARP (wireguard:// or warp://) ---
        elif line.startswith(("wireguard://", "warp://")):
            try:
                 # Use the existing warp line parser which handles both
                 parsed_configs, _ = parse_warp_line(line, 0, all_tags)
                 if parsed_configs:
                      # parse_warp_line returns a list, usually with one item
                      parsed_ob = parsed_configs[0]
                 else:
                      parsed_ob = None # Parsing failed within parse_warp_line
            except Exception as e:
                 print(f"Thread {pid}: Error parsing WG/WARP link: {e} - Link: {line[:80]}...")
                 parsed_ob = None

        # --- Hysteria/Hysteria2 (hysteria:// or hysteria2:// or hy2://) ---
        elif line.startswith(("hysteria://", "hysteria2://", "hy2://")):
            try:
                 # Common format: hy2://PASSWORD@SERVER:PORT?params...#TAG
                 protocol_name = line.split("://")[0]
                 parsed_url = urllib.parse.urlparse(line)
                 password = parsed_url.username # Password is often in the username part
                 if password is None: password = "" # Allow empty password?

                 server_part = parsed_url.netloc.split('@')[-1]
                 if ":" in server_part:
                     host_maybe_ipv6, port_str = server_part.rsplit(":", 1)
                     if host_maybe_ipv6.startswith("[") and host_maybe_ipv6.endswith("]"): server = host_maybe_ipv6[1:-1]
                     else: server = host_maybe_ipv6
                     try: port = int(port_str)
                     except ValueError: raise ValueError(f"Invalid port: {port_str}")
                 else: # No port specified
                     server = server_part
                     # Hysteria default port can vary, 443 is common for TLS-based setups
                     port = 443

                 if not server: raise ValueError("Server address missing")

                 params = urllib.parse.parse_qs(parsed_url.query)
                 frag = parsed_url.fragment
                 tag_name = urllib.parse.unquote(frag).strip() if frag else generate_unique_tag(all_tags)
                 if tag_name not in all_tags: all_tags.add(tag_name)

                 parsed_ob = {
                     # Use 'hysteria2' as the likely modern type for Xray
                     "type": "hysteria2",
                     "tag": tag_name,
                     "server": server,
                     "server_port": port,
                     "password": password,
                     "tls": { # Hysteria usually uses TLS/QUIC implicitly
                         "enabled": True,
                         # SNI is crucial
                         "server_name": params.get("sni", [server])[0],
                         "insecure": params.get("insecure", ["1"])[0] == "1", # Check for insecure=1
                         # ALPN might be needed ('h3' common)
                         "alpn": [a for a in params.get("alpn", ["h3"])[0].split(',') if a]
                     }
                 }

                 # OBFS (Obfuscation) - usually salamander/meta
                 obfs_type = params.get("obfs", [""])[0]
                 if obfs_type:
                      parsed_ob["obfs"] = {
                          "type": obfs_type,
                          "password": params.get("obfs-password", [""])[0]
                      }
                 # Other Hysteria params like up/down speed? Might not map directly to Xray outbound.


            except Exception as e:
                 print(f"Thread {pid}: Error parsing Hysteria/Hy2 link: {e} - Link: {line[:80]}...")
                 parsed_ob = None

        # --- Add other protocols here if needed (Trojan, Snell, etc.) ---

        # --- Append valid parsed outbound ---
        if parsed_ob and isinstance(parsed_ob, dict) and parsed_ob.get("type"):
             protocol = parsed_ob["type"]
             protocols_found[protocol] = protocols_found.get(protocol, 0) + 1
             outbounds.append(parsed_ob)

    # --- Final Log ---
    print(f"Thread {pid}: Finished line-by-line parsing. Processed {lines_processed} lines.")
    if protocols_found:
         print(f"Thread {pid}: Protocols found: {protocols_found}")
    else:
         print(f"Thread {pid}: No known proxy protocols found in line-by-line parse.")

    return outbounds


def deduplicate_outbounds(outbounds: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Deduplicates outbounds based on core connection parameters."""
    unique: Dict[Tuple[Any, ...], Dict[str, Any]] = {}
    duplicates_found = 0

    def get_key(ob: Dict[str, Any]) -> Optional[Tuple[Any, ...]]:
        # Use 'protocol' consistently if available, fallback to 'type'
        typ = ob.get("protocol", ob.get("type", "")).lower()
        # Normalize server address (e.g., lowercase domain)
        server = str(ob.get("server", "")).lower()
        port = ob.get("server_port", "")
        if not typ or not server or not port:
            return None # Cannot deduplicate without basic info

        key_base = (typ, server, port)

        try:
            if typ == "shadowsocks":
                # Method + Password + Plugin info
                plugin = ob.get("plugin", "")
                plugin_opts = str(ob.get("plugin_opts", {})) # Basic string representation
                return key_base + (ob.get("method", ""), ob.get("password", ""), plugin, plugin_opts)
            elif typ in ("vless", "vmess", "tuic"):
                # UUID is the primary identifier
                return key_base + (ob.get("uuid", ""),)
            elif typ in ("wireguard", "warp"):
                # Private key or Public key are identifiers
                # Use private key if available, otherwise peer public key
                priv_key = ob.get("private_key", ob.get("secretKey", ""))
                pub_key = ob.get("peer_public_key", ob.get("peer", {}).get("publicKey", ""))
                if priv_key: return key_base + (priv_key,)
                if pub_key: return key_base + (pub_key,)
                return key_base # Fallback if keys missing
            elif typ in ("hysteria", "hysteria2", "hy2"):
                # Password is the identifier
                return key_base + (ob.get("password", ""),)
            else:
                # Generic fallback (type, server, port)
                return key_base
        except Exception as e:
             print(f"Warning: Error generating dedupe key for {ob.get('tag')}: {e}")
             return None # Treat as unique if key generation fails

    for ob in outbounds:
        key = get_key(ob)
        if key is None: # If key couldn't be generated, treat as unique for safety
             # Generate a temporary unique key to avoid collision
             unique[(f"nokey_{ob.get('tag', '')}_{id(ob)}",)] = ob
             continue

        if key not in unique:
            unique[key] = ob
        else:
            duplicates_found += 1
            # --- Simple Deduplication: Keep the first one encountered ---
            # More complex logic (e.g., keeping based on delay) is handled later
            # during filtering, not during initial deduplication.
            pass

    if duplicates_found > 0:
        print(f"Deduplication removed {duplicates_found} duplicate configurations.")
    return list(unique.values())


def diversify_outbounds_by_protocol(protocol_outbounds: List[Dict[str, Any]], limit: int = 75) -> List[Dict[str, Any]]:
    """Selects a diverse set of outbounds from a single protocol group based on source."""
    if len(protocol_outbounds) <= limit:
        return protocol_outbounds # No need to diversify if below limit

    groups = {}
    for ob in protocol_outbounds:
        # Use source URL or a default if missing
        src = ob.get("source", "unknown_source")
        groups.setdefault(src, []).append(ob)

    # Sort within each source group by combined delay (lower is better)
    # Use xray_delay as the primary sorting key if available
    def sort_key(o: Dict[str, Any]) -> float:
        # Prioritize xray_delay > http_delay > tcp_delay > udp_delay
        delay = o.get("xray_delay", float('inf'))
        if delay == float('inf'):
             delay = o.get("http_delay", float('inf'))
        if delay == float('inf'):
             delay = o.get("tcp_delay", float('inf'))
        if delay == float('inf'):
             delay = o.get("udp_delay", float('inf'))
        return delay

    for src in groups:
        groups[src].sort(key=sort_key)

    diversified = []
    source_keys = list(groups.keys())
    current_source_index = 0
    # Round-robin selection from sources
    while len(diversified) < limit:
        added_this_round = False
        processed_sources = 0
        while processed_sources < len(source_keys) and len(diversified) < limit:
             source_key = source_keys[current_source_index]
             if groups[source_key]: # If list for this source is not empty
                 diversified.append(groups[source_key].pop(0))
                 added_this_round = True
             # Move to the next source
             current_source_index = (current_source_index + 1) % len(source_keys)
             processed_sources += 1

        if not added_this_round:
            break # Stop if no more configs can be added from any source

    print(f"Diversified protocol group: Selected {len(diversified)} outbounds from {len(protocol_outbounds)} based on source diversity.")
    return diversified


def filter_best_outbounds_by_protocol(outbounds: List[Dict[str, Any]], tests_run: List[str]) -> List[Dict[str, Any]]:
    """
    Filters outbounds that failed required tests and then selects the best
    (up to 75) per protocol, prioritizing low latency and source diversity.
    """
    protocols: Dict[str, List[Dict[str, Any]]] = {}
    total_passed_initial_filter = 0
    print(f"Filtering best outbounds based on tests run: {tests_run}")

    for ob in outbounds:
        typ = ob.get("protocol", ob.get("type")) # Use 'protocol' first
        if not typ: continue

        passed = True
        # --- Check if required tests passed ---
        # WG/WARP primarily need UDP and/or Real delay
        if typ in ("wireguard", "warp"):
            passed_udp = ob.get("udp_delay", float('inf')) != float('inf')
            passed_real = ob.get("xray_delay", float('inf')) != float('inf')
            if 'udp' in tests_run and not passed_udp: passed = False
            # If 'real' test was run, it MUST pass for WG/WARP
            if 'real' in tests_run and not passed_real: passed = False
            # If ONLY 'udp' was run, allow it
            # If ONLY 'real' was run, allow it
            # If NEITHER udp nor real was run (unlikely based on args), don't fail it here
        else: # Other protocols (SS, Vmess, Vless, TUIC, Hysteria etc.)
            if 'tcp' in tests_run and ob.get("tcp_delay", float('inf')) == float('inf'):
                passed = False
            if 'http' in tests_run and ob.get("http_delay", float('inf')) == float('inf'):
                passed = False
            # If 'real' test was run, it must pass for non-WG types too if included in tests
            if 'real' in tests_run and ob.get("xray_delay", float('inf')) == float('inf'):
                passed = False

        # --- Add to protocol group if passed ---
        if passed:
            protocols.setdefault(typ, []).append(ob)
            total_passed_initial_filter += 1
        # else:
        #     print(f"Debug: Outbound {ob.get('tag')} failed filter. Tests: {tests_run}, Delays: tcp={ob.get('tcp_delay')}, http={ob.get('http_delay')}, real={ob.get('xray_delay')}, udp={ob.get('udp_delay')}")

    print(f"Total outbounds passed initial test filter: {total_passed_initial_filter}")

    # --- Select best per protocol (Sort, Diversify, Limit) ---
    final_filtered = []
    for typ, obs_list in protocols.items():
        print(f"Processing protocol: {typ} ({len(obs_list)} passed initial filter)")
        if not obs_list: continue

        # Sort by latency (use the combined key function)
        def sort_key(o: Dict[str, Any]) -> float:
             delay = o.get("xray_delay", float('inf'))
             if delay == float('inf'): delay = o.get("http_delay", float('inf'))
             if delay == float('inf'): delay = o.get("tcp_delay", float('inf'))
             if delay == float('inf'): delay = o.get("udp_delay", float('inf'))
             # Add a small penalty if 'real' test failed but others passed (if real was run)
             if 'real' in tests_run and o.get("xray_delay", float('inf')) == float('inf') and delay != float('inf'):
                  delay += 5000 # Add 5s penalty
             return delay
        obs_list.sort(key=sort_key)

        # Apply diversification and limit
        diversified_limited = diversify_outbounds_by_protocol(obs_list, limit=75)
        final_filtered.extend(diversified_limited)
        print(f" -> Selected {len(diversified_limited)} for protocol {typ} after diversification/limit.")

    return final_filtered


def replace_existing_outbounds(base_config: Dict[str, Any], new_outbounds: List[Dict]) -> Dict:
    """Replaces outbounds in a base config, preserving specific tags if needed."""
    # This function might need adjustments depending on the desired base config structure.
    # The current implementation replaces almost everything except selector/urltest definitions.

    existing_selector_outbounds = []
    existing_urltest_outbounds = []
    preserved_outbounds = [] # Outbounds from base_config to keep (e.g., direct, block)

    # Identify selector/urltest tags and essential outbounds (direct, block)
    selector_tag = "select" # Default selector tag name
    urltest_tag = "auto"   # Default urltest tag name
    essential_tags = {"direct", "block"} # Tags to always preserve from base config

    for outbound in base_config.get("outbounds", []):
        tag = outbound.get("tag")
        protocol = outbound.get("protocol")
        if protocol == "selector":
            selector_tag = tag # Use the actual tag found
            existing_selector_outbounds = outbound.get("outbounds", [])
            # Keep the selector definition itself, but update its 'outbounds' list later
            preserved_outbounds.append(outbound)
        elif protocol == "urltest":
            urltest_tag = tag # Use the actual tag found
            existing_urltest_outbounds = outbound.get("outbounds", [])
            # Keep the urltest definition itself
            preserved_outbounds.append(outbound)
        elif tag in essential_tags:
             preserved_outbounds.append(outbound)
        # Add other tags/protocols to preserve from base_config if needed

    new_tags = {ob["tag"] for ob in new_outbounds}
    final_outbounds = []

    # 1. Add the new (tested and renamed) outbounds
    final_outbounds.extend(new_outbounds)

    # 2. Add the preserved essential/structural outbounds (direct, block, selector, urltest definitions)
    for po in preserved_outbounds:
         # Avoid adding duplicates if a new outbound somehow has the same tag as an essential one
         if po.get("tag") not in new_tags:
              final_outbounds.append(po)

    # 3. Update the 'outbounds' lists within selector/urltest
    updated_selector_list = list(new_tags) # Start with all new tags
    updated_urltest_list = list(new_tags)

    # Add back old tags *if they still exist* in the final list (e.g., direct/block) - probably not needed
    # for tag in existing_selector_outbounds:
    #     if tag not in new_tags and any(ob.get("tag") == tag for ob in final_outbounds):
    #          updated_selector_list.append(tag)
    # for tag in existing_urltest_outbounds:
    #      if tag not in new_tags and any(ob.get("tag") == tag for ob in final_outbounds):
    #          updated_urltest_list.append(tag)

    # Ensure 'auto' (urltest) is present in selector if urltest exists
    if any(ob.get("tag") == urltest_tag for ob in final_outbounds):
         if urltest_tag not in updated_selector_list:
              updated_selector_list.insert(0, urltest_tag) # Add urltest tag, often at the beginning

    # Find and update the selector/urltest definitions in the final list
    selector_found = False
    urltest_found = False
    for ob in final_outbounds:
         if ob.get("tag") == selector_tag and ob.get("protocol") == "selector":
             ob["outbounds"] = updated_selector_list
             # Set default for selector? 'auto' or the first new tag?
             ob["default"] = urltest_tag if urltest_tag in updated_selector_list else (updated_selector_list[0] if updated_selector_list else "direct")
             selector_found = True
         elif ob.get("tag") == urltest_tag and ob.get("protocol") == "urltest":
              ob["outbounds"] = updated_urltest_list
              # Update urltest parameters if needed
              ob["url"] = ob.get("url", "https://clients3.google.com/generate_204")
              ob["interval"] = ob.get("interval", "10m0s")
              urltest_found = True

    # If selector/urltest definitions were NOT preserved/found, add default ones
    if not selector_found:
        print(f"Adding default selector outbound with tag '{selector_tag}'.")
        final_outbounds.append({
            "protocol": "selector",
            "tag": selector_tag,
            "outbounds": updated_selector_list,
            "default": urltest_tag if urltest_found else (updated_selector_list[0] if updated_selector_list else "direct")
        })
    if not urltest_found and updated_urltest_list: # Only add urltest if there are proxies
        print(f"Adding default urltest outbound with tag '{urltest_tag}'.")
        final_outbounds.append({
            "protocol": "urltest",
            "tag": urltest_tag,
            "outbounds": updated_urltest_list,
            "url": "https://clients3.google.com/generate_204", # Standard test URL
            "interval": "10m0s" # 10 minute check interval
        })

    # Update the main config's outbounds list
    base_config["outbounds"] = final_outbounds
    return base_config


# --- Basic Delay Tests (TCP, HTTP, UDP) ---
# These are run *before* the 'real' test if specified, to pre-filter

async def tcp_test_outbound(ob: Dict[str, Any]) -> None:
    """Performs a basic TCP connection test."""
    tag = ob.get("tag")
    server = ob.get("server")
    port = ob.get("server_port")
    result_key = "tcp_delay"

    if not server or not port:
        ob[result_key] = float('inf')
        # print(f"TCP Test {tag}: Skip (no server/port)")
        return

    loop = asyncio.get_running_loop()
    start = loop.time()
    writer = None
    try:
        # Resolve DNS first (using system resolver) - may fail if host unreachable
        # Use first resolved address. Add try-except for DNS resolution failure.
        try:
            addr_info = await loop.getaddrinfo(server, port, proto=socket.IPPROTO_TCP)
            target_ip, target_port = addr_info[0][4][:2] # Use first resolved IP/port
            # print(f"TCP Test {tag}: Resolved {server} to {target_ip}")
        except socket.gaierror as dns_error:
             # print(f"TCP Test {tag}: DNS resolution failed for {server}: {dns_error}")
             ob[result_key] = float('inf')
             return

        # print(f"TCP Test {tag}: Connecting to {target_ip}:{target_port}...")
        # Short connection timeout
        _, writer = await asyncio.wait_for(asyncio.open_connection(target_ip, target_port), timeout=5)
        delay = (loop.time() - start) * 1000
        ob[result_key] = delay
        # print(f"TCP Test {tag}: Success ({delay:.0f} ms)")
    except (asyncio.TimeoutError, OSError, ConnectionRefusedError, socket.gaierror) as e:
        ob[result_key] = float('inf')
        # Short error message
        # print(f"TCP Test {tag}: Fail ({type(e).__name__})")
    except Exception as e: # Catch unexpected errors
         ob[result_key] = float('inf')
         print(f"TCP Test {tag}: Unexpected Error - {type(e).__name__}: {e}")
    finally:
        if writer:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass # Ignore errors during close

async def http_delay_test_outbound(ob: Dict[str, Any], proxy: Optional[str], repetitions: int) -> None:
    """Performs HTTP latency tests WITHOUT using Xray (direct or via optional *external* proxy)."""
    # This is different from measure_xray_latency_http which uses the internal Xray SOCKS proxy.
    # This test is less realistic for evaluating the specific outbound config via Xray.
    # Consider removing or clearly distinguishing its purpose (e.g., testing if server IP is web-accessible).

    tag = ob.get("tag")
    server = ob.get("server")
    port = ob.get("server_port")
    result_key = "http_delay" # Standard HTTP test (distinct from xray http test)

    if not server or not port:
        ob[result_key] = float('inf')
        # print(f"HTTP Direct Test {tag}: Skip (no server/port)")
        return

    # Use a small list of reliable HTTP(S) check URLs
    test_urls = [
        "http://detectportal.firefox.com/success.txt",
        "https://google.com/generate_204",
        "http://neverssl.com",
    ]
    session = requests.Session()
    session.trust_env = False # Isolate from system proxies
    if proxy:
         session.proxies = {'http': proxy, 'https': proxy}

    times = []
    loop = asyncio.get_running_loop()

    # print(f"HTTP Direct Test {tag} ({server}:{port}) started ({repetitions} reps)...")

    async def fetch_http(url: str) -> Optional[float]:
        start_time = time.time()
        try:
            # Run requests call in a separate thread via asyncio's executor
            response = await loop.run_in_executor(
                None, # Use default ThreadPoolExecutor
                lambda: session.get(url, timeout=5, allow_redirects=False, verify=False) # Short timeout, ignore redirects, ignore cert errors
            )
            response.raise_for_status()
            elapsed = (time.time() - start_time) * 1000
            # print(f"[{tag}] HTTP Direct Rep {i+1} OK ({url}): {elapsed:.0f} ms")
            return elapsed
        except requests.exceptions.RequestException as e:
            # print(f"[{tag}] HTTP Direct Rep {i+1} Fail ({url}): {type(e).__name__}")
            return None
        except Exception as e:
            print(f"[{tag}] HTTP Direct Rep {i+1} Unexpected Error ({url}): {type(e).__name__}: {e}")
            return None


    # Run repetitions
    all_results = []
    for i in range(repetitions):
         rep_results = []
         # Try each URL once per repetition
         tasks = [fetch_http(url) for url in test_urls]
         results_this_rep = await asyncio.gather(*tasks)
         successful_times_this_rep = [t for t in results_this_rep if t is not None]

         if successful_times_this_rep:
              # Take the best time from this repetition
              best_time_this_rep = min(successful_times_this_rep)
              all_results.append(best_time_this_rep)
         # else: # All URLs failed this repetition
              # all_results.append(float('inf')) # Could add inf, but averaging only successes might be better

    if all_results:
        avg = sum(all_results) / len(all_results)
        ob[result_key] = avg
        # print(f"HTTP Direct Test {tag} finished: Avg delay = {avg:.0f} ms over {len(all_results)} successful reps")
    else:
        ob[result_key] = float('inf')
        # print(f"HTTP Direct Test {tag} finished: All {repetitions} reps failed.")


async def udp_test_outbound(ob: Dict[str, Any]) -> None:
    """Performs a basic UDP connection/send test (e.g., for WireGuard initial check)."""
    tag = ob.get("tag")
    server = ob.get("server")
    port = ob.get("server_port")
    result_key = "udp_delay"

    if not server or not port or not str(port).isdigit(): # Ensure port is valid
        ob[result_key] = float('inf')
        # print(f"UDP Test {tag}: Skip (no server/port)")
        return

    port = int(port)
    ip = None
    try:
        # Resolve DNS first using asyncio's resolver
        loop = asyncio.get_running_loop()
        addr_info = await loop.getaddrinfo(server, port, proto=socket.IPPROTO_UDP)
        ip, target_port = addr_info[0][4][:2] # Use first resolved IP
        # print(f"UDP Test {tag}: Resolved {server} to {ip}")
    except socket.gaierror as dns_error:
        # print(f"UDP Test {tag}: DNS resolution failed for {server}: {dns_error}")
        ob[result_key] = float('inf')
        return
    except Exception as e:
         print(f"UDP Test {tag}: Unexpected DNS Error - {type(e).__name__}: {e}")
         ob[result_key] = float('inf')
         return

    start = loop.time()
    transport = None
    # print(f"UDP Test {tag}: Sending packet to {ip}:{port}...")
    try:
        # Create datagram endpoint and send a small packet
        transport, _ = await loop.create_datagram_endpoint(
            lambda: asyncio.DatagramProtocol(), remote_addr=(ip, port)
        )
        transport.sendto(b"PING")
        # Wait a very short time - we don't expect a reply, just that sendto didn't error immediately
        await asyncio.sleep(0.1)
        delay = (loop.time() - start) * 1000 # Measure time to resolve + send
        ob[result_key] = delay
        # print(f"UDP Test {tag}: Send OK ({delay:.0f} ms)")
    except (asyncio.TimeoutError, OSError, ConnectionRefusedError) as e:
        # ConnectionRefusedError can happen with UDP if previous ICMP port unreachable msg received
        ob[result_key] = float('inf')
        # print(f"UDP Test {tag}: Fail ({type(e).__name__})")
    except Exception as e: # Catch unexpected errors
         ob[result_key] = float('inf')
         print(f"UDP Test {tag}: Unexpected Error - {type(e).__name__}: {e}")
    finally:
        if transport:
            try:
                transport.close()
            except Exception:
                pass # Ignore errors during close


# --- Test Execution Wrapper ---
def run_async_test(test_func, ob, *args):
    """Runs an async test function for a single outbound in the current event loop."""
    global is_ctrl_c_pressed
    if is_ctrl_c_pressed:
         # print(f"Skipping test for {ob.get('tag')} due to Ctrl+C.")
         return # Don't start new tests if stopping

    tag = ob.get('tag', 'unknown')
    try:
        # Create a new event loop for each task run in thread pool
        # This avoids issues with loops being closed or reused across threads
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(test_func(ob, *args))
        loop.close()
    except RuntimeError as e:
         if "cannot schedule new futures after shutdown" in str(e):
              print(f"Warning: Event loop issue during test for {tag} (likely shutdown): {e}")
         else:
              print(f"RuntimeError during async test for {tag}: {e}")
         # Mark as failed if error occurs during execution
         fail_key = {
              tcp_test_outbound: "tcp_delay",
              http_delay_test_outbound: "http_delay",
              udp_test_outbound: "udp_delay"
         }.get(test_func, "unknown_delay")
         ob[fail_key] = float('inf')
    except Exception as e:
        print(f"Exception in run_async_test for tag {tag} ({test_func.__name__}): {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc() # Print stack trace for debugging async errors
        # Mark as failed
        fail_key = {
             tcp_test_outbound: "tcp_delay",
             http_delay_test_outbound: "http_delay",
             udp_test_outbound: "udp_delay"
        }.get(test_func, "unknown_delay")
        ob[fail_key] = float('inf')


def single_test_pass(outbounds: List[Dict[str, Any]],
                     test_type: str,
                     thread_pool_size=32,
                     proxy_for_http_test: Optional[str] = None, # Renamed for clarity
                     http_repetitions: int = 3) -> None: # Renamed for clarity
    """Runs a specific type of test (tcp, http, udp, real) across all outbounds using a thread pool."""
    global completed_outbounds_count, total_outbounds_count, is_ctrl_c_pressed
    completed_outbounds_count = 0 # Reset count for this pass
    total_outbounds_count = len(outbounds)
    if total_outbounds_count == 0:
         print(f"Skipping test pass '{test_type}': No outbounds to test.")
         return

    print(f"\n=== Starting Test Pass: {test_type.upper()} ({total_outbounds_count} outbounds) ===")
    start_time_pass = time.time()

    # Use context manager for ThreadPoolExecutor
    with concurrent.futures.ThreadPoolExecutor(max_workers=thread_pool_size, thread_name_prefix=f'Test_{test_type}') as executor:
        futures = []
        future_to_tag = {}

        for ob in outbounds:
            if is_ctrl_c_pressed:
                print(f"Ctrl+C detected during submission for '{test_type}' pass. No more tests will be scheduled.")
                break # Stop submitting new tasks

            tag = ob.get("tag")
            future = None
            if test_type == "tcp":
                future = executor.submit(run_async_test, tcp_test_outbound, ob)
            elif test_type == "http":
                # Note: This uses the basic http_delay_test_outbound, NOT the xray one
                future = executor.submit(run_async_test, http_delay_test_outbound, ob, proxy_for_http_test, http_repetitions)
            elif test_type == "udp":
                future = executor.submit(run_async_test, udp_test_outbound, ob)
            elif test_type == "real":
                # real_delay_test_outbound is synchronous internally (manages subprocess) but can be run in thread pool
                future = executor.submit(real_delay_test_outbound, ob)
            else:
                print(f"Error: Invalid test type '{test_type}' in single_test_pass.")
                continue # Should not happen

            if future:
                futures.append(future)
                future_to_tag[future] = tag

        print(f"Submitted {len(futures)} {test_type} tests to thread pool. Waiting for completion...")

        # Process completed futures
        try:
            for i, future in enumerate(concurrent.futures.as_completed(futures)):
                if is_ctrl_c_pressed and i % 10 == 0: # Check periodically
                     print(f"Stop requested, waiting for currently running {test_type} tests...")
                     # Don't break here, let already running tasks finish if possible

                tag = future_to_tag[future]
                try:
                    # Get result (or raise exception if task failed)
                    future.result() # We don't use the return value directly here, errors are handled inside wrappers
                except Exception as e:
                    # Errors within the submitted task *should* be caught by wrappers,
                    # but catch here just in case.
                    print(f"Error retrieving result for {test_type} test of tag {tag}: {type(e).__name__}: {e}")
                    # Ensure the corresponding delay key is set to infinity
                    delay_key = f"{test_type}_delay"
                    if test_type == "real": delay_key = "xray_delay"
                    ob_ref = next((o for o in outbounds if o.get("tag") == tag), None)
                    if ob_ref: ob_ref[delay_key] = float('inf')

                finally:
                    completed_outbounds_count += 1
                    # Print progress update less frequently to reduce log spam
                    if completed_outbounds_count % max(1, total_outbounds_count // 20) == 0 or completed_outbounds_count == total_outbounds_count:
                        percentage_completed = (completed_outbounds_count / total_outbounds_count) * 100
                        elapsed_time = time.time() - start_time_pass
                        print(f"Progress ({test_type}): {percentage_completed:.1f}% ({completed_outbounds_count}/{total_outbounds_count}) | Elapsed: {elapsed_time:.1f}s")

        except KeyboardInterrupt: # Catch Ctrl+C during as_completed iteration
             print(f"\nCtrl+C caught during {test_type} test completion. Cancelling remaining...")
             is_ctrl_c_pressed = True # Ensure flag is set
             # Attempt to cancel pending futures (may not work for already running tasks)
             cancelled_count = 0
             for f in futures:
                 if f.cancel():
                      cancelled_count += 1
             print(f"Requested cancellation for {cancelled_count} pending {test_type} futures.")

    end_time_pass = time.time()
    print(f"=== Finished Test Pass: {test_type.upper()} ({completed_outbounds_count}/{total_outbounds_count} completed) in {end_time_pass - start_time_pass:.2f}s ===")


# --- Output Generation ( Largely Unchanged, ensure robustness ) ---
def convert_outbound_to_string(ob: Dict[str, Any]) -> Optional[str]:
    """Converts an outbound dictionary back to a shareable link format."""
    # Use 'protocol' if available, fallback to 'type'
    protocol = ob.get("protocol", ob.get("type", "")).lower()
    tag = ob.get("tag", "")
    # Ensure required fields are present
    server = ob.get("server")
    port = ob.get("server_port")

    try: # Wrap conversion in try-except for robustness
        if protocol == "shadowsocks":
            if not server or not port or "method" not in ob or "password" not in ob: return None
            method = ob["method"]
            password = ob["password"]
            userinfo = base64.urlsafe_b64encode(f"{method}:{password}".encode()).decode().rstrip("=")
            link = f"ss://{userinfo}@{server}:{port}"
            # Add plugin string if present
            if ob.get("plugin") and ob.get("plugin_opts"):
                opts_str = ";".join([f"{k}={v}" for k,v in ob["plugin_opts"].items()])
                plugin_str = f"plugin={urllib.parse.quote(ob['plugin'] + ';' + opts_str)}"
                link += f"?{plugin_str}"
            link += f"#{urllib.parse.quote(tag)}"
            return link

        elif protocol == "vless":
            if not server or not port or "uuid" not in ob: return None
            uuid = ob["uuid"]
            query_params = {}
            # Basic VLESS params
            sec = "none" # Default
            if ob.get("tls", {}).get("enabled"):
                sec = "tls"
                if ob.get("tls", {}).get("reality", {}).get("enabled"):
                    sec = "reality"
            if sec != "none": query_params["security"] = sec

            if ob.get("flow"): query_params["flow"] = ob["flow"]
            tp = ob.get("transport", {}).get("type")
            if tp: query_params["type"] = tp

            # TLS/Reality specific params
            tls_settings = ob.get("tls", {})
            if tls_settings.get("enabled"):
                if tls_settings.get("server_name"): query_params["sni"] = tls_settings["server_name"]
                reality_settings = tls_settings.get("reality", {})
                if reality_settings.get("enabled"):
                    if reality_settings.get("public_key"): query_params["pbk"] = reality_settings["public_key"]
                    if reality_settings.get("short_id"): query_params["sid"] = reality_settings["short_id"]
                    # Fingerprint
                    utls_settings = tls_settings.get("utls", {})
                    if utls_settings.get("enabled") and utls_settings.get("fingerprint"):
                         query_params["fp"] = utls_settings["fingerprint"]
                else: # Plain TLS params
                    if tls_settings.get("alpn"): query_params["alpn"] = ",".join(tls_settings["alpn"])
                    # allowInsecure needs mapping back? often default is secure=0
                    # if tls_settings.get("insecure"): query_params["allowInsecure"] = "1"

            # Transport specific params
            transport_settings = ob.get("transport", {})
            if tp == "ws":
                if transport_settings.get("path"): query_params["path"] = transport_settings["path"]
                if transport_settings.get("headers", {}).get("Host"): query_params["host"] = transport_settings["headers"]["Host"]
            elif tp == "grpc":
                if transport_settings.get("serviceName"): query_params["serviceName"] = transport_settings["serviceName"]
                # if transport_settings.get("multiMode"): query_params["mode"] = "multi"

            query_str = urllib.parse.urlencode(query_params) if query_params else ""
            link = f"vless://{uuid}@{server}:{port}"
            if query_str: link += f"?{query_str}"
            link += f"#{urllib.parse.quote(tag)}"
            return link

        elif protocol == "vmess":
            # Reconstruct the original JSON format for VMess links
            if not server or not port or "uuid" not in ob: return None
            config_json = {
                "v": "2", # Version 2 is standard
                "ps": tag,
                "add": server,
                "port": str(port), # Port as string
                "id": ob["uuid"],
                "aid": str(ob.get("alter_id", 0)),
                "scy": ob.get("security", "auto"), # VMess encryption
                "net": "tcp", # Default network
                "type": "none", # Default header type for tcp
                "host": "", # Default host
                "path": "", # Default path
                "tls": "", # Default tls setting (empty string means none)
                "sni": "", # Default SNI
                "alpn": "" # Default ALPN
            }
            # Transport
            transport = ob.get("transport", {})
            net_type = transport.get("type")
            if net_type:
                 config_json["net"] = net_type
                 if net_type == "ws":
                      config_json["path"] = transport.get("path", "/")
                      config_json["host"] = transport.get("headers", {}).get("Host", server)
                 elif net_type == "grpc":
                      config_json["path"] = transport.get("serviceName", "") # serviceName often in path for grpc
                      # config_json["mode"] = "multi" if transport.get("multiMode") else "gun"
                 # Add other net types if needed

            # TLS
            tls = ob.get("tls", {})
            if tls.get("enabled"):
                 config_json["tls"] = "tls"
                 config_json["sni"] = tls.get("server_name", config_json["host"])
                 # config_json["allowInsecure"] = tls.get("insecure", False) # Not standard field?
                 if tls.get("alpn"): config_json["alpn"] = ",".join(tls["alpn"])

            config_b64 = base64.b64encode(json.dumps(config_json, separators=(',', ':')).encode()).decode().rstrip("=")
            return f"vmess://{config_b64}" # Tag is already inside the base64 part ("ps")

        elif protocol == "tuic":
            # Reconstruct TUIC v5 link
            if not server or not port or "uuid" not in ob or "password" not in ob: return None
            uuid = ob["uuid"]
            password = ob["password"]
            query_params = {
                 # No need to include password in query for v5 link format
                 "congestion_control": ob.get("congestion_control", "bbr"),
                 "udp_relay_mode": ob.get("udp_relay_mode", "native"),
            }
            tls = ob.get("tls", {})
            if tls.get("enabled"):
                 if tls.get("server_name"): query_params["sni"] = tls["server_name"]
                 if tls.get("insecure"): query_params["allow_insecure"] = "1"
                 if tls.get("alpn"): query_params["alpn"] = ",".join(tls["alpn"])
            else: # Should not happen for TUIC usually
                 query_params["disable_sni"] = "1" # Indicate SNI disabled?

            query_str = urllib.parse.urlencode(query_params)
            link = f"tuic://{uuid}:{password}@{server}:{port}"
            if query_str: link += f"?{query_str}"
            link += f"#{urllib.parse.quote(tag)}"
            return link

        elif protocol in ("wireguard", "warp"):
            if not server or not port or ("private_key" not in ob and "secretKey" not in ob): return None
            private_key = ob.get("private_key", ob.get("secretKey", ""))
            query_params = {}
            # Map back local addresses
            local_addr = ob.get("address", [])
            if local_addr: query_params["address"] = ",".join(local_addr)
            # Peer public key
            peer_key = ob.get("peer_public_key", ob.get("peers", [{}])[0].get("publicKey", ""))
            if peer_key: query_params["publickey"] = peer_key
            # Reserved bytes
            reserved_val = ob.get("reserved", ob.get("peers", [{}])[0].get("reserved", []))
            # Convert list of ints back to comma-sep string if needed, or use original string
            if isinstance(reserved_val, list) and reserved_val:
                 query_params["reserved"] = ",".join(map(str, reserved_val))
            elif isinstance(reserved_val, str) and reserved_val:
                 query_params["reserved"] = reserved_val
            # MTU
            if ob.get("mtu"): query_params["mtu"] = str(ob["mtu"])

            query_str = urllib.parse.urlencode(query_params)
            # Use wireguard:// scheme
            link = f"wireguard://{server}:{port}" # Host/port first
            if query_str: link += f"?{query_str}"
            # Add private key after fragment identifier? This seems non-standard.
            # Standard WG links often don't include private key directly.
            # Let's put private key in a non-standard query param? Or assume config file usage.
            # For link generation, maybe omit private key? Or add as 'pk='?
            # Let's omit for standard link generation. Config files are better for WG.
            link += f"#{urllib.parse.quote(tag)}"
            # print(f"Warning: WireGuard link generated for {tag} omits private key. Use config files for WG.")
            # Alternative (non-standard link):
            # query_params["pk"] = private_key
            # query_str = urllib.parse.urlencode(query_params)
            # link = f"wireguard://{server}:{port}?{query_str}#{urllib.parse.quote(tag)}"
            return link # Return link without private key for now

        elif protocol in ("hysteria", "hysteria2", "hy2"):
            if not server or not port or "password" not in ob: return None
            password = ob["password"]
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
            # Use hy2:// scheme
            link = f"hy2://{password}@{server}:{port}"
            if query_str: link += f"?{query_str}"
            link += f"#{urllib.parse.quote(tag)}"
            return link

        else:
            print(f"Warning: Cannot convert unknown protocol '{protocol}' for tag '{tag}' to string link.")
            return None

    except Exception as e:
        print(f"Error converting outbound {tag} (protocol: {protocol}) to string: {e}")
        return None


def save_config(outbounds: List[Dict[str, Any]], filepath: str = "merged_config.txt", base64_output: bool = True):
    """Saves the list of tested outbounds to a file, either as raw links or base64 encoded."""
    if not outbounds:
        print("No valid outbounds to save.")
        # Create empty file
        with open(filepath, "w") as outfile:
            outfile.write("")
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
             print("No outbounds could be converted to string format. Saving empty file.")
             output_str = ""
        else:
            output_str = "\n".join(output_lines)

        if base64_output:
            # Encode the entire multi-line string as base64
            output_str = base64.b64encode(output_str.encode()).decode()
            save_format = "single-line base64 encoded"
        else:
            save_format = "multi-line plaintext"

        with open(filepath, "w") as outfile:
            outfile.write(output_str)

        print(f"Merged {len(output_lines)} configs saved to {filepath} in {save_format} format.")

    except Exception as e:
        print(f"::error:: Error saving config to {filepath}: {e}")
        # Attempt to save partial results maybe? Or just log error.


def rename_outbound_tags(configs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Renames tags to a standardized format '🔒Pr0xySh4rk🦈[PROTOCOL_ABBR][COUNT]'."""
    protocol_abbr = {
        "shadowsocks": "SS",
        "vless": "VL",
        "vmess": "VM",
        "tuic": "TU",
        "wireguard": "WG",
        "warp": "WG", # Group warp with wireguard
        "hysteria": "HY", # Group old hysteria
        "hysteria2": "HY",# Group new hysteria
        "hy2": "HY",      # Group hy2 alias
        "trojan": "TJ",
        "snell": "SN",
        # Add other protocols if needed
    }
    renamed_configs = []
    protocol_counts: Dict[str, int] = {}
    unknown_count = 0

    print(f"Renaming tags for {len(configs)} configurations...")

    for config in configs:
        # Use protocol if available, fallback to type
        protocol = config.get("protocol", config.get("type", "unknown")).lower()

        abbr = protocol_abbr.get(protocol)
        if abbr:
            protocol_counts[abbr] = protocol_counts.get(abbr, 0) + 1
            count = protocol_counts[abbr]
            # Limit count per protocol if needed (already handled by filter_best?)
            # if count > 75: continue
            new_tag = f"🔒Pr0xySh4rk🦈{abbr}{count:02d}" # Use 2 digits for count
        else:
            unknown_count += 1
            print(f"Warning: Unknown protocol '{protocol}' for tag '{config.get('tag')}'. Using 'XX' prefix.")
            new_tag = f"🔒Pr0xySh4rk🦈XX{unknown_count:02d}"

        # print(f"Renaming '{config.get('tag')}' to '{new_tag}'")
        config["tag"] = new_tag
        renamed_configs.append(config)

    print("Tag renaming complete.")
    return renamed_configs

# --- Connectivity Check (Unchanged) ---
def check_connectivity(url="https://www.google.com", timeout=10):
    """Tests basic internet connectivity without using any proxies."""
    print(f"Testing direct internet connectivity to {url}...")
    try:
        # Use a session that explicitly ignores environment proxies
        session = requests.Session()
        session.trust_env = False
        response = session.get(url, timeout=timeout)
        response.raise_for_status()
        print(f"✅ Direct internet connectivity test passed! (Status: {response.status_code})")
        return True
    except requests.exceptions.RequestException as e:
        print(f"❌ Direct internet connectivity test failed: {e}")
        # Fallback check? Maybe try another URL?
        try:
            print("Attempting fallback connectivity check to http://neverssl.com...")
            session = requests.Session()
            session.trust_env = False
            response = session.get("http://neverssl.com", timeout=timeout)
            response.raise_for_status()
            print(f"✅ Fallback connectivity check passed! (Status: {response.status_code})")
            return True
        except requests.exceptions.RequestException as e2:
            print(f"❌ Fallback connectivity check also failed: {e2}")
            return False
    except Exception as e:
         print(f"❌ Unexpected error during connectivity check: {e}")
         return False


# --- Main Execution Logic ---
def fetch_and_parse_subscription_thread(url: str, proxy: Optional[str], all_tags: set) -> List[Dict[str, Any]]:
    """Worker function to fetch and parse a single subscription URL."""
    global is_ctrl_c_pressed
    if is_ctrl_c_pressed: return [] # Exit early if stop requested

    pid = os.getpid()
    print(f"Thread {pid}: Processing subscription URL: {url}")
    content = fetch_content(url, proxy)

    if is_ctrl_c_pressed: return [] # Check again after fetch

    if content:
        # Pass the shared all_tags set for unique tag generation
        outbounds_list = parse_config_url1_2(content, all_tags)
        if outbounds_list:
            # Add source URL to each outbound for tracking/diversification
            for outbound in outbounds_list:
                outbound["source"] = url
            print(f"Thread {pid}: Parsed {len(outbounds_list)} outbounds from {url}")
            return outbounds_list
        else:
            print(f"Thread {pid}: No outbounds parsed from {url}")
            return []
    else:
        print(f"Thread {pid}: Failed to fetch content from {url}, skipping.")
        return []

def main():
    global is_ctrl_c_pressed, total_outbounds_count, completed_outbounds_count
    # Setup signal handling for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    parser = argparse.ArgumentParser(description="Pr0xySh4rk Config Merger & Tester - Multi-threaded")
    parser.add_argument("--input", required=True, help="Input subscription file (URLs, one per line, plain text or base64 encoded list)")
    parser.add_argument("--output", required=True, help="Output file path for the final merged links")
    parser.add_argument("--proxy", help="Optional SOCKS or HTTP proxy for fetching subscription URLs (e.g., 'socks5://127.0.0.1:1080')")
    parser.add_argument("--threads", type=int, default=os.cpu_count() * 2, help=f"Number of threads for fetching and testing (default: {os.cpu_count() * 2})")
    # Removed --test-proxy, as tests should ideally run directly or via Xray instance
    # parser.add_argument("--test-proxy", help="Optional proxy for basic HTTP testing (e.g., 'http://127.0.0.1:1080')")
    parser.add_argument("--http-reps", type=int, default=3, help="Basic HTTP test repetitions (default: 3) - Used if 'http' is in --test")
    parser.add_argument("--test", choices=["tcp", "udp", "http", "tcp+http", "real", "http+real", "tcp+real", "tcp+http+real", "udp+real"], # Added udp+real
                        default="real", help="Test type(s) to run. 'real' uses Xray. Combined tests run sequentially. (default: real)")
    parser.add_argument("--no-base64", action="store_true", dest="no_base64_output",
                        help="Output links as multi-line plaintext instead of single-line base64")
    parser.set_defaults(no_base64_output=False)
    args = parser.parse_args()

    start_time_main = time.time()

    print("--- Pr0xySh4rk Initializing ---")
    print(f"Input File: {args.input}")
    print(f"Output File: {args.output}")
    print(f"Fetch Proxy: {args.proxy or 'None'}")
    print(f"Max Threads: {args.threads}")
    print(f"Tests to Run: {args.test}")
    print(f"Output Format: {'Plaintext' if args.no_base64_output else 'Base64'}")

    # --- 1. Connectivity Check ---
    if not check_connectivity():
        print("::error::Exiting due to failed internet connectivity test.")
        sys.exit(1) # Exit if no basic internet

    # --- 2. Read Subscription URLs ---
    subscription_urls: List[str] = []
    try:
        with open(args.input, "rb") as f:
            raw_content = f.read()
        # Try decoding as UTF-8 first
        try:
             decoded_content = raw_content.decode("utf-8").strip()
        except UnicodeDecodeError:
             # Fallback to latin-1 if UTF-8 fails
             print("Warning: Input file is not valid UTF-8, trying latin-1.")
             decoded_content = raw_content.decode("latin-1").strip()

        # Check if the decoded content itself might be base64
        is_likely_base64 = False
        if len(decoded_content) > 50 and re.match(r"^[a-zA-Z0-9+/=\s]*$", decoded_content):
             try:
                  # Attempt a strict decode to see if it looks like base64
                  base64.b64decode(decoded_content.replace("\n", "").replace("\r", ""), validate=True)
                  is_likely_base64 = True
             except Exception:
                  is_likely_base64 = False

        if is_likely_base64:
             print("Input content looks like base64, attempting decode...")
             try:
                  # Decode the base64 content to get the actual list of URLs
                  decoded_list = base64.b64decode(decoded_content.replace("\n", "").replace("\r", ""), validate=True).decode("utf-8")
                  subscription_urls = [line.strip() for line in decoded_list.splitlines() if line.strip() and not line.strip().startswith(("#", "//"))]
                  print(f"Decoded {len(subscription_urls)} URLs from base64 input.")
             except Exception as e:
                  print(f"::error::Failed to decode base64 input content: {e}. Please provide plain text URLs or a valid base64 encoded list.")
                  sys.exit(1)
        else:
             # Assume plain text URLs
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


    # --- 3. Fetch and Parse Subscriptions Concurrently ---
    print(f"\n--- Fetching and Parsing {len(subscription_urls)} Subscriptions ---")
    all_tags: set = set() # Shared set to track generated/used tags
    parsed_outbounds_lists: List[List[Dict[str, Any]]] = []
    fetch_start_time = time.time()

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads, thread_name_prefix='Fetcher') as executor:
        # Pass the shared 'all_tags' set to each worker
        futures = [executor.submit(fetch_and_parse_subscription_thread, url, args.proxy, all_tags)
                   for url in subscription_urls]
        try:
            for future in concurrent.futures.as_completed(futures):
                if is_ctrl_c_pressed:
                    print("Stop requested during subscription fetching/parsing.")
                    break
                try:
                    result = future.result()
                    if result: # Only append if non-empty list returned
                        parsed_outbounds_lists.append(result)
                except Exception as e:
                     print(f"::error::Error processing subscription future: {e}") # Log errors from futures

        except KeyboardInterrupt:
             print("\nCtrl+C caught during fetching. Stopping...")
             is_ctrl_c_pressed = True
             # Cancel pending futures
             # for f in futures: f.cancel() # Executor shutdown handles this

    fetch_end_time = time.time()
    print(f"Subscription fetching/parsing completed in {fetch_end_time - fetch_start_time:.2f}s.")

    if is_ctrl_c_pressed:
        print("Exiting early due to stop request during fetch/parse.")
        save_config([], filepath=args.output, base64_output=(not args.no_base64_output))
        sys.exit(0)

    # Flatten the list of lists and perform initial deduplication
    all_parsed_outbounds = [ob for sublist in parsed_outbounds_lists for ob in sublist]
    print(f"\nTotal parsed outbounds before deduplication: {len(all_parsed_outbounds)}")
    if not all_parsed_outbounds:
         print("::warning::No outbounds were parsed from any subscription. Saving empty output.")
         save_config([], filepath=args.output, base64_output=(not args.no_base64_output))
         sys.exit(0)

    all_parsed_outbounds = deduplicate_outbounds(all_parsed_outbounds)
    print(f"Total unique outbounds after deduplication: {len(all_parsed_outbounds)}")


    # --- 4. Run Selected Tests ---
    tests_to_run = args.test.split('+')
    print(f"\n--- Running Test Sequence: {' -> '.join(t.upper() for t in tests_to_run)} ---")

    current_outbounds = all_parsed_outbounds
    # Clear previous delay results before running tests
    for ob in current_outbounds:
         ob.pop("tcp_delay", None)
         ob.pop("http_delay", None)
         ob.pop("udp_delay", None)
         ob.pop("xray_delay", None)

    for test_name in tests_to_run:
        if is_ctrl_c_pressed:
            print(f"Stop requested before running '{test_name}' test.")
            break

        # Select the appropriate function and arguments for single_test_pass
        if test_name == "tcp":
            single_test_pass(current_outbounds, "tcp", args.threads)
            current_outbounds = [ob for ob in current_outbounds if ob.get("tcp_delay", float('inf')) != float('inf')]
        elif test_name == "http":
            # Using basic HTTP test here, requires proxy arg if needed
            # Pass None for proxy_for_http_test as we usually want direct basic http test
            single_test_pass(current_outbounds, "http", args.threads, None, args.http_reps)
            current_outbounds = [ob for ob in current_outbounds if ob.get("http_delay", float('inf')) != float('inf')]
        elif test_name == "udp":
             # Primarily for WG/Hysteria/TUIC
             # Filter based on protocol type before running UDP test? Or run on all?
             # Let's run on all for simplicity, non-UDP protocols will likely fail fast.
            single_test_pass(current_outbounds, "udp", args.threads)
            current_outbounds = [ob for ob in current_outbounds if ob.get("udp_delay", float('inf')) != float('inf')]
        elif test_name == "real":
            single_test_pass(current_outbounds, "real", args.threads)
            current_outbounds = [ob for ob in current_outbounds if ob.get("xray_delay", float('inf')) != float('inf')]
        else:
             print(f"::error::Unknown test type '{test_name}' encountered.")
             continue # Skip unknown test

        print(f"-> {len(current_outbounds)} outbounds remaining after {test_name.upper()} test.")
        if not current_outbounds:
             print(f"::warning::No outbounds passed the '{test_name}' test. Stopping test sequence.")
             break # Stop if no outbounds survive a test stage

    tested_outbounds = current_outbounds # The final list after all tests

    if is_ctrl_c_pressed:
        print("Exiting early due to stop request during testing.")
        # Save whatever passed up to this point? Or empty? Let's save what we have.
        print("Saving potentially partial results...")
        # Continue to filtering/saving with potentially incomplete results
    elif not tested_outbounds:
         print("::warning::No outbounds passed the required tests. Saving empty output file.")
         save_config([], filepath=args.output, base64_output=(not args.no_base64_output))
         sys.exit(0)


    # --- 5. Filter Best/Diverse Per Protocol ---
    print("\n--- Filtering and Diversifying Results ---")
    final_outbounds = filter_best_outbounds_by_protocol(tested_outbounds, tests_to_run)
    print(f"Total outbounds after final filtering/diversification: {len(final_outbounds)}")

    if not final_outbounds:
         print("::warning::No outbounds remaining after final filtering. Saving empty output file.")
         save_config([], filepath=args.output, base64_output=(not args.no_base64_output))
         sys.exit(0)

    # --- 6. Rename Tags ---
    print("\n--- Renaming Tags ---")
    renamed_outbounds = rename_outbound_tags(final_outbounds)

    # --- 7. Save Final Config ---
    print("\n--- Saving Final Configuration ---")
    save_config(renamed_outbounds, filepath=args.output, base64_output=(not args.no_base64_output))

    end_time_main = time.time()
    print(f"\n--- Pr0xySh4rk Finished in {end_time_main - start_time_main:.2f} seconds ---")

if __name__ == "__main__":
    # Ensure asyncio works correctly with ThreadPoolExecutor on all platforms
    if sys.platform == "win32":
         asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    main()
