#!/usr/bin/env python3
import argparse
import asyncio
import base64
import concurrent.futures
import json
import logging
import os
import signal
import socket
import sys
import time
import urllib.parse
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple, Any, Union
import ipaddress
import re
import random
import hashlib
import ssl
import aiohttp
import requests
from urllib3.exceptions import InsecureRequestWarning

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(threadName)s - %(message)s',  # Added threadName
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('proxy_tester.log')
    ]
)

logger = logging.getLogger("ProxyTester")

# Suppress SSL warnings for testing
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# Protocol Enum for better type safety
class Protocol(str, Enum):
    VMESS = "vmess"
    VLESS = "vless"
    SHADOWSOCKS = "ss"
    TROJAN = "trojan"  # Added Trojan
    TUIC = "tuic"
    HYSTERIA = "hysteria"
    HYSTERIA2 = "hysteria2"
    HY2 = "hy2"
    WIREGUARD = "wireguard"
    WARP = "warp"
    SOCKS5 = "socks5"  # Added SOCKS5
    HTTP = "http"      # Added HTTP
    HTTPS = "https"    # Added HTTPS
    UNKNOWN = "unknown"

    @classmethod
    def from_string(cls, protocol_str: str) -> "Protocol":
        """Convert string to Protocol enum."""
        try:
            return cls(protocol_str.lower())
        except ValueError:
            return cls.UNKNOWN

# Configuration class
@dataclass
class Config:
    """Configuration settings for the proxy tester."""
    # Test URLs for checking HTTP(S) connectivity - More diverse and reliable URLs
    TEST_URLS: List[str] = field(default_factory=lambda: [
        "https://www.cloudflare.com/cdn-cgi/trace", # Cloudflare trace, very reliable
        "https://checkip.amazonaws.com", # Simple and fast IP check
        "http://www.msftconnecttest.com/connecttest.txt",  # Microsoft Connect Test (Windows)
        "http://cp.cloudflare.com", # Another cloudflare endpoint.
        "https://google.com",  # Added google main page
        "https://ipleak.net/json",   #Added ip leak json.
        "https://www.example.com", # Added a standard website
        "https://fast.com", # Fast.com to test some speed.
        "https://ipinfo.io/ip",  # ipinfo.io for IP check

    ])

    # Number of best configs to keep per protocol
    BEST_CONFIGS_LIMIT: int = 100  # Increased limit

    # Default timeouts - adjusted for more realistic network conditions
    TCP_TIMEOUT: float = 7.0
    HTTP_TIMEOUT: float = 10.0
    UDP_TIMEOUT: float = 5.0

    # Protocol-specific timeouts - More granular control
    PROTOCOL_TIMEOUTS: Dict[Protocol, Dict[str, float]] = field(default_factory=lambda: {
        Protocol.SHADOWSOCKS: {"tcp": 7, "http": 10},
        Protocol.VLESS: {"tcp": 7, "http": 10},
        Protocol.VMESS: {"tcp": 6, "http": 9},
        Protocol.TROJAN: {"tcp": 7, "http": 10},
        Protocol.TUIC: {"tcp": 6, "http": 9},
        Protocol.HYSTERIA: {"tcp": 6, "http": 10},
        Protocol.HYSTERIA2: {"tcp": 6, "http": 10},
        Protocol.HY2: {"tcp": 6, "http": 10},
        Protocol.WARP: {"udp": 5},
        Protocol.WIREGUARD: {"udp": 5},
        Protocol.SOCKS5: {"tcp": 7, "http": 10},
        Protocol.HTTP: {"tcp": 7, "http": 10},
        Protocol.HTTPS: {"tcp": 7, "http": 10},
    })

    # Health check settings - Realistic repetitions and success ratios
    HTTP_TEST_REPETITIONS: int = 5  # Increased repetitions
    MIN_SUCCESS_RATIO: Dict[Protocol, float] = field(default_factory=lambda: {
        Protocol.SHADOWSOCKS: 0.6,
        Protocol.VLESS: 0.6,
        Protocol.VMESS: 0.6,
        Protocol.TROJAN: 0.6,
        Protocol.TUIC: 0.6,
        Protocol.HYSTERIA: 0.7,
        Protocol.HYSTERIA2: 0.7,
        Protocol.HY2: 0.7,
        Protocol.WARP: 0.8,
        Protocol.WIREGUARD: 0.8,
        Protocol.SOCKS5: 0.6,
        Protocol.HTTP: 0.6,
        Protocol.HTTPS: 0.6,
        Protocol.UNKNOWN: 0.6
    })

    # DNS settings - Optimized for speed and reliability
    DNS_TIMEOUT: float = 4.0
    DNS_RETRIES: int = 3 # Increased retries

    # Progress tracking
    total_outbounds_count: int = 0
    completed_outbounds_count: int = 0
    is_ctrl_c_pressed: bool = False

    # IP location checking (optional, but can be very useful)
    CHECK_IP_LOCATION: bool = True  # Enabled by default
    IP_LOCATION_SERVICES: List[str] = field(default_factory=lambda: [
        "https://ipapi.co/{}/json/",  # Reliable and free
        "https://ipinfo.io/{}/json",     # Another good option
        "https://freeipapi.com/api/json/{}" # Free IP API service.
    ])

    # Protocol abbreviations for renaming - Added more protocols
    PROTOCOL_ABBREVIATIONS: Dict[Protocol, str] = field(default_factory=lambda: {
        Protocol.SHADOWSOCKS: "SS",
        Protocol.VLESS: "VL",
        Protocol.VMESS: "VM",
        Protocol.TROJAN: "TR",
        Protocol.TUIC: "TU",
        Protocol.HYSTERIA: "HY",
        Protocol.HYSTERIA2: "HY2",
        Protocol.HY2: "HY2",  # Consistent naming
        Protocol.WARP: "WG",
        Protocol.WIREGUARD: "WG",
        Protocol.SOCKS5: "S5",
        Protocol.HTTP: "HTTP",
        Protocol.HTTPS: "HTTPS",
        Protocol.UNKNOWN: "UN"
    })

    # Number of retries for HTTP requests
    HTTP_RETRIES: int = 2

# Proxy Configuration dataclass
@dataclass
class ProxyConfig:
    """Represents a proxy configuration with its metadata and test results."""
    original_config: str
    source: str = ""
    protocol: Protocol = Protocol.UNKNOWN
    server: Optional[str] = None
    port: Optional[int] = None
    tcp_delay: float = float('inf')
    http_delay: float = float('inf')
    udp_delay: float = float('inf')
    combined_delay: float = float('inf')
    country_code: str = ""
    last_tested: float = 0.0
    successful_tests: int = 0
    total_tests: int = 0

    def __post_init__(self):
        """Extract protocol, server, and port after initialization."""
        try:
            if "://" in self.original_config:
                proto_str = self.original_config.split("://", 1)[0].lower()
                self.protocol = Protocol.from_string(proto_str)
            self.server, self.port = get_server_port(self.original_config)
        except Exception as e:
            logger.error(f"Error extracting config details: {e}")

    def success_ratio(self) -> float:
        """Calculate the success ratio of tests."""
        if self.total_tests == 0:
            return 0.0
        return self.successful_tests / self.total_tests

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "config": self.original_config,
            "source": self.source,
            "protocol": self.protocol.value,
            "server": self.server,
            "port": self.port,
            "tcp_delay": self.tcp_delay if self.tcp_delay != float('inf') else "timeout",
            "http_delay": self.http_delay if self.http_delay != float('inf') else "timeout",
            "udp_delay": self.udp_delay if self.udp_delay != float('inf') else "timeout",
            "combined_delay": self.combined_delay if self.combined_delay != float('inf') else "timeout",
            "success_ratio": f"{self.success_ratio():.2f}",
            "country": self.country_code,
            "last_tested": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self.last_tested))
        }

# Global configuration instance
config = Config()

# Signal handler for graceful interruption
def signal_handler(sig, frame):
    """Handle SIGINT (Ctrl+C) by setting flag for graceful shutdown."""
    logger.info("\nCtrl+C detected. Gracefully stopping...")
    config.is_ctrl_c_pressed = True

# ---- IP and DNS Utilities ----

async def resolve_hostname(hostname: str) -> Optional[str]:
    """Resolve hostname to IP address with retries."""
    for attempt in range(config.DNS_RETRIES + 1):
        try:
            loop = asyncio.get_running_loop()  # Use get_running_loop
            return await loop.run_in_executor(
                None, socket.gethostbyname, hostname
            )
        except (socket.gaierror, socket.herror) as e:
            if attempt == config.DNS_RETRIES:
                logger.warning(f"DNS resolution failed for {hostname}: {e}")
                return None
            await asyncio.sleep(0.5 * (attempt + 1))  # Exponential backoff
    return None

async def check_ip_location(ip_address: str) -> str:
    """Check the geographic location of an IP address."""
    if not config.CHECK_IP_LOCATION:
        return ""

    async with aiohttp.ClientSession() as session:
        for service_url in config.IP_LOCATION_SERVICES:
            try:
                url = service_url.format(ip_address) if "{}" in service_url else f"{service_url}{ip_address}"
                async with session.get(url, timeout=5) as response:  # Increased timeout
                    if response.status == 200:
                        data = await response.json()
                        # Check for different possible keys
                        if "country_name" in data:  # ipapi.co
                            return data["country_name"]
                        if "country" in data:  # ipinfo.io or freeipapi.com
                            return data["country"]
                        if "countryCode" in data: #For ipapi.co
                            return data["countryCode"]
                        return ""
            except (aiohttp.ClientError, asyncio.TimeoutError, json.JSONDecodeError) as e:
                logger.debug(f"IP location check failed: {e}")
    return ""

# ---- HTTP Utilities ----

async def fetch_content_async(url: str, proxy: Optional[str] = None, timeout: float = None, retries: int = 0) -> Optional[str]:
    """Fetch content from URL using aiohttp with retries."""
    if timeout is None:
        timeout = config.HTTP_TIMEOUT

    proxy_str = proxy if proxy else None
    logger.debug(f"Fetching {url} {'using proxy: ' + proxy if proxy else 'directly'}")

    async with aiohttp.ClientSession() as session:
        for attempt in range(retries + 1):
            try:
                async with session.get(
                    url,
                    proxy=proxy_str,
                    timeout=aiohttp.ClientTimeout(total=timeout),
                    ssl=False  # Disable SSL verification for testing
                ) as response:
                    if response.status == 200:
                        return await response.text()
                    elif response.status in (500,502,503,504):
                        logger.warning(f"Retry {attempt+1}/{retries+1}: HTTP error {response.status} fetching {url}, retrying...")
                        await asyncio.sleep(1 * (attempt + 1))  # Exponential backoff
                        continue
                    else:
                        logger.warning(f"HTTP error {response.status} fetching {url}")
                        return None
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                if attempt < retries:
                    logger.warning(f"Retry {attempt+1}/{retries+1}: Error fetching {url}: {type(e).__name__} - {e}, retrying...")
                    await asyncio.sleep(1*(attempt+1)) #Exponential backoff
                else:
                    logger.debug(f"Error fetching {url}: {type(e).__name__} - {e}")
                    return None

def fetch_content(url: str, proxy: Optional[str] = None, timeout: float = None, retries:int = config.HTTP_RETRIES) -> Optional[str]:
    """Synchronous wrapper for fetch_content_async."""
    if timeout is None:
        timeout = config.HTTP_TIMEOUT

    try:
        return asyncio.run(fetch_content_async(url, proxy, timeout, retries))
    except Exception as e:
        logger.debug(f"Error in fetch_content: {e}")
        return None

# ---- Configuration Parsing ----
def parse_trojan_config(config_line: str) -> Tuple[Optional[str], Optional[int]]:
    """Parse Trojan configuration."""
    try:
        parsed = urllib.parse.urlparse(config_line)
        return parsed.hostname, parsed.port
    except Exception as e:
        logger.debug(f"Error parsing trojan config: {e}")
        return None, None

def parse_socks5_http_config(config_line: str) -> Tuple[Optional[str], Optional[int]]:
    """Parse SOCKS5/HTTP/HTTPS configurations."""
    try:
        parsed = urllib.parse.urlparse(config_line)
        return parsed.hostname, parsed.port
    except Exception as e:
        logger.debug(f"Error parsing socks5/http/https config: {e}")
        return None, None

def parse_config_content(content: str) -> List[str]:
    """Parse configuration content to extract proxy URLs, handling various formats."""
    outbounds = []
    try:
        # Try to decode base64 if applicable
        try:
            decoded_content = base64.b64decode(content).decode('utf-8')
            content = decoded_content
        except Exception:
            pass

        # Extract configuration lines, handling comments and different separators
        for line in content.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                # Handle comma-separated configurations (sometimes found in subscriptions)
                for sub_line in line.split(","):
                    sub_line = sub_line.strip()
                    # Match valid protocol patterns including trojan, socks5, http, and https
                    if any(sub_line.startswith(f"{p.value}://") for p in Protocol if p != Protocol.UNKNOWN):
                        logger.debug(f"Found config: {sub_line[:50]}...")
                        outbounds.append(sub_line)
    except Exception as e:
        logger.error(f"Error processing content: {e}")

    return outbounds

def parse_vmess_config(config_line: str) -> Tuple[Optional[str], Optional[int]]:
    """Parse VMess configuration to extract server and port."""
    try:
        # For vmess, the part after vmess:// is base64 encoded
        remainder = config_line.split("://", 1)[1]

        # Handle trailing fragments or query parameters
        if "#" in remainder:
            remainder = remainder.split("#")[0]
        if "?" in remainder:
            remainder = remainder.split("?")[0]

        decoded = base64.b64decode(remainder).decode("utf-8")
        data = json.loads(decoded)

        server = data.get("add")
        port = int(data.get("port")) if data.get("port") else None

        return server, port
    except Exception as e:
        logger.debug(f"Error parsing vmess config: {e}")
        return None, None

def parse_ss_config(config_line: str) -> Tuple[Optional[str], Optional[int]]:
    """Parse Shadowsocks configuration to extract server and port."""
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
        else:
            # Handle ss://BASE64 format without @
            try:
                base_part = remainder.split("#")[0].split("?")[0]
                decoded = base64.b64decode(base_part).decode('utf-8')
                if ":" in decoded and "@" in decoded:
                    server_part = decoded.split("@", 1)[1]
                    if ":" in server_part:
                        server = server_part.split(":", 1)[0]
                        port = int(server_part.split(":", 1)[1])
                        return server, port
                else: #for ss://method:password@server:port type
                    method_password, server_port = decoded.split('@', 1)
                    server, port_str = server_port.split(":", 1)
                    return server, int(port_str)


            except Exception:
                pass
    except Exception as e:
        logger.debug(f"Error parsing ss config: {e}")

    return None, None

def parse_wireguard_config(config_line: str) -> Tuple[Optional[str], Optional[int]]:
    """Parse WireGuard/WARP configuration to extract endpoint and port."""
    try:
        parsed = urllib.parse.urlparse(config_line)
        query_params = urllib.parse.parse_qs(parsed.query)

        # Look for endpoint in query parameters
        if "endpoint" in query_params:
            endpoint = query_params["endpoint"][0]
            if ":" in endpoint:
                server, port_str = endpoint.split(":", 1)
                port = int(port_str)
                return server, port

        # Try to get from path for some implementations
        if parsed.netloc:
            if ":" in parsed.netloc:
                server, port_str = parsed.netloc.split(":", 1)
                try:
                    port = int(port_str)
                    return server, port
                except ValueError:
                    pass

        # Fallback to hostname and port from URL
        return parsed.hostname, parsed.port
    except Exception as e:
        logger.debug(f"Error parsing wireguard config: {e}")
        return None, None

def get_server_port(config_line: str) -> Tuple[Optional[str], Optional[int]]:
    """Extract server and port from different proxy protocols."""
    try:
        if "://" not in config_line:
            return None, None

        protocol = Protocol.from_string(config_line.split("://", 1)[0].lower())

        if protocol == Protocol.VMESS:
            return parse_vmess_config(config_line)
        elif protocol == Protocol.SHADOWSOCKS:
            return parse_ss_config(config_line)
        elif protocol in (Protocol.WIREGUARD, Protocol.WARP):
            return parse_wireguard_config(config_line)
        elif protocol == Protocol.TROJAN:
            return parse_trojan_config(config_line)
        elif protocol in (Protocol.SOCKS5, Protocol.HTTP, Protocol.HTTPS):
            return parse_socks5_http_config(config_line)
        else:
            # For other protocols use urlparse
            parsed_url = urllib.parse.urlparse(config_line)
            return parsed_url.hostname, parsed_url.port
    except Exception as e:
        logger.debug(f"Error extracting server/port from config: {e}")
        return None, None

def get_dedup_key(config: str) -> tuple:
    """Create a deduplication key based on protocol, server, and port."""
    if "://" not in config:
        return (config,)

    try:
        scheme = config.split("://", 1)[0].lower()
        protocol = Protocol.from_string(scheme)
        server, port = get_server_port(config)

        # Enhanced deduplication by adding protocol
        return (protocol.value, server, port)
    except Exception as e:
        logger.debug(f"Error creating deduplication key: {e}")
        return (config,)

def deduplicate_outbounds(configs: List[Union[str, ProxyConfig]]) -> List[Union[str, ProxyConfig]]:
    """Remove duplicate configurations based on protocol, server, and port."""
    dedup_dict = {}
    for config_item in configs:
        if isinstance(config_item, ProxyConfig):
            config_str = config_item.original_config
        else:
            config_str = config_item

        key = get_dedup_key(config_str)
        if key[1] is not None and key[2] is not None:  # Only include configs with valid server and port
            if key not in dedup_dict:
                dedup_dict[key] = config_item

    logger.info(f"Deduplicated {len(configs)} configs to {len(dedup_dict)} unique configs")
    return list(dedup_dict.values())

def get_protocol_timeout(protocol: Protocol, test_type: str, default_timeout: float) -> float:
    """Get protocol-specific timeout value."""
    if protocol in config.PROTOCOL_TIMEOUTS and test_type in config.PROTOCOL_TIMEOUTS[protocol]:
        return config.PROTOCOL_TIMEOUTS[protocol][test_type]
    return default_timeout

# ---- Testing Functions ----

async def tcp_test_outbound(proxy_config: ProxyConfig) -> None:
    """Test TCP connectivity to a proxy server."""
    server, port = proxy_config.server, proxy_config.port

    # Get protocol-specific timeout
    timeout = get_protocol_timeout(
        proxy_config.protocol,
        "tcp",
        config.TCP_TIMEOUT
    )

    if not server or not port:
        proxy_config.tcp_delay = float('inf')
        logger.debug(f"TCP Test: No server/port for {proxy_config.original_config[:30]}...")
        return

    loop = asyncio.get_running_loop()  # Use get_running_loop
    start = loop.time()
    logger.debug(f"TCP Test for {server}:{port} started (timeout: {timeout}s)...")

    try:
        # Resolve IP address first to ensure accurate testing
        resolved_ip = await resolve_hostname(server)
        if not resolved_ip:
            proxy_config.tcp_delay = float('inf')
            logger.debug(f"TCP Test for {server}:{port} DNS resolution failed")
            return

        # Use asyncio.wait_for to enforce a strict timeout
        conn_task = asyncio.open_connection(resolved_ip, port)
        reader, writer = await asyncio.wait_for(conn_task, timeout=timeout)

        delay = (loop.time() - start) * 1000
        writer.close()
        try:
            await writer.wait_closed()
        except:
            pass

        proxy_config.tcp_delay = delay
        logger.debug(f"TCP Test for {server}:{port} finished, delay={delay:.2f} ms")
    except asyncio.TimeoutError:
        proxy_config.tcp_delay = float('inf')
        logger.debug(f"TCP Test for {server}:{port} timed out after {timeout}s")
    except Exception as e:
        proxy_config.tcp_delay = float('inf')
        logger.debug(f"TCP Test for {server}:{port} error: {type(e).__name__} - {e}")

def tcp_test_outbound_sync(proxy_config: ProxyConfig) -> None:
    """Synchronous wrapper for tcp_test_outbound."""
    try:
        asyncio.run(tcp_test_outbound(proxy_config))
    except Exception as e:
        logger.error(f"Exception in tcp_test_outbound_sync: {e}")
        proxy_config.tcp_delay = float('inf')

async def http_delay_test_outbound(proxy_config: ProxyConfig, proxy_for_test: Optional[str], repetitions: int) -> None:
    """Test HTTP(S) connectivity through a proxy server."""
    server, port = proxy_config.server, proxy_config.port

    # Get protocol-specific timeout
    timeout = get_protocol_timeout(
        proxy_config.protocol,
        "http",
        config.HTTP_TIMEOUT
    )

    if not server or not port:
        proxy_config.http_delay = float('inf')
        logger.debug(f"HTTP Test: No server/port for {proxy_config.original_config[:30]}...")
        return

    # Get minimum success threshold based on protocol
    min_success_ratio = config.MIN_SUCCESS_RATIO.get(
        proxy_config.protocol,
        config.MIN_SUCCESS_RATIO[Protocol.UNKNOWN]
    )

    current_proxies = {'http': proxy_for_test, 'https': proxy_for_test} if proxy_for_test else None

    logger.debug(f"HTTP Test for {server}:{port} started with {repetitions} repetitions (timeout: {timeout}s)...")

    total_delay = 0.0
    proxy_config.successful_tests = 0
    proxy_config.total_tests = 0

    # Shuffle test URLs for more robust testing
    test_urls = config.TEST_URLS.copy()
    random.shuffle(test_urls)

    session = requests.Session()
    loop = asyncio.get_running_loop()  # Use get_running_loop

    for test_url in test_urls:
        for i in range(repetitions):
            if config.is_ctrl_c_pressed:
                logger.info("HTTP Test interrupted by Ctrl+C")
                proxy_config.http_delay = float('inf')
                return

            proxy_config.total_tests += 1
            start_time = loop.time()
            try:
                # Use the requests library for HTTP testing
                response_future = loop.run_in_executor(
                    None,
                    lambda: session.get(
                        test_url,
                        timeout=timeout,
                        proxies=current_proxies,
                        stream=True,
                        verify=False
                    )
                )

                response = await asyncio.wait_for(response_future, timeout=timeout * 1.2)  # Increased timeout slightly

                # Check status and read some content
                if response.status_code == 200:
                    # Read at least some content to ensure connection works
                    content_start = response.content[:100]
                    elapsed = (loop.time() - start_time) * 1000
                    total_delay += elapsed
                    proxy_config.successful_tests += 1
                    logger.debug(f"    [{server}:{port}] {test_url} Rep {i+1}: {elapsed:.2f} ms")
                else:
                    logger.debug(f"    [{server}:{port}] {test_url} Rep {i+1} status code: {response.status_code}")
            except Exception as e:
                logger.debug(f"    [{server}:{port}] {test_url} Rep {i+1} failed: {e}")
                # Continue testing instead of immediately failing

    # Calculate success ratio
    success_ratio = proxy_config.success_ratio()
    logger.debug(f"HTTP Test for {server}:{port} completed. Success ratio: {success_ratio:.2f} "
               f"({proxy_config.successful_tests}/{proxy_config.total_tests})")

    if success_ratio >= min_success_ratio and proxy_config.successful_tests > 0:
        overall_avg = total_delay / proxy_config.successful_tests
        proxy_config.http_delay = overall_avg
        logger.debug(f"HTTP Test for {server}:{port} PASSED. Average delay: {overall_avg:.2f} ms")
    else:
        proxy_config.http_delay = float('inf')
        logger.debug(f"HTTP Test for {server}:{port} FAILED. Success ratio below threshold.")

def http_delay_test_outbound_sync(proxy_config: ProxyConfig, proxy: Optional[str], repetitions: int) -> None:
    """Synchronous wrapper for http_delay_test_outbound."""
    try:
        asyncio.run(http_delay_test_outbound(proxy_config, proxy, repetitions))
    except Exception as e:
        logger.error(f"Exception in http_delay_test_outbound_sync: {e}")
        proxy_config.http_delay = float('inf')

async def udp_test_outbound(proxy_config: ProxyConfig) -> None:
    """Test UDP connectivity for WireGuard/WARP protocols."""
    server, port = proxy_config.server, proxy_config.port

    # Special case for WireGuard/WARP protocols
    is_wireguard = proxy_config.protocol in (Protocol.WIREGUARD, Protocol.WARP)

    # Get protocol-specific timeout
    timeout = get_protocol_timeout(
        proxy_config.protocol,
        "udp",
        config.UDP_TIMEOUT
    )

    if not server or not port:
        if is_wireguard:
            logger.debug(f"UDP Test: No server/port for WG/WARP, checking if config is valid: {proxy_config.original_config[:30]}...")
            try:
                if "#" in proxy_config.original_config:
                    proxy_config.udp_delay = 100.0  # Assign a default delay for WG/WARP
                    return
            except Exception:
                pass
        proxy_config.udp_delay = float('inf')
        logger.debug(f"UDP Test: No server/port detected")
        return

    try:
        resolved_ip = await resolve_hostname(server)
        if not resolved_ip:
            proxy_config.udp_delay = float('inf')
            logger.debug(f"UDP Test for {server}:{port} DNS resolution failed")
            return

        loop = asyncio.get_running_loop()  # Use get_running_loop
        start = loop.time()
        logger.debug(f"UDP Test for {server}:{port} ({resolved_ip}:{port}) started (timeout: {timeout}s)...")

        # Create UDP socket and send a test packet
        transport, _ = await loop.create_datagram_endpoint(
            lambda: asyncio.DatagramProtocol(),
            remote_addr=(resolved_ip, port)
        )

        # Send a test packet
        transport.sendto(b'\x00\x00\x00\x00')

        # Give some time for potential errors to surface
        await asyncio.sleep(0.1)

        delay = (loop.time() - start) * 1000
        transport.close()

        proxy_config.udp_delay = delay
        logger.debug(f"UDP Test for {server}:{port} finished, delay={delay:.2f} ms")
    except asyncio.TimeoutError:
        proxy_config.udp_delay = float('inf')
        logger.debug(f"UDP Test for {server}:{port} timed out after {timeout}s")
    except Exception as e:
        proxy_config.udp_delay = float('inf')
        logger.debug(f"UDP Test for {server}:{port} error: {type(e).__name__} - {e}")

def udp_test_outbound_sync(proxy_config: ProxyConfig) -> None:
    """Synchronous wrapper for udp_test_outbound."""
    try:
        asyncio.run(udp_test_outbound(proxy_config))
    except Exception as e:
        logger.error(f"Exception in udp_test_outbound_sync: {e}")
        proxy_config.udp_delay = float('inf')

def single_test_pass(
    outbounds: List[ProxyConfig],
    test_type: str,
    thread_pool_size=32,
    proxy_for_test: Optional[str] = None,
    repetitions: int = 3
) -> None:
    """Run a batch of tests on proxy configurations."""
    config.completed_outbounds_count = 0
    config.total_outbounds_count = len(outbounds)
    processed_outbound_indices = set()

    logger.info(f"Starting tests ({test_type}) on {config.total_outbounds_count} outbounds")

    with concurrent.futures.ThreadPoolExecutor(max_workers=thread_pool_size) as executor:
        futures_map = {}
        for index, proxy_config in enumerate(outbounds):
            if config.is_ctrl_c_pressed:
                logger.info("Ctrl+C detected, stopping tests.")
                break

            futures_list = []

            if test_type == "tcp+http":
                if proxy_config.protocol in (Protocol.WIREGUARD, Protocol.WARP):
                    future = executor.submit(udp_test_outbound_sync, proxy_config)
                    futures_list.append(future)
                else:
                    # First run TCP test, then HTTP test only if TCP succeeds
                    future_tcp = executor.submit(tcp_test_outbound_sync, proxy_config)
                    futures_list.append(future_tcp)
            elif test_type == "tcp":
                future = executor.submit(tcp_test_outbound_sync, proxy_config)
                futures_list.append(future)
            elif test_type == "http":
                future = executor.submit(http_delay_test_outbound_sync, proxy_config, proxy_for_test, repetitions)
                futures_list.append(future)
            elif test_type == "udp":
                if proxy_config.protocol in (Protocol.WIREGUARD, Protocol.WARP):
                    future = executor.submit(udp_test_outbound_sync, proxy_config)
                    futures_list.append(future)
                else:
                    proxy_config.udp_delay = float('inf')
                    continue

            futures_map[index] = futures_list

        # For tcp+http, wait for TCP tests first (if not WG/WARP)
        if test_type == "tcp+http":
            tcp_futures = [futures[0] for idx, futures in futures_map.items()
                           if futures and outbounds[idx].protocol not in (Protocol.WIREGUARD, Protocol.WARP)]
            for future in concurrent.futures.as_completed(tcp_futures):
                if config.is_ctrl_c_pressed:
                    break
                try:
                    future.result()
                except Exception as e:
                    logger.error(f"Exception during TCP test: {e}")

            # Now add HTTP tests for configs that passed TCP test
            for index, futures_list in list(futures_map.items()):
                if config.is_ctrl_c_pressed:
                    break

                if (outbounds[index].protocol not in (Protocol.WIREGUARD, Protocol.WARP) and
                    outbounds[index].tcp_delay != float('inf')):
                    future_http = executor.submit(
                        http_delay_test_outbound_sync,
                        outbounds[index],
                        proxy_for_test,
                        repetitions
                    )
                    futures_map[index].append(future_http)

        all_futures = [future for futures_list in futures_map.values() for future in futures_list]

        for future in concurrent.futures.as_completed(all_futures):
            if config.is_ctrl_c_pressed:
                break
            try:
                future.result()  # This will raise an exception if the task raised one
            except Exception as e:
                logger.error(f"Exception during test: {e}")
            finally:
                for index, futures_list in futures_map.items():
                    if future in futures_list and index not in processed_outbound_indices:
                        if all(f.done() for f in futures_list):
                            config.completed_outbounds_count += 1
                            processed_outbound_indices.add(index)
                            progress_percentage = (config.completed_outbounds_count / config.total_outbounds_count) * 100
                            # Reduced reporting frequency to reduce log clutter
                            if config.completed_outbounds_count % 25 == 0 or config.completed_outbounds_count == config.total_outbounds_count:
                                logger.info(f"Progress: {progress_percentage:.2f}% ({config.completed_outbounds_count}/{config.total_outbounds_count})")

    # Set the time tested
    current_time = time.time()
    for outbound in outbounds:
        outbound.last_tested = current_time

    logger.info("Testing completed.")

# ---- Output Functions ----

def save_config(
    outbounds: List[str],
    filepath: str = "merged_configs.txt",
    base64_encode: bool = True,
    include_metadata: bool = False
):
    """Save configurations to a file, handling both JSON and text formats."""
    try:
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(filepath) if os.path.dirname(filepath) else '.', exist_ok=True)

        if include_metadata and filepath.endswith('.json'):
            # Save full metadata as JSON
            with open(filepath, "w") as outfile:
                if isinstance(outbounds[0], ProxyConfig):
                    json_data = [config.to_dict() for config in outbounds]
                else:
                    json_data = outbounds
                json.dump(json_data, outfile, indent=2)
            logger.info(f"Config metadata saved to {filepath}")
            return

        # Standard text output (with optional base64 encoding)
        if isinstance(outbounds[0], ProxyConfig):
            combined = "\n".join(proxy.original_config for proxy in outbounds)
        else:
            combined = "\n".join(outbounds)

        if base64_encode:
            encoded = base64.b64encode(combined.encode()).decode("utf-8")
            with open(filepath, "w") as outfile:
                outfile.write(encoded)
            logger.info(f"Merged configs saved to {filepath} as base64 encoded.")
        else:
            with open(filepath, "w") as outfile:
                outfile.write(combined)
            logger.info(f"Merged configs saved to {filepath} as plaintext.")
    except Exception as e:
        logger.error(f"Error saving config: {e}")

def rename_configs_by_protocol(configs: List[ProxyConfig]) -> List[str]:
    """Rename configs by protocol and apply limits per protocol, with improved naming."""
    protocol_groups = {}
    renamed_configs = []

    # Group by protocol
    for config_item in configs:  # Renamed variable to avoid shadowing the global config
        abbr = config_item.protocol.value
        if config_item.protocol in config.PROTOCOL_ABBREVIATIONS:  # Use global config
            abbr = config.PROTOCOL_ABBREVIATIONS[config_item.protocol]
        else:
            abbr = "UN"  # Default to unknown if not found

        # Include country code if available
        country_suffix = f"-{config_item.country_code}" if config_item.country_code else ""
        protocol_groups.setdefault(f"{abbr}{country_suffix}", []).append(config_item)

    for group_key, conf_list in protocol_groups.items():
        # Filter for valid configs and sort by combined delay
        valid_list = [item for item in conf_list if item.combined_delay != float('inf')]
        valid_list.sort(key=lambda x: x.combined_delay)
        limited_list = valid_list[:config.BEST_CONFIGS_LIMIT]

        logger.info(f"Protocol {group_key}: {len(valid_list)} valid configs, keeping best {len(limited_list)}")

        for i, proxy_config in enumerate(limited_list, start=1):
            config_line = proxy_config.original_config
            # More descriptive naming, including index and potentially country
            new_tag = f"🚀Pr0xySh4rk-{group_key}-{i:02d}" # Changed emoji

            if "#" in config_line:
                base_part = config_line.split("#")[0].rstrip()
                new_config = f"{base_part}#{urllib.parse.quote(new_tag)}"
            else:
                new_config = f"{config_line}#{urllib.parse.quote(new_tag)}"

            renamed_configs.append(new_config)

    return renamed_configs

# ---- Subscription Processing ----

async def fetch_and_parse_subscription_async(url: str, proxy: Optional[str] = None) -> List[ProxyConfig]:
    """Fetch and parse a subscription URL asynchronously."""
    pid = os.getpid()
    logger.info(f"Thread {pid}: Fetching: {url}")

    content = await fetch_content_async(url, proxy)  # Use the improved fetch_content_async

    if not content:
        logger.warning(f"Thread {pid}: Failed to fetch {url}")
        return []

    normalized_content = content.strip().replace("\n", "").replace("\r", "").replace(" ", "")
    try:
        # Try base64 decoding
        decoded_possible = base64.b64decode(normalized_content, validate=True).decode("utf-8")
        content = decoded_possible
    except Exception:
        # Not base64 encoded, use as is
        pass

    outbounds_list = parse_config_content(content)

    if not outbounds_list:
        logger.warning(f"Thread {pid}: No outbounds parsed from {url}")
        return []

    # Convert to ProxyConfig objects
    proxy_configs = []
    for ob in outbounds_list:
        proxy_config = ProxyConfig(original_config=ob, source=url)
        proxy_configs.append(proxy_config)

    logger.info(f"Thread {pid}: Parsed {len(proxy_configs)} outbounds from {url}")
    return proxy_configs

def fetch_and_parse_subscription_thread(url: str, proxy: Optional[str] = None) -> List[ProxyConfig]:
    """Synchronous wrapper for fetch_and_parse_subscription_async."""
    try:
        return asyncio.run(fetch_and_parse_subscription_async(url, proxy))
    except Exception as e:
        logger.error(f"Error in fetch_and_parse_subscription_thread: {e}")
        return []

# ---- CLI Interface ----

async def async_main():
    """Asynchronous main function."""
    parser = argparse.ArgumentParser(description="Pr0xySh4rk Xray Config Merger")
    parser.add_argument("--input", required=True, help="Input file (base64 or URLs)")
    parser.add_argument("--output", required=True, help="Output file")
    parser.add_argument("--proxy", help="Proxy for fetching subscription URLs (e.g., http://user:pass@host:port)")
    parser.add_argument("--threads", type=int, default=64, help="Number of threads for fetching and testing") # Increased default threads
    parser.add_argument("--test-proxy", help="Proxy for HTTP testing (e.g., http://user:pass@host:port)")
    parser.add_argument("-r", "--repetitions", type=int, default=5, help="Number of HTTP test repetitions")  # Increased default repetitions
    parser.add_argument("--test", choices=["tcp", "udp", "http", "tcp+http"], default="tcp+http", help="Type of test to perform")
    parser.add_argument("--no-base64", action="store_true", help="Output in plaintext instead of base64 encoding")
    parser.add_argument("--tcp-timeout", type=float, default=config.TCP_TIMEOUT, help=f"TCP test timeout in seconds (default: {config.TCP_TIMEOUT})")
    parser.add_argument("--http-timeout", type=float, default=config.HTTP_TIMEOUT, help=f"HTTP test timeout in seconds (default: {config.HTTP_TIMEOUT})")
    parser.add_argument("--udp-timeout", type=float, default=config.UDP_TIMEOUT, help=f"UDP test timeout in seconds (default: {config.UDP_TIMEOUT})")
    parser.add_argument("--protocol-stats", action="store_true", help="Show detailed statistics for each protocol")
    parser.add_argument("--save-metadata", action="store_true", help="Save JSON metadata file")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    parser.add_argument("--check-ip-location", action="store_true", help="Enable IP location checking (requires external services)") # Added IP location argument
    args = parser.parse_args()

    # Set logging level based on verbose flag
    if args.verbose:
        logger.setLevel(logging.DEBUG)

    # Update global timeout values
    config.TCP_TIMEOUT = args.tcp_timeout
    config.HTTP_TIMEOUT = args.http_timeout
    config.UDP_TIMEOUT = args.udp_timeout
    config.HTTP_TEST_REPETITIONS = args.repetitions
    config.CHECK_IP_LOCATION = args.check_ip_location # Set IP Location check.

    # Save and clear environment proxy variables
    original_env = {}
    proxy_vars = ['http_proxy', 'https_proxy', 'all_proxy', 'HTTP_PROXY', 'PROXY', 'ALL_PROXY']
    for var in proxy_vars:
        if var in os.environ:
            original_env[var] = os.environ[var]
            del os.environ[var]  # Remove proxy settings from the environment

    subscription_urls = []
    try:
        with open(args.input, "rb") as f:
            encoded_content = f.read().strip()
            try:
                # Try decoding as base64
                decoded_content = base64.b64decode(encoded_content).decode("utf-8")
                subscription_urls = [line.strip() for line in decoded_content.splitlines() if line.strip()]
                logger.info("URLs decoded from base64.")
            except Exception:
                logger.info("Trying plain text format.")
                try:
                    with open(args.input, "r") as f2:
                         subscription_urls = [line.strip() for line in f2 if line.strip()]
                except UnicodeDecodeError:
                    logger.error("Error: Input file is neither valid base64 nor plain text.")
                    return
    except FileNotFoundError:
        logger.error(f"Error: {args.input} not found.")
        return

    if not subscription_urls:
        logger.error("No URLs found. Exiting.")
        return

    # Fetch and parse subscription URLs
    logger.info(f"Fetching {len(subscription_urls)} subscription URLs...")

    parsed_outbounds_lists = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = [
            executor.submit(fetch_and_parse_subscription_thread, url, args.proxy)
            for url in subscription_urls
        ]

        for future in concurrent.futures.as_completed(futures):
            if config.is_ctrl_c_pressed:
                logger.info("Ctrl+C during fetching.")
                break
            try:
                result = future.result()
                if result:
                    parsed_outbounds_lists.extend(result)
            except Exception as e:
                logger.error(f"Error processing subscription: {e}")

    if config.is_ctrl_c_pressed:
        logger.info("Exiting early due to Ctrl+C.")
        sys.exit(0)

    logger.info(f"Total parsed configurations: {len(parsed_outbounds_lists)}")

    # Deduplicate outbounds
    unique_outbounds = deduplicate_outbounds(parsed_outbounds_lists)
    logger.info(f"Unique deduplicated configs: {len(unique_outbounds)}")

    # Categorize configs by protocol to handle differently
    wireguard_warp_configs = [
        ob for ob in unique_outbounds
        if ob.protocol in (Protocol.WIREGUARD, Protocol.WARP)
    ]
    other_configs = [
        ob for ob in unique_outbounds
        if ob.protocol not in (Protocol.WIREGUARD, Protocol.WARP)
    ]

    # Combine configs for testing
    combined_outbounds_for_test = other_configs + wireguard_warp_configs

    # Run tests based on specified test type
    if args.test == "tcp+http":
        logger.info("\n=== Testing all configs (TCP+HTTP for regular configs, UDP for WG/WARP) ===")
        single_test_pass(
            combined_outbounds_for_test,
            "tcp+http",
            args.threads,
            args.test_proxy,
            args.repetitions
        )

        # Filter successful configs
        survivors_tcp_http = [
            ob for ob in other_configs
            if ob.tcp_delay != float('inf') and ob.http_delay != float('inf')
        ]
        survivors_udp = [
            ob for ob in wireguard_warp_configs
            if ob.udp_delay != float('inf')
        ]
        tested_outbounds = survivors_tcp_http + survivors_udp

        # Calculate combined delay
        for ob in survivors_tcp_http:
            ob.combined_delay = (ob.tcp_delay + ob.http_delay) / 2
        for ob in survivors_udp:
            ob.combined_delay = ob.udp_delay

    elif args.test == "tcp":
        single_test_pass(
            unique_outbounds,
            "tcp",
            args.threads,
            args.test_proxy,
            args.repetitions
        )
        tested_outbounds = [ob for ob in unique_outbounds if ob.tcp_delay != float('inf')]
        for ob in tested_outbounds:
            ob.combined_delay = ob.tcp_delay
    elif args.test == "http":
        single_test_pass(
            unique_outbounds,
            "http",
            args.threads,
            args.test_proxy,
            args.repetitions
        )
        tested_outbounds = [ob for ob in unique_outbounds if ob.http_delay != float('inf')]
        for ob in tested_outbounds:
            ob.combined_delay = ob.http_delay
    elif args.test == "udp":
        single_test_pass(
            unique_outbounds,
            "udp",
            args.threads,
            args.test_proxy,
            args.repetitions
        )
        tested_outbounds = [ob for ob in unique_outbounds if ob.udp_delay != float('inf')]
        for ob in tested_outbounds:
            ob.combined_delay = ob.udp_delay
    else:
        tested_outbounds = []
        logger.error(f"Error: Unknown test type: {args.test}")

    # Check IP Location if enabled
    if config.CHECK_IP_LOCATION:
        logger.info("Checking IP locations...")
        async def check_locations(configs):
            async with aiohttp.ClientSession() as session:
                tasks = [check_ip_location(config.server) for config in configs if config.server]
                results = await asyncio.gather(*tasks)
                for config, country_code in zip(configs, results):
                     config.country_code = country_code

        asyncio.run(check_locations(tested_outbounds))
        logger.info("IP location check complete.")

    # Save results
    if tested_outbounds:
        # Save metadata if requested
        if args.save_metadata:
            metadata_path = f"{os.path.splitext(args.output)[0]}_metadata.json"
            save_config(tested_outbounds, filepath=metadata_path, base64_encode=False, include_metadata=True)

        # Rename and limit configs by protocol
        renamed_final_outbounds = rename_configs_by_protocol(tested_outbounds)
        logger.info(f"Renamed and limited configs: {len(renamed_final_outbounds)}")
        save_config(renamed_final_outbounds, filepath=args.output, base64_encode=not args.no_base64)
    else:
        logger.error("No working configurations found.")

    # Protocol stats (Optional)
    if args.protocol_stats:
        protocol_stats: Dict[str, Dict[str, Any]] = {}
        for proxy_config in tested_outbounds:
            protocol = proxy_config.protocol.value
            if protocol not in protocol_stats:
                protocol_stats[protocol] = {
                    "count": 0,
                    "working_count": 0,
                    "total_delay": 0.0,
                    "min_delay": float('inf'),
                    "max_delay": 0.0
                }
            protocol_stats[protocol]["count"] += 1
            if proxy_config.combined_delay != float('inf'):
                protocol_stats[protocol]["working_count"] += 1
                protocol_stats[protocol]["total_delay"] += proxy_config.combined_delay
                protocol_stats[protocol]["min_delay"] = min(protocol_stats[protocol]["min_delay"], proxy_config.combined_delay)
                protocol_stats[protocol]["max_delay"] = max(protocol_stats[protocol]["max_delay"], proxy_config.combined_delay)

        logger.info("\n--- Protocol Statistics ---")
        for protocol, stats in protocol_stats.items():
            if stats["working_count"] > 0:
                avg_delay = stats["total_delay"] / stats["working_count"]
                success_rate = (stats["working_count"] / stats["count"]) * 100
                logger.info(f"Protocol: {protocol}")
                logger.info(f"  Count: {stats['count']} (Working: {stats['working_count']}, {success_rate:.1f}%)")
                logger.info(f"  Average Delay: {avg_delay:.2f} ms")
                logger.info(f"  Min Delay: {stats['min_delay']:.2f} ms" if stats['min_delay'] != float('inf') else "  Min Delay: N/A")
                logger.info(f"  Max Delay: {stats['max_delay']:.2f} ms" if stats['max_delay'] != 0.0 else "  Max Delay: N/A")
                logger.info("-" * 20)

    # Restore environment variables
    for var, value in original_env.items():
        os.environ[var] = value

def main():
    """Entry point."""
    # Set up signal handler
    signal.signal(signal.SIGINT, signal_handler)
    try:
        asyncio.run(async_main())
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Unhandled exception: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
