# -*- coding: utf-8 -*-
import requests
import re
import time
import base64
import os
import logging
import concurrent.futures
import random
import json
from urllib.parse import urlparse, unquote
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

# ==============================================================================
# CONFIGURATION
# ==============================================================================

# Setup Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)

# Output
OUTPUT_FILE = "collected_configs.txt"

# Networking
TIMEOUT = 20  # Seconds
RETRIES = 3
BACKOFF_FACTOR = 0.5
MAX_WORKERS = 40  # High concurrency for I/O bound tasks

# GitHub Token (Optional but recommended for Search)
GITHUB_TOKEN = os.getenv("API_TOKEN") or os.getenv("GITHUB_TOKEN")

# Headers Pool (Random rotation to avoid simple blocking)
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0"
]

# ==============================================================================
# SOURCES
# ==============================================================================
DIRECT_URLS = [
    # --- F0rc3Run ---
    "https://raw.githubusercontent.com/F0rc3Run/F0rc3Run/refs/heads/main/Best-Results/proxies.txt",
    "https://raw.githubusercontent.com/F0rc3Run/F0rc3Run/refs/heads/main/splitted-by-protocol/shadowsocks.txt",
    "https://raw.githubusercontent.com/F0rc3Run/F0rc3Run/refs/heads/main/splitted-by-protocol/vless.txt",
    "https://raw.githubusercontent.com/F0rc3Run/F0rc3Run/refs/heads/main/splitted-by-protocol/vmess.txt",
    "https://raw.githubusercontent.com/F0rc3Run/F0rc3Run/refs/heads/main/splitted-by-protocol/trojan.txt",
    "https://raw.githubusercontent.com/F0rc3Run/F0rc3Run/main/Special/Telegram.txt",
    "https://raw.githubusercontent.com/F0rc3Run/F0rc3Run/refs/heads/main/sstp-configs/sstp_with_country.txt",

    # --- NiREvil ---
    "https://raw.githubusercontent.com/NiREvil/vless/refs/heads/main/sub/clash-meta-wg.yml",
    "https://raw.githubusercontent.com/NiREvil/vless/refs/heads/main/sub/exclave-wg.txt",
    "https://raw.githubusercontent.com/NiREvil/vless/refs/heads/main/warp.json",
    "https://raw.githubusercontent.com/NiREvil/vless/refs/heads/main/sing-box.json",
    "https://raw.githubusercontent.com/NiREvil/vless/refs/heads/main/sub/nekobox-wg.txt",
    "https://raw.githubusercontent.com/NiREvil/vless/refs/heads/main/sub/v2rayng-wg.txt",
    "https://raw.githubusercontent.com/NiREvil/vless/refs/heads/main/hiddify/WarpOnWarp.json",
    "https://raw.githubusercontent.com/NiREvil/vless/refs/heads/main/sub/SSTime",
    "https://raw.githubusercontent.com/NiREvil/vless/refs/heads/main/sub/fragment",

    # --- Epodonios ---
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/Sub1.txt",
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/Sub2.txt",
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/Sub3.txt",
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/Splitted-By-Protocol/ss.txt",
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/Splitted-By-Protocol/vmess.txt",
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/Splitted-By-Protocol/vless.txt",
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/Splitted-By-Protocol/trojan.txt",
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/All_Configs_base64_Sub.txt",
    "https://raw.githubusercontent.com/Epodonios/bulk-xray-v2ray-vless-vmess-...-configs/main/sub/Iran/config.txt",
    "https://raw.githubusercontent.com/Epodonios/bulk-xray-v2ray-vless-vmess-...-configs/main/sub/United%20States/config.txt",
    "https://raw.githubusercontent.com/Epodonios/bulk-xray-v2ray-vless-vmess-...-configs/main/sub/Germany/config.txt",

    # --- Danialsamadi (V2Go) ---
    "https://raw.githubusercontent.com/Danialsamadi/v2go/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/Danialsamadi/v2go/main/Splitted-By-Protocol/vless.txt",
    "https://raw.githubusercontent.com/Danialsamadi/v2go/main/Splitted-By-Protocol/vmess.txt",
    "https://raw.githubusercontent.com/Danialsamadi/v2go/main/Splitted-By-Protocol/trojan.txt",
    "https://raw.githubusercontent.com/Danialsamadi/v2go/main/Splitted-By-Protocol/ss.txt",
    "https://raw.githubusercontent.com/Danialsamadi/v2go/main/Splitted-By-Protocol/ssr.txt",
    
    # --- BlackKnight / SoroushImanian ---
    "https://raw.githubusercontent.com/SoroushImanian/BlackKnight/main/sub/vless",
    "https://raw.githubusercontent.com/SoroushImanian/BlackKnight/main/sub/vmess",
    "https://raw.githubusercontent.com/SoroushImanian/BlackKnight/main/sub/trojan",
    "https://raw.githubusercontent.com/SoroushImanian/BlackKnight/main/sub/ss",
    "https://raw.githubusercontent.com/SoroushImanian/BlackKnight/main/sub/hysteria",
    "https://raw.githubusercontent.com/SoroushImanian/BlackKnight/main/sub/tuic",
    "https://raw.githubusercontent.com/SoroushImanian/BlackKnight/main/sub/mix",
    "https://raw.githubusercontent.com/SoroushImanian/BlackKnight/refs/heads/main/sub/wireguard",

    # --- FNET00 ---
    "https://raw.githubusercontent.com/FNET00bot/FNET00/Config/Main",
    "https://raw.githubusercontent.com/FNET00bot/FNET00/Config/Base64",
    "https://raw.githubusercontent.com/FNET00bot/FNET00/Config/Shadowrocket/Normal",
    "https://raw.githubusercontent.com/FNET00bot/FNET00/Config/Donate/Normal",

    # --- Mermeroo ---
    "https://raw.githubusercontent.com/mermeroo/V2RAY-FREE/main/Base64/Sub1_base64.txt",
    "https://raw.githubusercontent.com/mermeroo/V2RAY-FREE/main/All_Configs_base64_Sub.txt",
    "https://raw.githubusercontent.com/mermeroo/free-v2ray-collector/main/main/mix",
    "https://raw.githubusercontent.com/mermeroo/free-v2ray-collector/main/main/reality",
    "https://raw.githubusercontent.com/mermeroo/free-v2ray-collector/main/main/vless",
    
    # --- MhdiTaheri ---
    "https://raw.githubusercontent.com/MhdiTaheri/V2rayCollector/main/sub/mix",
    "https://raw.githubusercontent.com/MhdiTaheri/V2rayCollector/main/sub/vless",
    "https://raw.githubusercontent.com/MhdiTaheri/V2rayCollector/main/sub/vmess",
    "https://raw.githubusercontent.com/MhdiTaheri/V2rayCollector/main/sub/tuic",
    "https://raw.githubusercontent.com/MhdiTaheri/V2rayCollector/main/sub/hysteria",
    
    # --- 10ium ---
    "https://raw.githubusercontent.com/10ium/free-config/refs/heads/main/HighSpeed.txt",
    "https://raw.githubusercontent.com/10ium/ScrapeAndCategorize/refs/heads/main/output_configs/Vless.txt",
    "https://raw.githubusercontent.com/10ium/ScrapeAndCategorize/refs/heads/main/output_configs/Trojan.txt",
    "https://raw.githubusercontent.com/10ium/ScrapeAndCategorize/refs/heads/main/output_configs/Hysteria2.txt",
    
    # --- Barry-Far ---
    "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Sub1.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Sub2.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/vless.txt",

    # --- Hiddify / Singbox Specific ---
    "https://raw.githubusercontent.com/ndsphonemy/proxy-sub/refs/heads/main/mobile.txt",
    "https://raw.githubusercontent.com/ndsphonemy/proxy-sub/refs/heads/main/speed.txt",
    "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/normal/vless",
    "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/normal/reality",
    "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/normal/vmess",
    "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/normal/tuic",
    "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/normal/hysteria2",

    # --- AvenCores ---
    "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/githubmirror/1.txt",
    "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/githubmirror/10.txt",

    # --- Mixed / Others ---
    "https://vpny.online/VPNy.json",
    "https://raw.githubusercontent.com/Firmfox/Proxify/refs/heads/main/v2ray_configs/mixed/subscription-1.txt",
    "https://raw.githubusercontent.com/LalatinaHub/Mineral/refs/heads/master/result/nodes",
    "https://raw.githubusercontent.com/Farid-Karimi/Config-Collector/refs/heads/main/mixed_iran.txt",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/super-sub.txt",
    "https://raw.githubusercontent.com/itsyebekhe/PSG/main/subscriptions/nekobox/mix.json",
    "https://v2.alicivil.workers.dev",
    "https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/Eternity",
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge.txt",
    "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
    "https://shadowmere.xyz/api/b64sub",
    "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/refs/heads/main/Protocols/vless.txt",
    "https://raw.githubusercontent.com/arshiacomplus/v2rayExtractor/refs/heads/main/mix/sub.html",
    "https://raw.githubusercontent.com/Mahdi0024/ProxyCollector/master/sub/proxies.txt",
    "https://github.com/4n0nymou3/multi-proxy-config-fetcher/raw/refs/heads/main/configs/proxy_configs.txt",
    "https://sub.amiralter.com/config-lite",
    "https://raw.githubusercontent.com/DarknessShade/Sub/main/V2mix",
    "https://raw.githubusercontent.com/lagzian/IranConfigCollector/main/Base64.txt",
    "https://raw.githubusercontent.com/MahsaNetConfigTopic/config/refs/heads/main/xray_final.txt",
    "https://raw.githubusercontent.com/hamedcode/port-based-v2ray-configs/main/sub/vless.txt",
    "https://raw.githubusercontent.com/AzadNetCH/Clash/main/AzadNet.txt",
    "https://raw.githubusercontent.com/Leon406/SubCrawler/refs/heads/main/sub/share/a11",
    "https://raw.githubusercontent.com/youfoundamin/V2rayCollector/main/mixed_iran.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_BASE64.txt",
    "https://raw.githubusercontent.com/HosseinKoofi/GO_V2rayCollector/main/mixed_iran.txt",
    "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/refs/heads/main/V2Ray-Config-By-EbraSha.txt",
    "https://raw.githubusercontent.com/Argh94/V2RayAutoConfig/refs/heads/main/configs/Vmess.txt",
    "https://raw.githubusercontent.com/liketolivefree/kobabi/main/sub_all.txt",
    "https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/V2RAY_SUB/refs/heads/main/v2ray_configs.txt",
    "https://raw.githubusercontent.com/bamdad23/JavidnamanIran/refs/heads/main/WS%2BHysteria2",
    "https://raw.githubusercontent.com/mshojaei77/v2rayAuto/refs/heads/main/subs/hysteria",
    "https://trojanvmess.pages.dev/cmcm?b64",
    "https://raw.githubusercontent.com/Mosifree/-FREE2CONFIG/refs/heads/main/Vless",
    "https://raw.githubusercontent.com/Proxydaemitelegram/Proxydaemi44/refs/heads/main/Proxydaemi44",
    "https://raw.githubusercontent.com/MrMohebi/xray-proxy-grabber-telegram/refs/heads/master/collected-proxies/xray-json-full/actives_all.json",
    "https://raw.githubusercontent.com/rango-cfs/NewCollector/refs/heads/main/v2ray_links.txt",
    "https://raw.githubusercontent.com/jetwalk/japan-sub/refs/heads/main/japan_configs.txt",
    "https://raw.githubusercontent.com/mehran1404/Sub_Link/refs/heads/main/V2RAY-Sub.txt",
    "https://raw.githubusercontent.com/vxiaov/free_proxy_ss/main/v2ray/v2raysub",
    "https://raw.githubusercontent.com/anaer/Sub/main/clash.yaml",
    "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.txt",
    "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/clash.yml",
    "https://raw.githubusercontent.com/coldwater-10/Vpnclashfa/main/V2Hub4.yaml",
    "https://raw.githubusercontent.com/aiboboxx/clashfree/refs/heads/main/clash.yml",
    "https://raw.githubusercontent.com/mfuu/v2ray/master/clash.yaml",
    "https://raw.githubusercontent.com/darkvpnapp/CloudflarePlus/refs/heads/main/clash.yaml",
    "https://clash.221207.xyz/pubclashyaml",
    "https://raw.githubusercontent.com/SANYIMOE/VPN-free/master/sub",
    
    # --- API Links ---
    "http://subxfxssr.xfxvpn.me/api/v1/client/subscribe?token=0d5306ab80abb3f2012edf9169f5f00a",
    "https://sub.pmsub.me/base64"
]

# ==============================================================================
# LOGIC
# ==============================================================================

def get_session():
    """Creates a requests Session with robust retry logic."""
    session = requests.Session()
    retry = Retry(
        total=RETRIES,
        read=RETRIES,
        connect=RETRIES,
        backoff_factor=BACKOFF_FACTOR,
        status_forcelist=[500, 502, 503, 504, 429],
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session

def get_random_headers():
    return {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Connection": "keep-alive"
    }

def normalize_github_url(url):
    """Converts GitHub blob URLs to raw user content URLs."""
    if "github.com" in url and "/blob/" in url:
        return url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
    return url

def clean_base64(text):
    """
    Cleans text to be a valid base64 string.
    Removes whitespace, adds padding.
    """
    text = re.sub(r'\s+', '', text)
    missing_padding = len(text) % 4
    if missing_padding:
        text += '=' * (4 - missing_padding)
    return text

def extract_configs_from_text(text):
    """
    Recursively extracts configs from text.
    Handles:
    1. Direct protocol links (vmess://, etc.)
    2. Standard Base64 encoded subscriptions.
    3. URL-Safe Base64 encoded subscriptions.
    4. Mixed content (some text, some base64).
    """
    configs = set()
    
    # Regex to capture all modern proxy protocols including WireGuard variants
    # Covers: vmess, vless, trojan, ss, ssr, tuic, hysteria, hy2, wg, warp, juicity, dtech, nekoray
    proto_pattern = r'(?:vmess|vless|trojan|ss|ssr|hy2|hysteria2|hysteria|tuic|juicity|dtech|nekoray|wireguard|wg|warp)://[a-zA-Z0-9\+\=\-\_\.\?\&@\#%:/]+'
    
    # 1. Direct Scan
    matches = re.findall(proto_pattern, text)
    for m in matches:
        configs.add(m.strip())

    # 2. Base64 Decode Attempt
    # Split text by newlines or look for large chunks that might be base64
    # We try to decode the WHOLE text first, if that fails, we check lines.
    
    candidates = [text] # Treat whole text as candidate
    
    # If text is multiline, also treat each non-empty line as a potential base64 string
    # (Many subs are just a list of base64 strings)
    if '\n' in text:
        candidates.extend([line.strip() for line in text.split('\n') if len(line.strip()) > 20])

    for candidate in candidates:
        candidate_clean = clean_base64(candidate)
        try:
            # Try Standard Base64
            decoded_bytes = base64.b64decode(candidate_clean, validate=True)
            try:
                decoded_str = decoded_bytes.decode('utf-8')
            except UnicodeDecodeError:
                try:
                    decoded_str = decoded_bytes.decode('latin-1')
                except:
                    continue # Not text
            
            # Recursive scan on decoded text
            decoded_configs = re.findall(proto_pattern, decoded_str)
            if decoded_configs:
                for dc in decoded_configs:
                    configs.add(dc.strip())
            elif "\n" in decoded_str: 
                 # Maybe it's a list of links that regex didn't catch or need second pass
                 pass
                 
        except Exception:
            pass

    return configs

def parse_telegram_preview(html_content):
    """
    Extracts configs from the HTML preview of a public Telegram channel.
    Targeting 'tgme_widget_message_text' div content.
    """
    try:
        # Simple regex scrape for content inside message bubbles
        # This avoids needing BeautifulSoup dependency
        message_pattern = r'class="tgme_widget_message_text[^"]*">(.*?)</div>'
        messages = re.findall(message_pattern, html_content, re.DOTALL)
        
        combined_text = ""
        for msg in messages:
            # Clean HTML tags (br, etc)
            clean_msg = re.sub(r'<[^>]+>', '\n', msg)
            combined_text += clean_msg + "\n"
            
        return extract_configs_from_text(combined_text)
    except Exception as e:
        logger.error(f"Error parsing Telegram HTML: {e}")
        return set()

def fetch_source(url):
    """
    Worker function to fetch and extract from a single URL.
    """
    url = normalize_github_url(url)
    session = get_session()
    
    try:
        response = session.get(url, headers=get_random_headers(), timeout=TIMEOUT)
        
        if response.status_code == 200:
            content = response.text
            
            # Special handling for Telegram web previews
            if "t.me/s/" in url:
                configs = parse_telegram_preview(content)
                logger.info(f"Fetched Telegram {url}: found {len(configs)}")
                return configs
                
            configs = extract_configs_from_text(content)
            if configs:
                logger.info(f"Fetched {url}: found {len(configs)}")
                return configs
            else:
                logger.debug(f"Fetched {url}: No configs found.")
        else:
            logger.warning(f"Failed {url}: HTTP {response.status_code}")
            
    except Exception as e:
        logger.warning(f"Error fetching {url}: {str(e)}")
        
    return set()

def search_github_code(all_configs):
    """
    Uses GitHub Code Search API to find fresh text files containing proxy protocols.
    Handles Rate Limits.
    """
    if not GITHUB_TOKEN:
        logger.warning("No GITHUB_TOKEN provided. Skipping GitHub API Search.")
        return

    logger.info("Starting GitHub Code Search...")
    
    headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "Pr0xySh4rk-Collector"
    }
    
    # Specific queries to target files
    queries = [
        'filename:sub "vmess://"',
        'filename:config "vless://"',
        'filename:proxy "trojan://"',
        'extension:txt "tuic://"',
        'extension:txt "hysteria2://"',
        '"ss://" extension:txt'
    ]
    
    session = get_session()

    for query in queries:
        page = 1
        while page <= 2: # Limit depth to save API quota and time
            search_url = f"https://api.github.com/search/code?q={query}&sort=indexed&order=desc&per_page=20&page={page}"
            try:
                resp = session.get(search_url, headers=headers, timeout=10)
                
                if resp.status_code == 403 or resp.status_code == 429:
                    logger.warning("GitHub API Rate Limit Exceeded. Stopping search.")
                    return # Stop completely to avoid ban
                
                if resp.status_code != 200:
                    logger.error(f"GitHub API Error {resp.status_code}")
                    break
                    
                items = resp.json().get('items', [])
                if not items:
                    break
                    
                for item in items:
                    raw_url = item.get('html_url', '').replace('github.com', 'raw.githubusercontent.com').replace('/blob/', '/')
                    if raw_url:
                        found = fetch_source(raw_url)
                        if found:
                            all_configs.update(found)
                            
                page += 1
                time.sleep(2) # Be polite to API
                
            except Exception as e:
                logger.error(f"GitHub Search Error: {e}")
                break

# ==============================================================================
# MAIN EXECUTION
# ==============================================================================

def main():
    start_time = time.time()
    final_configs = set()

    # 1. Scrape Direct URLs (Concurrent)
    logger.info(f"Starting Scrape of {len(DIRECT_URLS)} direct sources...")
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_url = {executor.submit(fetch_source, url): url for url in DIRECT_URLS}
        
        for future in concurrent.futures.as_completed(future_to_url):
            try:
                data = future.result()
                if data:
                    final_configs.update(data)
            except Exception as exc:
                logger.error(f"Worker exception: {exc}")

    logger.info(f"Direct scrape complete. Current total: {len(final_configs)}")

    # 2. Dynamic GitHub Search
    search_github_code(final_configs)

    # 3. Save Output
    if not final_configs:
        logger.error("No configs collected!")
        # Create empty file to avoid pipeline errors
        open(OUTPUT_FILE, "w").close()
        return

    logger.info(f"Saving {len(final_configs)} unique configs to {OUTPUT_FILE}...")
    
    try:
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            for config in final_configs:
                f.write(config + "\n")
        logger.info("Write successful.")
    except Exception as e:
        logger.error(f"Failed to write output file: {e}")

    elapsed = time.time() - start_time
    logger.info(f"Collection finished in {elapsed:.2f} seconds.")

if __name__ == "__main__":
    main()
