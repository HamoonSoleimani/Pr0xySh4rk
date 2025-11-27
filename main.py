import requests
import re
import time
import base64
import os
import concurrent.futures

# Get token from GitHub Secrets
GITHUB_TOKEN = os.getenv("API_TOKEN")
OUTPUT_FILE = "collected_configs.txt"

# Timeout for each request (seconds)
TIMEOUT = 20

# ==============================================================================
# 1. MASSIVE LIST OF DIRECT SOURCES
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

    # --- Others Found in List ---
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
    
    # --- Specific API Links ---
    "http://subxfxssr.xfxvpn.me/api/v1/client/subscribe?token=0d5306ab80abb3f2012edf9169f5f00a",
    "https://sub.pmsub.me/base64"
]

def get_headers():
    return {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }

def extract_configs(text):
    configs = set()
    
    # EXPANDED PROTOCOLS: vmess, vless, trojan, ss, ssr, hy2, hysteria2, hysteria, tuic, juicity, wireguard
    # Added '/' to the character class to correctly capture paths and base64 slashes
    pattern = r'(?:vmess|vless|trojan|ss|ssr|hy2|hysteria2|hysteria|tuic|juicity|wireguard)://[a-zA-Z0-9\+\=\-\_\.\?\&@\#%:/]+'
    
    # 1. Raw Regex
    matches = re.findall(pattern, text)
    for match in matches:
        configs.add(match)

    # 2. Base64 Decode
    try:
        # Basic cleanup
        cleaned_text = "".join(text.split())
        
        # Heuristic: if it looks like a typical URL list (http...), skip deep decode
        # Only decode if it DOES NOT start with http/https
        if not cleaned_text.startswith("http") and len(cleaned_text) > 20:
            missing_padding = len(cleaned_text) % 4
            if missing_padding:
                cleaned_text += '=' * (4 - missing_padding)
            
            decoded_bytes = base64.b64decode(cleaned_text)
            decoded_str = decoded_bytes.decode('utf-8', errors='ignore')
            
            decoded_matches = re.findall(pattern, decoded_str)
            for dm in decoded_matches:
                configs.add(dm)
    except Exception:
        pass

    return configs

def fetch_and_extract(url):
    """Helper function for thread pool"""
    try:
        # Fix GitHub blob links
        if "github.com" in url and "/blob/" in url:
            url = url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
            
        response = requests.get(url, timeout=TIMEOUT, headers={"User-Agent": "Mozilla/5.0"})
        
        if response.status_code == 200:
            found = extract_configs(response.text)
            if found:
                print(f"    [+] Found {len(found)} configs from {url.split('/')[-1]}")
                return found
    except Exception:
        pass
    return set()

def scrape_direct_repos(all_configs):
    print(f"\n[*] Scraping {len(DIRECT_URLS)} high-quality sources (Concurrent)...")
    
    # 25 workers to speed up the huge list
    with concurrent.futures.ThreadPoolExecutor(max_workers=25) as executor:
        results = executor.map(fetch_and_extract, DIRECT_URLS)
        
    for result in results:
        if result:
            all_configs.update(result)

def search_github(all_configs):
    if not GITHUB_TOKEN:
        print("[-] Error: API_TOKEN is missing.")
        return

    # Smart queries covering all protocols
    search_queries = [
        'filename:Sub extension:txt',
        'filename:v2ray extension:txt',
        'filename:config extension:txt',
        'filename:proxy extension:txt',
        '"vmess://" extension:txt',
        '"vless://" extension:txt',
        '"ss://" extension:txt',
        '"trojan://" extension:txt',
        '"tuic://" extension:txt',
        '"hysteria2://" extension:txt'
    ]

    print(f"\n[*] Searching GitHub Code (Sorted by Recently Indexed)...")
    
    for query in search_queries:
        print(f"[*] Querying: {query}")
        page = 1
        # Limit to 2 pages to keep it fast
        while page <= 2: 
            url = f"https://api.github.com/search/code?q={query}&sort=indexed&order=desc&per_page=20&page={page}"
            
            try:
                response = requests.get(url, headers=get_headers())
                
                if response.status_code == 403:
                    print("[-] GitHub Search Rate limit hit. Skipping search.")
                    break 
                
                items = response.json().get('items', [])
                if not items:
                    break 

                for item in items:
                    raw_url = item.get('html_url').replace('github.com', 'raw.githubusercontent.com').replace('/blob/', '/')
                    try:
                        file_resp = requests.get(raw_url, timeout=5)
                        if file_resp.status_code == 200:
                            found = extract_configs(file_resp.text)
                            if found:
                                print(f"    [Search] Found {len(found)} in {item['name']}")
                                all_configs.update(found)
                    except Exception:
                        pass
                page += 1
                time.sleep(1) 
            except Exception as e:
                print(f"[-] Search Error: {e}")
                break

def save_configs(configs):
    if not configs:
        print("[-] No configs found.")
        open(OUTPUT_FILE, "w").close()
        return

    print(f"\n[SUCCESS] Total unique configs extracted: {len(configs)}")
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for conf in configs:
            f.write(conf + "\n")

if __name__ == "__main__":
    final_configs = set()
    
    # 1. Parallel scrape of the massive hardcoded list
    scrape_direct_repos(final_configs)
    
    # 2. Dynamic GitHub Search (Backfill with fresh random uploads)
    search_github(final_configs)
    
    # 3. Save to file
    save_configs(final_configs)
