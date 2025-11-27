import requests
import re
import time
import base64
import os

# Get token from GitHub Secrets
GITHUB_TOKEN = os.getenv("API_TOKEN")
OUTPUT_FILE = "collected_configs.txt"

def get_headers():
    return {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json"
    }

def extract_configs(text):
    configs = set()
    # FIXED REGEX: Added (?:...) to prevent capturing just the protocol
    pattern = r'(?:vmess|vless|trojan|ss|ssr)://[a-zA-Z0-9\+\=\-\_\.\?\&@\#%:]+'
    
    # 1. Raw Regex
    matches = re.findall(pattern, text)
    for match in matches:
        configs.add(match)

    # 2. Base64 Decode
    try:
        cleaned_text = "".join(text.split())
        if len(cleaned_text) > 20:
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

def scrape_direct_repos(all_configs):
    print(f"\n[*] Scraping specific known repositories...")
    direct_urls = [
        "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/Sub11.txt",
        "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/Sub1.txt",
        "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/Sub2.txt",
        "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/Sub3.txt",
        "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge.txt",
        "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/All_Configs_Sub.txt"
    ]
    for url in direct_urls:
        try:
            print(f"    --> Fetching: {url}")
            resp = requests.get(url, timeout=10)
            if resp.status_code == 200:
                found = extract_configs(resp.text)
                if found:
                    print(f"        [+] Found {len(found)} configs")
                    all_configs.update(found)
        except Exception:
            pass

def search_github(all_configs):
    if not GITHUB_TOKEN:
        print("[-] Error: API_TOKEN is missing.")
        return

    search_queries = [
        'filename:Sub extension:txt',
        'filename:v2ray extension:txt',
        'filename:config extension:txt',
        '"vmess://" extension:txt',
        '"vless://" extension:txt'
    ]

    print(f"\n[*] Searching GitHub Code...")
    
    for query in search_queries:
        print(f"[*] Querying: {query}")
        page = 1
        while page <= 2: 
            url = f"https://api.github.com/search/code?q={query}&sort=indexed&order=desc&per_page=15&page={page}"
            try:
                response = requests.get(url, headers=get_headers())
                if response.status_code == 403:
                    print("[-] Rate limit hit.")
                    break 
                
                items = response.json().get('items', [])
                if not items: break 

                for item in items:
                    raw_url = item.get('html_url').replace('github.com', 'raw.githubusercontent.com').replace('/blob/', '/')
                    try:
                        file_resp = requests.get(raw_url, timeout=5)
                        if file_resp.status_code == 200:
                            found = extract_configs(file_resp.text)
                            if found:
                                print(f"    [+] Found {len(found)} in {item['name']}")
                                all_configs.update(found)
                    except Exception:
                        pass
                page += 1
                time.sleep(1.5) 
            except Exception:
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
    search_github(final_configs)
    scrape_direct_repos(final_configs)
    save_configs(final_configs)
