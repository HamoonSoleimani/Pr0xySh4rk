import requests
import re
from datetime import datetime, timedelta
import time
import base64
import os

# Get token from GitHub Secrets environment variable
GITHUB_TOKEN = os.getenv("API_TOKEN")

TARGET_EXTENSIONS = ["txt", "yaml", "yml"]
OUTPUT_FILE = "collected_configs.txt"

def get_headers():
    return {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json"
    }

def get_pushed_date_query():
    # Look for files pushed in the last 24 hours
    yesterday = datetime.now() - timedelta(days=1)
    return yesterday.strftime("%Y-%m-%d")

def extract_configs(text):
    configs = set()
    pattern = r'(vmess|vless|trojan|ss)://[a-zA-Z0-9\+\=\-\_\.\?\&]+'
    
    # 1. Regex search
    matches = re.findall(pattern, text)
    for match in matches:
        configs.add(match)

    # 2. Base64 decode attempt
    if " " not in text.strip() and len(text) > 20:
        try:
            missing_padding = len(text) % 4
            if missing_padding:
                text += '=' * (4 - missing_padding)
            decoded_bytes = base64.b64decode(text)
            decoded_str = decoded_bytes.decode('utf-8', errors='ignore')
            decoded_matches = re.findall(pattern, decoded_str)
            for dm in decoded_matches:
                configs.add(dm)
        except Exception:
            pass
    return configs

def search_github():
    if not GITHUB_TOKEN:
        print("[-] Error: API_TOKEN is missing from environment variables.")
        return set()

    date_query = get_pushed_date_query()
    all_configs = set()
    
    print(f"[*] Searching for configs updated after: {date_query}")
    query_base = "vmess OR vless OR trojan"
    
    for ext in TARGET_EXTENSIONS:
        page = 1
        while True:
            # Construct query
            query = f"{query_base} extension:{ext} pushed:>{date_query}"
            url = f"https://api.github.com/search/code?q={query}&sort=indexed&order=desc&per_page=30&page={page}"
            
            try:
                response = requests.get(url, headers=get_headers())
                
                if response.status_code == 403:
                    print("[-] Rate limit hit. Stopping this extension.")
                    break
                
                data = response.json()
                items = data.get('items', [])
                
                if not items:
                    break 

                print(f"[*] Page {page}: Found {len(items)} potential files (.{ext})")

                for item in items:
                    raw_url = item.get('html_url').replace('github.com', 'raw.githubusercontent.com').replace('/blob/', '/')
                    try:
                        file_resp = requests.get(raw_url)
                        if file_resp.status_code == 200:
                            found = extract_configs(file_resp.text)
                            if found:
                                all_configs.update(found)
                    except Exception:
                        pass

                page += 1
                time.sleep(2) # Sleep to respect rate limits
                if page > 5: break # Limit depth to save time/resources

            except Exception as e:
                print(f"[-] Error: {e}")
                break
                
    return all_configs

def save_configs(configs):
    if not configs:
        print("[-] No configs found today.")
        # Create empty file so workflow doesn't fail on missing file
        open(OUTPUT_FILE, "w").close() 
        return

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for conf in configs:
            f.write(conf + "\n")
    print(f"[SUCCESS] Saved {len(configs)} configs.")

if __name__ == "__main__":
    configs = search_github()
    save_configs(configs)
