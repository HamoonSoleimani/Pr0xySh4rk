import requests
import re
from datetime import datetime, timedelta
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

def get_date_query():
    # Look back 3 days to account for GitHub indexing delays
    past_date = datetime.now() - timedelta(days=3)
    return past_date.strftime("%Y-%m-%d")

def extract_configs(text):
    configs = set()
    # Pattern for standard links
    pattern = r'(vmess|vless|trojan|ss)://[a-zA-Z0-9\+\=\-\_\.\?\&]+'
    
    # 1. Search in raw text
    matches = re.findall(pattern, text)
    for match in matches:
        configs.add(match)

    # 2. Try to decode Base64 (Handling the "Subscription" blobs)
    # Cleaning the text to handle files that might have newlines in the b64 string
    cleaned_text = text.replace("\n", "").replace(" ", "").strip()
    
    if len(cleaned_text) > 20:
        try:
            # Fix padding
            missing_padding = len(cleaned_text) % 4
            if missing_padding:
                cleaned_text += '=' * (4 - missing_padding)
            
            decoded_bytes = base64.b64decode(cleaned_text)
            decoded_str = decoded_bytes.decode('utf-8', errors='ignore')
            
            # Search inside the decoded string
            decoded_matches = re.findall(pattern, decoded_str)
            for dm in decoded_matches:
                configs.add(dm)
        except Exception:
            pass # Not a valid base64
            
    return configs

def search_github():
    if not GITHUB_TOKEN:
        print("[-] Error: API_TOKEN is missing.")
        return set()

    date_query = get_date_query()
    all_configs = set()
    
    # We run multiple specific queries to cast a wider net
    search_queries = [
        # Strategy 1: Look for raw links in text files
        f'"vmess://" extension:txt pushed:>{date_query}',
        f'"vless://" extension:txt pushed:>{date_query}',
        
        # Strategy 2: Look for subscription files (usually Base64 encoded)
        f'filename:v2ray extension:txt pushed:>{date_query}',
        f'filename:sub extension:txt pushed:>{date_query}',
        f'filename:config extension:txt pushed:>{date_query}'
    ]

    print(f"[*] Searching for configs updated after: {date_query}")
    
    for query in search_queries:
        print(f"[*] Querying: {query}")
        page = 1
        while True:
            url = f"https://api.github.com/search/code?q={query}&sort=indexed&order=desc&per_page=20&page={page}"
            
            try:
                response = requests.get(url, headers=get_headers())
                
                if response.status_code == 403:
                    print("[-] Rate limit hit. Moving to next query.")
                    break
                
                if response.status_code != 200:
                    break

                data = response.json()
                items = data.get('items', [])
                
                if not items:
                    break 

                for item in items:
                    raw_url = item.get('html_url').replace('github.com', 'raw.githubusercontent.com').replace('/blob/', '/')
                    try:
                        file_resp = requests.get(raw_url, timeout=10)
                        if file_resp.status_code == 200:
                            found = extract_configs(file_resp.text)
                            if found:
                                print(f"    [+] Found {len(found)} in {item['name']}")
                                all_configs.update(found)
                    except Exception:
                        pass

                page += 1
                time.sleep(2)
                if page > 3: break # Keep it fast, max 3 pages per query
