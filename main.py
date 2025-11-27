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
    # We look back 2 days to be safe with timezones and indexing lag
    past_date = datetime.now() - timedelta(days=2)
    return past_date.strftime("%Y-%m-%d")

def extract_configs(text):
    configs = set()
    
    # IMPROVED REGEX: matches vmess://... including @, :, ?, &, #, % (for url encoding)
    pattern = r'(vmess|vless|trojan|ss|ssr)://[a-zA-Z0-9\+\=\-\_\.\?\&@\#%:]+'
    
    # 1. METHOD A: Raw Regex (Best for files like Sub11.txt)
    # This finds links even if they are mixed with text or HTML
    matches = re.findall(pattern, text)
    for match in matches:
        configs.add(match)

    # 2. METHOD B: Base64 Decode (Best for "Subscription" blobs)
    # Some files are just one giant Base64 string. We try to decode it.
    try:
        # Remove whitespace/newlines to clean the string for decoding
        cleaned_text = "".join(text.split())
        
        # Check if it looks like base64 (length multiple of 4 roughly, no spaces)
        if len(cleaned_text) > 20:
            # Fix padding
            missing_padding = len(cleaned_text) % 4
            if missing_padding:
                cleaned_text += '=' * (4 - missing_padding)
            
            decoded_bytes = base64.b64decode(cleaned_text)
            decoded_str = decoded_bytes.decode('utf-8', errors='ignore')
            
            # Run regex again on the decoded text
            decoded_matches = re.findall(pattern, decoded_str)
            for dm in decoded_matches:
                configs.add(dm)
    except Exception:
        pass # Decoding failed, likely just a plain text file

    return configs

def search_github():
    if not GITHUB_TOKEN:
        print("[-] Error: API_TOKEN is missing. Make sure it is set in Repository Secrets.")
        return set()

    date_query = get_date_query()
    all_configs = set()
    
    # Multiple search queries to find different types of files
    search_queries = [
        # 1. Look for files named like the example (Sub11.txt)
        f'filename:Sub extension:txt pushed:>{date_query}',
        f'filename:v2ray extension:txt pushed:>{date_query}',
        
        # 2. Look for keywords inside the file
        f'"vmess://" extension:txt pushed:>{date_query}',
        f'"vless://" extension:txt pushed:>{date_query}'
    ]

    print(f"[*] Searching for configs updated after: {date_query}")
    
    for query in search_queries:
        print(f"[*] Querying: {query}")
        page = 1
        # Max 3 pages per query to prevent timeout/rate limits
        while page <= 3: 
            url = f"https://api.github.com/search/code?q={query}&sort=indexed&order=desc&per_page=20&page={page}"
            
            try:
                response = requests.get(url, headers=get_headers())
                
                if response.status_code == 403:
                    print("[-] Rate limit hit. Moving to next query.")
                    break # Stop this query, try next one
                
                if response.status_code != 200:
                    print(f"[-] Status {response.status_code}. Skipping.")
                    break

                data = response.json()
                items = data.get('items', [])
                
                if not items:
                    break 

                for item in items:
                    # Convert GitHub UI URL to RAW content URL
                    raw_url = item.get('html_url').replace('github.com', 'raw.githubusercontent.com').replace('/blob/', '/')
                    
                    try:
                        print(f"    --> Checking: {item['name']}")
                        file_resp = requests.get(raw_url, timeout=10)
                        
                        if file_resp.status_code == 200:
                            found = extract_configs(file_resp.text)
                            if found:
                                print(f"        [+] Found {len(found)} configs")
                                all_configs.update(found)
                    except Exception as e:
                        print(f"        [!] Error downloading file: {e}")

                page += 1
                time.sleep(2) # Sleep to be nice to API

            except Exception as e:
                print(f"[-] Critical Error: {e}")
                break
                
    return all_configs

def save_configs(configs):
    if not configs:
        print("[-] No configs found.")
        # Create empty file so git push doesn't fail
        with open(OUTPUT_FILE, "w") as f:
            f.write("")
        return

    print(f"\n[SUCCESS] Total unique configs extracted: {len(configs)}")
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for conf in configs:
            f.write(conf + "\n")

if __name__ == "__main__":
    configs = search_github()
    save_configs(configs)
