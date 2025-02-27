# Pr0xySh4rk

![image](https://github.com/user-attachments/assets/c3ba4213-3a1f-4d76-809a-42d1a8a1e993)

**Pr0xySh4rk** is a Python-based tool designed to merge and test proxy configuration links for Hiddify. This project automatically runs every 24 hours using GitHub Actions. It fetches subscription URLs, tests each configuration using both TCP and HTTP tests (in a two-pass approach), filters out unhealthy configurations, and updates a Base64-encoded configuration file (`Pr0xySh4rk`) for use in Hiddify/Xray.

## Features

- **Automated Fetching:** Reads subscription URLs from a file (`subs.txt`).
- **Two-Pass Testing:**  
  - First pass: Performs a TCP test.  
  - Second pass: On the survivors from the TCP test, performs an HTTP test.
- **Filtering and Diversification:**  
  - Keeps only the healthy configurations.  
  - Applies “best 75 per protocol” filtering and diversifies sources.
- **Output:**  
  - The final merged configuration is output in Base64 by default.
 
### Usage
Simply import this url into your Hiddify/V2ray client applications!

`https://raw.githubusercontent.com/HamoonSoleimani/Pr0xySh4rk/refs/heads/main/Pr0xySh4rkBase64.txt`



