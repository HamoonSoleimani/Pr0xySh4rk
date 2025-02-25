# Pr0xySh4rk

![Pr0xySh4rk](https://github.com/user-attachments/assets/373d2b5d-eaac-4772-bc76-a7cd009ff51f)

**Pr0xySh4rk** is a Python-based tool designed to merge and test proxy configuration links for Hiddify. This project automatically runs every 24 hours using GitHub Actions. It fetches subscription URLs, tests each configuration using both TCP and HTTP tests (in a two-pass approach), filters out unhealthy configurations, and updates a Base64-encoded configuration file (`configsbase64.txt`) for use in Hiddify.

## Features

- **Automated Fetching:** Reads subscription URLs from a file (`subs.txt`).
- **Two-Pass Testing:**  
  - First pass: Performs a TCP test.  
  - Second pass: On the survivors from the TCP test, performs an HTTP test.
- **Filtering and Diversification:**  
  - Keeps only the healthy configurations.  
  - Applies “best 50 per protocol” filtering and diversifies sources.
- **Output:**  
  - The final merged configuration is output in Base64 by default.
 
## Usage
Simply copy this subscription link and paste it on Hiddify Application
```bash
https://raw.githubusercontent.com/HamoonSoleimani/Pr0xySh4rk24/refs/heads/main/configsbase64.txt


