# Pr0xySh4rk

![image](https://github.com/user-attachments/assets/c3ba4213-3a1f-4d76-809a-42d1a8a1e993)

**Pr0xySh4rk** is a Python-based tool designed to merge and test proxy configuration links for Xray, Sing-box. This project automatically runs every 24 hours using GitHub Actions. It fetches subscription URLs, tests each configuration using both TCP and HTTP tests (in a two-pass approach), filters out unhealthy configurations, and updates a Base64-encoded configuration file (`Pr0xySh4rk`) for use in Xray, Sing-box clients (V2rayNG, MahsaNG, Hiddify, etc).
 
### Usage
Simply import this url into your Hiddify/V2ray client applications!

`https://raw.githubusercontent.com/HamoonSoleimani/Pr0xySh4rk/refs/heads/main/Pr0xySh4rk_SubBase64.txt`



