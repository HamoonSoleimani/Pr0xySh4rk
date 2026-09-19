# Pr0xySh4rk
![image](https://github.com/user-attachments/assets/c3ba4213-3a1f-4d76-809a-42d1a8a1e993)
**Pr0xySh4rk** collects free vmess / vless / trojan / shadowsocks / hysteria2 /
tuic / wireguard configs from a curated set of public sources, actually
**tests every one of them for real connectivity, latency, and (optionally)
throughput**, and publishes only the ones that currently work as a single
ready-to-import subscription. A GitHub Actions workflow re-runs the whole
pipeline every 6 hours and commits the refreshed subscription back into this
repo.

### Subscription URL

```
https://raw.githubusercontent.com/HamoonSoleimani/Pr0xySh4rk/refs/heads/main/Pr0xySh4rk_SubBase64.txt
```

Import this URL into V2rayNG, Hiddify, NekoBox, Streisand, or any client that
accepts a base64 subscription link.

---

## How it works

```
main.py            ──►  collected_configs.txt   ──►  Pr0xySh4rk.py  ──►  Pr0xySh4rk_SubBase64.txt
(collector)              (raw, de-duplicated)         (tester + reporter)      (published subscription)
```

1. **`main.py`** downloads each source in `SOURCES`, extracts every config
   link it can find regardless of how the source packages them (plain text,
   one link per line; the whole file as a single base64 blob; individual
   base64 lines; with or without `#comment` header lines mixed in), and
   writes the de-duplicated result to `collected_configs.txt`.

2. **`Pr0xySh4rk.py`** hands that list to
   [`xray-knife`](https://github.com/lilendian0x00/xray-knife)'s built-in
   batch HTTP tester (`xray-knife http -f ... -x csv`), which does the actual
   work: TCP pre-screening to quickly drop dead endpoints, concurrent
   real-connection tests through each proxy, an optional throughput
   measurement, and IP/country lookup - all in one process, using
   `xray-knife`'s own embedded engine (no separate `xray` binary needed).

3. The script reads `xray-knife`'s structured CSV output, keeps only configs
   with `status == passed`, groups them by protocol, ranks each group by a
   score that favors low latency *and* high throughput, keeps the top
   `--limit` per protocol, renames them (`🔒Pr0xySh4rk🦈[VLESS][01][🇺🇸][45.2Mbps][120ms]`),
   and writes the result as the final subscription (base64 by default).

   If **nothing** passes in a given run (it happens - these are free public
   proxies), the script leaves the previously published subscription file
   untouched instead of overwriting it with an empty list.

## Running it yourself

```bash
pip install -r requirements.txt
python main.py --output collected_configs.txt

# xray-knife v11+ is a single self-contained binary - no xray-core, no
# geoip.dat/geosite.dat needed for HTTP testing.
curl -fsSL -o xray-knife.zip \
  https://github.com/lilendian0x00/xray-knife/releases/latest/download/Xray-knife-linux-64.zip
unzip xray-knife.zip xray-knife && chmod +x xray-knife

python Pr0xySh4rk.py \
  --input collected_configs.txt \
  --output Pr0xySh4rk_SubBase64.txt \
  --xray-knife-path ./xray-knife \
  --limit 50 \
  --speedtest
```

Run `python Pr0xySh4rk.py --help` for every option (thread count, max delay,
test URL, insecure/strict TLS, prescan, retries, `--csv-report` for a full
per-config diagnostic dump, etc).

## Configuration

- **Sources** live in the `SOURCES` list at the top of `main.py`. Add or
  remove URLs there; a trailing `#name` fragment on a source URL is purely a
  cosmetic label for the logs (fragments are never sent to the server).
- **Per-protocol limit**, **thread count**, and whether to **speed-test**
  are all controllable from the GitHub Actions "Run workflow" button
  (`workflow_dispatch` inputs), or via `--limit` / `--threads` / `--speedtest`
  when running locally.
- The workflow schedule is set in
  `.github/workflows/complete_procedure.yml` (`cron: '0 */6 * * *'`, every 6
  hours by default).

## Notes on this rewrite

This version replaces the previous implementation, which shelled out to a
`xray-knife net http` subcommand that no longer exists in current
`xray-knife` releases (the CLI moved to a single batch-oriented `http`
command) - so the old tester would fail outright against any up-to-date
`xray-knife` binary. It also resolved the "latest" release via
`api.github.com` + `jq`, which is unauthenticated-rate-limited to 60
requests/hour and fails silently under load. Both are fixed here: the
tester is rebuilt around the current `xray-knife http` engine, and releases
are fetched via GitHub's `releases/latest/download/<asset>` redirect, which
doesn't touch the API at all.
