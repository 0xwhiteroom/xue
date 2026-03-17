<div align="center">

```
  ██╗  ██╗██╗   ██╗███████╗
  ╚██╗██╔╝██║   ██║██╔════╝
   ╚███╔╝ ██║   ██║█████╗
   ██╔██╗ ██║   ██║██╔══╝
  ██╔╝ ██╗╚██████╔╝███████╗
  ╚═╝  ╚═╝ ╚═════╝ ╚══════╝
```

# xue 雪

### *Subdomain Hunter*

[![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat-square&logo=go&logoColor=white)](https://go.dev)
[![Platform](https://img.shields.io/badge/Platform-Linux%20amd64-lightgrey?style=flat-square&logo=linux)](.)
[![Version](https://img.shields.io/badge/Version-1.0.0-blueviolet?style=flat-square)](.)
[![0xAscension](https://img.shields.io/badge/0xAscension-red?style=flat-square)](https://github.com/0xAscension)

> Passive subdomain enumeration from **6 sources** with **live output** — subdomains print as they are found. Wildcard filtering, HTTP probing, takeover detection, and ASN lookup. No API keys required.


</div>

---

##  Why xue?

| Feature |  |  | **xue** |
|---------|-----------|-------|---------|
| No API keys needed |  |  | ✅ |
| Live output |  |  | ✅ |
| HTTP probe built-in |  |  | ✅ |
| Takeover detect |  |  | ✅ 20 services |
| ASN lookup |  |  | ✅ |
| Wildcard filter |  |  | ✅ |
| `>>` redirect |  |  | ✅ |
| JSON output |  |  | ✅ |

---

##  Features

-  **Live Output** — subdomains print immediately as found, no waiting
-  **6 Passive Sources** — no API keys, works out of the box
-  **Wildcard Filter** — auto-detects and removes wildcard DNS results
-  **DNS Resolve** — resolves all subdomains, displays IPs
-  **HTTP Probe** — built-in alive check with status code + page title
-  **Takeover Detect** — fingerprints 20 services for dangling CNAMEs
-  **ASN Lookup** — organization, country, ASN number from IP
-  **Output Formats** — TXT · JSON · JSONL
-  **Pipe Friendly** — stdout/stderr split, `>>` works perfectly

---

##  Passive DNS Sources

| Source | Description |
|--------|-------------|
| `crt.sh` | Certificate transparency logs |
| `hackertarget` | HackerTarget API |
| `alienvault` | AlienVault OTX passive DNS |
| `rapiddns` | RapidDNS subdomain search |
| `anubis` | Anubis subdomain database |
| `threatcrowd` | ThreatCrowd domain report |

---

##  Flags

```
INPUT
  -d <domain>          Target domain  (required)

FEATURES
  -resolve             DNS resolve all subdomains — show IPs
  -wt                  Wildcard DNS detect + filter results
  -probe               HTTP probe — status code + page title
  -takeover            Subdomain takeover detect (20 services)
  -asn                 ASN + org + country lookup from IP

CONFIG
  -c <int>             Threads                        (default: 50)
  -src                 Show which source found each subdomain
  -ip                  Show resolved IPs inline

OUTPUT
  -o <file>            Save subdomains as TXT
  -oj <file>           Save as JSON (full enriched data)
  -ojl <file>          Save as JSONL
  -silent              Subdomains only to stdout — pipe friendly
  -version             Print version
  --install-license    Activate license on this machine
```

---

##  Examples

```bash
# Basic — live passive DNS enumeration
xue -d example.com

# Show source of each subdomain
xue -d example.com -src

# DNS resolve + show IPs
xue -d example.com -resolve -ip

# Full recon — probe + takeover + ASN
xue -d example.com -probe -takeover -asn

# With wildcard DNS filter
xue -d example.com -probe -wt

# Save full JSON results
xue -d example.com -probe -takeover -asn -oj results.json

# Silent — subdomains only to stdout
xue -d example.com -silent

# Append to file
xue -d example.com -silent >> subs.txt

# Pipe to hx for HTTP probing
xue -d example.com -silent | hx -td -waf -mc 200,403

# Pipe to xun for port scanning
xue -d example.com -silent | xargs -I{} xun -h {} -top100

# Full pipeline
xue -d target.com -silent | hx -c 100 -td -waf -mc 200,403 -er
```

---

##  Output

```
  [*] Querying passive DNS for example.com

  api.example.com           [crt.sh]
  mail.example.com          [hackertarget]
  dev.example.com           [alienvault]
  staging.example.com       [crt.sh]
  admin.example.com         [rapiddns]     🎯 TAKEOVER: GitHub Pages

  [+] Found 47 unique subdomains

  [*] Resolving 47 subdomains  threads:50

  [+] 39 alive after DNS resolve
```

---

##  Takeover Detection (20 services)

`GitHub Pages` · `Heroku` · `Shopify` · `Fastly` · `Ghost` · `Pantheon` · `Tumblr` · `WordPress.com` · `AWS S3` · `Azure` · `Netlify` · `Zendesk` · `Surge.sh` · `Bitbucket` · `HubSpot` · `Squarespace` · `Webflow` · `Vercel` · `Intercom` · `Unbounce`

---

##  Installation

```bash
# Build
unzip xue-v1.zip -d xue && cd xue
bash build.sh

# Install
sudo dpkg -i xue_1.0.0_amd64.deb

# Or manual
sudo mv xue /usr/local/bin/
sudo xue --install-license

# Verify
xue -version
```

> **Requirements:** Go 1.21+ · Linux amd64

---

##  Disclaimer

> For authorized security testing and educational purposes only.
> Use only on systems you have explicit permission to test.

---

<div align="center">

*xue 雪 v1.0 — by WHITEROOM 「0xホワイトルーム」*

**[0xwhiteroom](https://github.com/0xwhiteroom)** · *We don't hack systems. We ascend them.*

</div>
