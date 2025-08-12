# Netstat‑Who

A single‑file PowerShell tool that inspects your machine’s network activity and generates a clean, searchable **HTML report** with **one‑click research links** for each remote IP (RDAP, VirusTotal, Shodan, etc.). It uses a small GUI to pick options at runtime—no parameters to remember.

![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-5391FE?logo=powershell\&logoColor=white)
![Windows](https://img.shields.io/badge/Windows-10%2F11-0078D6?logo=windows\&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)

---

## Why

* **Faster triage**: See which processes are talking to the internet, with owner and network details for public IPs.
* **Noise‑free by default**: Loopback and your **local subnets** are excluded from results unless you opt in.
* **Zero setup**: One PowerShell script. No modules to install.
* **Rich drill‑downs**: The HTML report links out to popular OSINT tools for deeper investigation.

---

## Features

* GUI to choose options (no command‑line flags needed)
* Filters: include **ESTABLISHED** connections, include **LISTENING** sockets, include **Local/LAN/Loopback** peers
* **Local CIDR override** (e.g., `192.168.2.0/23`)
* RDAP lookups (via rdap.org) for public remote IPs
* Optional reverse DNS
* Self‑contained **HTML report** with search box and expand/collapse details per IP
* One‑click research links: RDAP, ARIN RDAP, VirusTotal, AbuseIPDB, Shodan, Censys, GreyNoise, Cisco Talos, SecurityTrails, BGP.he.net, MXToolbox PTR, IPinfo

> Example: On a /23 like `192.168.2.0/23`, the script detects your active NIC prefixes and excludes `192.168.2.0–192.168.3.255` from the public analysis unless you explicitly include local peers.

---

## Quick Start

1. **Download** `Netstat-Who.ps1` to your machine.
2. (Recommended) **Run as Administrator** for full process visibility.
3. If needed, allow script execution **for this session only**:

   ```powershell
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
   ```
4. **Run it**:

   ```powershell
   # Windows PowerShell 5.1
   .\Netstat-Who.ps1

   # PowerShell 7+ (ensure STA for WinForms UI)
   pwsh -STA -File .\Netstat-Who.ps1
   ```
5. Choose your options in the popup, select a report path (HTML), and click **OK**.

> The report opens automatically (optional). You can commit the HTML to your case notes or attach it to tickets.

---

## Options (GUI)

* **Include ESTABLISHED connections** — add active TCP connections.
* **Show LISTENING sockets** — include TCP/UDP listeners.
* **Include Local/LAN/Loopback peers** — by default these are **excluded** to focus on internet traffic.
* **Resolve reverse DNS** — do PTR lookups for remote IPs.
* **Local CIDR(s)** — comma‑separated overrides to treat as local (e.g., `192.168.2.0/23,10.6.0.0/24`).
* **Export HTML report** — choose where to save the resulting `*.html` file.

---

## Output: HTML Report

* **Search box**: filters rows client‑side by process, IP, owner, etc.
* **Details expander**: click a remote IP to reveal owner, network, CIDR, country, and reverse DNS.
* **Research links** (open in a new tab):

  * RDAP.org, ARIN RDAP
  * VirusTotal, AbuseIPDB
  * Shodan, Censys, GreyNoise
  * Cisco Talos, SecurityTrails, BGP.he.net
  * MXToolbox PTR, IPinfo

> *Screenshot placeholders*
>
> `docs/screenshot-ui.png` — Options dialog
>
> `docs/screenshot-report.png` — HTML report (table + details + search)

---

## How it Works

* Collects sockets via `Get-NetTCPConnection` and `Get-NetUDPEndpoint`.
* Joins owning **process** (if accessible) for friendly names.
* Detects and **excludes local addresses** by default:

  * Loopback (127.0.0.1 / ::1)
  * RFC1918 IPv4 (10/8, 172.16/12, 192.168/16), link‑local (169.254/16)
  * Active NIC IPv4 subnets (derived from `PrefixLength`), plus any user overrides
* Runs **RDAP** lookups (public IPs only) through `https://rdap.org`.
* Optionally does reverse DNS.
* Renders a standalone HTML report (no external assets).

---

## Requirements

* **Windows 10/11**
* **PowerShell**

  * Windows PowerShell **5.1** (default console is STA)
  * or PowerShell **7+** with `-STA` when launching (required for WinForms)
* **Internet access** for RDAP queries (and for using external research links)
* **Administrator** permissions are recommended (to resolve all process names/PIDs)

---

## Security & Privacy Notes

* The script does **not** connect to any remote IPs you’re inspecting; it only queries **RDAP** (and optional **reverse DNS**).
* The HTML includes links to third‑party services. Clicking them navigates your browser to those sites.
* Output lives on disk where you choose; review before sharing (it may contain hostnames, processes, and internal ports).

---

## Troubleshooting

**Script won’t run** — Execution Policy

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

**UI doesn’t appear / WinForms error** — Use STA mode (PowerShell 7+)

```powershell
pwsh -STA -File .\Netstat-Who.ps1
```

**Process names missing / Access denied** — Run the console **as Administrator**.

**RDAP timeouts / Corp proxy** — Configure system proxy or wrap `Invoke-RestMethod` with your proxy settings; try again later (registries sometimes rate‑limit).

**Local peers still show up** — Add explicit CIDRs in the GUI (e.g., `192.168.2.0/23`), then re‑run.

**Reverse DNS is slow** — Uncheck **Resolve reverse DNS**.

---

## Roadmap

* Sortable columns (client‑side)
* Light/Dark theme toggle
* CSV/JSON export button inside the report
* Simple **whois** fallback if RDAP fails
* Optional on‑disk cache for RDAP results

---

## Contributing

Issues and PRs welcome!

1. Fork the repo
2. Create your feature branch: `git checkout -b feat/something`
3. Commit changes: `git commit -m "feat: add something"`
4. Push branch: `git push origin feat/something`
5. Open a Pull Request

Please keep changes self‑contained (it’s meant to be single‑file/portable).

---

## Acknowledgments

* RDAP courtesy of the RIR ecosystem via **rdap.org** (routes to ARIN/RIPE/APNIC/LACNIC/AFRINIC)
* Community OSINT services linked in the report: VirusTotal, AbuseIPDB, Shodan, Censys, GreyNoise, Cisco Talos, SecurityTrails, BGP.he.net, MXToolbox, IPinfo
