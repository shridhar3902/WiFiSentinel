# WiFiSentinel

A modern orchestration framework built on top of the classic wireless-auditing
toolchain — **aircrack-ng suite, hcxtools, and hashcat** — with a scoped
authorization gate, a scriptable CLI, and clean HTML/JSON reporting.

WiFiSentinel doesn't reinvent WiFi attacks. It wraps the same battle-tested
tools that `aircrack-ng` and `wifite` use under the hood, and adds:

- ✅ A **mandatory scope + authorization gate** (like a lightweight rules-of-engagement check) that blocks any active command against a target that isn't explicitly listed as authorized.
- ✅ A single **Python CLI** (`wifisentinel scan`, `wifisentinel audit`) instead of juggling 4–5 separate tools and copy-pasting BSSIDs/channels between them.
- ✅ Support for both **4-way handshake capture** (airodump-ng + aireplay-ng) and **clientless PMKID capture** (hcxdumptool) — PMKID doesn't require deauthing a connected client.
- ✅ **hashcat integration** (mode 22000) for GPU-accelerated cracking, alongside classic `aircrack-ng` CPU cracking.
- ✅ Auto-generated **HTML + JSON engagement reports** you can hand off alongside a pentest write-up.

> ⚠️ **This tool is for authorized security testing and research only.**
> See [Legal & Ethical Use](#legal--ethical-use) before doing anything else.

---

## Table of Contents

- [Why this project exists](#why-this-project-exists)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Command Reference](#command-reference)
- [Workflow Walkthrough](#workflow-walkthrough)
- [Reports](#reports)
- [Project Structure](#project-structure)
- [Roadmap](#roadmap)
- [Legal & Ethical Use](#legal--ethical-use)
- [License](#license)

---

## Why this project exists

`aircrack-ng` is powerful but low-level: you manually run `airmon-ng`,
`airodump-ng`, `aireplay-ng`, and `aircrack-ng` as 4 separate steps, copying
BSSIDs and channel numbers between terminal windows. Newer clientless
techniques (PMKID) and GPU cracking (hashcat) live in a completely separate
toolchain (`hcxtools`).

WiFiSentinel ties all of it together into one guided workflow with:

1. A **scope file** you fill in once per engagement (or once for your home lab), listing exactly which BSSIDs/ESSIDs you're authorized to test.
2. One CLI command per phase — `scan`, `audit` — that calls the right underlying tool automatically and refuses to run against anything outside scope.
3. A shareable **report** at the end, instead of raw terminal scrollback.

This project is designed as a **learning + portfolio piece** for wireless
security fundamentals (802.11 monitor mode, 4-way handshake, PMKID, WPA/WPA2
cracking) — not as a replacement for `aircrack-ng` itself, which remains the
underlying engine.

## Architecture

```
                     ┌─────────────────────┐
                     │   wifisentinel CLI   │
                     └──────────┬──────────┘
                                │
        ┌───────────────────────┼───────────────────────┐
        │                       │                       │
┌───────▼────────┐     ┌────────▼────────┐     ┌────────▼────────┐
│  authorization  │     │    interface     │     │     scanner      │
│  (scope gate)   │     │  (airmon-ng)     │     │  (airodump-ng)   │
└─────────────────┘     └──────────────────┘     └──────────────────┘
                                │
                ┌───────────────┴───────────────┐
                │                               │
       ┌────────▼─────────┐           ┌─────────▼─────────┐
       │ HandshakeCapture  │           │   PMKIDCapture     │
       │ (airodump/aireplay)│         │   (hcxdumptool)     │
       └────────┬──────────┘          └─────────┬──────────┘
                │                                │
                └───────────────┬────────────────┘
                                │
                       ┌────────▼────────┐
                       │     Cracker      │
                       │ aircrack-ng /    │
                       │ hashcat (22000)  │
                       └────────┬────────┘
                                │
                       ┌────────▼────────┐
                       │  HTML/JSON report │
                       └──────────────────┘
```

## Prerequisites

WiFiSentinel is a **wrapper**, not a replacement — you need the underlying
tools installed and a wireless adapter that supports monitor mode + packet
injection.

| Requirement | Notes |
|---|---|
| Linux (Kali Linux recommended) | Monitor mode support is far more reliable on Linux than Windows/macOS |
| Python 3.9+ | `python3 --version` |
| `aircrack-ng` suite | `sudo apt install aircrack-ng` (provides `airmon-ng`, `airodump-ng`, `aireplay-ng`, `aircrack-ng`) |
| `hcxtools` | `sudo apt install hcxtools` (provides `hcxdumptool`, `hcxpcapngtool`) — needed for PMKID capture |
| `hashcat` | `sudo apt install hashcat` — optional, only needed for GPU-accelerated cracking |
| A monitor-mode-capable wireless adapter | e.g. Alfa AWUS036ACH/NHA, TP-Link TL-WN722N v1. Most built-in laptop WiFi chipsets do **not** support packet injection. |

## Installation

```bash
git clone https://github.com/shridhar3902/wifisentinel.git
cd wifisentinel

python3 -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
pip install -e .          # installs the `wifisentinel` command
```

Verify the underlying tools are on your PATH:

```bash
airmon-ng --help
hcxdumptool --version
hashcat --version
```

## Quick Start

**1. Configure your scope** (mandatory, one-time per engagement):

```bash
cp config/scope.yaml.example config/scope.yaml
nano config/scope.yaml   # fill in your own network's BSSID/ESSID
```

**2. Put your adapter into monitor mode:**

```bash
sudo wifisentinel monitor-on --interface wlan0
# -> prints the resulting monitor interface, e.g. wlan0mon
```

**3. Scan for nearby networks:**

```bash
sudo wifisentinel scan --interface wlan0mon --duration 30
```

You'll see a `*` next to any AP that matches your `config/scope.yaml` — those
are the only targets `audit` will let you run against.

**4. Run a full capture + crack workflow** against a scoped target:

```bash
sudo wifisentinel audit \
  --interface wlan0mon \
  --bssid AA:BB:CC:DD:EE:FF \
  --essid "MyHomeNetwork" \
  --channel 6 \
  --method pmkid \
  --wordlist wordlists/rockyou.txt \
  --engine hashcat
```

This will:
1. Verify the target is in your confirmed scope (refuses otherwise).
2. Ask you to type `I CONFIRM` before doing anything active.
3. Capture a PMKID (or 4-way handshake) with `hcxdumptool` / `airodump-ng` + `aireplay-ng`.
4. Run the capture through `hashcat` (or `aircrack-ng`) against your wordlist.
5. Write an HTML + JSON report to `reports/report.html`.

**5. Restore your adapter when you're done:**

```bash
sudo wifisentinel monitor-off --interface wlan0mon
```

## Command Reference

```
wifisentinel [--scope PATH] [--yes] <command> [options]
```

| Command | Description |
|---|---|
| `monitor-on --interface IFACE` | Enable monitor mode on an adapter |
| `monitor-off --interface IFACE` | Restore an adapter to managed mode |
| `scan --interface IFACE [--duration N] [--channel N]` | Passive/active AP discovery via `airodump-ng` |
| `audit --interface IFACE --bssid BSSID --channel CH --wordlist FILE [options]` | Full capture + crack workflow against one scoped target |

**`audit` options:**

| Flag | Default | Description |
|---|---|---|
| `--essid` | `target` | Friendly name for the target network |
| `--method` | `handshake` | `handshake` (4-way, needs a client) or `pmkid` (clientless) |
| `--engine` | `aircrack` | `aircrack` (CPU) or `hashcat` (GPU, requires 22000-format hash) |
| `--listen-seconds` | `45` | How long to listen for a capture |
| `--deauth-count` | `5` | Deauth frames sent to accelerate handshake capture (`handshake` method only) |
| `--report` | `reports/report.html` | Output path for the generated report |

Global flags:

| Flag | Description |
|---|---|
| `--scope PATH` | Path to your scope file (default `config/scope.yaml`) |
| `--yes` | Skip the interactive `I CONFIRM` prompt (still requires scope.yaml to list the target) |

## Workflow Walkthrough

1. **Reconnaissance** — `scan` passively listens and lists every AP/channel/encryption type in range, flagging which ones match your scope.
2. **Capture** — depending on `--method`:
   - `handshake`: listens with `airodump-ng` on the target's channel, optionally sends a short `aireplay-ng` deauth burst to force a client to reconnect and produce a fresh 4-way handshake, then validates the capture with `aircrack-ng <file>`.
   - `pmkid`: uses `hcxdumptool` to request the PMKID directly from the AP — no client or deauth required, and it works even against networks with no connected clients.
3. **Cracking** — the capture is fed to either `aircrack-ng -a 2` (dictionary attack, CPU) or `hashcat -m 22000` (GPU-accelerated, supports both handshake and PMKID hashes in the unified format).
4. **Reporting** — every scan/capture/crack result is compiled into a single HTML report plus a machine-readable JSON export.

## Reports

Each `audit` run produces:

- `reports/report.html` — a dark-themed, self-contained report with scope details, discovered APs, capture outcomes, and crack results (key redacted unless found).
- `reports/report.json` — the same data as structured JSON, handy for feeding into other tooling or a CI pipeline.

## Project Structure

```
wifisentinel/
├── wifisentinel/
│   ├── cli.py                  # argparse CLI entrypoint
│   ├── core/
│   │   ├── authorization.py    # scope file + confirmation gate
│   │   ├── interface.py        # airmon-ng wrapper (monitor mode)
│   │   ├── scanner.py          # airodump-ng wrapper + CSV parsing
│   │   ├── capture.py          # handshake (airodump/aireplay) + PMKID (hcxdumptool)
│   │   ├── cracker.py          # aircrack-ng / hashcat wrappers
│   │   └── report.py           # HTML/JSON report generator
│   └── utils/
│       ├── shell.py            # subprocess wrapper, binary detection
│       └── logger.py           # centralized logging
├── config/
│   └── scope.yaml.example      # copy to scope.yaml and fill in
├── requirements.txt
├── setup.py
├── LICENSE
└── README.md
```

## Roadmap

- [ ] `--json` output mode for `scan` (for piping into other tools)
- [ ] WPA3-SAE / PWNagotchi-style continuous capture mode
- [ ] Rich/TUI live-updating scan table (currently static print-based)
- [ ] Docker image with the full toolchain pre-installed
- [ ] Automatic wordlist recommendation based on ESSID patterns (e.g. common ISP default naming schemes)

Contributions and issues welcome — this is an actively evolving learning project.

## Legal & Ethical Use

**WiFiSentinel performs active attacks against wireless networks** (packet
injection, deauthentication, handshake/PMKID capture, and offline password
cracking). Running it against any network you do not own, or do not have
**explicit written permission** to test, is illegal in most jurisdictions —
including under India's **IT Act, 2000 (Sections 43 & 66)** and equivalent
computer-misuse laws elsewhere (e.g. the U.S. CFAA, UK Computer Misuse Act).

- Only run this against your **own home/lab equipment**, or networks covered
  by a **signed penetration-testing agreement or bug-bounty scope** that
  explicitly authorizes wireless testing.
- The tool's built-in `Scope`/authorization gate is a workflow safeguard, not
  a legal substitute — you are responsible for having real authorization
  before you run anything.
- Deauthentication frames disrupt legitimate users' connectivity; only send
  them against networks/clients you're authorized to test, and for the
  minimum duration needed.
- The author is not responsible for misuse of this software. Use it to
  learn, to secure your own network, or as part of authorized engagements
  only.

## License

MIT — see [LICENSE](LICENSE).

---

Built by [Shridhar Vinayak Kirtane](https://github.com/shridhar3902) — CEH / CCNA certified, focused on SOC analysis, cybersecurity research, and bug bounty work. Check out my other security tooling: [VulnScout](https://github.com/shridhar3902) (recon automation) and [DomaScanner](https://github.com/shridhar3902) (domain intel).
