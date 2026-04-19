# RemedeX — Browser extension security & remediation

A comprehensive browser extension security analysis, management, and remediation tool. Scan, analyze, remove, and audit browser extensions across your environment — locally or remotely via EDR.

## Key capabilities

### Extension discovery & analysis
- **Multi-browser scanning** — Chrome, Edge, and Brave (Chromium-based)
- **Cross-platform** — Windows, macOS, and Linux
- **Heuristic analysis** — detects obfuscated code, dynamic script injection, eval/atob payloads, crypto address patterns
- **Domain/IP extraction** — scans all JS files for URLs, domains, and IPs (including Base64-encoded hidden indicators)
- **Permission risk scoring** — 0-100 risk score based on permissions, heuristics, domains, obfuscation, and DNR rules
- **Obfuscation detection** — flags minified non-bundled code, high hex/unicode escape density, excessive eval/Function calls

### Forensic reporting
- **HTML forensic reports** — standalone reports with risk scores, permission analysis, extracted domains, and heuristic findings
- **Interactive architecture graphs** — Vis.js network maps showing extension file-to-domain-to-permission relationships
- **VirusTotal integration** — scan extracted domains, IPs, and file hashes against VT (supports free and premium API keys)
- **Batch domain extraction** — download extensions by ID and extract all domains/IPs they communicate with

### Remediation & policy enforcement
- **Local extension removal** — force-closes browser, deletes extension files, cleans Preferences/Secure Preferences, disables sync
- **Remote cleanup scripts** — generate PowerShell (Windows), Bash (macOS/Linux), or Python scripts for deployment via EDR tools
- **OS-level blocklisting** — Windows Registry, macOS managed preferences, Linux Chrome policy files
- **Remote extension inventory** — generate lister scripts to audit extensions fleet-wide via SentinelOne, CrowdStrike, etc.
- **Webhook integration** — optional start/completion webhooks with execution status and detailed results

### Extension intelligence
- **Chrome Web Store downloader** — download any extension by ID or URL for offline analysis
- **Permissions dictionary** — built-in reference of all Chrome API permissions with risk levels, descriptions, and abuse scenarios
- **Batch processing** — analyze lists of extension IDs from lister output, JSON, CSV, or plain text

## Requirements

- Python 3.7+
- `requests` library (for Chrome Web Store downloads and VirusTotal)
- `tkinter` (for GUI mode — included with Python on Windows; `sudo apt install python3-tk` on Linux; `brew install python-tk` on macOS)

### Installation

```bash
git clone https://github.com/noel-15/RemedeX.git
cd RemedeX
pip install -r requirements.txt
```

Main entry point: **`remedex.py`** (CLI and `--gui`).

### Windows launcher (optional)

Double-click **`run_remedex.bat`** in the project folder for a menu-driven launcher (same commands as below).

## Usage

### GUI mode

```bash
python remedex.py --gui
```

The GUI is organized into three panels:

**Manage Extensions** — Scan the local system for installed extensions, view them in a sortable/filterable table, analyze individual extensions in detail, remove extensions with full cleanup, or copy extension source files for offline analysis.

**Forensic Tools** — Analyze extensions from local folders (downloaded/extracted CRX files), scan network indicators against VirusTotal, export HTML forensic reports, and download extensions directly from the Chrome Web Store.

**System & Environment** — Clean browser data (localStorage, cache, cookies, etc.), manage OS-level extension blocklists, generate remote inventory scripts (lister), generate remote cleanup scripts for EDR deployment, browse the permissions reference dictionary, and batch-extract domains from extension ID lists.

### CLI mode

#### Discovery

```bash
# List all installed extensions
python remedex.py --list-extensions

# List with full details (permissions, paths, risk scores)
python remedex.py --list-extensions --details

# List for specific browsers only
python remedex.py --list-extensions --browsers=chrome,edge

# Scan a local extension folder
python remedex.py --scan-path ./extracted_extension

# Scan and export a forensic HTML report
python remedex.py --scan-path ./extracted_extension --export-report report.html

# Scan and export an interactive architecture graph
python remedex.py --scan-path ./extracted_extension --export-graph graph.html
```

#### Batch domain extraction

```bash
# Extract domains from a list of extension IDs (one per line)
python remedex.py --extract-domains ids.txt

# Extract domains and save to CSV
python remedex.py --extract-domains ids.txt --domains-output results.csv

# Works with JSON output from the remote lister as well
python remedex.py --extract-domains lister_output.json
```

#### Removal & remediation

```bash
# Remove an extension by ID (force-closes browser, cleans preferences, disables sync)
python remedex.py --remove-extension <id> --force

# Remove without adding to blocklist
python remedex.py --remove-extension <id> --force --no-blocklist

# Remove from specific browser only
python remedex.py --remove-extension <id> --browsers=chrome
```

#### Policy management

```bash
# List all blocklisted extensions
python remedex.py --list-blocklist

# Unblock a specific extension
python remedex.py --unblock-extension <id>

# Clear all blocklists
python remedex.py --clear-blocklist

# Disable extension sync across all profiles
python remedex.py --disable-sync
```

**Windows:** `--list-blocklist`, `--unblock-extension`, and `--clear-blocklist` read and write Chromium enterprise policy in the **registry**. On macOS/Linux they are not applicable in the same way; use generated scripts or OS policy files for those platforms.

#### Download & analyze

```bash
# Download and extract an extension from the Chrome Web Store
python remedex.py --download-extension <id> --extract

# Download from a Chrome Web Store URL
python remedex.py --download-url "https://chromewebstore.google.com/detail/name/id"

# Copy an installed extension to a folder
python remedex.py --copy-installed <id> --download-dir ./analysis

# Scan with VirusTotal
python remedex.py --scan-path ./extension --vt-api-key YOUR_KEY
```

#### Browser data cleanup

`--clean` / `--clean-all` use the built-in cleanup path: **localStorage** (LevelDB), **cache** (including Code/GPU/Shader caches), **service workers**, and optionally **cookies** (`--cookies`). Session storage and IndexedDB are covered by **generated remote cleanup scripts**, not this CLI shortcut.

```bash
# Clean all browsers (localStorage, caches, service workers)
python remedex.py --clean-all --force

# Specific browsers only; include cookies (logs you out of sites)
python remedex.py --clean -b chrome,edge --cookies --force

# Skip localStorage or cache
python remedex.py --clean-all --no-storage --force
python remedex.py --clean-all --no-cache --force
```

#### Remote script generation

```bash
# Generate a Python cleanup script for remote deployment
python remedex.py --generate-script --script-type python -o cleanup.py

# Generate a PowerShell script with webhook tracking
python remedex.py --generate-script --script-type powershell --webhook-url https://webhook.site/xxx

# Generate and upload to a temporary paste service for one-liner fetch
python remedex.py --generate-script --script-type bash --share

# Generate a remote extension lister script
python remedex.py --generate-lister --target-os windows --webhook-url https://webhook.site/xxx
```

## How it works

### Risk scoring (0-100)

Extensions are scored based on multiple factors:

| Factor | Max points | Description |
|--------|------------|---------------|
| Permissions | 35 | Based on highest-risk API permission (CRITICAL=35, HIGH=25, MEDIUM=12, LOW=5) |
| Heuristic warnings | 30 | eval+atob patterns, dynamic script injection, crypto addresses (10 pts each) |
| DNR rule warnings | 30 | Declarative Net Request rules blocking security/search sites (15 pts each) |
| External domains | 20 | Number of unique domains/IPs found in JS code (5-20 based on count) |
| Obfuscated files | 30 | Files with suspicious minification, high escape density, base64 blobs (10 pts each) |

Score thresholds: **CRITICAL** (76+), **HIGH** (51-75), **MEDIUM** (26-50), **LOW** (1-25), **SAFE** (0)

### Domain extraction

For each JS file in an extension:
1. Regex scan for `https://domain.tld/...` patterns to extract domains
2. Context-aware IP extraction — only IPs appearing in URL/network contexts (not version numbers)
3. IP validation — rejects octets >254, leading zeros, and common noise (localhost, broadcast)
4. Base64 decoding — decodes embedded Base64 strings and rescans for hidden domains/IPs
5. Results tracked per-file for attribution

### Remote cleanup scripts

Generated scripts (PowerShell, Bash, Python) perform these steps in order:
1. Force-close all targeted browsers
2. Disable extension sync in Chromium Preferences (prevents re-download)
3. Remove extension directories and all related data (Extensions, Local Extension Settings, Sync Extension Settings, IndexedDB, etc.)
4. Clean extension entries from Preferences and Secure Preferences files
5. Apply OS-level blocklist policy (Windows Registry / macOS managed prefs / Linux policy JSON)
6. Optionally clean browser data (localStorage, cache, cookies, etc.)
7. Log all actions to a file in the OS temp directory
8. Send start/completion webhooks with full status and error details (if configured)

## Browser support

RemedeX only supports **Chrome**, **Microsoft Edge**, and **Brave** (Chromium profiles). Other browsers are not scanned or managed.

| Browser | Windows | macOS | Linux |
|---------|---------|-------|-------|
| Chrome | Yes | Yes | Yes |
| Edge | Yes | Yes | Yes |
| Brave | Yes | Yes | Yes |

### Windows blocklist display names

On Windows, friendly names shown in **Manage Blocklist** are stored in the registry value `RemedexBlocklistNames` (alongside Chromium policy keys). That value name is stable for compatibility with earlier installs.

## Troubleshooting

### Extension not removed after script execution
- Ensure all browser processes are fully terminated (check Task Manager / Activity Monitor)
- On macOS, the script uses `killall "Google Chrome"` — verify the exact process name matches
- Check the log file in the temp directory for specific error messages

### VirusTotal scan returns no results
- Verify your API key is valid
- Free tier is limited to 4 requests/minute — the tool auto-detects and throttles accordingly
- Corporate proxies may block VT API — check for SSL certificate errors

### tkinter not found
```bash
# Ubuntu/Debian
sudo apt install python3-tk

# macOS
brew install python-tk

# Windows — included with standard Python installation
```

### Permission denied
Run as administrator (Windows) or with `sudo` (Linux/macOS). Required for blocklist policy management and cleaning other users' profiles.

## License

See [LICENSE](LICENSE). MIT License — free for personal and commercial use.

## Disclaimer

This tool modifies browser data and system policies. Always backup important data before running cleanup operations. Test scripts in a non-production environment first. The authors are not responsible for any data loss.
