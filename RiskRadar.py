#!/usr/bin/env python3
"""
vCISO-RiskRadar
The Most Comprehensive Open-Source CLI Tool for Automated Cybersecurity Risk Assessments

by Adam Rivers — A product of Hello Security LLC Research Labs
"""

import argparse
import json
import logging
import os
import sys
import socket
import ssl
import requests
import re
import csv
import base64
import hashlib
import time
from datetime import datetime
from urllib.parse import urlparse, urljoin
from http.client import HTTPConnection
from typing import Dict, List, Optional, Tuple

# Optional imports with graceful fallbacks
try:
    import markdown
    HAS_MARKDOWN = True
except ImportError:
    HAS_MARKDOWN = False

try:
    import dns.resolver
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

try:
    import xml.etree.ElementTree as ET
    HAS_XML = True
except ImportError:
    HAS_XML = False

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.progress import Progress, BarColumn, TextColumn, TimeElapsedColumn
    from rich.markdown import Markdown
    from rich.text import Text
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

# ========== Constants ==========
CONFIG_FILE = "config.json"
LOG_FILE = "riskradar.log"
REPORT_DIR = "reports"
VERSION = "2.1.3"  # Updated for rich UI enhancements

# Comprehensive compliance framework mappings
FRAMEWORK_MAPPINGS = {
    "NIST": {
        "Server header exposed": "CM-8: System Component Inventory",
        "Missing X-Frame-Options header": "SC-7: Boundary Protection",
        "Missing Content-Security-Policy header": "SC-8: Secure Data Transmission",
        "Missing Strict-Transport-Security header": "SC-8: Secure Data Transmission",
        "Missing X-Content-Type-Options header": "SC-8: Secure Data Transmission",
        "Missing Referrer-Policy header": "SC-8: Secure Data Transmission",
        "Open port detected": "CA-3: System Interconnections",
        "Expired SSL certificate": "SC-13: Cryptographic Protection",
        "SSL certificate expires soon": "SC-13: Cryptographic Protection",
        "Weak SSL cipher detected": "SC-13: Cryptographic Protection",
        "Weak TLS version detected": "SC-13: Cryptographic Protection",
        "Weak HTTP methods enabled": "AC-6: Least Privilege",
        "Robots.txt exposes sensitive paths": "AC-4: Information Flow Enforcement",
        "Sitemap exposes sensitive paths": "AC-4: Information Flow Enforcement",
        "Directory listing enabled": "AC-4: Information Flow Enforcement",
        "Missing SPF record": "SC-20: Secure Name/Address Resolution",
        "Missing DMARC record": "SC-20: Secure Name/Address Resolution",
        "Missing DKIM record": "SC-20: Secure Name/Address Resolution",
        "No DNSSEC enabled": "SC-20: Secure Name/Address Resolution",
        "DNS resolution failed": "SC-20: Secure Name/Address Resolution",
        "WHOIS privacy not enabled": "CM-8: System Component Inventory",
        "Potential header injection vulnerability": "SC-8: Secure Data Transmission",
        "Outdated software detected": "CM-8: System Component Inventory",
        "Insecure cookies detected": "SC-28: Protection of Information at Rest",
        "CORS misconfiguration detected": "AC-4: Information Flow Enforcement",
        "Too many redirects": "SC-8: Secure Data Transmission"
    },
    "ISO 27001": {
        "Server header exposed": "A.12.4.1: Information Security Event Logging",
        "Missing X-Frame-Options header": "A.12.6.1: Management of Technical Vulnerabilities",
        "Missing Content-Security-Policy header": "A.12.6.1: Management of Technical Vulnerabilities",
        "Missing Strict-Transport-Security header": "A.12.6.1: Management of Technical Vulnerabilities",
        "Missing X-Content-Type-Options header": "A.12.6.1: Management of Technical Vulnerabilities",
        "Missing Referrer-Policy header": "A.12.6.1: Management of Technical Vulnerabilities",
        "Open port detected": "A.13.1.1: Network Controls",
        "Expired SSL certificate": "A.12.4.3: System Use Notification",
        "SSL certificate expires soon": "A.12.4.3: System Use Notification",
        "Weak SSL cipher detected": "A.10.1.1: Policy on the Use of Cryptographic Controls",
        "Weak TLS version detected": "A.10.1.1: Policy on the Use of Cryptographic Controls",
        "Weak HTTP methods enabled": "A.9.4.1: Information Access Restriction",
        "Robots.txt exposes sensitive paths": "A.9.4.5: Access Control to Program Source Code",
        "Sitemap exposes sensitive paths": "A.9.4.5: Access Control to Program Source Code",
        "Directory listing enabled": "A.9.4.5: Access Control to Program Source Code",
        "Missing SPF record": "A.13.1.2: Security of Network Services",
        "Missing DMARC record": "A.13.1.2: Security of Network Services",
        "Missing DKIM record": "A.13.1.2: Security of Network Services",
        "No DNSSEC enabled": "A.13.1.2: Security of Network Services",
        "DNS resolution failed": "A.13.1.2: Security of Network Services",
        "WHOIS privacy not enabled": "A.9.1.2: Access to Networks and Network Services",
        "Potential header injection vulnerability": "A.12.6.1: Management of Technical Vulnerabilities",
        "Outdated software detected": "A.12.6.1: Management of Technical Vulnerabilities",
        "Insecure cookies detected": "A.12.4.3: System Use Notification",
        "CORS misconfiguration detected": "A.9.4.1: Information Access Restriction",
        "Too many redirects": "A.12.6.1: Management of Technical Vulnerabilities"
    },
    "GDPR": {
        "Server header exposed": "Art. 32: Security of Processing",
        "Missing X-Frame-Options header": "Art. 32: Security of Processing",
        "Missing Content-Security-Policy header": "Art. 32: Security of Processing",
        "Missing Strict-Transport-Security header": "Art. 32: Security of Processing",
        "Missing X-Content-Type-Options header": "Art. 32: Security of Processing",
        "Missing Referrer-Policy header": "Art. 32: Security of Processing",
        "Open port detected": "Art. 25: Data Protection by Design",
        "Expired SSL certificate": "Art. 32: Security of Processing",
        "SSL certificate expires soon": "Art. 32: Security of Processing",
        "Weak SSL cipher detected": "Art. 32: Security of Processing",
        "Weak TLS version detected": "Art. 32: Security of Processing",
        "Weak HTTP methods enabled": "Art. 32: Security of Processing",
        "Robots.txt exposes sensitive paths": "Art. 25: Data Protection by Design",
        "Sitemap exposes sensitive paths": "Art. 25: Data Protection by Design",
        "Directory listing enabled": "Art. 25: Data Protection by Design",
        "Missing SPF record": "Art. 32: Security of Processing",
        "Missing DMARC record": "Art. 32: Security of Processing",
        "Missing DKIM record": "Art. 32: Security of Processing",
        "No DNSSEC enabled": "Art. 32: Security of Processing",
        "DNS resolution failed": "Art. 32: Security of Processing",
        "WHOIS privacy not enabled": "Art. 25: Data Protection by Design",
        "Potential header injection vulnerability": "Art. 32: Security of Processing",
        "Outdated software detected": "Art. 32: Security of Processing",
        "Insecure cookies detected": "Art. 32: Security of Processing",
        "CORS misconfiguration detected": "Art. 32: Security of Processing",
        "Too many redirects": "Art. 32: Security of Processing"
    },
    "PCI-DSS": {
        "Server header exposed": "Req 6.1: Identify security vulnerabilities",
        "Missing X-Frame-Options header": "Req 6.5: Protect against common vulnerabilities",
        "Missing Content-Security-Policy header": "Req 6.5: Protect against common vulnerabilities",
        "Missing Strict-Transport-Security header": "Req 4.1: Encrypt transmission of cardholder data",
        "Missing X-Content-Type-Options header": "Req 6.5: Protect against common vulnerabilities",
        "Missing Referrer-Policy header": "Req 6.5: Protect against common vulnerabilities",
        "Open port detected": "Req 1.3: Prohibit direct public access",
        "Expired SSL certificate": "Req 4.1: Encrypt transmission of cardholder data",
        "SSL certificate expires soon": "Req 4.1: Encrypt transmission of cardholder data",
        "Weak SSL cipher detected": "Req 4.1: Encrypt transmission of cardholder data",
        "Weak TLS version detected": "Req 4.1: Encrypt transmission of cardholder data",
        "Weak HTTP methods enabled": "Req 6.5: Protect against common vulnerabilities",
        "Robots.txt exposes sensitive paths": "Req 6.5: Protect against common vulnerabilities",
        "Sitemap exposes sensitive paths": "Req 6.5: Protect against common vulnerabilities",
        "Directory listing enabled": "Req 6.5: Protect against common vulnerabilities",
        "Missing SPF record": "Req 5.1: Deploy anti-malware software",
        "Missing DMARC record": "Req 5.1: Deploy anti-malware software",
        "Missing DKIM record": "Req 5.1: Deploy anti-malware software",
        "No DNSSEC enabled": "Req 5.1: Deploy anti-malware software",
        "DNS resolution failed": "Req 1.3: Prohibit direct public access",
        "WHOIS privacy not enabled": "Req 6.1: Identify security vulnerabilities",
        "Potential header injection vulnerability": "Req 6.5: Protect against common vulnerabilities",
        "Outdated software detected": "Req 6.1: Identify security vulnerabilities",
        "Insecure cookies detected": "Req 4.1: Encrypt transmission of cardholder data",
        "CORS misconfiguration detected": "Req 6.5: Protect against common vulnerabilities",
        "Too many redirects": "Req 6.5: Protect against common vulnerabilities"
    },
    "HIPAA": {
        "Server header exposed": "164.312(a)(1): Access Control",
        "Missing X-Frame-Options header": "164.312(e)(1): Transmission Security",
        "Missing Content-Security-Policy header": "164.312(e)(1): Transmission Security",
        "Missing Strict-Transport-Security header": "164.312(e)(1): Transmission Security",
        "Missing X-Content-Type-Options header": "164.312(e)(1): Transmission Security",
        "Missing Referrer-Policy header": "164.312(e)(1): Transmission Security",
        "Open port detected": "164.312(a)(1): Access Control",
        "Expired SSL certificate": "164.312(e)(1): Transmission Security",
        "SSL certificate expires soon": "164.312(e)(1): Transmission Security",
        "Weak SSL cipher detected": "164.312(e)(1): Transmission Security",
        "Weak TLS version detected": "164.312(e)(1): Transmission Security",
        "Weak HTTP methods enabled": "164.312(a)(1): Access Control",
        "Robots.txt exposes sensitive paths": "164.312(a)(1): Access Control",
        "Sitemap exposes sensitive paths": "164.312(a)(1): Access Control",
        "Directory listing enabled": "164.312(a)(1): Access Control",
        "Missing SPF record": "164.312(e)(1): Transmission Security",
        "Missing DMARC record": "164.312(e)(1): Transmission Security",
        "Missing DKIM record": "164.312(e)(1): Transmission Security",
        "No DNSSEC enabled": "164.312(e)(1): Transmission Security",
        "DNS resolution failed": "164.312(a)(1): Access Control",
        "WHOIS privacy not enabled": "164.312(a)(1): Access Control",
        "Potential header injection vulnerability": "164.312(e)(1): Transmission Security",
        "Outdated software detected": "164.312(a)(1): Access Control",
        "Insecure cookies detected": "164.312(e)(1): Transmission Security",
        "CORS misconfiguration detected": "164.312(e)(1): Transmission Security",
        "Too many redirects": "164.312(e)(1): Transmission Security"
    },
    "CMMC": {
        "Server header exposed": "CM.L2-3.4.5",
        "Missing X-Frame-Options header": "SC.L2-3.13.4",
        "Missing Content-Security-Policy header": "SC.L2-3.13.4",
        "Missing Strict-Transport-Security header": "SC.L2-3.13.4",
        "Missing X-Content-Type-Options header": "SC.L2-3.13.4",
        "Missing Referrer-Policy header": "SC.L2-3.13.4",
        "Open port detected": "CA.L2-3.3.4",
        "Expired SSL certificate": "SC.L2-3.13.1",
        "SSL certificate expires soon": "SC.L2-3.13.1",
        "Weak SSL cipher detected": "SC.L2-3.13.1",
        "Weak TLS version detected": "SC.L2-3.13.1",
        "Weak HTTP methods enabled": "AC.L2-3.1.3",
        "Robots.txt exposes sensitive paths": "AC.L2-3.1.3",
        "Sitemap exposes sensitive paths": "AC.L2-3.1.3",
        "Directory listing enabled": "AC.L2-3.1.3",
        "Missing SPF record": "SC.L2-3.13.4",
        "Missing DMARC record": "SC.L2-3.13.4",
        "Missing DKIM record": "SC.L2-3.13.4",
        "No DNSSEC enabled": "SC.L2-3.13.4",
        "DNS resolution failed": "SC.L2-3.13.4",
        "WHOIS privacy not enabled": "CM.L2-3.4.5",
        "Potential header injection vulnerability": "SC.L2-3.13.4",
        "Outdated software detected": "CM.L2-3.4.5",
        "Insecure cookies detected": "SC.L2-3.13.1",
        "CORS misconfiguration detected": "AC.L2-3.1.3",
        "Too many redirects": "SC.L2-3.13.4"
    }
}

# Expanded risk severity levels
RISK_LEVELS = {
    "critical": ["Expired SSL certificate", "DNS resolution failed", "Weak TLS version detected", "Potential header injection vulnerability"],
    "high": ["Server header exposed", "Missing Content-Security-Policy header", "Open port detected", "Weak SSL cipher detected", "Weak HTTP methods enabled", "Outdated software detected", "Directory listing enabled", "Too many redirects"],
    "medium": ["Missing X-Frame-Options header", "Missing Strict-Transport-Security header", "Missing X-Content-Type-Options header", "Missing Referrer-Policy header", "SSL certificate expires soon", "Robots.txt exposes sensitive paths", "Sitemap exposes sensitive paths", "Missing SPF record", "Missing DMARC record", "Missing DKIM record", "Insecure cookies detected", "CORS misconfiguration detected"],
    "low": ["No DNSSEC enabled", "WHOIS privacy not enabled"]
}

# Define scan functions globally
SCAN_FUNCTIONS = {
    "http_headers": lambda t, c: scan_http_headers(t, c),
    "http_methods": lambda t, c: scan_http_methods(t, c),
    "robots_txt": lambda t, c: scan_robots_txt(t, c),
    "sitemap": lambda t, c: scan_sitemap(t, c),
    "ports": lambda t, c: scan_ports(t, c),
    "ssl": lambda t, c: scan_ssl(t, c),
    "dns": lambda t, c: scan_dns(t, c),
    "whois": lambda t, c: scan_whois(t, c),
    "directory_listing": lambda t, c: scan_directory_listing(t, c),
    "cookies": lambda t, c: scan_cookies(t, c),
    "cors": lambda t, c: scan_cors(t, c)
}

# ========== Init ==========
def init_logging(verbose: bool = False):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        filename=LOG_FILE,
        level=level,
        format="%(asctime)s - %(levelname)s - %(message)s"
    )
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    logging.getLogger().addHandler(console_handler)
    if HAS_RICH:
        console = Console()
        console.print(
            Panel(
                f"[bold cyan]vCISO-RiskRadar v{VERSION}[/]\n"
                "The Most Comprehensive Open-Source CLI Tool for Automated Cybersecurity Risk Assessments\n"
                "by Adam Rivers — A product of Hello Security LLC Research Labs",
                title="Welcome",
                border_style="blue",
                padding=(1, 2)
            )
        )
        logging.info(f"Started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}.")
    else:
        logging.info(f"vCISO-RiskRadar v{VERSION} started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}.")

# ========== Config ==========
def load_config() -> Dict:
    default_config = {
        "frameworks": list(FRAMEWORK_MAPPINGS.keys()),
        "scan_targets": [],
        "default_ports": [20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3389, 5900, 8080],
        "timeout": 5,
        "user_agent": f"vCISO-RiskRadar/{VERSION} (+https://github.com/AdamRiversCEO/vCISO-RiskRadar)",
        "risk_levels": RISK_LEVELS,
        "scan_modules": list(SCAN_FUNCTIONS.keys()),
        "max_redirects": 5,
        "whois_servers": {"com": "whois.verisign-grs.com", "net": "whois.verisign-grs.com", "org": "whois.pir.org"},
        "outdated_software": {
            "Apache/2.2": "Apache < 2.4",
            "Apache/2.4.0": "Apache < 2.4.10",
            "IIS/7.5": "IIS < 8.0",
            "nginx/1.14": "nginx < 1.16"
        },
        "sensitive_paths": ["admin", "login", "backup", "config", "db", "api", "private", "internal", "wp-admin", ".git"],
        "retry_attempts": 2,
        "retry_delay": 1
    }

    if not os.path.exists(CONFIG_FILE):
        logging.info("No config.json found; creating with default settings.")
        save_config(default_config)
        return default_config

    try:
        with open(CONFIG_FILE, "r") as f:
            config = json.load(f)
        
        required_keys = {
            "frameworks": (list, "list of compliance frameworks"),
            "scan_targets": (list, "list of target URLs"),
            "default_ports": (list, "list of integers for ports"),
            "timeout": (int, "positive integer for timeout"),
            "user_agent": (str, "string for user agent"),
            "risk_levels": (dict, "dictionary of risk levels"),
            "scan_modules": (list, "list of scan modules"),
            "max_redirects": (int, "positive integer for max redirects"),
            "whois_servers": (dict, "dictionary of WHOIS servers"),
            "outdated_software": (dict, "dictionary of outdated software patterns"),
            "sensitive_paths": (list, "list of sensitive paths"),
            "retry_attempts": (int, "non-negative integer for retry attempts"),
            "retry_delay": (int, "positive integer for retry delay")
        }

        missing_or_invalid = False
        for key, (expected_type, description) in required_keys.items():
            if key not in config:
                logging.warning(f"Missing config key '{key}' ({description}); resetting to default.")
                config[key] = default_config[key]
                missing_or_invalid = True
            elif not isinstance(config[key], expected_type):
                logging.warning(f"Invalid type for config key '{key}' ({description}); expected {expected_type.__name__}, got {type(config[key]).__name__}. Resetting to default.")
                config[key] = default_config[key]
                missing_or_invalid = True
            elif key == "default_ports" and not all(isinstance(p, int) and 1 <= p <= 65535 for p in config[key]):
                logging.warning("default_ports contains invalid ports; resetting to default.")
                config[key] = default_config[key]
                missing_or_invalid = True
            elif key == "timeout" and config[key] <= 0:
                logging.warning("timeout must be positive; resetting to default.")
                config[key] = default_config[key]
                missing_or_invalid = True
            elif key == "scan_modules" and not all(m in SCAN_FUNCTIONS for m in config[key]):
                logging.warning("scan_modules contains invalid entries; resetting to default.")
                config[key] = default_config[key]
                missing_or_invalid = True
            elif key == "retry_attempts" and config[key] < 0:
                logging.warning("retry_attempts must be non-negative; resetting to default.")
                config[key] = default_config[key]
                missing_or_invalid = True
            elif key == "retry_delay" and config[key] <= 0:
                logging.warning("retry_delay must be positive; resetting to default.")
                config[key] = default_config[key]
                missing_or_invalid = True

        if missing_or_invalid:
            logging.info("Invalid config detected; saving corrected config.")
            save_config(config)

        return config
    except (json.JSONDecodeError, Exception) as e:
        logging.error(f"Failed to load config.json: {e}. Resetting to default.")
        if os.path.exists(CONFIG_FILE):
            try:
                os.rename(CONFIG_FILE, f"{CONFIG_FILE}.backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
                logging.info(f"Backed up invalid config to {CONFIG_FILE}.backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
            except Exception as backup_e:
                logging.error(f"Failed to back up config: {backup_e}")
        save_config(default_config)
        return default_config

def save_config(config: Dict):
    try:
        with open(CONFIG_FILE, "w") as f:
            json.dump(config, f, indent=4)
        logging.info("Configuration saved to config.json.")
    except Exception as e:
        logging.error(f"Failed to save config: {e}")

# ========== Scan Functions ==========
def validate_target(target: str) -> str:
    parsed = urlparse(target)
    if not parsed.scheme in ["http", "https"]:
        target = "https://" + target
    parsed = urlparse(target)
    if not parsed.netloc:
        raise ValueError(f"Invalid target: {target}")
    return target

def get_hostname(target: str) -> str:
    parsed = urlparse(target)
    return parsed.hostname if parsed.hostname else target

def scan_http_headers(target: str, config: Dict) -> Tuple[List[str], List[str]]:
    vulns = []
    recs = []
    headers = {"User-Agent": config["user_agent"]}
    session = requests.Session()
    session.max_redirects = config["max_redirects"]
    
    for attempt in range(config["retry_attempts"] + 1):
        try:
            resp = session.get(target, headers=headers, timeout=config["timeout"], allow_redirects=True)
            if resp.status_code >= 400:
                vulns.append(f"HTTP status: {resp.status_code}")
                recs.append("Investigate server availability or configuration.")
                break

            for header in ['X-Frame-Options', 'Content-Security-Policy', 'Strict-Transport-Security', 'X-Content-Type-Options', 'Referrer-Policy']:
                if header not in resp.headers:
                    vulns.append(f"Missing {header} header")
                    recs.append(f"Implement {header} to enhance security.")
            if 'Server' in resp.headers:
                vulns.append(f"Server header exposed: {resp.headers['Server']}")
                recs.append("Remove or obfuscate Server header to reduce fingerprinting.")
                for pattern, desc in config["outdated_software"].items():
                    if pattern in resp.headers['Server']:
                        vulns.append(f"Outdated software detected: {desc}")
                        recs.append(f"Update {desc} to the latest version.")
            test_header = "X-RiskRadar-Test"
            test_value = "RiskRadarTest"
            resp_test = session.get(target, headers={**headers, test_header: test_value}, timeout=config["timeout"], allow_redirects=True)
            if test_header in resp_test.headers and resp_test.headers[test_header] == test_value:
                vulns.append("Potential header injection vulnerability")
                recs.append("Sanitize user-controlled headers to prevent injection attacks.")
            break
        except requests.exceptions.TooManyRedirects:
            vulns.append("Too many redirects")
            recs.append("Check for redirect loops or increase max_redirects in config.")
            break
        except requests.RequestException as e:
            if attempt < config["retry_attempts"]:
                logging.debug(f"HTTP scan retry {attempt + 1}/{config['retry_attempts']} after error: {e}")
                time.sleep(config["retry_delay"])
            else:
                vulns.append(f"HTTP scan failed: {str(e)}")
                recs.append("Check network connectivity or target URL.")
        finally:
            session.close()
    return vulns, recs

def scan_http_methods(target: str, config: Dict) -> Tuple[List[str], List[str]]:
    vulns = []
    recs = []
    parsed = urlparse(target)
    hostname = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    for attempt in range(config["retry_attempts"] + 1):
        try:
            conn = HTTPConnection(hostname, port=port, timeout=config["timeout"])
            conn.request("OPTIONS", "/")
            resp = conn.getresponse()
            methods = resp.getheader("Allow")
            if methods:
                unsafe_methods = [m for m in methods.split(", ") if m in ["TRACE", "DELETE", "PUT", "CONNECT", "PATCH"]]
                if unsafe_methods:
                    vulns.append(f"Weak HTTP methods enabled: {', '.join(unsafe_methods)}")
                    recs.append("Disable unsafe HTTP methods unless required for functionality.")
            conn.close()
            break
        except Exception as e:
            if attempt < config["retry_attempts"]:
                logging.debug(f"HTTP methods scan retry {attempt + 1}/{config['retry_attempts']} after error: {e}")
                time.sleep(config["retry_delay"])
            else:
                logging.debug(f"HTTP methods scan error on {target}: {e}")
    return vulns, recs

def scan_robots_txt(target: str, config: Dict) -> Tuple[List[str], List[str]]:
    vulns = []
    recs = []
    robots_url = urljoin(target, "/robots.txt")
    for attempt in range(config["retry_attempts"] + 1):
        try:
            resp = requests.get(robots_url, timeout=config["timeout"])
            if resp.status_code == 200:
                sensitive_paths = config["sensitive_paths"]
                disallowed = re.findall(r'Disallow:\s*/(.*)', resp.text, re.IGNORECASE)
                exposed = [path for path in disallowed if any(sp in path.lower() for sp in sensitive_paths)]
                if exposed:
                    vulns.append(f"Robots.txt exposes sensitive paths: {', '.join(exposed[:5])} (showing first 5)")
                    recs.append("Review robots.txt to avoid disclosing sensitive directories.")
            break
        except requests.RequestException as e:
            if attempt < config["retry_attempts"]:
                logging.debug(f"Robots.txt scan retry {attempt + 1}/{config['retry_attempts']} after error: {e}")
                time.sleep(config["retry_delay"])
            else:
                logging.debug(f"Robots.txt scan error on {target}: {e}")
    return vulns, recs

def scan_sitemap(target: str, config: Dict) -> Tuple[List[str], List[str]]:
    vulns = []
    recs = []
    sitemap_url = urljoin(target, "/sitemap.xml")
    for attempt in range(config["retry_attempts"] + 1):
        try:
            resp = requests.get(sitemap_url, timeout=config["timeout"])
            if resp.status_code == 200 and HAS_XML:
                root = ET.fromstring(resp.text)
                sensitive_paths = config["sensitive_paths"]
                locations = [loc.text for loc in root.iter('{http://www.sitemaps.org/schemas/sitemap/0.9}loc') if loc.text]
                exposed = [loc for loc in locations if any(sp in loc.lower() for sp in sensitive_paths)]
                if exposed:
                    vulns.append(f"Sitemap exposes sensitive paths: {', '.join(exposed[:5])} (showing first 5)")
                    recs.append("Review sitemap.xml to avoid indexing sensitive URLs.")
            elif not HAS_XML:
                logging.info("XML parser unavailable; skipping sitemap scan.")
            break
        except requests.RequestException as e:
            if attempt < config["retry_attempts"]:
                logging.debug(f"Sitemap scan retry {attempt + 1}/{config['retry_attempts']} for {sitemap_url}: {e}")
                time.sleep(config["retry_delay"])
            else:
                logging.debug(f"Sitemap scan error on {target}: {e}")
    return vulns, recs

def scan_ports(hostname: str, config: Dict) -> Tuple[List[str], List[str]]:
    vulns = []
    recs = []
    for port in config["default_ports"]:
        for attempt in range(config["retry_attempts"] + 1):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(config["timeout"])
                result = sock.connect_ex((hostname, port))
                if result == 0:
                    try:
                        service = socket.getservbyport(port, "tcp")
                    except:
                        service = "unknown"
                    vulns.append(f"Open port detected: {port} ({service})")
                    recs.append(f"Evaluate exposure of port {port} ({service}); implement firewall if unnecessary.")
                    if port in [80, 443]:
                        try:
                            banner_sock = socket.socket()
                            banner_sock.settimeout(config["timeout"])
                            banner_sock.connect((hostname, port))
                            banner_sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                            banner = banner_sock.recv(1024).decode(errors='ignore')
                            for pattern, desc in config["outdated_software"].items():
                                if pattern in banner:
                                    vulns.append(f"Outdated software detected on port {port}: {desc}")
                                    recs.append(f"Update {desc} on port {port} to the latest version.")
                            banner_sock.close()
                        except:
                            pass
                sock.close()
                break
            except Exception as e:
                if attempt < config["retry_attempts"]:
                    logging.debug(f"Port scan retry {attempt + 1}/{config['retry_attempts']} for {hostname}:{port}: {e}")
                    time.sleep(config["retry_delay"])
                else:
                    logging.debug(f"Port scan error on {hostname}:{port}: {e}")
    return vulns, recs

def scan_ssl(target: str, hostname: str, config: Dict) -> Tuple[List[str], List[str]]:
    vulns = []
    recs = []
    if not target.startswith("https://"):
        return vulns, recs
    for attempt in range(config["retry_attempts"] + 1):
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=config["timeout"]) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    expiry_str = cert['notAfter']
                    expiry = datetime.strptime(expiry_str, '%b %d %H:%M:%S %Y %Z')
                    days_to_expiry = (expiry - datetime.now()).days
                    if days_to_expiry < 0:
                        vulns.append("Expired SSL certificate")
                        recs.append("Renew SSL certificate immediately.")
                    elif days_to_expiry < 30:
                        vulns.append(f"SSL certificate expires soon ({days_to_expiry} days): {expiry_str}")
                        recs.append("Plan SSL certificate renewal.")
                    cipher, tls_version, _ = ssock.cipher()
                    weak_ciphers = ['RC4', '3DES', 'MD5']
                    if any(wc in cipher for wc in weak_ciphers):
                        vulns.append(f"Weak SSL cipher detected: {cipher}")
                        recs.append(f"Disable weak ciphers ({', '.join(weak_ciphers)}) in SSL configuration.")
                    if tls_version in ['TLSv1', 'TLSv1.1']:
                        vulns.append(f"Weak TLS version detected: {tls_version}")
                        recs.append("Enforce TLS 1.2 or higher.")
                    cert_pem = ssl.DER_cert_to_PEM_cert(cert['raw'])
                    cert_hash = hashlib.sha256(cert_pem.encode()).hexdigest()
                    logging.debug(f"Certificate SHA256 for {hostname}: {cert_hash}")
            break
        except Exception as e:
            if attempt < config["retry_attempts"]:
                logging.debug(f"SSL scan retry {attempt + 1}/{config['retry_attempts']} for {hostname}: {e}")
                time.sleep(config["retry_delay"])
            else:
                vulns.append(f"SSL check failed: {str(e)}")
                recs.append("Verify HTTPS configuration.")
    return vulns, recs

def scan_dns(hostname: str, config: Dict) -> Tuple[List[str], List[str]]:
    vulns = []
    recs = []
    try:
        socket.gethostbyname(hostname)
        if HAS_DNSPYTHON:
            resolver = dns.resolver.Resolver()
            resolver.timeout = config["timeout"]
            for attempt in range(config["retry_attempts"] + 1):
                try:
                    answers = resolver.resolve(hostname, 'TXT')
                    has_spf = any("v=spf1" in str(r) for r in answers)
                    has_dmarc = any("v=DMARC1" in str(r) for r in answers)
                    has_dkim = any("v=DKIM1" in str(r) for r in answers)
                    if not has_spf:
                        vulns.append("Missing SPF record")
                        recs.append("Configure SPF to prevent email spoofing.")
                    if not has_dmarc:
                        vulns.append("Missing DMARC record")
                        recs.append("Implement DMARC for email authentication.")
                    if not has_dkim:
                        vulns.append("Missing DKIM record")
                        recs.append("Add DKIM for email integrity.")
                    try:
                        resolver.resolve(hostname, 'DS')
                    except dns.resolver.NoAnswer:
                        vulns.append("No DNSSEC enabled")
                        recs.append("Enable DNSSEC for domain validation.")
                    break
                except dns.resolver.NoAnswer:
                    vulns.append("No TXT records found")
                    recs.append("Add TXT records for SPF, DMARC, DKIM.")
                    break
                except Exception as e:
                    if attempt < config["retry_attempts"]:
                        logging.debug(f"DNS scan retry {attempt + 1}/{config['retry_attempts']} for {hostname}: {e}")
                        time.sleep(config["retry_delay"])
                    else:
                        vulns.append(f"DNS query failed: {str(e)}")
                        recs.append("Verify DNS configuration.")
        else:
            logging.info("dnspython not installed; limited DNS checks.")
            vulns.append("Advanced DNS checks unavailable")
            recs.append("Install dnspython for SPF/DMARC/DKIM/DNSSEC verification.")
    except socket.gaierror as e:
        vulns.append(f"DNS resolution failed: {str(e)}")
        recs.append("Verify domain registration and DNS configuration.")
    return vulns, recs

def scan_whois(hostname: str, config: Dict) -> Tuple[List[str], List[str]]:
    vulns = []
    recs = []
    domain = ".".join(hostname.split(".")[-2:])
    whois_server = config["whois_servers"].get(domain.split(".")[-1], "whois.iana.org")
    for attempt in range(config["retry_attempts"] + 1):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(config["timeout"])
            sock.connect((whois_server, 43))
            sock.sendall((hostname + "\r\n").encode())
            response = b""
            while True:
                data = sock.recv(4096)
                response += data
                if not data:
                    break
            sock.close()
            whois_data = response.decode(errors='ignore')
            if "REDACTED FOR PRIVACY" not in whois_data and "Privacy" not in whois_data:
                vulns.append("WHOIS privacy not enabled")
                recs.append("Enable WHOIS privacy protection to hide sensitive registrant info.")
            break
        except Exception as e:
            if attempt < config["retry_attempts"]:
                logging.debug(f"WHOIS scan retry {attempt + 1}/{config['retry_attempts']} for {hostname}: {e}")
                time.sleep(config["retry_delay"])
            else:
                logging.debug(f"WHOIS scan error on {hostname}: {e}")
    return vulns, recs

def scan_directory_listing(target: str, config: Dict) -> Tuple[List[str], List[str]]:
    vulns = []
    recs = []
    test_paths = ["/", "/admin/", "/config/", "/backup/"]
    for path in test_paths:
        test_url = urljoin(target, path)
        for attempt in range(config["retry_attempts"] + 1):
            try:
                resp = requests.get(test_url, timeout=config["timeout"], allow_redirects=False)
                if resp.status_code == 200 and "Index of" in resp.text:
                    vulns.append(f"Directory listing enabled at {path}")
                    recs.append(f"Disable directory listing for {path} to prevent unauthorized access.")
                break
            except requests.RequestException as e:
                if attempt < config["retry_attempts"]:
                    logging.debug(f"Directory listing scan retry {attempt + 1}/{config['retry_attempts']} for {test_url}: {e}")
                    time.sleep(config["retry_delay"])
                else:
                    logging.debug(f"Directory listing scan error on {test_url}: {e}")
    return vulns, recs

def scan_cookies(target: str, config: Dict) -> Tuple[List[str], List[str]]:
    vulns = []
    recs = []
    for attempt in range(config["retry_attempts"] + 1):
        try:
            resp = requests.get(target, timeout=config["timeout"], allow_redirects=True)
            cookies = resp.cookies
            for cookie in cookies:
                if not cookie.secure and target.startswith("https://"):
                    vulns.append(f"Insecure cookie detected: {cookie.name} (not Secure)")
                    recs.append(f"Set Secure flag on cookie {cookie.name} for HTTPS.")
                if not cookie.has_nonstandard_attr('HttpOnly'):
                    vulns.append(f"Insecure cookie detected: {cookie.name} (not HttpOnly)")
                    recs.append(f"Set HttpOnly flag on cookie {cookie.name} to prevent client-side access.")
            break
        except requests.RequestException as e:
            if attempt < config["retry_attempts"]:
                logging.debug(f"Cookies scan retry {attempt + 1}/{config['retry_attempts']} for {target}: {e}")
                time.sleep(config["retry_delay"])
            else:
                logging.debug(f"Cookies scan error on {target}: {e}")
    return vulns, recs

def scan_cors(target: str, config: Dict) -> Tuple[List[str], List[str]]:
    vulns = []
    recs = []
    for attempt in range(config["retry_attempts"] + 1):
        try:
            resp = requests.get(target, headers={"Origin": "https://test.riskradar.local"}, timeout=config["timeout"])
            acao = resp.headers.get("Access-Control-Allow-Origin")
            if acao == "*" or acao == "https://test.riskradar.local":
                vulns.append(f"CORS misconfiguration detected: {acao}")
                recs.append("Restrict Access-Control-Allow-Origin to trusted domains only.")
            break
        except requests.RequestException as e:
            if attempt < config["retry_attempts"]:
                logging.debug(f"CORS scan retry {attempt + 1}/{config['retry_attempts']} for {target}: {e}")
                time.sleep(config["retry_delay"])
            else:
                logging.debug(f"CORS scan error on {target}: {e}")
    return vulns, recs

# ========== Scan Orchestration and Risk Scoring ==========
def assign_risk_levels(vulns: List[str], config: Dict) -> Dict[str, List[str]]:
    levels = {"critical": [], "high": [], "medium": [], "low": []}
    for vuln in vulns:
        assigned = False
        for level, patterns in config["risk_levels"].items():
            if any(pattern in vuln for pattern in patterns):
                levels[level].append(vuln)
                assigned = True
                break
        if not assigned:
            levels["low"].append(vuln)
    return levels

def calculate_risk_score(levels: Dict[str, List[str]]) -> Tuple[int, str]:
    weights = {"critical": 10, "high": 7, "medium": 4, "low": 1}
    score = sum(len(vulns) * weights[level] for level, vulns in levels.items())
    score = min(score, 100)  # Cap at 100
    if score >= 80:
        category = "Critical"
    elif score >= 50:
        category = "High"
    elif score >= 20:
        category = "Medium"
    else:
        category = "Low"
    return score, category

def perform_scan(target: str, config: Dict) -> Dict[str, List[str]]:
    console = Console() if HAS_RICH else None
    try:
        target = validate_target(target)
    except ValueError as e:
        if console:
            console.print(f"[red]✖ Error:[/] Invalid target: {e}", style="bold")
        else:
            logging.error(str(e))
        return {"vulnerabilities": [str(e)], "recommendations": ["Correct target format and retry."]}
    
    hostname = get_hostname(target)
    vulns = []
    recs = []
    start_time = time.time()

    if console:
        console.print(f"[bold green]🔍 Scanning {target} with {len(config['scan_modules'])} modules...[/]")
        with Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            task = progress.add_task("Scanning modules...", total=len(config["scan_modules"]))
            for module in config["scan_modules"]:
                if module in SCAN_FUNCTIONS:
                    progress.update(task, description=f"Running {module}...")
                    try:
                        scan_vulns, scan_recs = SCAN_FUNCTIONS[module](target if module not in ["ports", "dns", "whois"] else hostname, config)
                        vulns.extend(scan_vulns)
                        recs.extend(scan_recs)
                        progress.update(task, advance=1)
                    except Exception as e:
                        console.print(f"[red]✖ Module {module} failed: {e}[/]", style="bold")
                        vulns.append(f"Scan module {module} failed: {str(e)}")
                        recs.append(f"Review module {module} configuration or dependencies.")
                        progress.update(task, advance=1)
    else:
        logging.info(f"Scanning {target} with {len(config['scan_modules'])} modules...")
        for module in config["scan_modules"]:
            if module in SCAN_FUNCTIONS:
                logging.debug(f"Running module {module} on {target}")
                try:
                    scan_vulns, scan_recs = SCAN_FUNCTIONS[module](target if module not in ["ports", "dns", "whois"] else hostname, config)
                    vulns.extend(scan_vulns)
                    recs.extend(scan_recs)
                except Exception as e:
                    logging.error(f"Module {module} failed: {e}")
                    vulns.append(f"Scan module {module} failed: {str(e)}")
                    recs.append(f"Review module {module} configuration or dependencies.")

    elapsed = time.time() - start_time
    if console:
        console.print(f"[green]✔ Scan of {target} completed in {elapsed:.2f} seconds.[/]", style="bold")
    else:
        logging.info(f"Scan of {target} completed in {elapsed:.2f} seconds.")
    return {"vulnerabilities": vulns, "recommendations": recs}

# ========== Reporting ==========
def generate_report(results: Dict[str, List[str]], framework: str, target: str, config: Dict) -> str:
    levels = assign_risk_levels(results["vulnerabilities"], config)
    score, category = calculate_risk_score(levels)

    report = (
        f"# vCISO-RiskRadar Assessment Report\n\n"
        f"**Target**: {target}\n"
        f"**Generated on**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"**Framework**: {framework}\n"
        f"**Overall Risk Score**: {score}/100 ({category})\n"
        f"**Version**: {VERSION}\n\n"
    )

    report += "## Executive Summary\n"
    total_vulns = len(results["vulnerabilities"])
    report += f"Scanned {target} using {len(config['scan_modules'])} modules, identifying {total_vulns} vulnerabilities and {len(results['recommendations'])} recommendations.\n"
    report += f"**Risk Category**: {category} (Score: {score}/100)\n"
    report += "Prioritize critical and high-severity issues for immediate remediation. Consult a vCISO for detailed analysis.\n\n"

    report += "## Vulnerabilities by Severity\n"
    for level, vulns in levels.items():
        if vulns:
            report += f"### {level.capitalize()} (Count: {len(vulns)})\n"
            for vuln in sorted(vulns):
                control = FRAMEWORK_MAPPINGS.get(framework, {}).get(vuln, "N/A")
                report += f"- {vuln} (Control: {control})\n"
        else:
            report += f"### {level.capitalize()}\n- None detected\n"

    report += "\n## Recommendations\n"
    if results["recommendations"]:
        for i, rec in enumerate(sorted(set(results["recommendations"])), 1):
            report += f"{i}. {rec}\n"
    else:
        report += "- No recommendations at this time\n"

    report += "\n## Methodology\n"
    report += f"- **Modules Used**: {', '.join(config['scan_modules'])}\n"
    report += f"- **Compliance Framework**: {framework}\n"
    report += f"- **Risk Scoring**: Weighted (Critical=10, High=7, Medium=4, Low=1), capped at 100\n"
    report += f"- **Scan Duration**: {(time.time() - time.time()):.2f} seconds\n"
    report += "- **Approach**: Non-intrusive, automated scans respecting target permissions\n\n"

    report += "## Notes\n"
    report += "- Automated scans; manual review recommended for comprehensive assessment.\n"
    report += f"- Logs in `{LOG_FILE}`; enable --verbose for detailed debugging.\n"
    report += "- Optional dependencies: `markdown` (HTML reports), `dnspython` (DNS checks), `rich` (enhanced console UI).\n"
    report += "- Extend via contributions: add modules, frameworks, or integrations.\n"
    report += "- Legal: Obtain permission before scanning targets.\n"
    return report

def display_rich_results(results: Dict[str, List[str]], framework: str, target: str, config: Dict, console: Console):
    levels = assign_risk_levels(results["vulnerabilities"], config)
    score, category = calculate_risk_score(levels)
    
    # Summary Panel
    console.print(
        Panel(
            f"[bold]Target:[/] {target}\n"
            f"[bold]Framework:[/] {framework}\n"
            f"[bold]Risk Score:[/] {score}/100 ([{category.lower()}]{category}[/])\n"
            f"[bold]Vulnerabilities:[/] {len(results['vulnerabilities'])}\n"
            f"[bold]Recommendations:[/] {len(set(results['recommendations']))}\n"
            f"[bold]Generated:[/] {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            title="Scan Summary",
            border_style="green" if score < 50 else "red" if score >= 80 else "yellow",
            padding=(1, 2)
        )
    )

    # Vulnerabilities Table
    table = Table(title="Vulnerabilities by Severity", show_header=True, header_style="bold cyan")
    table.add_column("Severity", style="bold", justify="center")
    table.add_column("Vulnerability", style="white")
    table.add_column("Framework Control", style="white")
    table.add_column("Recommendation", style="white")
    
    severity_styles = {"critical": "red", "high": "orange_red1", "medium": "yellow", "low": "green"}
    for level, vulns in levels.items():
        for vuln in sorted(vulns):
            control = FRAMEWORK_MAPPINGS.get(framework, {}).get(vuln, "N/A")
            rec = next((r for r in results["recommendations"] if vuln in r), "N/A")
            table.add_row(
                f"[{severity_styles[level]}]{level.capitalize()}[/]",
                vuln,
                control,
                rec
            )
    
    console.print(table)

    # Recommendations List
    if results["recommendations"]:
        console.print("\n[bold cyan]Recommendations[/]")
        for i, rec in enumerate(sorted(set(results["recommendations"])), 1):
            console.print(f"[cyan]{i}.[/] {rec}")
    else:
        console.print("\n[bold green]No recommendations at this time.[/]")

def save_report(report: str, target: str, framework: str, output_format: str, config: Dict, results: Dict[str, List[str]]):
    console = Console() if HAS_RICH else None
    os.makedirs(REPORT_DIR, exist_ok=True)
    safe_target = re.sub(r'[^\w\-_\.]', '_', target.replace("://", "_"))
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    base_filename = f"report_{safe_target}_{framework}_{timestamp}"

    formats = [output_format] if output_format != "all" else ["md", "html", "json", "csv"]
    for fmt in formats:
        try:
            if fmt == "md":
                filepath = os.path.join(REPORT_DIR, f"{base_filename}.md")
                with open(filepath, "w") as f:
                    f.write(report)
                if console:
                    console.print(f"[green]✔ Markdown report saved to {filepath}[/]", style="bold")
                else:
                    logging.info(f"Markdown report saved to {filepath}")
            elif fmt == "html" and HAS_MARKDOWN:
                html_path = os.path.join(REPORT_DIR, f"{base_filename}.html")
                html = markdown.markdown(report, extensions=['tables', 'fenced_code', 'sane_lists', 'codehilite'])
                with open(html_path, "w") as f:
                    f.write(f"""
                        <html>
                        <head>
                            <title>RiskRadar Report: {target}</title>
                            <style>
                                body {{ font-family: Arial, sans-serif; margin: 20px; line-height: 1.6; }}
                                h1, h2, h3 {{ color: #2c3e50; }}
                                pre, code {{ background: #f4f4f4; padding: 5px; border-radius: 4px; }}
                                table {{ border-collapse: collapse; width: 100%; }}
                                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                                th {{ background: #2c3e50; color: white; }}
                            </style>
                        </head>
                        <body>{html}</body>
                        </html>
                    """)
                if console:
                    console.print(f"[green]✔ HTML report saved to {html_path}[/]", style="bold")
                else:
                    logging.info(f"HTML report saved to {html_path}")
            elif fmt == "json":
                json_path = os.path.join(REPORT_DIR, f"{base_filename}.json")
                with open(json_path, "w") as f:
                    json.dump({
                        "target": target,
                        "framework": framework,
                        "timestamp": timestamp,
                        "results": results,
                        "report": report
                    }, f, indent=4)
                if console:
                    console.print(f"[green]✔ JSON report saved to {json_path}[/]", style="bold")
                else:
                    logging.info(f"JSON report saved to {json_path}")
            elif fmt == "csv":
                csv_path = os.path.join(REPORT_DIR, f"{base_filename}.csv")
                levels = assign_risk_levels(results["vulnerabilities"], config)
                with open(csv_path, "w", newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(["Severity", "Vulnerability", "Framework Control", "Recommendation"])
                    for level, vulns in levels.items():
                        for vuln in sorted(vulns):
                            control = FRAMEWORK_MAPPINGS.get(framework, {}).get(vuln, "N/A")
                            rec = next((r for r in results["recommendations"] if vuln in r), "")
                            writer.writerow([level, vuln, control, rec])
                if console:
                    console.print(f"[green]✔ CSV report saved to {csv_path}[/]", style="bold")
                else:
                    logging.info(f"CSV report saved to {csv_path}")
        except Exception as e:
            if console:
                console.print(f"[red]✖ Failed to save {fmt} report: {e}[/]", style="bold")
            else:
                logging.error(f"Failed to save {fmt} report: {e}")

# ========== CLI ==========
def main():
    parser = argparse.ArgumentParser(
        description="vCISO-RiskRadar: The Most Comprehensive Open-Source Cybersecurity Risk Assessment Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Advanced Examples:\n"
            "  python riskradar.py scan https://example.com --framework PCI-DSS --output all --verbose\n"
            "  python riskradar.py batch --framework HIPAA --output json\n"
            "  python riskradar.py config --add-module cors --remove-module whois --set-retries 3\n"
            "  python riskradar.py report --export report_https_example.com_NIST_20250930_205858.md"
        )
    )
    parser.add_argument("--version", action="version", version=f"vCISO-RiskRadar {VERSION}")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging (debug mode)")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Perform a comprehensive risk scan on a single target")
    scan_parser.add_argument("target", help="Target URL or hostname (e.g., https://example.com)")
    scan_parser.add_argument(
        "--framework",
        default="NIST",
        choices=list(FRAMEWORK_MAPPINGS.keys()),
        help="Compliance framework for report"
    )
    scan_parser.add_argument(
        "--output",
        default="md",
        choices=["md", "html", "json", "csv", "all"],
        help="Output format for report (default: md)"
    )

    # Batch scan command
    batch_parser = subparsers.add_parser("batch", help="Perform comprehensive risk scans on all configured targets")
    batch_parser.add_argument(
        "--framework",
        default="NIST",
        choices=list(FRAMEWORK_MAPPINGS.keys()),
        help="Compliance framework for reports"
    )
    batch_parser.add_argument(
        "--output",
        default="md",
        choices=["md", "html", "json", "csv", "all"],
        help="Output format for reports (default: md)"
    )

    # Config command
    config_parser = subparsers.add_parser("config", help="Manage configuration settings")
    config_parser.add_argument("--add-target", help="Add a scan target")
    config_parser.add_argument("--remove-target", help="Remove a scan target")
    config_parser.add_argument("--list-targets", action="store_true", help="List all scan targets")
    config_parser.add_argument("--clear-targets", action="store_true", help="Clear all scan targets")
    config_parser.add_argument("--set-timeout", type=int, help="Set scan timeout in seconds (positive integer)")
    config_parser.add_argument("--set-retries", type=int, help="Set retry attempts for scans (0 or positive)")
    config_parser.add_argument("--add-port", type=int, help="Add a port to scan")
    config_parser.add_argument("--remove-port", type=int, help="Remove a port from scan")
    config_parser.add_argument("--list-ports", action="store_true", help="List default ports")
    config_parser.add_argument("--reset-ports", action="store_true", help="Reset ports to default")
    config_parser.add_argument("--add-module", choices=list(SCAN_FUNCTIONS.keys()), help="Add a scan module")
    config_parser.add_argument("--remove-module", choices=list(SCAN_FUNCTIONS.keys()), help="Remove a scan module")
    config_parser.add_argument("--list-modules", action="store_true", help="List active scan modules")
    config_parser.add_argument("--reset-modules", action="store_true", help="Reset modules to default")
    config_parser.add_argument("--list-frameworks", action="store_true", help="List supported frameworks")
    config_parser.add_argument("--reset", action="store_true", help="Reset entire config to default")

    # Report command
    report_parser = subparsers.add_parser("report", help="Manage and view reports")
    report_parser.add_argument("--list", action="store_true", help="List all generated reports")
    report_parser.add_argument("--last", action="store_true", help="Show contents of last report")
    report_parser.add_argument("--clean", action="store_true", help="Delete all reports")
    report_parser.add_argument("--export", help="Export specific report to console (filename)")

    args = parser.parse_args()
    console = Console() if HAS_RICH else None
    init_logging(args.verbose)
    config = load_config()

    if args.command == "scan":
        results = perform_scan(args.target, config)
        report = generate_report(results, args.framework, args.target, config)
        if console:
            display_rich_results(results, args.framework, args.target, config, console)
            console.print("\n[bold cyan]Full Report[/]")
            console.print(Markdown(report))
        else:
            print(report)
        save_report(report, args.target, args.framework, args.output, config, results)
    elif args.command == "batch":
        if not config["scan_targets"]:
            if console:
                console.print("[red]✖ No scan targets configured. Use 'config --add-target' to add some.[/]", style="bold")
            else:
                logging.error("No scan targets configured. Use 'config --add-target' to add some.")
            sys.exit(1)
        for target in config["scan_targets"]:
            if console:
                console.print(f"\n[bold blue]Batch Scanning: {target}[/]", style="bold")
            else:
                logging.info(f"Batch scanning: {target}")
            results = perform_scan(target, config)
            report = generate_report(results, args.framework, target, config)
            if console:
                display_rich_results(results, args.framework, target, config, console)
                console.print("\n[bold cyan]Full Report[/]")
                console.print(Markdown(report))
            else:
                print(report)
            save_report(report, target, args.framework, args.output, config, results)
    elif args.command == "config":
        updated = False
        if args.add_target:
            try:
                args.add_target = validate_target(args.add_target)
                if args.add_target not in config["scan_targets"]:
                    config["scan_targets"].append(args.add_target)
                    updated = True
                    if console:
                        console.print(f"[green]✔ Added target: {args.add_target}[/]", style="bold")
                    else:
                        logging.info(f"Added target: {args.add_target}")
                else:
                    if console:
                        console.print(f"[yellow]⚠ Target already exists: {args.add_target}[/]", style="bold")
                    else:
                        logging.info(f"Target already exists: {args.add_target}")
            except ValueError as e:
                if console:
                    console.print(f"[red]✖ Error: {str(e)}[/]", style="bold")
                else:
                    logging.error(str(e))
        if args.remove_target:
            if args.remove_target in config["scan_targets"]:
                config["scan_targets"].remove(args.remove_target)
                updated = True
                if console:
                    console.print(f"[green]✔ Removed target: {args.remove_target}[/]", style="bold")
                else:
                    logging.info(f"Removed target: {args.remove_target}")
            else:
                if console:
                    console.print(f"[yellow]⚠ Target not found: {args.remove_target}[/]", style="bold")
                else:
                    logging.info(f"Target not found: {args.remove_target}")
        if args.list_targets:
            if console:
                table = Table(title="Scan Targets", show_header=True, header_style="bold cyan")
                table.add_column("Target", style="white")
                for target in config["scan_targets"] or ["No targets configured"]:
                    table.add_row(target)
                console.print(table)
            else:
                logging.info("Scan targets: " + ", ".join(config["scan_targets"]) if config["scan_targets"] else "No targets configured.")
        if args.clear_targets:
            config["scan_targets"] = []
            updated = True
            if console:
                console.print("[green]✔ Cleared all scan targets.[/]", style="bold")
            else:
                logging.info("Cleared all scan targets.")
        if args.set_timeout:
            if args.set_timeout > 0:
                config["timeout"] = args.set_timeout
                updated = True
                if console:
                    console.print(f"[green]✔ Set timeout to {args.set_timeout} seconds.[/]", style="bold")
                else:
                    logging.info(f"Set timeout to {args.set_timeout} seconds.")
            else:
                if console:
                    console.print("[red]✖ Timeout must be positive.[/]", style="bold")
                else:
                    logging.error("Timeout must be positive.")
        if args.set_retries:
            if args.set_retries >= 0:
                config["retry_attempts"] = args.set_retries
                updated = True
                if console:
                    console.print(f"[green]✔ Set retry attempts to {args.set_retries}.[/]", style="bold")
                else:
                    logging.info(f"Set retry attempts to {args.set_retries}.")
            else:
                if console:
                    console.print("[red]✖ Retry attempts must be non-negative.[/]", style="bold")
                else:
                    logging.error("Retry attempts must be non-negative.")
        if args.add_port:
            if args.add_port > 0 and args.add_port <= 65535:
                if args.add_port not in config["default_ports"]:
                    config["default_ports"].append(args.add_port)
                    config["default_ports"].sort()
                    updated = True
                    if console:
                        console.print(f"[green]✔ Added port: {args.add_port}[/]", style="bold")
                    else:
                        logging.info(f"Added port: {args.add_port}")
                else:
                    if console:
                        console.print(f"[yellow]⚠ Port already exists: {args.add_port}[/]", style="bold")
                    else:
                        logging.info(f"Port already exists: {args.add_port}")
            else:
                if console:
                    console.print("[red]✖ Port must be between 1 and 65535.[/]", style="bold")
                else:
                    logging.error("Port must be between 1 and 65535.")
        if args.remove_port:
            if args.remove_port in config["default_ports"]:
                config["default_ports"].remove(args.remove_port)
                updated = True
                if console:
                    console.print(f"[green]✔ Removed port: {args.remove_port}[/]", style="bold")
                else:
                    logging.info(f"Removed port: {args.remove_port}")
            else:
                if console:
                    console.print(f"[yellow]⚠ Port not found: {args.remove_port}[/]", style="bold")
                else:
                    logging.info(f"Port not found: {args.remove_port}")
        if args.list_ports:
            if console:
                table = Table(title="Default Ports", show_header=True, header_style="bold cyan")
                table.add_column("Port", style="white")
                for port in config["default_ports"] or ["No ports configured"]:
                    table.add_row(str(port))
                console.print(table)
            else:
                logging.info("Default ports: " + ", ".join(map(str, config["default_ports"])) if config["default_ports"] else "No ports configured.")
        if args.reset_ports:
            config["default_ports"] = [20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3389, 5900, 8080]
            updated = True
            if console:
                console.print("[green]✔ Reset ports to default.[/]", style="bold")
            else:
                logging.info("Reset ports to default.")
        if args.add_module:
            if args.add_module not in config["scan_modules"]:
                config["scan_modules"].append(args.add_module)
                updated = True
                if console:
                    console.print(f"[green]✔ Added module: {args.add_module}[/]", style="bold")
                else:
                    logging.info(f"Added module: {args.add_module}")
            else:
                if console:
                    console.print(f"[yellow]⚠ Module already enabled: {args.add_module}[/]", style="bold")
                else:
                    logging.info(f"Module already enabled: {args.add_module}")
        if args.remove_module:
            if args.remove_module in config["scan_modules"]:
                config["scan_modules"].remove(args.remove_module)
                updated = True
                if console:
                    console.print(f"[green]✔ Removed module: {args.remove_module}[/]", style="bold")
                else:
                    logging.info(f"Removed module: {args.remove_module}")
            else:
                if console:
                    console.print(f"[yellow]⚠ Module not found: {args.remove_module}[/]", style="bold")
                else:
                    logging.info(f"Module not found: {args.remove_module}")
        if args.list_modules:
            if console:
                table = Table(title="Active Modules", show_header=True, header_style="bold cyan")
                table.add_column("Module", style="white")
                for module in config["scan_modules"] or ["No modules configured"]:
                    table.add_row(module)
                console.print(table)
            else:
                logging.info("Active modules: " + ", ".join(config["scan_modules"]) if config["scan_modules"] else "No modules configured.")
        if args.reset_modules:
            config["scan_modules"] = list(SCAN_FUNCTIONS.keys())
            updated = True
            if console:
                console.print("[green]✔ Reset modules to default.[/]", style="bold")
            else:
                logging.info("Reset modules to default.")
        if args.list_frameworks:
            if console:
                table = Table(title="Supported Frameworks", show_header=True, header_style="bold cyan")
                table.add_column("Framework", style="white")
                for framework in config["frameworks"]:
                    table.add_row(framework)
                console.print(table)
            else:
                logging.info("Supported frameworks: " + ", ".join(config["frameworks"]))
        if args.reset:
            if os.path.exists(CONFIG_FILE):
                try:
                    os.rename(CONFIG_FILE, f"{CONFIG_FILE}.backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
                    if console:
                        console.print(f"[green]✔ Backed up old config to {CONFIG_FILE}.backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}[/]", style="bold")
                    else:
                        logging.info(f"Backed up old config to {CONFIG_FILE}.backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
                except Exception as e:
                    if console:
                        console.print(f"[red]✖ Failed to back up config: {e}[/]", style="bold")
                    else:
                        logging.error(f"Failed to back up config: {e}")
            config = load_config()  # Recreates default
            updated = True
            if console:
                console.print("[green]✔ Reset configuration to default.[/]", style="bold")
            else:
                logging.info("Reset configuration to default.")
        if updated:
            save_config(config)
        elif not any([args.add_target, args.remove_target, args.list_targets, args.clear_targets, args.set_timeout, args.set_retries, args.add_port, args.remove_port, args.list_ports, args.add_module, args.remove_module, args.list_modules, args.reset_modules, args.list_frameworks, args.reset]):
            if console:
                console.print("[yellow]⚠ No config action specified. Use --help for options.[/]", style="bold")
            else:
                logging.info("No config action specified. Use --help for options.")
    elif args.command == "report":
        reports_dir = REPORT_DIR
        md_reports = sorted([f for f in os.listdir(reports_dir) if f.endswith(".md")] if os.path.exists(reports_dir) else [])
        if args.list:
            if console:
                table = Table(title="Generated Reports", show_header=True, header_style="bold cyan")
                table.add_column("Report", style="white")
                for report in md_reports or ["No reports found"]:
                    table.add_row(report)
                console.print(table)
            else:
                logging.info("Generated reports: " + ", ".join(md_reports) if md_reports else "No reports found.")
        if args.last:
            if md_reports:
                last_report = os.path.join(reports_dir, md_reports[-1])
                with open(last_report, "r") as f:
                    content = f.read()
                if console:
                    console.print(Panel(Markdown(content), title="Last Report", border_style="cyan", padding=(1, 2)))
                else:
                    print(content)
            else:
                if console:
                    console.print("[yellow]⚠ No reports found.[/]", style="bold")
                else:
                    logging.info("No reports found.")
        if args.clean:
            if os.path.exists(reports_dir):
                for file in os.listdir(reports_dir):
                    try:
                        os.remove(os.path.join(reports_dir, file))
                    except Exception as e:
                        if console:
                            console.print(f"[red]✖ Failed to delete report {file}: {e}[/]", style="bold")
                        else:
                            logging.error(f"Failed to delete report {file}: {e}")
                if console:
                    console.print("[green]✔ Cleared all reports.[/]", style="bold")
                else:
                    logging.info("Cleared all reports.")
            else:
                if console:
                    console.print("[yellow]⚠ No reports to clean.[/]", style="bold")
                else:
                    logging.info("No reports to clean.")
        if args.export:
            export_path = os.path.join(reports_dir, args.export)
            if os.path.exists(export_path):
                with open(export_path, "r") as f:
                    content = f.read()
                if console:
                    console.print(Panel(Markdown(content), title=f"Report: {args.export}", border_style="cyan", padding=(1, 2)))
                else:
                    print(content)
            else:
                if console:
                    console.print(f"[red]✖ Report not found: {args.export}[/]", style="bold")
                else:
                    logging.error(f"Report not found: {args.export}")
        if not any([args.list, args.last, args.clean, args.export]):
            if console:
                console.print("[yellow]⚠ No report action specified. Use --help for options.[/]", style="bold")
            else:
                logging.info("No report action specified. Use --help for options.")

if __name__ == "__main__":
    main()
