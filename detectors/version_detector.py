#!/usr/bin/env python3
"""
WordPress version detection
"""

import re
import sys
sys.path.append('..')
from core.utils import print_info, print_vuln, send_request, normalize_url

def detect_wordpress_version(url):
    """
    Detect WordPress version from various sources
    Returns: (version, confidence)
    """
    url = normalize_url(url)
    
    # Method 1: Check meta generator tag
    response = send_request(url)
    if response:
        meta_match = re.search(r'<meta name="generator" content="WordPress ([0-9.]+)"', response.text)
        if meta_match:
            version = meta_match.group(1)
            print_info(f"Found version {version} from meta tag")
            return version, "high"
    
    # Method 2: Check readme.html
    readme_url = f"{url}/readme.html"
    response = send_request(readme_url)
    if response and response.status_code == 200:
        version_match = re.search(r'Version ([0-9.]+)', response.text)
        if version_match:
            version = version_match.group(1)
            print_info(f"Found version {version} from readme.html")
            return version, "high"
    
    # Method 3: Check CSS/JS files
    css_url = f"{url}/wp-includes/css/dist/block-library/style.min.css"
    response = send_request(css_url)
    if response:
        version_match = re.search(r'WordPress ([0-9.]+)', response.text)
        if version_match:
            version = version_match.group(1)
            print_info(f"Found version {version} from CSS")
            return version, "medium"
    
    # Method 4: Check RSS feeds
    feed_url = f"{url}/feed/"
    response = send_request(feed_url)
    if response:
        version_match = re.search(r'<generator>https://wordpress.org/\?v=([0-9.]+)</generator>', response.text)
        if version_match:
            version = version_match.group(1)
            print_info(f"Found version {version} from RSS feed")
            return version, "medium"
    
    return None, "none"

def check_version_vulnerabilities(version):
    """Check if detected version has known vulnerabilities"""
    if not version:
        return []
    
    # Known vulnerable versions (from CVE database)
    # In production, you'd fetch this from an API or local DB
    vulnerable = {
        "6.4.0": ["CVE-2023-5522", "XSS vulnerability in template"],
        "6.3.0": ["CVE-2023-3999", "SQL injection in XML-RPC"],
        "6.1.0": ["CVE-2022-4410", "RCE in file upload"],
        "5.9.0": ["CVE-2022-2630", "CSRF in admin area"],
        "5.8.0": ["CVE-2021-39200", "Stored XSS"],
        "5.7.0": ["CVE-2021-29450", "Privilege escalation"],
        "5.6.0": ["CVE-2021-2415", "XSS vulnerability"],
        "5.5.0": ["CVE-2020-28039", "SQL injection"],
        "5.4.0": ["CVE-2020-11025", "CSRF vulnerability"],
        "5.3.0": ["CVE-2019-17671", "XSS vulnerability"],
        "5.2.0": ["CVE-2019-16223", "SQL injection"],
        "5.1.0": ["CVE-2019-8943", "XSS vulnerability"],
        "5.0.0": ["CVE-2019-6977", "XSS vulnerability"],
        "4.9.8": ["CVE-2018-20152", "CSRF vulnerability"],
        "4.7.0": ["CVE-2017-8295", "SQL injection"],
    }
    
    vulnerabilities = []
    if version in vulnerable:
        for cve, desc in vulnerable[version]:
            vulnerabilities.append(f"{cve}: {desc}")
            print_vuln(f"Vulnerable version {version} - {cve}: {desc}")
    else:
        print_info(f"Version {version} may be secure (check CVE database)")
    
    return vulnerabilities