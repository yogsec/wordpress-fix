#!/usr/bin/env python3
"""
WordPress theme detection and vulnerability checking
"""

import re
import sys
sys.path.append('..')
from core.utils import print_info, print_vuln, send_request, normalize_url

# Known vulnerable themes
VULNERABLE_THEMES = {
    "divi": ["3.0.0", "XSS vulnerability"],
    "avada": ["5.0.0", "RCE vulnerability"],
    "enfold": ["4.0.0", "SQL injection"],
    "jupiter": ["6.0.0", "XSS vulnerability"],
    "the7": ["9.0.0", "CSRF vulnerability"],
}

def detect_themes(url):
    """
    Detect active and installed themes
    Returns: dict {theme_name: version}
    """
    url = normalize_url(url)
    themes = {}
    
    # Method 1: Check active theme from CSS
    css_url = f"{url}/wp-content/themes/"
    response = send_request(css_url)
    
    if response and response.status_code == 200:
        # Extract theme names from directory listing
        theme_pattern = r'href="([^/]+)/"'
        found_themes = re.findall(theme_pattern, response.text)
        
        for theme in found_themes:
            if theme not in ['..', 'index.html', 'themes']:
                # Try to get theme version from style.css
                style_url = f"{url}/wp-content/themes/{theme}/style.css"
                style_response = send_request(style_url)
                
                version = "unknown"
                if style_response and style_response.status_code == 200:
                    version_match = re.search(r'Version:\s*([0-9.]+)', style_response.text)
                    if version_match:
                        version = version_match.group(1)
                
                themes[theme] = version
                print_info(f"Found theme: {theme} (version: {version})")
    
    # Method 2: Check for theme README files
    common_theme_files = ["readme.txt", "changelog.txt", "style.css"]
    for theme in list(VULNERABLE_THEMES.keys()):
        for theme_file in common_theme_files:
            test_url = f"{url}/wp-content/themes/{theme}/{theme_file}"
            response = send_request(test_url)
            if response and response.status_code == 200:
                if theme not in themes:
                    themes[theme] = "unknown"
                    print_info(f"Found theme: {theme}")
                break
    
    return themes

def check_theme_vulnerabilities(theme_name, version):
    """
    Check if theme version is vulnerable
    Returns: list of vulnerabilities
    """
    vulnerabilities = []
    theme_key = theme_name.lower().replace(' ', '-')
    
    if theme_key in VULNERABLE_THEMES:
        vuln_version, vuln_desc = VULNERABLE_THEMES[theme_key]
        
        # Simple version comparison (improve with packaging.version in production)
        if version == "unknown" or version <= vuln_version:
            vuln_info = f"{theme_name} {version}: {vuln_desc}"
            vulnerabilities.append(vuln_info)
            print_vuln(vuln_info)
    
    return vulnerabilities