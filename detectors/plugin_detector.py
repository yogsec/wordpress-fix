#!/usr/bin/env python3
"""
WordPress plugin detection and vulnerability checking
"""

import json
import re
import sys
sys.path.append('..')
from core.utils import print_info, print_vuln, send_request, normalize_url

# Common vulnerable plugins (simplified - expand with actual database)
VULNERABLE_PLUGINS = {
    "wp-file-manager": ["6.0", "RCE vulnerability"],
    "duplicator": ["1.3.26", "Information disclosure"],
    "wp-statistics": ["12.6.7", "SQL injection"],
    "woocommerce": ["3.2.0", "XSS vulnerability"],
    "elementor": ["2.8.0", "XSS vulnerability"],
    "revslider": ["4.6.0", "Multiple vulnerabilities"],
    "gravity-forms": ["2.2.0", "SQL injection"],
    "contact-form-7": ["4.9.0", "XSS vulnerability"],
    "yoast-seo": ["9.0.0", "XSS vulnerability"],
    "jetpack": ["6.4.0", "CSRF vulnerability"],
}

def detect_plugins(url):
    """
    Detect installed plugins by scanning common patterns
    Returns: dict {plugin_name: version}
    """
    url = normalize_url(url)
    plugins = {}
    
    # Method 1: Check CSS/JS files in wp-content/plugins
    response = send_request(f"{url}/wp-content/plugins/")
    if response:
        # Extract plugin names from directory listing
        plugin_pattern = r'href="([^/]+)/"'
        found_plugins = re.findall(plugin_pattern, response.text)
        for plugin in found_plugins:
            if plugin not in ['..', 'akismet', 'hello.php']:  # Exclude default
                plugins[plugin] = "unknown"
                print_info(f"Found plugin: {plugin}")
    
    # Method 2: Check for common plugin files
    plugin_files = [
        "readme.txt", "changelog.txt", "readme.html", "info.php"
    ]
    
    for plugin in list(VULNERABLE_PLUGINS.keys())[:10]:  # Check top vulnerable
        for plugin_file in plugin_files:
            test_url = f"{url}/wp-content/plugins/{plugin}/{plugin_file}"
            response = send_request(test_url)
            if response and response.status_code == 200:
                # Try to extract version
                version_match = re.search(r'Version:\s*([0-9.]+)', response.text)
                if version_match:
                    plugins[plugin] = version_match.group(1)
                else:
                    plugins[plugin] = "unknown"
                print_info(f"Found plugin: {plugin} (version: {plugins[plugin]})")
                break
    
    return plugins

def check_plugin_vulnerabilities(plugin_name, version):
    """Check if plugin version is vulnerable"""
    vulnerabilities = []
    
    if plugin_name.lower() in VULNERABLE_PLUGINS:
        vuln_version, vuln_desc = VULNERABLE_PLUGINS[plugin_name.lower()]
        
        # Version comparison simplified - use packaging.version in production
        if version == "unknown" or version <= vuln_version:
            vuln_info = f"{plugin_name} {version}: {vuln_desc}"
            vulnerabilities.append(vuln_info)
            print_vuln(vuln_info)
    
    return vulnerabilities