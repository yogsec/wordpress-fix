#!/usr/bin/env python3
"""
wp-config.php scanner for exposed configuration files
"""

import re
import sys
sys.path.append('..')
from core.utils import print_info, print_vuln, print_warning, send_request, normalize_url

def scan_wp_config(url):
    """
    Check for exposed wp-config.php file
    Returns: dict with configuration data if found
    """
    url = normalize_url(url)
    config_urls = [
        f"{url}/wp-config.php",
        f"{url}/wp-config.php.bak",
        f"{url}/wp-config.old",
        f"{url}/wp-config.save",
        f"{url}/../wp-config.php",
        f"{url}/admin/wp-config.php",
        f"{url}/wp-admin/wp-config.php"
    ]
    
    config_data = {}
    
    for config_url in config_urls:
        response = send_request(config_url)
        
        if response and response.status_code == 200:
            # Check if it's a PHP file (might not execute but could be source)
            if '<?php' in response.text and 'DB_NAME' in response.text:
                print_vuln(f"CRITICAL: Exposed wp-config.php found at {config_url}")
                
                # Extract database credentials
                db_name_match = re.search(r"define\(\s*'DB_NAME',\s*'([^']+)'", response.text)
                db_user_match = re.search(r"define\(\s*'DB_USER',\s*'([^']+)'", response.text)
                db_pass_match = re.search(r"define\(\s*'DB_PASSWORD',\s*'([^']+)'", response.text)
                db_host_match = re.search(r"define\(\s*'DB_HOST',\s*'([^']+)'", response.text)
                auth_keys_match = re.search(r"define\(\s*'AUTH_KEY',\s*'([^']+)'", response.text)
                
                if db_name_match:
                    config_data['DB_NAME'] = db_name_match.group(1)
                    print_vuln(f"  Database Name: {config_data['DB_NAME']}")
                
                if db_user_match:
                    config_data['DB_USER'] = db_user_match.group(1)
                    print_vuln(f"  Database User: {config_data['DB_USER']}")
                
                if db_pass_match:
                    config_data['DB_PASSWORD'] = db_pass_match.group(1)
                    print_vuln(f"  Database Password: {config_data['DB_PASSWORD']}")
                
                if db_host_match:
                    config_data['DB_HOST'] = db_host_match.group(1)
                    print_info(f"  Database Host: {config_data['DB_HOST']}")
                
                if auth_keys_match:
                    config_data['AUTH_KEY'] = auth_keys_match.group(1)
                    print_warning("  Authentication keys exposed!")
                
                break
            elif response.status_code == 200 and ('Page not found' not in response.text):
                print_warning(f"Potential config file found (not standard): {config_url}")
    
    return config_data