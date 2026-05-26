#!/usr/bin/env python3
"""
Directory listing vulnerability scanner
"""

import sys
sys.path.append('..')
from core.utils import print_info, print_vuln, send_request, normalize_url

# Common WordPress directories to check for listing
DIRECTORIES_TO_CHECK = [
    "wp-admin",
    "wp-content",
    "wp-includes",
    "wp-content/plugins",
    "wp-content/themes",
    "wp-content/uploads",
    "wp-content/languages",
    "wp-content/backup",
    "wp-content/cache",
    "wp-content/upgrade",
    "wp-content/wflogs",
    "wp-content/ai1wm-backups",  # All-in-one migration
    "wp-content/backup-db",
    "wp-content/mu-plugins",
]

def check_directory_listing(url):
    """
    Check for directory listing vulnerabilities
    Returns: list of directories with listing enabled
    """
    url = normalize_url(url)
    vulnerable_dirs = []
    
    print_info("Checking for directory listing vulnerabilities...")
    
    for directory in DIRECTORIES_TO_CHECK:
        test_url = f"{url}/{directory}/"
        response = send_request(test_url)
        
        if response and response.status_code == 200:
            # Check for directory listing indicators
            listing_indicators = [
                "Index of /",
                "Parent Directory",
                "<title>Index of",
                "Directory listing for",
                "[DIR]",
                "<pre>",
                "Directory:",
            ]
            
            for indicator in listing_indicators:
                if indicator in response.text:
                    vulnerable_dirs.append(test_url)
                    print_vuln(f"Directory listing enabled: {test_url}")
                    break
            
            # Check if it's not a standard WordPress file
            if "wp-admin" in test_url and "wp-login.php" not in response.text:
                if "Directory" in response.text or "Index of" in response.text:
                    vulnerable_dirs.append(test_url)
                    print_vuln(f"Directory listing enabled: {test_url}")
    
    # Check for version-specific directories
    version_dirs = [
        "wp-content/themes/twentyseventeen",
        "wp-content/themes/twentysixteen",
        "wp-content/themes/twentyfifteen",
    ]
    
    for directory in version_dirs:
        test_url = f"{url}/{directory}/"
        response = send_request(test_url)
        
        if response and response.status_code == 200:
            if "Index of" in response.text or "Parent Directory" in response.text:
                vulnerable_dirs.append(test_url)
                print_vuln(f"Directory listing enabled: {test_url}")
    
    return vulnerable_dirs