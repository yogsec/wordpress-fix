#!/usr/bin/env python3
"""
Uploads directory scanner for exposed sensitive files
"""

import re
import sys
sys.path.append('..')
from core.utils import print_info, print_vuln, print_warning, send_request, normalize_url

def scan_uploads_directory(url):
    """
    Scan wp-content/uploads for exposed sensitive files
    Returns: list of found sensitive files
    """
    url = normalize_url(url)
    sensitive_files = []
    
    uploads_url = f"{url}/wp-content/uploads/"
    response = send_request(uploads_url)
    
    if response and response.status_code == 200:
        print_warning("Uploads directory has directory listing enabled!")
        
        # Look for sensitive file types
        sensitive_patterns = [
            r'href="([^"]+\.(?:sql|log|txt|conf|cfg|ini|xml|json|yml|yaml))"',
            r'href="([^"]*\.(?:php|phtml|php\d|inc))"',
            r'href="([^"]*backup[^"]*\.(?:zip|tar|gz|7z))"',
            r'href="([^"]*\.(?:sql|db))"'
        ]
        
        for pattern in sensitive_patterns:
            matches = re.findall(pattern, response.text, re.IGNORECASE)
            for match in matches:
                full_url = normalize_url(f"{uploads_url}{match}")
                sensitive_files.append(full_url)
                print_vuln(f"Sensitive file found in uploads: {full_url}")
    else:
        # Try common upload paths
        common_paths = [
            "uploads/2023/",
            "uploads/2024/",
            "uploads/backup/",
            "uploads/temp/",
            "uploads/logs/",
            "uploads/sql/",
        ]
        
        for path in common_paths:
            test_url = f"{url}/wp-content/{path}"
            response = send_request(test_url)
            if response and response.status_code == 200:
                print_warning(f"Potential uploads subdirectory accessible: {test_url}")
    
    # Check for specific vulnerable files
    vulnerable_files = [
        "wp-content/uploads/shell.php",
        "wp-content/uploads/webshell.php",
        "wp-content/uploads/backdoor.php",
        "wp-content/uploads/malware.php",
        "wp-content/uploads/error_log",
        "wp-content/uploads/.htaccess",
        "wp-content/uploads/phpinfo.php",
    ]
    
    for file_path in vulnerable_files:
        test_url = f"{url}/{file_path}"
        response = send_request(test_url)
        if response and response.status_code == 200:
            sensitive_files.append(test_url)
            print_vuln(f"Potentially malicious file found: {test_url}")
    
    return sensitive_files