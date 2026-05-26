#!/usr/bin/env python3
"""
Sensitive information leak detector
"""

import re
import sys
sys.path.append('..')
from core.utils import print_info, print_vuln, send_request, normalize_url

def scan_sensitive_info_leak(url):
    """
    Scan for sensitive information leaks
    Returns: list of found sensitive info
    """
    url = normalize_url(url)
    leaks = []
    
    # Files that might contain sensitive info
    sensitive_files = [
        "/debug.log",
        "/error_log",
        "/error.log",
        "/php_error_log",
        "/wp-content/debug.log",
        "/wp-content/error_log",
        "/.git/config",
        "/.env",
        "/.gitignore",
        "/robots.txt",
        "/sitemap.xml",
        "/phpinfo.php",
        "/info.php",
        "/wp-content/uploads/error_log",
        "/wp-admin/error_log",
        "/wp-includes/error_log",
    ]
    
    for file_path in sensitive_files:
        test_url = f"{url}{file_path}"
        response = send_request(test_url)
        
        if response and response.status_code == 200:
            # Check for sensitive information in response
            patterns = {
                'database': [
                    r'DB_NAME\s*=\s*[\'"](\w+)[\'"]',
                    r'DB_USER\s*=\s*[\'"](\w+)[\'"]',
                    r'DB_PASSWORD\s*=\s*[\'"](\w+)[\'"]',
                    r'mysql[_-]connect',
                    r'pg_connect',
                ],
                'api_keys': [
                    r'[A-Za-z0-9]{32,}',
                    r'api[_-]key[\s]*=[\s]*[\'"](\w+)[\'"]',
                    r'secret[\s]*=[\s]*[\'"](\w+)[\'"]',
                    r'access_token[\s]*=[\s]*[\'"](\w+)[\'"]',
                ],
                'paths': [
                    r'\/home\/[a-z]+\/',
                    r'\/var\/www\/',
                    r'C:\\[a-z]+\\',
                ],
                'emails': [
                    r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
                ],
                'ips': [
                    r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
                ]
            }
            
            content = response.text
            found_items = []
            
            for category, pattern_list in patterns.items():
                for pattern in pattern_list:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    if matches:
                        for match in matches[:3]:  # Limit to first 3 matches
                            found_items.append(f"{category}: {match[:50]}")
            
            if found_items:
                leak_info = f"Sensitive information found in {test_url}: {', '.join(found_items[:5])}"
                leaks.append(leak_info)
                print_vuln(leak_info)
    
    # Check for PHP errors in HTML comments
    response = send_request(url)
    if response:
        error_patterns = [
            r'<!--.*?Warning:.*?-->',
            r'<!--.*?Fatal error:.*?-->',
            r'<!--.*?Notice:.*?-->',
            r'<!--.*?Deprecated:.*?-->',
        ]
        
        for pattern in error_patterns:
            errors = re.findall(pattern, response.text, re.DOTALL | re.IGNORECASE)
            if errors:
                for error in errors[:3]:
                    error_preview = error[:200].replace('\n', ' ')
                    leak_info = f"PHP error disclosure in HTML: {error_preview}"
                    leaks.append(leak_info)
                    print_vuln(leak_info)
    
    return leaks