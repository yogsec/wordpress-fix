#!/usr/bin/env python3
"""
WordPress backup file scanner
"""

import sys
sys.path.append('..')
from core.utils import print_info, print_vuln, send_request, normalize_url

COMMON_BACKUP_PATHS = [
    "wp-config.php.bak",
    "wp-config.php~",
    "wp-config.old",
    "wp-config.save",
    ".wp-config.php.swp",
    "wp-config.php.backup",
    "backup.sql",
    "db_backup.sql",
    "database.sql",
    "wp-backup.sql",
    "wp-content/backup-db/",
    "wp-content/backups/",
    "wp-content/backup/",
    "backup.zip",
    "site-backup.zip",
    "backup.tar.gz",
    "wp-content/plugins/backup/",
    "wp-content/uploads/backup/",
]

def scan_backup_files(url):
    """
    Scan for exposed backup files and directories
    Returns: list of found backup files
    """
    url = normalize_url(url)
    found_backups = []
    
    print_info("Scanning for exposed backup files...")
    
    for backup_path in COMMON_BACKUP_PATHS:
        test_url = f"{url}/{backup_path}"
        response = send_request(test_url)
        
        if response and response.status_code == 200:
            found_backups.append(test_url)
            print_vuln(f"Exposed backup file found: {test_url}")
        
        # Also check directory index
        if backup_path.endswith('/'):
            response = send_request(test_url)
            if response and response.status_code == 200:
                found_backups.append(test_url)
                print_vuln(f"Exposed backup directory: {test_url}")
    
    return found_backups

def scan_wp_config_backups(url):
    """
    Specifically scan for wp-config.php backups
    Returns: list of found backups
    """
    url = normalize_url(url)
    wpconfig_variations = [
        "wp-config.php.bak",
        "wp-config.php~",
        "wp-config.old",
        "wp-config.save",
        "wp-config.php.backup",
        "wp-config.php.old",
        "wp-config.php.original",
        "wp-config.php1",
        "wp-config.php2",
        "wp-config.php.swp",
        "wp-config.php.swo",
        ".wp-config.php.swp",
        "wp-config.php.txt",
    ]
    
    found = []
    for variation in wpconfig_variations:
        test_url = f"{url}/{variation}"
        response = send_request(test_url)
        
        if response and response.status_code == 200:
            # Check if it contains database credentials
            if 'DB_NAME' in response.text and 'DB_USER' in response.text:
                found.append(test_url)
                print_vuln(f"CRITICAL: wp-config.php backup with credentials found: {test_url}")
            else:
                found.append(test_url)
                print_vuln(f"wp-config.php backup found: {test_url}")
    
    return found