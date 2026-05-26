#!/usr/bin/env python3
"""
Setup script for WordPress Vulnerability Scanner
"""

import subprocess
import sys
import os

def install_requirements():
    """Install required packages"""
    requirements = [
        'requests>=2.28.0',
        'beautifulsoup4>=4.11.0',
        'colorama>=0.4.6',
        'urllib3>=1.26.0',
        'python-whois>=0.7.0'
    ]
    
    print("[*] Installing required packages...")
    for package in requirements:
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", package])
            print(f"[+] Installed: {package}")
        except Exception as e:
            print(f"[-] Failed to install {package}: {e}")

def create_directories():
    """Create necessary directories"""
    directories = ['logs', 'reports', 'temp']
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
        print(f"[+] Created directory: {directory}")

def setup_config():
    """Create initial configuration file"""
    config_content = '''# WordPress Scanner Configuration
# Modify as needed

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
TIMEOUT = 10
MAX_RETRIES = 3
THREADS = 5

# Common WordPress paths to scan
COMMON_PATHS = [
    "/wp-admin/",
    "/wp-content/",
    "/wp-includes/",
    "/wp-json/",
    "/xmlrpc.php",
    "/wp-login.php",
    "/readme.html",
    "/license.txt"
]

# Common backup file patterns
BACKUP_PATTERNS = [
    ".sql", ".tar", ".gz", ".zip", ".bak", ".old",
    "backup", ".backup", "_backup", "-backup"
]

# Known vulnerable WordPress versions (example - update from database)
VULNERABLE_VERSIONS = {
    "5.0.0": ["CVE-2019-6977", "XSS vulnerability"],
    "4.9.8": ["CVE-2018-20152", "CSRF vulnerability"],
    "4.7.0": ["CVE-2017-8295", "SQL injection"],
    # Add more versions from CVE database
}
'''
    
    with open('config.py', 'w') as f:
        f.write(config_content)
    print("[+] Created config.py")

def main():
    print("=" * 50)
    print("WordPress Vulnerability Scanner Setup")
    print("=" * 50)
    
    install_requirements()
    create_directories()
    setup_config()
    
    print("\n[+] Setup completed successfully!")
    print("[*] Run 'python main.py <url>' to start scanning")

if __name__ == "__main__":
    main()