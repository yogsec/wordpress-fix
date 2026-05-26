#!/usr/bin/env python3
"""
Utility functions for WordPress scanner
"""

import requests
import re
import urllib3
from urllib.parse import urlparse, urljoin
import sys
from colorama import Fore, Style, init

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

init(autoreset=True)

class Colors:
    INFO = Fore.CYAN
    SUCCESS = Fore.GREEN
    WARNING = Fore.YELLOW
    ERROR = Fore.RED
    VULN = Fore.MAGENTA
    RESET = Style.RESET_ALL

def print_info(msg):
    print(f"{Colors.INFO}[*]{Colors.RESET} {msg}")

def print_success(msg):
    print(f"{Colors.SUCCESS}[+]{Colors.RESET} {msg}")

def print_warning(msg):
    print(f"{Colors.WARNING}[!]{Colors.RESET} {msg}")

def print_error(msg):
    print(f"{Colors.ERROR}[-]{Colors.RESET} {msg}")

def print_vuln(msg):
    print(f"{Colors.VULN}[VULN]{Colors.RESET} {msg}")

def normalize_url(url):
    """Ensure URL has proper format"""
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    return url.rstrip('/')

def send_request(url, method='GET', data=None, headers=None, timeout=10):
    """Send HTTP request with error handling"""
    try:
        default_headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        if headers:
            default_headers.update(headers)
        
        if method.upper() == 'GET':
            response = requests.get(url, headers=default_headers, timeout=timeout, verify=False)
        elif method.upper() == 'POST':
            response = requests.post(url, headers=default_headers, data=data, timeout=timeout, verify=False)
        else:
            response = requests.request(method, url, headers=default_headers, data=data, timeout=timeout, verify=False)
        
        return response
    except requests.exceptions.RequestException as e:
        print_error(f"Request failed for {url}: {e}")
        return None

def extract_links(html_content, base_url):
    """Extract all links from HTML content"""
    links = re.findall(r'href=["\'](.*?)["\']', html_content)
    absolute_links = []
    for link in links:
        absolute_link = urljoin(base_url, link)
        absolute_links.append(absolute_link)
    return absolute_links