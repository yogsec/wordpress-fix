#!/usr/bin/env python3
"""
WordPress XML-RPC vulnerability scanner
"""

import sys
import xml.etree.ElementTree as ET
sys.path.append('..')
from core.utils import print_info, print_vuln, print_warning, send_request, normalize_url

def check_xmlrpc_enabled(url):
    """
    Check if XML-RPC is enabled
    Returns: boolean
    """
    url = normalize_url(url)
    xmlrpc_url = f"{url}/xmlrpc.php"
    
    response = send_request(xmlrpc_url)
    
    if response and response.status_code == 200:
        if 'XML-RPC' in response.text or 'XML-RPC server accepts POST requests only' in response.text:
            print_warning("XML-RPC is enabled!")
            return True
    
    return False

def check_xmlrpc_methods(url):
    """
    Check available XML-RPC methods
    Returns: list of available methods
    """
    url = normalize_url(url)
    xmlrpc_url = f"{url}/xmlrpc.php"
    
    # XML-RPC request to list methods
    xml_body = '''<?xml version="1.0"?>
    <methodCall>
    <methodName>system.listMethods</methodName>
    <params></params>
    </methodCall>'''
    
    headers = {'Content-Type': 'text/xml'}
    response = send_request(xmlrpc_url, method='POST', data=xml_body, headers=headers)
    
    if response and response.status_code == 200:
        try:
            root = ET.fromstring(response.text)
            methods = []
            for method in root.findall('.//value/string'):
                methods.append(method.text)
            
            print_info(f"Found {len(methods)} XML-RPC methods")
            
            # Check for dangerous methods
            dangerous_methods = [
                'wp.getUsersBlogs',
                'wp.getCategories',
                'wp.getComments',
                'wp.deletePost',
                'wp.editPost',
                'wp.newPost',
                'wp.uploadFile',
                'system.multicall',
                'pingback.ping'
            ]
            
            dangerous_found = []
            for method in methods:
                if any(danger in method for danger in dangerous_methods):
                    dangerous_found.append(method)
                    print_vuln(f"Dangerous method found: {method}")
            
            return methods, dangerous_found
        except ET.ParseError:
            pass
    
    return [], []

def check_pingback_vulnerability(url):
    """
    Check for pingback amplification vulnerability
    Returns: boolean if vulnerable
    """
    url = normalize_url(url)
    xmlrpc_url = f"{url}/xmlrpc.php"
    
    # Pingback request to test if site can be used for DDoS
    pingback_body = f'''<?xml version="1.0"?>
    <methodCall>
    <methodName>pingback.ping</methodName>
    <params>
    <param><value><string>http://example.com/test</string></value></param>
    <param><value><string>{url}</string></value></param>
    </params>
    </methodCall>'''
    
    headers = {'Content-Type': 'text/xml'}
    response = send_request(xmlrpc_url, method='POST', data=pingback_body, headers=headers)
    
    if response:
        # If target doesn't exist but returns no error about pingbacks being disabled
        if response.status_code == 200 and 'Target URI' in response.text:
            print_vuln("Site is vulnerable to pingback reflection/amplification attacks!")
            return True
    
    return False

def scan_xmlrpc_vulnerabilities(url):
    """Main function to scan all XML-RPC vulnerabilities"""
    vulnerabilities = []
    
    print_info("Scanning XML-RPC vulnerabilities...")
    
    if not check_xmlrpc_enabled(url):
        print_info("XML-RPC is disabled or not accessible")
        return vulnerabilities
    
    methods, dangerous = check_xmlrpc_methods(url)
    
    if dangerous:
        vulnerabilities.extend(dangerous)
        print_vuln(f"Found {len(dangerous)} dangerous XML-RPC methods")
    
    if check_pingback_vulnerability(url):
        vulnerabilities.append("Pingback amplification vulnerability")
    
    return vulnerabilities