#!/usr/bin/env python3
"""
Security headers checker for WordPress sites
"""

import sys
sys.path.append('..')
from core.utils import print_info, print_warning, print_vuln, send_request, normalize_url

def check_security_headers(url):
    """
    Check for missing security headers
    Returns: dict with header status
    """
    url = normalize_url(url)
    response = send_request(url)
    
    if not response:
        return {}
    
    security_headers = {
        'X-Frame-Options': {
            'required': True,
            'value': 'DENY or SAMEORIGIN',
            'found': False,
            'current': None
        },
        'X-XSS-Protection': {
            'required': True,
            'value': '1; mode=block',
            'found': False,
            'current': None
        },
        'X-Content-Type-Options': {
            'required': True,
            'value': 'nosniff',
            'found': False,
            'current': None
        },
        'Strict-Transport-Security': {
            'required': True,
            'value': 'max-age=31536000; includeSubDomains',
            'found': False,
            'current': None
        },
        'Content-Security-Policy': {
            'required': True,
            'value': "script-src 'self'",
            'found': False,
            'current': None
        },
        'Referrer-Policy': {
            'required': False,
            'value': 'strict-origin-when-cross-origin',
            'found': False,
            'current': None
        },
        'Permissions-Policy': {
            'required': False,
            'value': 'geolocation=(), microphone=(), camera=()',
            'found': False,
            'current': None
        },
        'Cache-Control': {
            'required': False,
            'value': 'no-cache, no-store, must-revalidate',
            'found': False,
            'current': None
        },
    }
    
    # Check for headers in response
    for header in security_headers:
        if header in response.headers:
            security_headers[header]['found'] = True
            security_headers[header]['current'] = response.headers[header]
    
    # Report missing headers
    print_info("Checking security headers...")
    
    for header, info in security_headers.items():
        if info['required'] and not info['found']:
            print_vuln(f"Missing required security header: {header} (Recommended: {info['value']})")
        elif not info['found']:
            print_warning(f"Missing recommended security header: {header}")
        else:
            print_info(f"✓ {header}: {info['current']}")
    
    # Check for WordPress-specific headers
    if 'X-Pingback' in response.headers:
        print_warning("X-Pingback header exposed - consider disabling XML-RPC if not needed")
    
    if 'Link' in response.headers and 'rel="https://api.w.org/"' in response.headers['Link']:
        print_info("REST API endpoint exposed via Link header")
    
    return security_headers