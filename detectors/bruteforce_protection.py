#!/usr/bin/env python3
"""
Brute force protection checker for WordPress
"""

import sys
import time
sys.path.append('..')
from core.utils import print_info, print_vuln, print_warning, send_request, normalize_url

def check_bruteforce_protection(url):
    """
    Check if the site has brute force protection
    Returns: dict with protection status
    """
    url = normalize_url(url)
    login_url = f"{url}/wp-login.php"
    
    protection_status = {
        'has_protection': False,
        'lockout_time': None,
        'max_attempts': None,
        'notes': []
    }
    
    print_info("Testing brute force protection (this may take a moment)...")
    
    # Test with multiple invalid login attempts
    failed_attempts = 0
    response_times = []
    
    for attempt in range(10):  # Try 10 failed logins
        start_time = time.time()
        
        data = {
            'log': 'invalid_user_' + str(attempt),
            'pwd': 'invalid_password_' + str(attempt),
            'wp-submit': 'Log In',
            'redirect_to': f"{url}/wp-admin/",
            'testcookie': '1'
        }
        
        response = send_request(login_url, method='POST', data=data)
        response_time = time.time() - start_time
        response_times.append(response_time)
        
        if response:
            # Check for lockout message
            lockout_indicators = [
                "too many attempts",
                "try again later",
                "locked out",
                "too many failed login attempts",
                "slow down",
                "are you human?",
                "captcha",
                "reCAPTCHA",
                "cloudflare",
                "brute force"
            ]
            
            for indicator in lockout_indicators:
                if indicator.lower() in response.text.lower():
                    protection_status['has_protection'] = True
                    protection_status['notes'].append(f"Lockout detected after {attempt + 1} attempts")
                    print_info(f"Brute force protection detected: {indicator}")
                    break
            
            # Check for CAPTCHA
            captcha_indicators = ['captcha', 'recaptcha', 'are you human']
            for indicator in captcha_indicators:
                if indicator in response.text.lower():
                    protection_status['has_protection'] = True
                    protection_status['notes'].append("CAPTCHA protection detected")
                    print_info("CAPTCHA protection detected")
            
            # Check response time patterns
            if attempt > 3 and response_times[-1] > response_times[0] * 2:
                protection_status['has_protection'] = True
                protection_status['notes'].append("Response time increasing (rate limiting detected)")
                print_info("Rate limiting detected - response times increasing")
        
        # Small delay between attempts
        time.sleep(0.5)
    
    if not protection_status['has_protection']:
        print_vuln("No brute force protection detected! Site is vulnerable to password attacks")
        protection_status['notes'].append("No protection mechanisms detected")
        
        # Check for common protection plugins
        protection_plugins = [
            "wordfence", "loginizer", "limit-login-attempts", 
            "cerber", "bulletproof", "all-in-one-wp-security"
        ]
        
        for plugin in protection_plugins:
            plugin_check_url = f"{url}/wp-content/plugins/{plugin}/readme.txt"
            response = send_request(plugin_check_url)
            if response and response.status_code == 200:
                print_info(f"Protection plugin found but not active? {plugin}")
                protection_status['notes'].append(f"{plugin} detected but may not be configured")
    
    # Check for login page URL changes (security by obscurity)
    custom_login_urls = [
        f"{url}/login",
        f"{url}/admin",
        f"{url}/wp-admin",
        f"{url}/backend",
        f"{url}/cms-login",
    ]
    
    custom_login_found = False
    for custom_url in custom_login_urls:
        response = send_request(custom_url)
        if response and response.status_code == 200:
            if "wp-login" in response.text or "wordpress" in response.text.lower():
                print_info(f"Custom login URL found: {custom_url}")
                custom_login_found = True
                break
    
    if custom_login_found:
        protection_status['notes'].append("Using custom login URL (obscurity)")
    
    return protection_status