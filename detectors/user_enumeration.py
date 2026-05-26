#!/usr/bin/env python3
"""
WordPress user enumeration detection
"""

import re
import json
import sys
sys.path.append('..')
from core.utils import print_info, print_vuln, print_warning, send_request, normalize_url

def check_user_enumeration_rest(url):
    """
    Check if users can be enumerated via REST API
    Returns: list of found users
    """
    url = normalize_url(url)
    users = []
    
    rest_url = f"{url}/wp-json/wp/v2/users"
    response = send_request(rest_url)
    
    if response and response.status_code == 200:
        try:
            data = response.json()
            for user in data:
                username = user.get('slug', '')
                user_id = user.get('id', '')
                if username:
                    users.append({'id': user_id, 'username': username})
                    print_vuln(f"User found via REST API: {username} (ID: {user_id})")
        except json.JSONDecodeError:
            pass
    
    return users

def check_user_enumeration_author(url):
    """
    Check if users can be enumerated via author archives
    Returns: list of found users
    """
    url = normalize_url(url)
    users = []
    
    for author_id in range(1, 20):  # Check first 20 authors
        author_url = f"{url}/?author={author_id}"
        response = send_request(author_url)
        
        if response and response.status_code == 200:
            # Check for redirect to author page
            if response.url != author_url and '/author/' in response.url:
                username = response.url.split('/author/')[1].rstrip('/')
                if username not in [u['username'] for u in users]:
                    users.append({'id': author_id, 'username': username})
                    print_vuln(f"User found via author enumeration: {username} (ID: {author_id})")
    
    return users

def check_user_enumeration_login_messages(url):
    """
    Check if login form reveals valid usernames
    Returns: boolean indicating if vulnerable
    """
    url = normalize_url(url)
    login_url = f"{url}/wp-login.php"
    
    # Test with valid username (if known)
    known_username = "admin"  # Test with common username
    
    response = send_request(login_url)
    if response:
        # Extract nonce for login
        nonce_match = re.search(r'name="log" value="(.*?)"', response.text)
        
        # Test with valid username
        data = {
            'log': known_username,
            'pwd': 'invalid_password',
            'wp-submit': 'Log In',
            'redirect_to': f"{url}/wp-admin/",
            'testcookie': '1'
        }
        
        post_response = send_request(login_url, data=data)
        if post_response:
            # Different error messages
            if 'The password you entered for the username' in post_response.text:
                print_vuln(f"Login form reveals that username '{known_username}' exists!")
                return True
            
            if 'Invalid username' in post_response.text:
                print_warning("Login form differentiates between username and password errors")
                return True
    
    return False

def enumerate_users(url):
    """Run all user enumeration checks"""
    all_users = []
    
    print_info("Checking user enumeration via REST API...")
    rest_users = check_user_enumeration_rest(url)
    all_users.extend(rest_users)
    
    print_info("Checking user enumeration via author parameter...")
    author_users = check_user_enumeration_author(url)
    all_users.extend(author_users)
    
    print_info("Checking login message user enumeration...")
    is_vulnerable = check_user_enumeration_login_messages(url)
    
    if is_vulnerable:
        print_vuln("Site is vulnerable to user enumeration via login messages!")
    
    return all_users