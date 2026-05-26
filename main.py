#!/usr/bin/env python3
"""
WordPress Vulnerability Scanner - Main Entry Point
"""

import sys
import argparse
from datetime import datetime
from core.utils import print_info, print_success, print_error, print_vuln, print_warning, normalize_url
from detectors import version_detector, plugin_detector, user_enumeration
from detectors import xmlrpc_scanner, backup_scanner
from detectors.theme_detector import detect_themes, check_theme_vulnerabilities
from detectors.wp_config_scanner import scan_wp_config
from detectors.uploads_scanner import scan_uploads_directory
from detectors.sql_injection import scan_sql_injection
from detectors.xss_scanner import scan_xss_vulnerabilities
from detectors.directory_listing import check_directory_listing
from detectors.security_headers import check_security_headers
from detectors.bruteforce_protection import check_bruteforce_protection
from detectors.sensitive_info_leak import scan_sensitive_info_leak

class WordPressScanner:
    def __init__(self, url):
        self.url = normalize_url(url)
        self.vulnerabilities = []
        self.results = {}
    
    def print_banner(self):
        """Print scanner banner"""
        print("\n" + "="*60)
        print("🔍 WORDPRESS VULNERABILITY SCANNER")
        print("="*60)
        print(f"Target: {self.url}")
        print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*60 + "\n")
    
    def scan_all(self):
        """Run all scans"""
        self.print_banner()
        
        all_vulnerabilities = []
        
        # 1. Version detection
        print_info("[1/12] Detecting WordPress version...")
        try:
            version, confidence = version_detector.detect_wordpress_version(self.url)
            if version:
                self.results['version'] = version
                print_success(f"✓ WordPress Version: {version} (confidence: {confidence})")
                vulns = version_detector.check_version_vulnerabilities(version)
                if vulns:
                    all_vulnerabilities.extend(vulns)
            else:
                print_warning("Could not detect WordPress version")
        except Exception as e:
            print_error(f"Version detection failed: {e}")
        
        print()  # Empty line for readability
        
        # 2. Plugin vulnerabilities
        print_info("[2/12] Scanning for plugins...")
        try:
            plugins = plugin_detector.detect_plugins(self.url)
            self.results['plugins'] = plugins
            if plugins:
                print_success(f"✓ Found {len(plugins)} plugin(s):")
                for plugin, version in plugins.items():
                    print(f"  - {plugin} (version: {version if version != 'unknown' else 'unknown'})")
                    vulns = plugin_detector.check_plugin_vulnerabilities(plugin, version)
                    if vulns:
                        all_vulnerabilities.extend(vulns)
            else:
                print_warning("No plugins detected or unable to scan")
        except Exception as e:
            print_error(f"Plugin scan failed: {e}")
        
        print()
        
        # 3. Theme detection
        print_info("[3/12] Scanning for themes...")
        try:
            themes = detect_themes(self.url)
            self.results['themes'] = themes
            if themes:
                print_success(f"✓ Found {len(themes)} theme(s):")
                for theme, version in themes.items():
                    print(f"  - {theme} (version: {version})")
                    vulns = check_theme_vulnerabilities(theme, version)
                    if vulns:
                        all_vulnerabilities.extend(vulns)
            else:
                print_warning("No themes detected")
        except Exception as e:
            print_error(f"Theme scan failed: {e}")
        
        print()
        
        # 4. User enumeration
        print_info("[4/12] Checking user enumeration...")
        try:
            users = user_enumeration.enumerate_users(self.url)
            self.results['users'] = users
            if users:
                print_vuln(f"⚠ Found {len(users)} user(s) exposed:")
                for user in users:
                    print(f"  - Username: {user.get('username', 'unknown')} (ID: {user.get('id', 'unknown')})")
                all_vulnerabilities.append(f"User enumeration possible: {len(users)} users found")
            else:
                print_success("✓ No user enumeration vulnerabilities found")
        except Exception as e:
            print_error(f"User enumeration check failed: {e}")
        
        print()
        
        # 5. XML-RPC vulnerabilities
        print_info("[5/12] Checking XML-RPC...")
        try:
            xmlrpc_vulns = xmlrpc_scanner.scan_xmlrpc_vulnerabilities(self.url)
            self.results['xmlrpc_vulns'] = xmlrpc_vulns
            if xmlrpc_vulns:
                print_vuln(f"⚠ Found {len(xmlrpc_vulns)} XML-RPC issue(s):")
                for vuln in xmlrpc_vulns:
                    print(f"  - {vuln}")
                    all_vulnerabilities.append(f"XML-RPC: {vuln}")
            else:
                print_success("✓ XML-RPC appears secure or disabled")
        except Exception as e:
            print_error(f"XML-RPC scan failed: {e}")
        
        print()
        
        # 6. Backup files
        print_info("[6/12] Scanning for exposed backup files...")
        try:
            backups = backup_scanner.scan_backup_files(self.url)
            self.results['backups'] = backups
            if backups:
                print_vuln(f"⚠ Found {len(backups)} exposed backup file(s):")
                for backup in backups[:5]:  # Show first 5
                    print(f"  - {backup}")
                if len(backups) > 5:
                    print(f"  ... and {len(backups) - 5} more")
                all_vulnerabilities.append(f"Exposed backup files: {len(backups)} found")
            else:
                print_success("✓ No exposed backup files found")
        except Exception as e:
            print_error(f"Backup scan failed: {e}")
        
        print()
        
        # 7. wp-config backups
        print_info("[7/12] Scanning for wp-config.php backups...")
        try:
            wpconfig_backups = backup_scanner.scan_wp_config_backups(self.url)
            self.results['wpconfig_backups'] = wpconfig_backups
            if wpconfig_backups:
                print_vuln(f"⚠ CRITICAL: Found {len(wpconfig_backups)} wp-config backup(s):")
                for backup in wpconfig_backups:
                    print(f"  - {backup}")
                all_vulnerabilities.append(f"CRITICAL: wp-config.php backups exposed")
            else:
                print_success("✓ No wp-config.php backups found")
        except Exception as e:
            print_error(f"wp-config scan failed: {e}")
        
        print()
        
        # 8. Uploads directory scan
        print_info("[8/12] Scanning uploads directory...")
        try:
            uploads = scan_uploads_directory(self.url)
            self.results['uploads'] = uploads
            if uploads:
                print_vuln(f"⚠ Found {len(uploads)} sensitive file(s) in uploads:")
                for upload in uploads[:5]:
                    print(f"  - {upload}")
                all_vulnerabilities.append(f"Sensitive files in uploads directory")
            else:
                print_success("✓ Uploads directory appears secure")
        except Exception as e:
            print_error(f"Uploads scan failed: {e}")
        
        print()
        
        # 9. SQL Injection
        print_info("[9/12] Testing for SQL injection vulnerabilities...")
        try:
            sql_vulns = scan_sql_injection(self.url)
            self.results['sql_injection'] = sql_vulns
            if sql_vulns:
                print_vuln(f"⚠ Found {len(sql_vulns)} potential SQL injection(s):")
                for vuln in sql_vulns[:3]:
                    print(f"  - {vuln[:100]}")
                all_vulnerabilities.extend(sql_vulns)
            else:
                print_success("✓ No SQL injection vulnerabilities detected")
        except Exception as e:
            print_error(f"SQL injection scan failed: {e}")
        
        print()
        
        # 10. XSS Vulnerabilities
        print_info("[10/12] Testing for XSS vulnerabilities...")
        try:
            xss_vulns = scan_xss_vulnerabilities(self.url)
            self.results['xss'] = xss_vulns
            if xss_vulns:
                print_vuln(f"⚠ Found {len(xss_vulns)} potential XSS vulnerability(s):")
                for vuln in xss_vulns[:3]:
                    print(f"  - {vuln[:100]}")
                all_vulnerabilities.extend(xss_vulns)
            else:
                print_success("✓ No XSS vulnerabilities detected")
        except Exception as e:
            print_error(f"XSS scan failed: {e}")
        
        print()
        
        # 11. Directory listing
        print_info("[11/12] Checking for directory listing vulnerabilities...")
        try:
            directories = check_directory_listing(self.url)
            self.results['directory_listing'] = directories
            if directories:
                print_vuln(f"⚠ Found {len(directories)} directory(ies) with listing enabled:")
                for directory in directories[:5]:
                    print(f"  - {directory}")
                all_vulnerabilities.append(f"Directory listing enabled on {len(directories)} directories")
            else:
                print_success("✓ No directory listing vulnerabilities found")
        except Exception as e:
            print_error(f"Directory listing check failed: {e}")
        
        print()
        
        # 12. Security Headers
        print_info("[12/12] Checking security headers...")
        try:
            headers = check_security_headers(self.url)
            self.results['security_headers'] = headers
            missing = [h for h, info in headers.items() if info.get('required', False) and not info.get('found', False)]
            if missing:
                print_vuln(f"⚠ Missing {len(missing)} required security header(s):")
                for header in missing:
                    print(f"  - {header}")
                all_vulnerabilities.append(f"Missing security headers: {', '.join(missing)}")
            else:
                print_success("✓ All required security headers present")
        except Exception as e:
            print_error(f"Security headers check failed: {e}")
        
        # Summary
        print("\n" + "="*60)
        print("📊 SCAN SUMMARY")
        print("="*60)
        
        if all_vulnerabilities:
            print_vuln(f"⚠ Total vulnerabilities found: {len(all_vulnerabilities)}")
            print("\n🔴 VULNERABILITIES DETECTED:")
            for i, vuln in enumerate(all_vulnerabilities, 1):
                print(f"  {i}. {vuln}")
        else:
            print_success("✓ No vulnerabilities detected!")
        
        print("\n" + "="*60)
        print_success("Scan completed successfully!")
        print("="*60 + "\n")
        
        # Save report to file (optional)
        self.save_report(all_vulnerabilities)
        
        return self.results
    
    def save_report(self, vulnerabilities):
        """Save scan report to file (optional)"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = f"reports/scan_{timestamp}.txt"
        
        import os
        os.makedirs("reports", exist_ok=True)
        
        with open(report_file, 'w') as f:
            f.write("="*60 + "\n")
            f.write("WORDPRESS VULNERABILITY SCAN REPORT\n")
            f.write("="*60 + "\n")
            f.write(f"Target: {self.url}\n")
            f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("="*60 + "\n\n")
            
            if vulnerabilities:
                f.write(f"VULNERABILITIES FOUND: {len(vulnerabilities)}\n\n")
                for i, vuln in enumerate(vulnerabilities, 1):
                    f.write(f"{i}. {vuln}\n")
            else:
                f.write("No vulnerabilities detected.\n")
        
        print_info(f"Report saved to: {report_file}")

def main():
    parser = argparse.ArgumentParser(description="WordPress Vulnerability Scanner")
    parser.add_argument("url", help="Target WordPress URL")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output")
    parser.add_argument("--no-save", action="store_true", help="Don't save report to file")
    
    args = parser.parse_args()
    
    scanner = WordPressScanner(args.url)
    results = scanner.scan_all()

if __name__ == "__main__":
    main()