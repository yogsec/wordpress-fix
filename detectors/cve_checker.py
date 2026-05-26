#!/usr/bin/env python3
"""
CVE checker for WordPress core, plugins, and themes
"""

import json
import sys
from datetime import datetime
sys.path.append('..')
from core.utils import print_info, print_vuln, send_request

# This would ideally connect to an API like WPVulnDB, NVD, etc.
# For now, using a local database

class CVEChecker:
    def __init__(self):
        self.cve_database = self._load_cve_database()
    
    def _load_cve_database(self):
        """Load local CVE database (in production, fetch from API)"""
        return {
            "wordpress": {
                "6.4.0": [
                    {"cve": "CVE-2023-5522", "severity": "HIGH", "description": "XSS vulnerability in template"},
                    {"cve": "CVE-2023-5523", "severity": "MEDIUM", "description": "CSRF in admin panel"}
                ],
                "6.3.2": [
                    {"cve": "CVE-2023-3999", "severity": "CRITICAL", "description": "SQL injection in XML-RPC"}
                ],
                "5.9.0": [
                    {"cve": "CVE-2022-2630", "severity": "HIGH", "description": "RCE in image upload"}
                ]
            },
            "plugins": {
                "woocommerce": {
                    "3.2.0": [
                        {"cve": "CVE-2018-12895", "severity": "MEDIUM", "description": "XSS vulnerability"}
                    ]
                },
                "elementor": {
                    "2.8.0": [
                        {"cve": "CVE-2020-13114", "severity": "MEDIUM", "description": "Stored XSS"}
                    ]
                }
            },
            "themes": {
                "divi": {
                    "3.0.0": [
                        {"cve": "CVE-2017-18362", "severity": "MEDIUM", "description": "XSS in customizer"}
                    ]
                }
            }
        }
    
    def check_wordpress_cves(self, version):
        """Check for CVEs in WordPress core version"""
        if version in self.cve_database['wordpress']:
            cves = self.cve_database['wordpress'][version]
            for cve in cves:
                print_vuln(f"WordPress {version} - {cve['cve']} ({cve['severity']}): {cve['description']}")
            return cves
        return []
    
    def check_plugin_cves(self, plugin_name, version):
        """Check for CVEs in plugin version"""
        plugin_key = plugin_name.lower().replace(' ', '-')
        if plugin_key in self.cve_database['plugins']:
            if version in self.cve_database['plugins'][plugin_key]:
                cves = self.cve_database['plugins'][plugin_key][version]
                for cve in cves:
                    print_vuln(f"{plugin_name} {version} - {cve['cve']} ({cve['severity']}): {cve['description']}")
                return cves
        return []
    
    def check_theme_cves(self, theme_name, version):
        """Check for CVEs in theme version"""
        theme_key = theme_name.lower().replace(' ', '-')
        if theme_key in self.cve_database['themes']:
            if version in self.cve_database['themes'][theme_key]:
                cves = self.cve_database['themes'][theme_key][version]
                for cve in cves:
                    print_vuln(f"{theme_name} {version} - {cve['cve']} ({cve['severity']}): {cve['description']}")
                return cves
        return []
    
    def fetch_latest_cves(self):
        """Fetch latest CVEs from external API (placeholder)"""
        print_info("Fetching latest CVEs from WPVulnDB...")
        # In production, implement API call to https://wpvulndb.com/api
        # or use NVD API: https://services.nvd.nist.gov/rest/json/cves/2.0
        return []