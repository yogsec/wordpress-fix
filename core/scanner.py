#!/usr/bin/env python3
"""
Base scanner class and common scanning functionality
"""

import threading
import queue
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin
from .utils import print_info, print_vuln, print_warning, send_request, normalize_url

class BaseScanner:
    """Base class for all scanners"""
    
    def __init__(self, url, timeout=10, threads=5):
        self.url = normalize_url(url)
        self.timeout = timeout
        self.threads = threads
        self.results = []
        self.vulnerabilities = []
    
    def scan(self):
        """Override this method in child classes"""
        raise NotImplementedError("Child classes must implement scan()")
    
    def add_result(self, result, is_vulnerability=False):
        """Add result to results list"""
        self.results.append(result)
        if is_vulnerability:
            self.vulnerabilities.append(result)
            print_vuln(result)
        else:
            print_info(result)

class ThreadedScanner(BaseScanner):
    """Scanner that supports threading for faster scanning"""
    
    def __init__(self, url, timeout=10, threads=5):
        super().__init__(url, timeout, threads)
        self.task_queue = queue.Queue()
        self.results_lock = threading.Lock()
    
    def worker(self):
        """Worker thread function"""
        while True:
            try:
                task = self.task_queue.get(timeout=1)
                if task is None:
                    break
                func, args, kwargs = task
                result = func(*args, **kwargs)
                with self.results_lock:
                    self.results.append(result)
            except queue.Empty:
                break
            except Exception as e:
                print(f"Worker error: {e}")
            finally:
                self.task_queue.task_done()
    
    def run_parallel(self, tasks):
        """Run tasks in parallel using threads"""
        for task in tasks:
            self.task_queue.put(task)
        
        workers = []
        for _ in range(min(self.threads, len(tasks))):
            t = threading.Thread(target=self.worker)
            t.start()
            workers.append(t)
        
        self.task_queue.join()
        
        for t in workers:
            t.join()
        
        return self.results

class VulnerabilityDatabase:
    """In-memory vulnerability database"""
    
    def __init__(self):
        self.cve_data = self._load_cve_data()
        self.version_vulnerabilities = self._load_version_vulns()
        self.plugin_vulnerabilities = self._load_plugin_vulns()
        self.theme_vulnerabilities = self._load_theme_vulns()
    
    def _load_cve_data(self):
        """Load CVE data (simplified - would connect to API in production)"""
        return {
            "2023-5522": {
                "title": "WordPress Core XSS Vulnerability",
                "affected_versions": ["6.4.0", "6.4.1"],
                "severity": "HIGH",
                "cvss_score": 7.2
            },
            "2023-3999": {
                "title": "WordPress SQL Injection in XML-RPC",
                "affected_versions": ["6.3.0", "6.3.1", "6.3.2"],
                "severity": "CRITICAL",
                "cvss_score": 9.8
            },
            "2022-4410": {
                "title": "WordPress RCE in File Upload",
                "affected_versions": ["6.1.0", "6.1.1"],
                "severity": "CRITICAL",
                "cvss_score": 9.0
            }
        }
    
    def _load_version_vulns(self):
        """Load version-specific vulnerabilities"""
        return {
            "6.4.0": ["CVE-2023-5522"],
            "6.3.0": ["CVE-2023-3999"],
            "6.1.0": ["CVE-2022-4410"],
            "5.9.0": ["CVE-2022-2630"],
            "5.8.0": ["CVE-2021-39200"],
            "5.7.0": ["CVE-2021-29450"],
            "5.6.0": ["CVE-2021-2415"],
            "5.5.0": ["CVE-2020-28039"],
            "5.4.0": ["CVE-2020-11025"],
            "5.3.0": ["CVE-2019-17671"],
            "5.2.0": ["CVE-2019-16223"],
            "5.1.0": ["CVE-2019-8943"],
            "5.0.0": ["CVE-2019-6977"],
            "4.9.8": ["CVE-2018-20152"],
            "4.7.0": ["CVE-2017-8295"]
        }
    
    def _load_plugin_vulns(self):
        """Load plugin vulnerabilities"""
        return {
            "wp-file-manager": {
                "vulnerable_versions": ["<=6.0"],
                "cves": ["CVE-2020-25213"],
                "description": "RCE vulnerability"
            },
            "duplicator": {
                "vulnerable_versions": ["<=1.3.26"],
                "cves": ["CVE-2020-25214"],
                "description": "Information disclosure"
            },
            "woocommerce": {
                "vulnerable_versions": ["<=3.2.0"],
                "cves": ["CVE-2018-12895"],
                "description": "XSS vulnerability"
            },
            "elementor": {
                "vulnerable_versions": ["<=2.8.0"],
                "cves": ["CVE-2020-13114"],
                "description": "XSS vulnerability"
            }
        }
    
    def _load_theme_vulns(self):
        """Load theme vulnerabilities"""
        return {
            "divi": {
                "vulnerable_versions": ["<=3.0.0"],
                "cves": ["CVE-2017-18362"],
                "description": "XSS vulnerability"
            }
        }
    
    def check_version(self, version):
        """Check if a WordPress version is vulnerable"""
        if version in self.version_vulnerabilities:
            return self.version_vulnerabilities[version]
        return []
    
    def check_plugin(self, plugin_name, version):
        """Check if a plugin version is vulnerable"""
        plugin_key = plugin_name.lower().replace(' ', '-')
        if plugin_key in self.plugin_vulnerabilities:
            return self.plugin_vulnerabilities[plugin_key]
        return None
    
    def get_cve_details(self, cve_id):
        """Get detailed information about a CVE"""
        return self.cve_data.get(cve_id, {})