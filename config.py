# WordPress Scanner Configuration
# Modify as needed

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
TIMEOUT = 10
MAX_RETRIES = 3
THREADS = 5

# Common WordPress paths to scan
COMMON_PATHS = [
    "/wp-admin/",
    "/wp-content/",
    "/wp-includes/",
    "/wp-json/",
    "/xmlrpc.php",
    "/wp-login.php",
    "/readme.html",
    "/license.txt"
]

# Common backup file patterns
BACKUP_PATTERNS = [
    ".sql", ".tar", ".gz", ".zip", ".bak", ".old",
    "backup", ".backup", "_backup", "-backup"
]

# Known vulnerable WordPress versions (example - update from database)
VULNERABLE_VERSIONS = {
    "5.0.0": ["CVE-2019-6977", "XSS vulnerability"],
    "4.9.8": ["CVE-2018-20152", "CSRF vulnerability"],
    "4.7.0": ["CVE-2017-8295", "SQL injection"],
    # Add more versions from CVE database
}
