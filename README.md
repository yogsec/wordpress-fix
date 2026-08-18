# WordPress Fix

Advanced WordPress REST API endpoint vulnerability scanner designed to identify exposed endpoints and potential security risks in WordPress installations.

<img width="713" height="734" alt="image" src="https://github.com/user-attachments/assets/5677bb90-5a7a-4452-b7b8-885c64890d33" />


## Overview

WordPress-Fix is a security assessment tool that systematically scans WordPress websites for exposed REST API endpoints. It helps security professionals and system administrators identify potential vulnerabilities, misconfigurations, and sensitive data exposures in WordPress installations.

The tool performs comprehensive endpoint scanning, filters out false positives, and provides clear security recommendations based on findings.

## Features

- Comprehensive WordPress REST API endpoint scanning
- Intelligent exception filtering to eliminate false positives
- Multi-threaded scanning for improved performance
- Sensitive data detection (emails, passwords, API keys, tokens)
- Automatic gzip decompression support
- Human-readable response size formatting
- Only displays genuine 200 OK responses with actual data
- JSON response parsing and validation
- Security recommendations based on scan results
- Verbose mode for detailed debugging
- Customizable payload files
- Thread control for performance tuning

## Installation

### Prerequisites

```bash
# Debian/Ubuntu
sudo apt-get install curl jq grep sed awk

# RHEL/CentOS
sudo yum install curl jq grep sed awk

# macOS
brew install curl jq grep sed awk
```

### Download

```bash
git clone https://github.com/yourusername/wordpress-fix.git
cd wordpress-fix
chmod +x wordpress-fix.sh
```

### Files Required

- `wordpress-fix.sh` - Main scanner script
- `payloads.txt` - Endpoint list file (included or custom)

## Usage

### Basic Scan

```bash
./wordpress-fix.sh -u https://example.com
```

### Advanced Usage

```bash
# With custom timeout and output file
./wordpress-fix.sh -u https://example.com -t 15 -o custom_results.txt

# With more threads for faster scanning
./wordpress-fix.sh -u https://example.com -T 20

# Verbose mode to see all status codes
./wordpress-fix.sh -u https://example.com -v

# Custom payloads file
./wordpress-fix.sh -u https://example.com -f custom_payloads.txt

# All options combined
./wordpress-fix.sh -u https://example.com -t 10 -T 15 -v -o results.txt
```

### Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `-u, --url` | Target WordPress site URL | Required |
| `-t, --timeout` | Connection timeout in seconds | 10 |
| `-o, --output` | Custom output file name | Auto-generated |
| `-f, --file` | Custom payloads file | payloads.txt |
| `-T, --threads` | Number of parallel threads | 5 |
| `-v, --verbose` | Verbose output mode | Disabled |
| `-h, --help` | Display help information | - |

## Output Format

### Console Output

```
[+] FOUND: /wp-json/wp/v2/users
    Status: 200 | Type: application/json | Size: 2KB
    Items: 10
    [!] WARNING: Sensitive data detected!
---
[+] FOUND: /wp-json/wp/v2/posts
    Status: 200 | Type: application/json | Size: 15KB
    Items: 50
---
```

### Results File

Results are saved in CSV-like format:

```
# WordPress-Fix Scan Results
# Target: https://example.com
# Date: Mon Jan 1 12:00:00 UTC 2024
# ==================================

https://example.com/wp-json/wp/v2/users|200|application/json|2048|10|SENSITIVE
https://example.com/wp-json/wp/v2/posts|200|application/json|15360|50
```

## Security Recommendations

Based on scan results, WordPress-Fix provides actionable security recommendations:

- Restrict access to exposed REST API endpoints
- Implement proper authentication mechanisms
- Disable REST API for unauthorized users
- Configure .htaccess or nginx rules for access control
- Enable WordPress security plugins
- Update WordPress core, themes, and plugins
- Monitor API request logs for suspicious activity
- Implement Web Application Firewall (WAF)
- Enforce strong authentication and session management
- Regular security audits and penetration testing

## Payloads File Format

The `payloads.txt` file contains endpoints to scan. Format:

```
# Comments start with #
/wp-json
/wp-json/wp/v2/users
/wp-json/wp/v2/posts?per_page=100
```

### Included Endpoints

The default payloads file includes:

- WordPress Core REST API endpoints
- Plugin-specific endpoints (Wordfence, Yoast, WooCommerce, Elementor)
- Admin and system endpoints
- Configuration and database exposure checks
- File access and directory listing endpoints
- Backup and security plugin endpoints
- User enumeration endpoints
- GraphQL endpoints

## Common Use Cases

### Security Audits

Regular security scanning to identify newly exposed endpoints after updates or plugin installations.

```bash
./wordpress-fix.sh -u https://example.com -o weekly_audit_$(date +%Y%m%d).txt
```

### Pre-Deployment Testing

Scan staging environments before deploying to production.

```bash
./wordpress-fix.sh -u https://staging.example.com -v
```

### Vulnerability Assessment

Identify potential data leaks and misconfigurations.

```bash
./wordpress-fix.sh -u https://example.com -T 20 -v
```

## Technical Details

### How It Works

1. Reads endpoints from payloads file
2. Makes HTTP requests to each endpoint
3. Filters responses for genuine 200 OK results
4. Parses and validates JSON responses
5. Detects sensitive data patterns
6. Displays formatted summary
7. Saves detailed results to file

### Exception Filtering

The tool intelligently filters out false positives including:

- WordPress REST API error responses
- Authentication required pages
- Permission denied responses
- HTML error pages (403, 404, 500)
- Empty or null data responses
- Login page redirects

### Sensitive Data Detection

Scans for patterns including:

- Email addresses
- Password fields
- API keys and tokens
- User credentials
- Database connection strings
- Configuration files
- Backup files
- Session tokens

## Troubleshooting

### Common Issues

**Size: Unknown**

Occurs when Content-Length header is missing. The tool uses actual file size from downloaded response.

**No results found**

Target may not be WordPress or endpoints are properly secured. Try verbose mode to see status codes.

**Permission denied**

Ensure script has execute permissions: `chmod +x wordpress-fix.sh`

**Dependency missing**

Install required packages as shown in installation section.

### Verbose Mode

Enable verbose mode to see all HTTP status codes and filtered endpoints:

```bash
./wordpress-fix.sh -u https://example.com -v
```

## Security Best Practices

1. Always obtain proper authorization before scanning
2. Use on systems you own or have permission to test
3. Run scans during maintenance windows to minimize impact
4. Keep results confidential
5. Act on findings promptly
6. Implement defense-in-depth security measures
7. Regular scanning as part of security maintenance

## License

This tool is provided for authorized security testing and educational purposes. Users are responsible for ensuring they have proper authorization before scanning any systems.

## Disclaimer

This tool is for security research and testing purposes only. The authors are not responsible for misuse or damage caused by this software. Always ensure you have written permission before scanning any systems.

LinkTree: [https://linktr.ee/abhinavsingwal](https://linktr.ee/abhinavsingwal)
