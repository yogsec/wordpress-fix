#!/bin/bash

# ============================================================
# WordPress-Fix Security Scanner v3.1
# ============================================================
# Author: Security Research Team
# Description: WordPress endpoint vulnerability scanner
#              Shows clean summary with proper size formatting
# Usage: ./wordpress-fix.sh -u <target_url> [options]
# ============================================================

set -euo pipefail

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Default variables
TARGET_URL=""
TIMEOUT=10
OUTPUT_FILE="wordpress_fix_results_$(date +%Y%m%d_%H%M%S).txt"
PAYLOADS_FILE="payloads.txt"
THREADS=5
VERBOSE=0
MAX_RETRIES=2
USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

# Exception patterns
declare -a EXCEPTION_PATTERNS=(
    "rest_cannot_see"
    "rest_forbidden"
    "rest_authentication_required"
    "rest_no_route"
    "rest_invalid"
    "not_found"
    "not_allowed"
    "permission_denied"
    "access_denied"
    "login_required"
    "unauthorized"
)

# Function to format file size
format_size() {
    local size="$1"
    
    # If size is empty or 0, return "Unknown"
    if [[ -z "$size" ]] || [[ "$size" == "0" ]] || [[ "$size" == "null" ]]; then
        echo "Unknown"
        return
    fi
    
    # Remove any non-numeric characters
    size=$(echo "$size" | tr -cd '0-9')
    
    if [[ -z "$size" ]] || [[ "$size" -eq 0 ]]; then
        echo "Unknown"
        return
    fi
    
    if [[ "$size" -lt 1024 ]]; then
        echo "${size}B"
    elif [[ "$size" -lt 1048576 ]]; then
        echo "$((size / 1024))KB"
    elif [[ "$size" -lt 1073741824 ]]; then
        echo "$((size / 1048576))MB"
    else
        echo "$((size / 1073741824))GB"
    fi
}

# Function to display banner
show_banner() {
    echo -e "${CYAN}"
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║                                                               ║"
    echo "║          W O R D P R E S S - F I X                          ║"
    echo "║       Security Scanner v3.1                                  ║"
    echo "║                                                               ║"
    echo "║  [*] WordPress endpoint vulnerability detection              ║"
    echo "║  [*] Shows only summary (no response data)                   ║"
    echo "║  [*] Proper size formatting (B, KB, MB)                      ║"
    echo "║                                                               ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Function to display usage
usage() {
    echo -e "${YELLOW}Usage:${NC}"
    echo "  $0 -u <target_url> [options]"
    echo ""
    echo -e "${YELLOW}Required:${NC}"
    echo "  -u, --url <url>          Target WordPress site URL"
    echo ""
    echo -e "${YELLOW}Options:${NC}"
    echo "  -t, --timeout <seconds>  Connection timeout (default: 10)"
    echo "  -o, --output <file>      Output file (default: auto-generated)"
    echo "  -f, --file <file>        Custom payloads file (default: payloads.txt)"
    echo "  -T, --threads <num>      Number of parallel threads (default: 5)"
    echo "  -v, --verbose            Verbose output"
    echo "  -h, --help               Show this help message"
    echo ""
    echo -e "${YELLOW}Examples:${NC}"
    echo "  $0 -u https://example.com"
    echo "  $0 -u https://example.com -T 10 -v"
}

# Function to check dependencies
check_dependencies() {
    for cmd in curl jq grep sed awk; do
        if ! command -v "$cmd" &> /dev/null; then
            echo -e "${RED}[!] Missing: $cmd${NC}"
            echo "[*] Install: sudo apt-get install curl jq grep sed awk"
            exit 1
        fi
    done
}

# Function to validate URL
validate_url() {
    if [[ ! "$1" =~ ^https?:// ]]; then
        echo -e "${RED}[!] Invalid URL format${NC}"
        exit 1
    fi
}

# Function to normalize URL
normalize_url() {
    echo "${1%/}"
}

# Function to check if response contains exception
has_exception() {
    local response="$1"
    
    if [[ -z "$response" ]] || [[ ${#response} -lt 5 ]]; then
        return 0
    fi
    
    for pattern in "${EXCEPTION_PATTERNS[@]}"; do
        if echo "$response" | grep -qi "$pattern"; then
            return 0
        fi
    done
    
    if echo "$response" | head -100 | grep -qiE "<html|<!DOCTYPE"; then
        return 0
    fi
    
    return 1
}

# Function to check endpoint (summary only)
check_endpoint() {
    local base_url="$1"
    local endpoint="$2"
    local timeout="$3"
    local retries="$4"
    local full_url="${base_url}${endpoint}"
    
    # Skip comments and empty lines
    if [[ "$endpoint" =~ ^[[:space:]]*# ]] || [[ -z "$endpoint" ]]; then
        return 1
    fi
    
    endpoint=$(echo "$endpoint" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
    if [[ -z "$endpoint" ]]; then
        return 1
    fi
    
    full_url="${base_url}${endpoint}"
    
    local tmp_file=$(mktemp)
    local headers_file=$(mktemp)
    local status_code="000"
    local content_type=""
    local content_length="0"
    local actual_size="0"
    
    # Make request
    curl -s -k -L \
        --max-time "$timeout" \
        --connect-timeout "$timeout" \
        -H "User-Agent: $USER_AGENT" \
        -H "Accept: application/json, */*" \
        -H "Accept-Encoding: gzip, deflate" \
        -D "$headers_file" \
        -o "$tmp_file" \
        "$full_url" 2>/dev/null || true
    
    # Get status
    status_code=$(head -1 "$headers_file" | awk '{print $2}' || echo "000")
    content_type=$(grep -i "^Content-Type:" "$headers_file" | awk '{print $2}' | tr -d '\r' | cut -d';' -f1 || echo "unknown")
    
    # Get actual file size (from saved file)
    if [[ -f "$tmp_file" ]]; then
        actual_size=$(stat -c%s "$tmp_file" 2>/dev/null || stat -f%z "$tmp_file" 2>/dev/null || echo "0")
    fi
    
    # Also try to get from Content-Length header
    header_length=$(grep -i "^Content-Length:" "$headers_file" | awk '{print $2}' | tr -d '\r' || echo "0")
    
    # Use the larger of the two (if one is 0, use the other)
    if [[ "$header_length" -gt "$actual_size" ]]; then
        actual_size="$header_length"
    fi
    
    # Format the size
    formatted_size=$(format_size "$actual_size")
    
    # Only process 200 responses
    if [[ "$status_code" == "200" ]]; then
        local body=""
        
        # Handle gzipped content
        if grep -qi "^Content-Encoding:.*gzip" "$headers_file"; then
            body=$(gunzip -c "$tmp_file" 2>/dev/null || cat "$tmp_file" 2>/dev/null)
        else
            body=$(cat "$tmp_file" 2>/dev/null || echo "")
        fi
        
        # Clean binary
        body=$(echo "$body" | tr -cd '[:print:]\t\n' 2>/dev/null || echo "")
        
        # Skip if empty or exception
        if [[ -z "$body" ]] || [[ ${#body} -lt 5 ]] || has_exception "$body"; then
            rm -f "$tmp_file" "$headers_file"
            return 1
        fi
        
        # Get item count if JSON
        local item_count=""
        if echo "$body" | jq empty 2>/dev/null; then
            if echo "$body" | jq -e 'type == "array"' >/dev/null 2>&1; then
                item_count=$(echo "$body" | jq 'length' 2>/dev/null || echo "")
            elif echo "$body" | jq -e 'has("data")' >/dev/null 2>&1; then
                item_count=$(echo "$body" | jq '.data | length' 2>/dev/null || echo "")
            elif echo "$body" | jq -e 'has("results")' >/dev/null 2>&1; then
                item_count=$(echo "$body" | jq '.results | length' 2>/dev/null || echo "")
            elif echo "$body" | jq -e 'has("items")' >/dev/null 2>&1; then
                item_count=$(echo "$body" | jq '.items | length' 2>/dev/null || echo "")
            fi
        fi
        
        # Display summary only
        echo -e "${GREEN}[+] FOUND: $endpoint${NC}"
        echo -e "    Status: $status_code | Type: $content_type | Size: $formatted_size"
        
        if [[ -n "$item_count" ]] && [[ "$item_count" != "0" ]] && [[ "$item_count" != "null" ]] && [[ "$item_count" != "" ]]; then
            echo -e "    Items: $item_count"
        fi
        
        # Check for sensitive data
        local sensitive=""
        if echo "$body" | grep -qiE "email|password|api_key|secret|token|user_login|user_email|display_name|nonce|admin_url"; then
            sensitive="|SENSITIVE"
            echo -e "${RED}    [!] WARNING: Sensitive data detected!${NC}"
        fi
        
        # Save to file
        echo "$full_url|$status_code|$content_type|$actual_size|$item_count$sensitive" >> "$OUTPUT_FILE"
        echo "---"
    elif [[ $VERBOSE -eq 1 ]] && [[ "$status_code" != "000" ]]; then
        echo -e "${YELLOW}[*] $endpoint -> Status: $status_code${NC}"
    fi
    
    rm -f "$tmp_file" "$headers_file"
}

# Export functions
export -f check_endpoint
export -f has_exception
export -f format_size
export EXCEPTION_PATTERNS
export OUTPUT_FILE
export USER_AGENT
export VERBOSE

# Function to process endpoints
process_endpoints() {
    local base_url="$1"
    local timeout="$2"
    local threads="$3"
    local retries="$4"
    
    local total_lines=$(grep -vE '^[[:space:]]*#|^[[:space:]]*$' "$PAYLOADS_FILE" | wc -l)
    
    echo -e "${CYAN}[*] Scanning $total_lines endpoints with $threads threads${NC}"
    echo -e "${CYAN}[*] Target: $base_url${NC}"
    echo -e "${CYAN}[*] Timeout: ${timeout}s${NC}"
    echo ""
    
    local temp_file=$(mktemp)
    
    while IFS= read -r endpoint || [[ -n "$endpoint" ]]; do
        if [[ "$endpoint" =~ ^[[:space:]]*# ]] || [[ -z "$endpoint" ]]; then
            continue
        fi
        echo "$endpoint" >> "$temp_file"
    done < "$PAYLOADS_FILE"
    
    cat "$temp_file" | xargs -I {} -P "$threads" bash -c "check_endpoint '$base_url' '{}' '$timeout' '$retries'"
    
    rm -f "$temp_file"
}

# Function to generate recommendations
generate_recommendations() {
    local results_file="$1"
    
    if [[ ! -f "$results_file" ]] || [[ ! -s "$results_file" ]]; then
        echo -e "${GREEN}[+] No exposed endpoints found. Site appears secure!${NC}"
        return
    fi
    
    echo -e "\n${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}              SECURITY RECOMMENDATIONS${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    
    local total=$(wc -l < "$results_file")
    local sensitive=$(grep -c "SENSITIVE" "$results_file" || echo "0")
    
    echo -e "${YELLOW}[*] Total exposed endpoints: $total${NC}"
    
    if [[ $sensitive -gt 0 ]]; then
        echo -e "${RED}[!] $sensitive endpoints contain sensitive data!${NC}"
        echo ""
        echo -e "${YELLOW}Actions Required:${NC}"
        echo "1. Review endpoints marked as SENSITIVE"
        echo "2. Restrict access using .htaccess or nginx"
        echo "3. Implement proper authentication"
        echo "4. Disable REST API for unauthorized users"
        echo "5. Update WordPress and all plugins"
    else
        echo -e "${GREEN}[+] No sensitive data detected${NC}"
        echo ""
        echo -e "${YELLOW}General Recommendations:${NC}"
        echo "1. Regular security audits"
        echo "2. Keep WordPress updated"
        echo "3. Use security plugins"
        echo "4. Implement WAF"
    fi
    
    echo ""
    echo -e "${CYAN}[*] Results saved to: $results_file${NC}"
}

# Cleanup
cleanup() {
    rm -f /tmp/wordpress_fix_* 2>/dev/null
    rm -f /tmp/tmp.* 2>/dev/null
}

# Main function
main() {
    trap cleanup EXIT INT TERM
    
    show_banner
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -u|--url)
                TARGET_URL="$2"
                shift 2
                ;;
            -t|--timeout)
                TIMEOUT="$2"
                shift 2
                ;;
            -o|--output)
                OUTPUT_FILE="$2"
                shift 2
                ;;
            -f|--file)
                PAYLOADS_FILE="$2"
                shift 2
                ;;
            -T|--threads)
                THREADS="$2"
                shift 2
                ;;
            -v|--verbose)
                VERBOSE=1
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                echo -e "${RED}[!] Unknown option: $1${NC}"
                usage
                exit 1
                ;;
        esac
    done
    
    if [[ -z "$TARGET_URL" ]]; then
        echo -e "${RED}[!] Target URL required${NC}"
        usage
        exit 1
    fi
    
    validate_url "$TARGET_URL"
    TARGET_URL=$(normalize_url "$TARGET_URL")
    check_dependencies
    
    if [[ ! -f "$PAYLOADS_FILE" ]]; then
        echo -e "${RED}[!] Payloads file not found: $PAYLOADS_FILE${NC}"
        exit 1
    fi
    
    # Initialize output
    echo "# WordPress-Fix Scan Results" > "$OUTPUT_FILE"
    echo "# Target: $TARGET_URL" >> "$OUTPUT_FILE"
    echo "# Date: $(date)" >> "$OUTPUT_FILE"
    echo "# ==================================" >> "$OUTPUT_FILE"
    echo "" >> "$OUTPUT_FILE"
    
    echo -e "${CYAN}[*] Results: $OUTPUT_FILE${NC}"
    echo -e "${CYAN}[*] Started: $(date)${NC}"
    echo ""
    
    local start_time=$(date +%s)
    process_endpoints "$TARGET_URL" "$TIMEOUT" "$THREADS" "$MAX_RETRIES"
    local end_time=$(date +%s)
    
    echo -e "\n${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}                    SCAN COMPLETE${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    
    local duration=$((end_time - start_time))
    echo -e "${GREEN}[+] Duration: ${duration}s${NC}"
    
    generate_recommendations "$OUTPUT_FILE"
    
    echo -e "\n${GREEN}[+] Done!${NC}"
}

# Run main
main "$@"
