#!/bin/bash
# =============================================================================
# c5_csrf_cookie_check.sh
# =============================================================================
# Description : Tests for CSRF protection and cookie security misconfigurations.
#               Inspects Set-Cookie headers for security flags (Secure,
#               HttpOnly, SameSite), checks for CSRF token presence in
#               responses, and validates security headers (CSP, X-Frame-Options).
#
# Usage       : bash c5_csrf_cookie_check.sh <target_url>
#               Example: bash c5_csrf_cookie_check.sh https://example.com
#
# Dependencies: curl
# Output      : results/c5_results_<timestamp>.txt
#
# Note        : Raw cookie values are printed to terminal only and are NOT
#               written to file to avoid committing session data to the repo.
#
# Context     : Written for an authorized academic security assessment of
#               BAConnect. Use only against systems you have explicit
#               written permission to test.
#
# Author      : Immanuel John Sia
# Assessment  : BAConnect - Web Application Security Assessment (FYP 2025)
# =============================================================================

# ── CONFIG ────────────────────────────────────────────────────────────────────

TARGET="${1}"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

if [ -z "$TARGET" ]; then
    echo "[!] Usage: bash c5_csrf_cookie_check.sh <target_url>"
    echo "    Example: bash c5_csrf_cookie_check.sh https://example.com"
    exit 1
fi

mkdir -p results
OUTPUT="results/c5_results_${TIMESTAMP}.txt"

echo "=== C5 CSRF & COOKIE SECURITY TEST ==="   > "$OUTPUT"
echo "Target    : $TARGET"                       >> "$OUTPUT"
echo "Timestamp : $(date)"                       >> "$OUTPUT"
echo ""                                          >> "$OUTPUT"

echo "[*] Starting C5 CSRF and Cookie Security tests"
echo "[*] Target : $TARGET"
echo ""

# ── COOKIE FLAGS ─────────────────────────────────────────────────────────────
# Captures Set-Cookie headers from the HTTP response.
# Security flags to look for:
#   Secure   — cookie only sent over HTTPS
#   HttpOnly — cookie inaccessible to JavaScript (reduces XSS theft risk)
#   SameSite — controls cross-site cookie sending (Strict/Lax reduce CSRF risk)

echo "1. COOKIE FLAGS:" >> "$OUTPUT"
# Raw cookie values printed to terminal only — not written to file
echo "[*] Raw Set-Cookie headers (terminal only — not saved to file):"
curl -sI "$TARGET" | grep -i "set-cookie"
echo ""

# Write only flag presence, not cookie values
COOKIE_HEADERS=$(curl -sI "$TARGET" | grep -i "set-cookie")
echo "$COOKIE_HEADERS" | grep -oiE "(Secure|HttpOnly|SameSite=[^;]+)" >> "$OUTPUT"
echo "" >> "$OUTPUT"

# ── SECURITY HEADERS ─────────────────────────────────────────────────────────
# Checks for HTTP security headers that defend against XSS and clickjacking.
#   Content-Security-Policy — restricts resource loading, mitigates XSS
#   X-Frame-Options         — prevents clickjacking via iframe embedding
#   Strict-Transport-Security — enforces HTTPS

echo "2. SECURITY HEADERS:" >> "$OUTPUT"
curl -sI "$TARGET" | grep -E "(Content-Security-Policy|X-Frame-Options|Strict-Transport-Security)" >> "$OUTPUT"
echo "" >> "$OUTPUT"

# ── CSRF TOKEN PRESENCE ───────────────────────────────────────────────────────
# Searches HTML response for CSRF token strings.
# Absence of CSRF tokens on state-changing endpoints indicates vulnerability.

echo "3. CSRF TOKEN SEARCH:" >> "$OUTPUT"
curl -s "$TARGET" | grep -i "csrf" | head -5 >> "$OUTPUT"
echo "" >> "$OUTPUT"

# ── QUICK ANALYSIS ───────────────────────────────────────────────────────────

echo "=== QUICK ANALYSIS ===" >> "$OUTPUT"

echo "Cookie Security Flags:"
echo "Cookie Security Flags:" >> "$OUTPUT"

if echo "$COOKIE_HEADERS" | grep -qi "Secure"; then
    echo "  ✅ Secure flag    : YES" | tee -a "$OUTPUT"
else
    echo "  ❌ Secure flag    : NO" | tee -a "$OUTPUT"
fi

if echo "$COOKIE_HEADERS" | grep -qi "HttpOnly"; then
    echo "  ✅ HttpOnly flag  : YES" | tee -a "$OUTPUT"
else
    echo "  ❌ HttpOnly flag  : NO" | tee -a "$OUTPUT"
fi

if echo "$COOKIE_HEADERS" | grep -qi "SameSite"; then
    echo "  ✅ SameSite       : YES" | tee -a "$OUTPUT"
else
    echo "  ❌ SameSite       : NO" | tee -a "$OUTPUT"
fi

echo ""
echo "CSRF Protection:" | tee -a "$OUTPUT"
if grep -qi "csrf" "$OUTPUT"; then
    echo "  ✅ CSRF token     : FOUND" | tee -a "$OUTPUT"
else
    echo "  ❌ CSRF token     : NOT FOUND" | tee -a "$OUTPUT"
fi

echo ""
echo "Security Headers:" | tee -a "$OUTPUT"
if curl -sI "$TARGET" | grep -qi "Content-Security-Policy"; then
    echo "  ✅ CSP            : SET" | tee -a "$OUTPUT"
else
    echo "  ❌ CSP            : NOT SET" | tee -a "$OUTPUT"
fi

if curl -sI "$TARGET" | grep -qi "X-Frame-Options"; then
    echo "  ✅ X-Frame-Options: SET" | tee -a "$OUTPUT"
else
    echo "  ❌ X-Frame-Options: NOT SET" | tee -a "$OUTPUT"
fi

echo ""
echo "[*] C5 testing complete → $OUTPUT"
