#!/bin/bash
# =============================================================================
# c4_xss_reflected.sh
# =============================================================================
# Description : Tests for reflected Cross-Site Scripting (XSS) vulnerabilities
#               by injecting payloads via GET parameters across common
#               application endpoints. Logs all responses for manual review.
#
# Usage       : bash c4_xss_reflected.sh <target_url>
#               Example: bash c4_xss_reflected.sh https://example.com
#
# Dependencies: curl, python3 (for URL encoding)
# Payload file: payloads/xss_basic_payloads.txt
# Output      : results/c4_reflected_testing_<timestamp>.txt
#               results/c4_reflected_findings_<timestamp>.txt
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
PAYLOAD_FILE="payloads/xss_basic_payloads.txt"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

if [ -z "$TARGET" ]; then
    echo "[!] Usage: bash c4_xss_reflected.sh <target_url>"
    echo "    Example: bash c4_xss_reflected.sh https://example.com"
    exit 1
fi

if [ ! -f "$PAYLOAD_FILE" ]; then
    echo "[!] Payload file not found: $PAYLOAD_FILE"
    echo "    Ensure payloads/xss_basic_payloads.txt exists in the repo."
    exit 1
fi

mkdir -p results
OUTPUT_ALL="results/c4_reflected_testing_${TIMESTAMP}.txt"
OUTPUT_HITS="results/c4_reflected_findings_${TIMESTAMP}.txt"

echo "[*] Starting reflected XSS testing"
echo "[*] Target    : $TARGET"
echo "[*] Timestamp : $TIMESTAMP"
echo "[*] Payloads  : $PAYLOAD_FILE"

# ── TEST: REFLECTED XSS VIA GET PARAMETERS ───────────────────────────────────
# Injects each payload as a URL query parameter across common endpoints.
# If the raw payload string appears in the server response, it may indicate
# that user input is reflected without sanitization — a potential XSS vector.
# Note: React SPAs often return index.html for all routes (catch-all routing),
# which can produce false positives. All hits require manual browser verification.

ENDPOINTS=("" "/search" "/contact" "/login" "/register" "/profile")

for endpoint in "${ENDPOINTS[@]}"; do
    echo "[*] Testing endpoint: ${endpoint:-/}"

    while IFS= read -r payload; do
        if [ -n "$payload" ]; then
            encoded_payload=$(python3 -c "import urllib.parse; print(urllib.parse.quote('''$payload'''))")
            url="${TARGET}${endpoint}?test=${encoded_payload}"

            echo "Testing: $url"                          >> "$OUTPUT_ALL"
            curl -s -H "User-Agent: Mozilla/5.0" "$url"  >> "$OUTPUT_ALL"
            echo -e "\n--- END RESPONSE ---\n"            >> "$OUTPUT_ALL"

            response=$(curl -s "$url")
            if echo "$response" | grep -Fq "$payload"; then
                echo "POSSIBLE REFLECTION: $payload @ $endpoint" >> "$OUTPUT_HITS"
                echo "URL: $url"                                  >> "$OUTPUT_HITS"
                echo "---"                                        >> "$OUTPUT_HITS"
            fi
        fi
    done < "$PAYLOAD_FILE"
done

echo ""
echo "[*] Reflected XSS testing complete"
echo "    Full log  : $OUTPUT_ALL"
echo "    Findings  : $OUTPUT_HITS"

# ── MANUAL BROWSER VERIFICATION ──────────────────────────────────────────────
# After running this script, verify any flagged findings manually in a browser.
# Automated curl checks cannot execute JavaScript — browser verification is
# required to confirm whether a payload actually executes.
#
# Example manual test URLs (substitute your target):
#   <target>/?test=<script>alert(1)</script>
#   <target>/#<img src=x onerror=alert(1)>
#   <target>/search?q=<svg onload=alert(1)>
#
# Evidence to capture:
#   - Browser console output
#   - Screenshots of any alert() execution or DOM manipulation
#   - DevTools Network tab showing the reflected payload in responses
