#!/bin/bash
# =============================================================================
# c8_platform_hygiene.sh
# =============================================================================
# Description : Checks for platform hygiene issues including exposed debug
#               ports, accessible debug/admin endpoints, leftover development
#               files, and dependency information leakage.
#
# Usage       : bash c8_platform_hygiene.sh <target_url>
#               Example: bash c8_platform_hygiene.sh https://example.com
#
# Dependencies: curl
# Output      : results/c8_results_<timestamp>.txt
#
# Note        : React SPAs use catch-all routing — HTTP 200 on debug/dev
#               endpoints does not confirm real exposure. All 200 responses
#               require content inspection to rule out false positives.
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
    echo "[!] Usage: bash c8_platform_hygiene.sh <target_url>"
    echo "    Example: bash c8_platform_hygiene.sh https://example.com"
    exit 1
fi

# Strip protocol for port scanning (curl needs explicit port in URL)
HOST=$(echo "$TARGET" | sed 's|https://||;s|http://||;s|/.*||')

mkdir -p results
OUTPUT="results/c8_results_${TIMESTAMP}.txt"

echo "=== C8 PLATFORM HYGIENE TESTS ==="  > "$OUTPUT"
echo "Target    : $TARGET"                >> "$OUTPUT"
echo "Host      : $HOST"                  >> "$OUTPUT"
echo "Timestamp : $(date)"               >> "$OUTPUT"
echo ""                                  >> "$OUTPUT"

echo "[*] Starting C8 platform hygiene tests"
echo "[*] Target : $TARGET"
echo ""

# ── TEST 1: DEBUG PORT SCAN ───────────────────────────────────────────────────
# Probes common development and debug ports.
# Open ports on a production host may expose admin panels, Node.js
# debug interfaces (9229), or internal services that should not be public.

echo "1. DEBUG PORT SCAN:" >> "$OUTPUT"
echo "[*] Scanning debug ports..."
for port in 3000 5000 8000 8080 9229 5858 3001 5001 8001 8081; do
    result=$(curl -s --max-time 2 -o /dev/null -w "%{http_code}" "http://${HOST}:${port}" 2>/dev/null)
    if [ "$result" != "000" ]; then
        echo "  Port $port : OPEN (HTTP $result)" | tee -a "$OUTPUT"
    else
        echo "  Port $port : closed"              >> "$OUTPUT"
    fi
done
echo "" >> "$OUTPUT"

# ── TEST 2: DEBUG & ADMIN ENDPOINTS ──────────────────────────────────────────
# Probes common debug and admin route patterns.
# Note: React SPA catch-all routing returns 200 for all unknown routes —
# content inspection is required to confirm real endpoint exposure.

echo "2. DEBUG & ADMIN ENDPOINTS:" >> "$OUTPUT"
echo "[*] Probing debug endpoints..."
for endpoint in "/debug" "/_debug" "/console" "/api/debug" "/_/debug" "/dev" "/development" "/test" "/admin" "/status" "/health"; do
    status=$(curl -s -o /dev/null -w "%{http_code}" "${TARGET}${endpoint}")
    # Flag 200 responses for manual content review
    if [ "$status" = "200" ]; then
        echo "  ${endpoint} : ${status} ← verify content (may be SPA catch-all)" | tee -a "$OUTPUT"
    else
        echo "  ${endpoint} : ${status}" >> "$OUTPUT"
    fi
done
echo "" >> "$OUTPUT"

# ── TEST 3: DEVELOPMENT FILE EXPOSURE ────────────────────────────────────────
# Checks whether lockfiles, build configs, and ignore files are publicly
# accessible. These files can expose dependency versions, internal paths,
# and project structure to an attacker.

echo "3. DEVELOPMENT FILE EXPOSURE:" >> "$OUTPUT"
echo "[*] Probing development file paths..."
for file in "/package-lock.json" "/yarn.lock" "/composer.lock" "/Gemfile.lock" "/pom.xml" "/build.gradle" "/.gitignore" "/.dockerignore" "/.env" "/.env.production"; do
    status=$(curl -s -o /dev/null -w "%{http_code}" "${TARGET}${file}")
    if [ "$status" = "200" ]; then
        echo "  ${file} : ${status} ← verify content (may be SPA catch-all)" | tee -a "$OUTPUT"
    else
        echo "  ${file} : ${status}" >> "$OUTPUT"
    fi
done
echo "" >> "$OUTPUT"

# ── TEST 4: DEPENDENCY INFO ───────────────────────────────────────────────────
# Attempts to retrieve package.json to check for exposed dependency data.
# If the response is JSON (not HTML), dependency versions are publicly
# exposed — this aids attacker reconnaissance for known CVEs.

echo "4. DEPENDENCY INFO (/package.json):" >> "$OUTPUT"
echo "[*] Checking /package.json exposure..."
CONTENT=$(curl -s "${TARGET}/package.json" | head -5)
if echo "$CONTENT" | grep -q "{"; then
    echo "  [FLAG] JSON content returned — dependency data may be exposed:" >> "$OUTPUT"
    echo "$CONTENT" >> "$OUTPUT"
else
    echo "  No JSON data returned — likely SPA catch-all (HTML response)" >> "$OUTPUT"
fi
echo "" >> "$OUTPUT"

# ── QUICK ANALYSIS ───────────────────────────────────────────────────────────

echo "=== QUICK ANALYSIS ===" | tee -a "$OUTPUT"

echo "Open Ports:" | tee -a "$OUTPUT"
if grep -q "OPEN" "$OUTPUT"; then
    grep "OPEN" "$OUTPUT" | sed 's/^/  /' | tee -a "$OUTPUT"
else
    echo "  ✅ No debug ports open" | tee -a "$OUTPUT"
fi

echo "Debug Endpoints:" | tee -a "$OUTPUT"
if awk '/DEBUG & ADMIN/,/^$/' "$OUTPUT" | grep -q "← verify"; then
    echo "  ⚠️  HTTP 200 responses found — manual content inspection required" | tee -a "$OUTPUT"
else
    echo "  ✅ No accessible debug endpoints detected" | tee -a "$OUTPUT"
fi

echo "Development Files:" | tee -a "$OUTPUT"
if awk '/DEVELOPMENT FILE/,/^$/' "$OUTPUT" | grep -q "← verify"; then
    echo "  ⚠️  HTTP 200 responses found — manual content inspection required" | tee -a "$OUTPUT"
else
    echo "  ✅ No development files accessible" | tee -a "$OUTPUT"
fi

echo ""
echo "[*] C8 testing complete → $OUTPUT"
