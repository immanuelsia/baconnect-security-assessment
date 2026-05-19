#!/bin/bash
# =============================================================================
# c7_bundle_scan.sh
# =============================================================================
# Description : Tests for sensitive data exposure in client-side JavaScript
#               bundles and common configuration endpoints. Scans for
#               hardcoded Firebase/GCP credentials, exposed API endpoints,
#               and accessible configuration files.
#
# Usage       : bash c7_bundle_scan.sh <target_url>
#               Example: bash c7_bundle_scan.sh https://example.com
#
# Dependencies: curl, grep
# Output      : results/c7_results_<timestamp>.txt
#
# Note        : Bundle filenames are discovered dynamically from the page
#               source rather than hardcoded, making this script reusable
#               across different builds and deployments.
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
    echo "[!] Usage: bash c7_bundle_scan.sh <target_url>"
    echo "    Example: bash c7_bundle_scan.sh https://example.com"
    exit 1
fi

mkdir -p results
OUTPUT="results/c7_results_${TIMESTAMP}.txt"

echo "=== C7 SENSITIVE DATA EXPOSURE TESTS ==="  > "$OUTPUT"
echo "Target       : $TARGET"                    >> "$OUTPUT"
echo "Architecture : React SPA + Express + GCP"  >> "$OUTPUT"
echo "Timestamp    : $(date)"                    >> "$OUTPUT"
echo ""                                          >> "$OUTPUT"

echo "[*] Starting C7 sensitive data exposure tests"
echo "[*] Target : $TARGET"
echo ""

# ── TEST 1: JS BUNDLE DISCOVERY & CREDENTIAL SCAN ────────────────────────────
# React build tools produce hashed bundle filenames (e.g. main.abc123.js).
# Fetches the page source to extract bundle filenames dynamically, then
# scans each bundle for hardcoded Firebase/GCP credential strings.
# Exposed credentials in client-side bundles are a HIGH severity finding —
# any visitor can extract them without authentication.

echo "1. JS BUNDLE CREDENTIAL SCAN:" >> "$OUTPUT"
echo "[*] Discovering JS bundle filenames from page source..."

PAGE_SOURCE=$(curl -s "$TARGET")

# Extract JS bundle paths from HTML source
BUNDLES=$(echo "$PAGE_SOURCE" | grep -oE 'src="(/static/js/[^"]+\.js)"' | grep -oE '/static/js/[^"]+\.js')

if [ -z "$BUNDLES" ]; then
    echo "  No /static/js/ bundles found in page source" >> "$OUTPUT"
    echo "[!] No bundles discovered — application may use a different asset path"
else
    while IFS= read -r bundle; do
        bundle_url="${TARGET}${bundle}"
        echo "  Scanning: $bundle_url" | tee -a "$OUTPUT"

        # Scan bundle for Firebase/GCP credential indicators
        HITS=$(curl -s "$bundle_url" | \
            grep -oE '"(apiKey|authDomain|projectId|storageBucket|messagingSenderId|appId|databaseURL)"[[:space:]]*:[[:space:]]*"[^"]+"' | \
            head -10)

        if [ -n "$HITS" ]; then
            echo "  [FLAG] Firebase/GCP credentials found in bundle:" >> "$OUTPUT"
            echo "$HITS" >> "$OUTPUT"
        else
            echo "  No credential strings found in $bundle" >> "$OUTPUT"
        fi
    done <<< "$BUNDLES"
fi
echo "" >> "$OUTPUT"

# ── TEST 2: API ENDPOINT ENUMERATION ─────────────────────────────────────────
# Probes common API paths. HTTP 200 responses warrant manual inspection
# to determine whether data is returned or the React catch-all is firing.

echo "2. API ENDPOINT ENUMERATION:" >> "$OUTPUT"
echo "[*] Probing API endpoints..."
for endpoint in "/api/" "/_next/" "/api/auth" "/api/users" "/api/firestore" "/api/config"; do
    status=$(curl -s -o /dev/null -w "%{http_code}" "${TARGET}${endpoint}")
    echo "  ${endpoint} : ${status}" | tee -a "$OUTPUT"
done
echo "" >> "$OUTPUT"

# ── TEST 3: CONFIGURATION FILE EXPOSURE ──────────────────────────────────────
# Checks whether common development config files are publicly accessible.
# These files can contain secrets, dependencies, and deployment details.

echo "3. CONFIGURATION FILE EXPOSURE:" >> "$OUTPUT"
echo "[*] Probing config file paths..."
for file in "/.env" "/.env.local" "/.env.production" "/config.js" "/firebase.json" "/next.config.js" "/package.json"; do
    status=$(curl -s -o /dev/null -w "%{http_code}" "${TARGET}${file}")
    echo "  ${file} : ${status}" | tee -a "$OUTPUT"
done
echo "" >> "$OUTPUT"

# ── TEST 4: GCP METADATA IN PAGE SOURCE ──────────────────────────────────────
# Scans the main page HTML for GCP/Firebase references that could
# contribute to reconnaissance exposure even without full credential leaks.

echo "4. GCP/FIREBASE REFERENCES IN PAGE SOURCE:" >> "$OUTPUT"
GCP_HITS=$(echo "$PAGE_SOURCE" | grep -E "(googleapis\.com|firebaseio\.com|firebaseapp\.com|google\.cloud)" | head -5)
if [ -n "$GCP_HITS" ]; then
    echo "$GCP_HITS" >> "$OUTPUT"
else
    echo "  No GCP/Firebase references found in page source" >> "$OUTPUT"
fi
echo "" >> "$OUTPUT"

# ── QUICK ANALYSIS ───────────────────────────────────────────────────────────

echo "=== QUICK ANALYSIS ===" | tee -a "$OUTPUT"

# Firebase check — look specifically in the bundle scan section
echo "Firebase Credential Exposure:" | tee -a "$OUTPUT"
if grep -q "\[FLAG\]" "$OUTPUT"; then
    echo "  ❌ Credentials found in client-side bundle — HIGH RISK" | tee -a "$OUTPUT"
else
    echo "  ✅ No hardcoded credentials detected" | tee -a "$OUTPUT"
fi

echo "Config File Exposure:" | tee -a "$OUTPUT"
# Only flag 200 responses on actual config file paths
if awk '/CONFIGURATION FILE/,/^$/' "$OUTPUT" | grep -q ": 200"; then
    echo "  ❌ Config file(s) returning HTTP 200 — review manually" | tee -a "$OUTPUT"
else
    echo "  ✅ No config files publicly accessible" | tee -a "$OUTPUT"
fi

echo ""
echo "[*] C7 testing complete → $OUTPUT"
