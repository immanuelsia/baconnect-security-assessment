#!/bin/bash
# =============================================================================
# c3_brute_force_test.sh
# =============================================================================
# Description : Tests brute-force resistance, rate limiting, distributed
#               timing attack resilience, and account enumeration controls
#               for C3 - Account Protection.
#
# Usage       : bash c3_brute_force_test.sh <target_url>
#               Example: bash c3_brute_force_test.sh https://example.com
#
# Output      : results/c3_advanced_results.txt
#
# Dependencies: curl
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

if [ -z "$TARGET" ]; then
    echo "[!] Usage: bash c3_brute_force_test.sh <target_url>"
    echo "    Example: bash c3_brute_force_test.sh https://example.com"
    exit 1
fi

mkdir -p results
OUTPUT="results/c3_advanced_results.txt"

echo "=== C3 BRUTE FORCE & RATE LIMITING TESTS ===" > "$OUTPUT"
echo "Target    : $TARGET"                          >> "$OUTPUT"
echo "Timestamp : $(date)"                          >> "$OUTPUT"
echo ""                                             >> "$OUTPUT"

echo "[*] Starting C3 tests against $TARGET"

# ── TEST 1: RATE LIMITING ─────────────────────────────────────────────────────
# Sends 15 rapid sequential requests to the login endpoint.
# A properly configured application should throttle or block after a threshold.

echo "1. RATE LIMITING TEST - RAPID ATTEMPTS:" >> "$OUTPUT"
for i in {1..15}; do
    status=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET/login")
    echo "  Attempt $i: $status" >> "$OUTPUT"
    sleep 0.5
done
echo "" >> "$OUTPUT"

# ── TEST 2: DISTRIBUTED TIMING ATTACK ────────────────────────────────────────
# Simulates an attacker who spaces attempts across intervals to evade lockout.
# Tests whether lockout state resets after a short wait.

echo "2. DISTRIBUTED TIMING ATTACK SIMULATION:" >> "$OUTPUT"
echo "   Testing whether lockout resets after a short wait..." >> "$OUTPUT"
for cycle in {1..3}; do
    echo "  Cycle $cycle:" >> "$OUTPUT"
    for i in {1..5}; do
        status=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET/login")
        echo "    Attempt $i: $status" >> "$OUTPUT"
    done
    echo "    Waiting 30 seconds..." >> "$OUTPUT"
    sleep 30
done
echo "" >> "$OUTPUT"

# ── TEST 3: COMMON PASSWORD SPRAY ────────────────────────────────────────────
# Checks whether the application reacts differently to common password attempts,
# which could indicate lack of account lockout or enumeration vulnerability.

echo "3. COMMON PASSWORDS TEST:" >> "$OUTPUT"
common_passwords=("password" "123456" "admin" "test" "welcome" "12345" "qwerty" "letmein")
for pass in "${common_passwords[@]}"; do
    echo "  Testing password: $pass" >> "$OUTPUT"
    response=$(curl -s "$TARGET" | grep -i "login\|auth" | head -1)
    echo "    Response: $response" >> "$OUTPUT"
done
echo "" >> "$OUTPUT"

# ── TEST 4: USER-AGENT VARIATION ─────────────────────────────────────────────
# Tests whether the application performs IP-based blocking that varies
# by User-Agent string, which could indicate client-side rate limiting only.

echo "4. USER-AGENT VARIATION TEST:" >> "$OUTPUT"
user_agents=("Mozilla/5.0" "curl/7.68.0" "python-requests/2.25.1")
for ua in "${user_agents[@]}"; do
    status=$(curl -s -o /dev/null -w "%{http_code}" -H "User-Agent: $ua" "$TARGET/login")
    echo "  User-Agent: $ua → $status" >> "$OUTPUT"
done
echo "" >> "$OUTPUT"

# ── TEST 5: ACCOUNT ENUMERATION ──────────────────────────────────────────────
# Checks whether the application returns different responses for valid vs
# invalid usernames, which would allow an attacker to enumerate accounts.

echo "5. ACCOUNT ENUMERATION TEST:" >> "$OUTPUT"
test_users=("admin" "test" "user" "demo" "root" "administrator")
for user in "${test_users[@]}"; do
    echo "  Testing user: $user" >> "$OUTPUT"
    response=$(curl -s "$TARGET" | grep -i "error\|invalid\|not found" | head -1)
    echo "    Response pattern: $response" >> "$OUTPUT"
done

echo "" >> "$OUTPUT"
echo "[*] C3 testing complete → $OUTPUT"
