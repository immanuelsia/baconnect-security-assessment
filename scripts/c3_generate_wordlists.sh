#!/bin/bash
# =============================================================================
# c3_generate_wordlists.sh
# =============================================================================
# Description : Generates username and password wordlists for use in
#               brute-force resistance testing (C3 - Account Protection).
#               Outputs C3_users.txt and C3_passes.txt for use with Hydra
#               or similar tools.
#
# Usage       : bash c3_generate_wordlists.sh
# Output      : payloads/C3_users.txt
#               payloads/C3_passes.txt
#
# Context     : Written for an authorized academic security assessment of
#               BAConnect. Use only against systems you have explicit
#               written permission to test.
#
# Author      : Immanuel John Sia
# Assessment  : BAConnect - Web Application Security Assessment (FYP 2025-2026)
# =============================================================================

OUTPUT_DIR="payloads"
mkdir -p "$OUTPUT_DIR"

echo "[+] Generating wordlists for brute-force resistance testing..."

# ── USERNAMES ─────────────────────────────────────────────────────────────────

echo "[+] Generating username list..."

cat > "$OUTPUT_DIR/C3_users.txt" << 'EOF'
admin
administrator
root
user
test
guest
demo
user1
user2
admin1
admin2
testuser
guestuser
demouser
testuser@example.com
admin@example.com
administrator@example.com
user@example.com
test@example.com
guest@example.com
demo@example.com
webmaster@example.com
info@example.com
support@example.com
help@example.com
contact@example.com
sales@example.com
service@example.com
john.doe@example.com
jane.smith@example.com
bob.johnson@example.com
alice.williams@example.com
mike.brown@example.com
admin@company.com
user@company.com
test@company.com
administrator@company.com
webmaster@company.com
info@company.com
support@company.com
IT@company.com
dev@company.com
developer@company.com
sysadmin@company.com
security@company.com
EOF

# ── PASSWORDS ─────────────────────────────────────────────────────────────────

echo "[+] Generating password list..."

cat > "$OUTPUT_DIR/C3_passes.txt" << 'EOF'
password
Password
password123
Password123
password1
Password1
admin
Admin
admin123
Admin123
administrator
Administrator
123456
12345678
123456789
1234567890
qwerty
abc123
letmein
monkey
welcome
Welcome
login
Login
pass
Pass
pass123
Pass123
secret
Secret
test
Test
test123
Test123
guest
Guest
guest123
Guest123
123
1234
12345
000000
111111
999999
00000000
11111111
99999999
Spring2024
Summer2024
Fall2024
Winter2024
Spring2025
Summer2025
Fall2025
Winter2025
Company123
company123
Company2024
company2024
Password!
password!
Admin123!
admin123!
Welcome123!
Test123!
Pass123!
EOF

# ── SUMMARY ───────────────────────────────────────────────────────────────────

echo ""
echo "[+] Wordlist generation complete"
echo "    Usernames : $(wc -l < "$OUTPUT_DIR/C3_users.txt") entries → $OUTPUT_DIR/C3_users.txt"
echo "    Passwords : $(wc -l < "$OUTPUT_DIR/C3_passes.txt") entries → $OUTPUT_DIR/C3_passes.txt"
echo ""
echo "[+] Example Hydra usage:"
echo "    hydra -L $OUTPUT_DIR/C3_users.txt -P $OUTPUT_DIR/C3_passes.txt \\"
echo "          -t 4 -W 5 -o results/c3_hydra_output.txt \\"
echo "          <TARGET> http-post-form \"/login:username=^USER^&password=^PASS^:F=invalid\""
