# Script Usage Guide

All scripts run against an authorized target in a Kali Linux environment.
Replace `<target_url>` with the application URL before running.

> **Dependency:** Python scripts require the `requests` library — `pip install requests`

---

## C3 — Account Protection

**Generate wordlists**
```bash
bash scripts/c3_generate_wordlists.sh
# Output: payloads/C3_users.txt, payloads/C3_passes.txt
```

**Brute-force resistance & rate limiting test**
```bash
bash scripts/c3_brute_force_test.sh <target_url>
# Output: results/c3_advanced_results.txt
```

**Hydra login brute-force (uses generated wordlists)**
```bash
hydra -L payloads/C3_users.txt -P payloads/C3_passes.txt \
      -t 4 -W 5 -o results/c3_hydra_output.txt \
      <target_url> http-post-form "/login:username=^USER^&password=^PASS^:F=invalid"
```

---

## C4 — Cross-Site Scripting (XSS)

**Reflected XSS — GET parameter injection across common endpoints**
```bash
bash scripts/c4_xss_reflected.sh <target_url>
# Output: results/c4_reflected_testing_<timestamp>.txt
#         results/c4_reflected_findings_<timestamp>.txt
```

**Advanced XSS — CSP inspection, form discovery, DOM-based vectors**
```bash
python3 scripts/c4_xss_advanced.py <target_url>
# Output: results/c4_csp_<timestamp>.txt
#         results/c4_forms_<timestamp>.txt
#         results/c4_dom_<timestamp>.txt
#         results/c4_page_source_<timestamp>.html
```

**Stored XSS — POST payload injection to common form endpoints**
```bash
python3 scripts/c4_xss_stored.py <target_url>
# Output: results/c4_stored_<timestamp>.txt
```

---

## C5 — CSRF & Cookie Policy

**Cookie flag inspection, CSRF token check, security header validation**
```bash
bash scripts/c5_csrf_cookie_check.sh <target_url>
# Output: results/c5_results_<timestamp>.txt
# Note  : Raw cookie values are printed to terminal only — not saved to file
```

---

## C7 — Sensitive Data Exposure

**JS bundle credential scan, API endpoint enumeration, config file exposure**
```bash
bash scripts/c7_bundle_scan.sh <target_url>
# Output: results/c7_results_<timestamp>.txt
```

---

## C8 — Platform Hygiene

**Debug port scan, admin endpoint probing, dev file exposure check**
```bash
bash scripts/c8_platform_hygiene.sh <target_url>
# Output: results/c8_results_<timestamp>.txt
```

---

## Output Structure

```
results/
├── c3_advanced_results.txt
├── c3_hydra_output.txt
├── c4_reflected_testing_<timestamp>.txt
├── c4_reflected_findings_<timestamp>.txt
├── c4_csp_<timestamp>.txt
├── c4_forms_<timestamp>.txt
├── c4_dom_<timestamp>.txt
├── c4_stored_<timestamp>.txt
├── c5_results_<timestamp>.txt
├── c7_results_<timestamp>.txt
└── c8_results_<timestamp>.txt
```

> All output files are excluded from the repository via `.gitignore`.
> Results containing application-specific data are not committed.

---

## Disclaimer

All scripts were written for an authorized academic assessment of BAConnect.
Do not use against any system without explicit written authorization.
