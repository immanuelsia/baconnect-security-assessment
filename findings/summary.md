# Findings Summary — BAConnect Security Assessment

> All findings are sanitized. No application-specific URLs, credentials, or user data are included.

---

## Results Overview

| ID | Domain | Severity | Result |
|----|--------|----------|--------|
| C1 | Recon & Exposure | — | ✅ Pass |
| C2 | Authentication & Session Management | — | ✅ Pass |
| C3 | Account Protection | — | ✅ Pass |
| C4 | Cross-Site Scripting (XSS) | Medium | ✅ Pass* |
| C5 | CSRF & Cookie Policy | **High** | ❌ Fail |
| C6 | SSRF / Cloud Metadata | — | ✅ Pass |
| C7 | Sensitive Data Exposure | **High** | ❌ Fail |
| C8 | Platform Hygiene | — | ✅ Pass |

**6 of 8 domains passed. 2 high-severity findings require immediate remediation.**

---

## Detailed Findings

---

### C1 — Recon & Exposure ✅ Pass

**Finding:** Passive subdomain enumeration (subfinder/amass) returned no additional public subdomains. No admin panels, sitemap.xml, or backup files were discovered. Public surface area is limited to the main SPA entry point.

**Notes:** Passive enumeration is not exhaustive. DNS brute-force and Wayback Machine searches are recommended before concluding absence of hidden hosts.

---

### C2 — Authentication & Session Management ✅ Pass

**Finding:** Session cookies are correctly invalidated on logout — local and session storage confirmed empty. URL manipulation to access restricted routes (e.g. `/dashboard`) after logout returns HTTP 304 and redirects to the login page. `HttpOnly` flag confirmed on session cookie, preventing JavaScript-based cookie theft.

---

### C3 — Account Protection ✅ Pass

**Finding:** Rate limiting and account lockout triggered after approximately 10 failed login attempts during manual testing. Brute-force attempts were captured as warning logs in GCP Logs Explorer, confirming server-side detection is functioning.

---

### C4 — Cross-Site Scripting (XSS) ✅ Pass*

**Finding:** No active stored or reflected XSS vulnerabilities identified across tested input fields. Python and Bash payload scripts returned no successful injections.

**Caveat:** Content Security Policy (CSP) header is absent, removing a critical defensive layer. DOM-based XSS in React front-end logic was not fully verified and warrants further manual code review.

**OWASP Mapping:** A03:2021 — Injection
**Severity:** Medium (defensive gap, no active exploit)

**Recommendation:** Implement a strict Content Security Policy header. Conduct a manual review of React component logic for DOM-based XSS vectors.

---

### C5 — CSRF & Cookie Policy ❌ Fail

**Finding:** No CSRF token present in application responses. `Content-Security-Policy` and `X-Frame-Options` headers are absent. The application permits credentialed cross-origin requests (`Access-Control-Allow-Credentials: true`). State-changing endpoints are exposed to CSRF attacks.

**OWASP Mapping:** A05:2021 — Security Misconfiguration
**Severity:** High

**Recommendation:**
- Implement server-side CSRF tokens on all state-changing endpoints
- Add `Content-Security-Policy` header with a strict policy
- Add `X-Frame-Options: DENY` or `SAMEORIGIN` to prevent clickjacking
- Review `SameSite` cookie attribute — set to `Strict` or `Lax` where appropriate

---

### C6 — SSRF / Cloud Metadata ✅ Pass

**Finding:** No SSRF-injectable parameters identified in the public interface. Cloud metadata endpoints (169.254.169.254, metadata.google.internal) returned no data from the tester environment. No internal services reachable from the public application surface.

**Notes:** Port 8080 responded during testing — confirmed as the local Burp Suite proxy, not application exposure.

---

### C7 — Sensitive Data Exposure ❌ Fail

**Finding:** Firebase API key, project ID, storage bucket name, messaging sender ID, and backend API URL are hardcoded and exposed in the production client-side JavaScript bundle. These values are publicly accessible to any visitor without authentication.

**OWASP Mapping:** A02:2021 — Cryptographic Failures
**Severity:** High

**Impact:** Exposed Firebase credentials increase risk of unauthorized data access if Firestore or Cloud Storage security rules are permissive. The exposed backend URL contributes to reconnaissance exposure.

**Recommendation:**
- Migrate all Firebase configuration values to server-side environment variables
- Audit and enforce strict Firestore and Cloud Storage security rules
- Rotate any exposed API keys immediately
- Implement secret scanning in CI/CD pipeline to prevent future credential exposure

---

### C8 — Platform Hygiene ✅ Pass

**Finding:** No active debug interfaces, exposed development endpoints, or leaked configuration files identified. All probed debug routes returned the React SPA `index.html` — confirmed as false positives from the static catch-all routing behaviour. No sensitive dependency data exposed via `/package.json`.

**Notes:** Port 8080 open — confirmed as local Burp Suite proxy throughout testing, not a production exposure.
