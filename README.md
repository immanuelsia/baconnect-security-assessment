# baconnect-security-assessment
The Project:

**BAConnect** is Tour Booking Platform for a local tour company in Kuching, Sarawak - that our FYP team had taken up and built specifically for the operations department to help:
1. Make data processing/entry more streamlined and efficient by incorporating AI tools for document parsing.
2. Have a centralized platform for tour guides and department staff to liaise and share tour information.
3. Handle complex scheduling logic to prevent bottlenecks when assigning tours to tour guides.
   
- BAConnect requires personal customer data (i.e. Passport number) as part of their SOP and business workflow, hence why keeping this data secured and abstracted is of significant importance and priority in accordance with PDPA and GDPR regulations.

---

## Authorization & Scope

This assessment was conducted as an authorized academic engagement with explicit permission from the system owners (project team). All testing was non-destructive and read-only. Throttled requests were used throughout to prevent service degradation, and evidence was collected under data minimization principles with sensitive information redacted.

**Target:** BAConnect — React SPA hosted on DigitalOcean  
**Testing Environment:** Kali Linux (Virtual Machine)  
**Authorization:** Academic Final Year Project — authorized by project team  
**Scope:** Public-facing React SPA and associated surface area only. Internal authenticated endpoints and the API layer were out of scope.

---

## Methodology

Assessment followed OWASP guidelines adapted for single-page application architecture, covering 8 test domains. Both automated scanning and manual verification techniques were used to ensure accurate, reproducible results.

| Domain | Description |
|--------|-------------|
| C1 | Recon & Exposure — subdomain enumeration, admin panel discovery |
| C2 | Authentication & Session Management — URL manipulation, cookie inspection |
| C3 | Account Protection — brute-force resistance, rate limiting |
| C4 | Cross-Site Scripting — stored and reflected XSS payload testing |
| C5 | CSRF & Cookie Policy — token presence, header analysis |
| C6 | SSRF / Cloud Metadata — metadata endpoint probing, internal service exposure |
| C7 | Sensitive Data Exposure — frontend bundle analysis, credential scanning |
| C8 | Platform Hygiene — debug ports, exposed config files, dependency scanning |

---

## Tools Used

| Tool | Purpose |
|------|---------|
| Burp Suite | Traffic interception, session analysis, request inspection |
| subfinder / amass | Passive subdomain enumeration |
| ffuf | Directory and file fuzzing |
| Hydra | Brute-force login testing |
| Nmap | Port scanning |
| Python | Custom payload scripts — XSS, HTTP automation, bundle analysis |
| Bash | Tool-chain orchestration, cookie/CSRF analysis, platform hygiene checks |
| GCP Logs Explorer | Server-side log analysis, brute-force attempt monitoring |
| Browser DevTools | Cookie flag inspection, storage analysis |

---

## Findings Summary

| ID | Vulnerability | OWASP Mapping | Severity | Result |
|----|--------------|---------------|----------|--------|
| C1 | No hidden subdomains or admin panels discovered | A05: Security Misconfiguration | — | ✅ Pass |
| C2 | Session correctly invalidated on logout; URL manipulation blocked | A07: Identification & Auth Failures | — | ✅ Pass |
| C3 | Rate limiting and lockout functioning; attempts logged in GCP | A07: Identification & Auth Failures | — | ✅ Pass |
| C4 | No active XSS vulnerabilities; Content Security Policy absent | A03: Injection | Medium | ✅ Pass* |
| C5 | No CSRF token present; missing CSP and X-Frame-Options headers | A05: Security Misconfiguration | **High** | ❌ Fail |
| C6 | No SSRF parameters identified; cloud metadata endpoints unreachable | A10: SSRF | — | ✅ Pass |
| C7 | Firebase API key, project ID, storage bucket, and backend URL hardcoded in client-side JS bundle | A02: Cryptographic Failures | **High** | ❌ Fail |
| C8 | No active debug interfaces or exposed config files | A05: Security Misconfiguration | — | ✅ Pass |

*C4 passes on active exploitation — CSP absence noted as a defensive gap requiring remediation.

**6 of 8 domains passed. 2 high-severity findings require immediate remediation.**

---

## Disclaimer

All testing was conducted in a controlled academic environment with explicit authorization from the system owners. Scripts in this repository are provided for educational and portfolio purposes only. Do not use against any system without explicit written authorization.
