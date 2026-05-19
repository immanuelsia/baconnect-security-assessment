# Test Plan — BAConnect Security Assessment

## Engagement Overview

| Field | Detail |
|-------|--------|
| **Target** | BAConnect — React SPA hosted on DigitalOcean |
| **Assessment Type** | Web Application Penetration Test (Black-Box, Non-Destructive) |
| **Testing Environment** | Kali Linux Virtual Machine |
| **Authorization** | Academic Final Year Project — explicit written authorization from project team |
| **Tester** | Immanuel John Sia |

---

## Rules of Engagement (RoE)

- All testing was **read-only and non-destructive** — no data was modified, deleted, or exfiltrated
- Requests were **throttled** throughout to prevent service degradation
- An **immediate cessation protocol** was established for any unintended system effects
- Evidence collection followed **data minimization principles** — sensitive values redacted in all outputs
- Emergency contacts from the operations and database teams were on standby during the testing window
- Scope was limited to the **public-facing application surface only**

---

## Scope

**In Scope:**
- Public-facing React SPA and all unauthenticated surface area
- Authentication and session management flows
- Client-side JavaScript bundles and static assets
- Public HTTP headers and cookie configurations

**Out of Scope:**
- Internal endpoints behind authentication
- API endpoints covered under separate RBAC validation
- Third-party services (Firebase backend rules, DigitalOcean infrastructure)
- Social engineering or physical security

---

## Test Domains

| ID | Domain | Objective |
|----|--------|-----------|
| C1 | Recon & Exposure | Identify publicly exposed subdomains, admin panels, backup files, and unintended surface area |
| C2 | Authentication & Session Management | Validate login/logout flows, session cookie security flags, and URL manipulation resistance |
| C3 | Account Protection | Test brute-force resistance, rate limiting enforcement, and account lockout behaviour |
| C4 | Cross-Site Scripting (XSS) | Probe stored and reflected XSS vectors across all user-controlled input fields |
| C5 | CSRF & Cookie Policy | Inspect CSRF token presence, cookie flag configuration, and security header implementation |
| C6 | SSRF / Cloud Metadata | Probe for server-side request forgery vectors and cloud metadata endpoint exposure |
| C7 | Sensitive Data Exposure | Scan frontend JavaScript bundles and common endpoints for hardcoded credentials and secrets |
| C8 | Platform Hygiene | Check for exposed debug ports, development endpoints, and leftover configuration files |

---

## Methodology

The assessment followed OWASP Web Security Testing Guide (WSTG) principles adapted for single-page application architecture. Each test domain combined:

- **Passive reconnaissance** — non-intrusive enumeration before active testing
- **Automated scanning** — tool-assisted discovery to ensure coverage
- **Manual verification** — hands-on confirmation of all findings to eliminate false positives
- **Evidence collection** — all findings documented with request/response captures and output logs

Results for each domain were recorded as **Pass**, **Fail**, or **Pass with Notes**, with OWASP severity classifications applied to all failures.
