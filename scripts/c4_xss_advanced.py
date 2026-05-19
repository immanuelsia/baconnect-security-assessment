#!/usr/bin/env python3
# =============================================================================
# c4_xss_advanced.py
# =============================================================================
# Description : Advanced XSS testing covering CSP header inspection,
#               form discovery, DOM-based XSS vector probing, and
#               page source capture for manual analysis.
#
# Usage       : python3 c4_xss_advanced.py <target_url>
#               Example: python3 c4_xss_advanced.py https://example.com
#
# Dependencies: requests  (pip install requests)
# Output      : results/c4_csp_<timestamp>.txt
#               results/c4_forms_<timestamp>.txt
#               results/c4_dom_<timestamp>.txt
#               results/c4_page_source_<timestamp>.html
#
# Context     : Written for an authorized academic security assessment of
#               BAConnect. Use only against systems you have explicit
#               written permission to test.
#
# Author      : Immanuel John Sia
# Assessment  : BAConnect - Web Application Security Assessment (FYP 2025-2026)
# =============================================================================

import requests
import sys
import os
from datetime import datetime


def setup_dirs():
    """Create output directory if it doesn't exist."""
    os.makedirs("results", exist_ok=True)


class XSSTester:
    def __init__(self, target):
        self.target = target.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Security-Test",
            "Accept":     "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        })
        self.ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    def test_csp_headers(self):
        """
        Inspect HTTP response headers for Content Security Policy (CSP).
        CSP absence is a significant defensive gap — it allows injected scripts
        to execute if an XSS vector is found elsewhere.
        """
        print("[*] Checking Content Security Policy headers...")
        try:
            response = self.session.get(self.target, timeout=10)
            csp = response.headers.get("Content-Security-Policy", "NOT SET")
            xfo = response.headers.get("X-Frame-Options",         "NOT SET")
            sts = response.headers.get("Strict-Transport-Security","NOT SET")

            output_path = f"results/c4_csp_{self.ts}.txt"
            with open(output_path, "w") as f:
                f.write(f"Target    : {self.target}\n")
                f.write(f"Timestamp : {self.ts}\n\n")
                f.write(f"Content-Security-Policy    : {csp}\n")
                f.write(f"X-Frame-Options            : {xfo}\n")
                f.write(f"Strict-Transport-Security  : {sts}\n\n")
                f.write("All Response Headers:\n")
                for header, value in response.headers.items():
                    f.write(f"  {header}: {value}\n")

            print(f"    CSP             : {csp}")
            print(f"    X-Frame-Options : {xfo}")
            print(f"    Output          : {output_path}")
            return csp
        except Exception as e:
            print(f"[!] Error checking CSP headers: {e}")
            return None

    def test_form_discovery(self):
        """
        Check main page for HTML forms that could be entry points for
        stored XSS. Saves full page source for manual review.
        React SPAs often have no traditional forms — any forms found
        warrant further manual investigation.
        """
        print("[*] Discovering HTML forms...")
        try:
            response = self.session.get(self.target, timeout=10)
            forms_found = []

            if "<form" in response.text.lower():
                forms_found.append("Form element found on main page")

            forms_path  = f"results/c4_forms_{self.ts}.txt"
            source_path = f"results/c4_page_source_{self.ts}.html"

            with open(forms_path, "w") as f:
                f.write(f"Form Discovery — {self.target}\n")
                f.write(f"Timestamp: {self.ts}\n\n")
                if forms_found:
                    for form in forms_found:
                        f.write(f"[FOUND] {form}\n")
                else:
                    f.write("No HTML forms detected on main page.\n")
                f.write("\nSee page source for manual analysis.\n")

            with open(source_path, "w", encoding="utf-8") as f:
                f.write(response.text)

            status = "FOUND" if forms_found else "none detected"
            print(f"    Forms           : {status}")
            print(f"    Output          : {forms_path}")
            print(f"    Page source     : {source_path}")
            return forms_found
        except Exception as e:
            print(f"[!] Error during form discovery: {e}")
            return []

    def test_dom_based_vectors(self):
        """
        Probe common DOM-based XSS vectors by appending payloads to the URL
        via fragment (#) and query parameters. DOM-based XSS is processed
        client-side by JavaScript and may not appear in server responses —
        results here require manual browser verification to confirm execution.
        """
        print("[*] Probing DOM-based XSS vectors...")

        dom_payloads = [
            "#<script>alert('DOM1')</script>",
            "#<img src=x onerror=alert('DOM2')>",
            "#javascript:alert('DOM3')",
            "?test#<script>alert('DOM4')</script>",
        ]

        output_path = f"results/c4_dom_{self.ts}.txt"
        with open(output_path, "w") as f:
            f.write(f"DOM-Based XSS Probe — {self.target}\n")
            f.write(f"Timestamp: {self.ts}\n")
            f.write("=" * 60 + "\n")
            f.write("NOTE: DOM-based XSS is processed client-side.\n")
            f.write("curl responses below do NOT confirm execution.\n")
            f.write("Manually verify all flagged URLs in a browser.\n")
            f.write("=" * 60 + "\n\n")

            for payload in dom_payloads:
                test_url = f"{self.target}{payload}"
                f.write(f"Testing : {test_url}\n")
                try:
                    response = self.session.get(test_url, timeout=10)
                    f.write(f"Status  : {response.status_code}\n")
                    if payload in response.text:
                        f.write("FLAG    : Payload reflected in server response\n")
                    else:
                        f.write("Result  : Payload not reflected in server response\n")
                except Exception as e:
                    f.write(f"Error   : {e}\n")
                f.write("-" * 40 + "\n")

        print(f"    Output          : {output_path}")


def main():
    if len(sys.argv) < 2:
        print("[!] Usage: python3 c4_xss_advanced.py <target_url>")
        print("    Example: python3 c4_xss_advanced.py https://example.com")
        sys.exit(1)

    target = sys.argv[1]
    setup_dirs()

    print(f"[*] Advanced XSS testing against {target}")
    print()

    tester = XSSTester(target)
    tester.test_csp_headers()
    print()
    tester.test_form_discovery()
    print()
    tester.test_dom_based_vectors()
    print()
    print(f"[*] Testing complete — results saved to results/")


if __name__ == "__main__":
    main()
