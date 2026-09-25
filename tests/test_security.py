"""Checks the URL scanner. Run: python tests/test_security.py (needs internet for the last cases)."""
import asyncio
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))
os.environ["DATA_DIR"] = tempfile.mkdtemp()

import security  # noqa: E402

CASES = [
    # (input, expected status)
    ("javascript:alert(document.cookie)", "blocked"),
    ("data:text/html;base64,PHNjcmlwdD4=", "blocked"),
    ("file:///etc/passwd", "blocked"),
    ("https://paypal.com@evil.example/login", "blocked"),     # credentials trick
    ("http://127.0.0.1:8000/", "blocked"),
    ("http://169.254.169.254/latest/meta-data", "blocked"),   # cloud metadata
    ("http://192.168.1.1", "blocked"),
    ("https://[::1]/", "blocked"),
    ("http://printer.local", "blocked"),
    ("https://no-such-domain-zz9q7x.com", "blocked"),
    ("https://xn--pypal-4ve.com", "warn"),                    # look-alike paypal
    ("https://github.com/flet-dev/flet", "safe"),
    ("http://github.com", "safe"),                            # upgrades to https
]


async def main():
    security.add_to_blocklist("blocked-by-admin.example")
    CASES.append(("https://sub.blocked-by-admin.example/x", "blocked"))
    failed = 0
    for url, expected in CASES:
        r = await security.scan_url(url)
        ok = r.status == expected
        failed += not ok
        print(f"{'ok ' if ok else 'FAIL'} {expected:7} {url[:45]:47} {r.reasons[:1]}")
    assert not failed, f"{failed} case(s) failed"
    print("ALL SECURITY CASES PASSED")


if __name__ == "__main__":
    asyncio.run(main())
