"""
URL safety checks.

Every link goes through `scan_url()` before it is stored or shared:

  1. Structural checks   - scheme, embedded credentials, private/internal hosts,
                           raw IPs, look-alike (punycode) domains, odd ports,
                           abused TLDs, direct executable downloads.
  2. Local blocklist     - /data/blocklist.txt (one domain per line, subdomains match).
  3. DNS                 - the domain must resolve, and only to public IP addresses.
  4. Safe fetch          - follows redirects manually (max 5 hops), re-checking every
                           hop, so a shortener can't hide a bad destination. Reads at
                           most 256 KB to get the page title and embedding headers.
  5. Reputation          - Google Safe Browsing, if an API key is configured.

Result status:
  safe    -> no problems found
  warn    -> saved, but shown with a warning and an extra confirmation before opening
  blocked -> refused
"""
from __future__ import annotations

import asyncio
import html
import ipaddress
import logging
import os
import re
import socket
import ssl
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx

from config import BLOCKLIST_FILE, FETCH_PAGE_METADATA, GSB_API_KEY

log = logging.getLogger("linkvault.security")

MAX_URL_LENGTH = 2048
MAX_REDIRECTS = 5
MAX_BYTES = 256 * 1024
FETCH_TIMEOUT = httpx.Timeout(6.0, connect=4.0)
USER_AGENT = "Mozilla/5.0 (compatible; LinkVaultBot/1.0; +link-safety-check)"

SAFE, WARN, BLOCKED = "safe", "warn", "blocked"

BLOCKED_HOST_SUFFIXES = (".localhost", ".local", ".internal", ".lan", ".home.arpa", ".intranet", ".corp")
ABUSED_TLDS = {"zip", "mov", "tk", "ml", "ga", "cf", "gq", "top", "click", "country", "kim", "loan", "work", "rest", "support"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rebrand.ly", "shorturl.at", "rb.gy", "tiny.cc"}
RISKY_EXTENSIONS = (".exe", ".scr", ".msi", ".bat", ".cmd", ".ps1", ".vbs", ".jar", ".apk", ".dmg", ".pkg", ".iso", ".hta", ".lnk", ".com")
DOWNLOAD_TYPES = ("application/octet-stream", "application/x-msdownload", "application/x-msdos-program",
                  "application/vnd.android.package-archive", "application/x-apple-diskimage", "application/java-archive")


_ORDER = {SAFE: 0, WARN: 1, BLOCKED: 2}


@dataclass
class ScanResult:
    url: str = ""
    final_url: str = ""
    domain: str = ""
    title: str = ""
    embeddable: bool = False
    findings: list[tuple[str, str]] = field(default_factory=list)  # (level, reason)

    @property
    def status(self) -> str:
        return max((lvl for lvl, _ in self.findings), key=_ORDER.get, default=SAFE)

    @property
    def reasons(self) -> list[str]:
        # most serious first
        return [r for _, r in sorted(self.findings, key=lambda f: -_ORDER[f[0]])]

    @property
    def blocked(self) -> bool:
        return self.status == BLOCKED

    def add(self, level: str, reason: str) -> None:
        if (level, reason) not in self.findings:
            self.findings.append((level, reason))

    def drop(self, prefix: str) -> None:
        self.findings = [f for f in self.findings if not f[1].startswith(prefix)]


# --------------------------------------------------------------------------- blocklist
_blocklist: set[str] = set()
_blocklist_mtime: float = -1.0


def _load_blocklist() -> set[str]:
    global _blocklist, _blocklist_mtime
    try:
        mtime = BLOCKLIST_FILE.stat().st_mtime
    except FileNotFoundError:
        _blocklist, _blocklist_mtime = set(), -1.0
        return _blocklist
    if mtime != _blocklist_mtime:
        entries = set()
        for line in BLOCKLIST_FILE.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.split("#", 1)[0].strip().lower()
            if line:
                entries.add(line.lstrip("*.").rstrip("."))
        _blocklist, _blocklist_mtime = entries, mtime
    return _blocklist


def add_to_blocklist(domain: str) -> None:
    domain = domain.strip().lower()
    if not domain or domain in _load_blocklist():
        return
    BLOCKLIST_FILE.parent.mkdir(parents=True, exist_ok=True)
    with BLOCKLIST_FILE.open("a", encoding="utf-8") as f:
        f.write(domain + "\n")


def is_blocklisted(host: str) -> bool:
    bl = _load_blocklist()
    labels = host.lower().split(".")
    return any(".".join(labels[i:]) in bl for i in range(len(labels)))


# --------------------------------------------------------------------------- helpers
def _using_proxy() -> bool:
    return any(os.environ.get(k) for k in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY"))


def _ip_or_none(host: str):
    try:
        return ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return None


def _is_public_ip(ip) -> bool:
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast


def display_domain(host: str) -> str:
    """Human-readable form of an IDNA host (xn--...)."""
    try:
        return host.encode("ascii").decode("idna")
    except Exception:
        return host


def normalize(raw: str) -> str:
    """Trim, add https:// if missing, lower-case scheme/host, IDNA-encode host."""
    raw = (raw or "").strip()
    if not raw:
        raise ValueError("Please enter a link.")
    if len(raw) > MAX_URL_LENGTH:
        raise ValueError("That link is too long.")
    if any(ord(c) < 32 or c.isspace() for c in raw):
        raise ValueError("Links can't contain spaces or control characters.")
    if "://" not in raw.split("?", 1)[0]:
        if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", raw) and not re.match(r"^[^:/]+:\d+", raw):
            # e.g. javascript:..., data:..., file:...
            raise ValueError("Only http:// and https:// links are allowed.")
        raw = "https://" + raw
    parts = urlsplit(raw)
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        raise ValueError("Only http:// and https:// links are allowed.")
    if parts.username is not None or parts.password is not None:
        raise ValueError("Links with a username or password before the domain are not allowed "
                         "(a common phishing trick).")
    host = (parts.hostname or "").rstrip(".")
    if not host:
        raise ValueError("That link has no domain.")
    if _ip_or_none(host) is None:
        try:
            host = host.encode("idna").decode("ascii").lower()
        except UnicodeError:
            raise ValueError("That domain name isn't valid.")
    try:
        port = parts.port
    except ValueError:
        raise ValueError("That link has an invalid port.")
    netloc = f"[{host}]" if ":" in host else host
    if port and not ((scheme == "https" and port == 443) or (scheme == "http" and port == 80)):
        netloc += f":{port}"
    return urlunsplit((scheme, netloc, parts.path or "/", parts.query, parts.fragment))


def structural_check(url: str, result: ScanResult) -> str:
    """Checks that need no network. Returns the ASCII host."""
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    ip = _ip_or_none(host)

    if ip is not None:
        if not _is_public_ip(ip):
            result.add(BLOCKED, "Points to a private or internal network address.")
        else:
            result.add(WARN, "Uses a raw IP address instead of a domain name.")
    else:
        if host == "localhost" or host.endswith(BLOCKED_HOST_SUFFIXES) or "." not in host:
            result.add(BLOCKED, "Not a public website address.")
        labels = host.split(".")
        if any(label.startswith("xn--") for label in labels):
            result.add(WARN, f"International domain ({display_domain(host)}) - check it isn't "
                             "imitating a well-known site with look-alike letters.")
        if labels[-1] in ABUSED_TLDS:
            result.add(WARN, f"The .{labels[-1]} domain ending is frequently used for scams.")
        if len(labels) > 5 or len(host) > 80:
            result.add(WARN, "Unusually long domain name.")
        if is_blocklisted(host):
            result.add(BLOCKED, "This domain is on the site's blocklist.")

    if parts.port and parts.port not in (80, 443):
        result.add(WARN, f"Uses an unusual port ({parts.port}).")
    if parts.scheme == "http":
        result.add(WARN, "Not encrypted (http://). Anything you enter there can be intercepted.")
    if parts.path.lower().endswith(RISKY_EXTENSIONS):
        result.add(WARN, "Links directly to a program or installer file.")
    return host


async def resolve_public(host: str, port: int) -> str | None:
    """Return an error message if the host doesn't resolve, or resolves to a non-public IP."""
    if _ip_or_none(host) is not None:
        return None
    loop = asyncio.get_running_loop()
    try:
        infos = await asyncio.wait_for(
            loop.getaddrinfo(host, port, type=socket.SOCK_STREAM), timeout=5
        )
    except (socket.gaierror, asyncio.TimeoutError, UnicodeError):
        return "The domain doesn't exist or couldn't be resolved."
    ips = {ipaddress.ip_address(info[4][0].split("%", 1)[0]) for info in infos}
    if not ips:
        return "The domain doesn't exist or couldn't be resolved."
    if not all(_is_public_ip(ip) for ip in ips):
        return "The domain resolves to a private or internal network address."
    return None


def _extract_title(text: str) -> str:
    for pattern in (
        r'<meta[^>]+property=["\']og:title["\'][^>]+content=["\']([^"\']{1,300})',
        r"<title[^>]*>(.{1,300}?)</title>",
    ):
        m = re.search(pattern, text, re.IGNORECASE | re.DOTALL)
        if m:
            title = re.sub(r"\s+", " ", html.unescape(m.group(1))).strip()
            if title:
                return title[:200]
    return ""


def _allows_framing(headers: httpx.Headers, url: str) -> bool:
    if urlsplit(url).scheme != "https":
        return False  # browsers block http pages inside an https app
    xfo = headers.get("x-frame-options", "").lower()
    if "deny" in xfo or "sameorigin" in xfo:
        return False
    csp = headers.get("content-security-policy", "").lower()
    m = re.search(r"frame-ancestors([^;]*)", csp)
    if m and "*" not in m.group(1).split():
        return False
    return True


async def _check_hop(url: str, result: ScanResult) -> bool:
    """Structural + DNS check for a redirect target. Returns False if it is blocked."""
    hop = ScanResult()
    host = structural_check(url, hop)
    parts = urlsplit(url)
    err = await resolve_public(host, parts.port or (443 if parts.scheme == "https" else 80))
    if err:
        hop.add(BLOCKED, err)
    for level, reason in hop.findings:
        result.add(level, f"Redirects to {display_domain(host)}: {reason}")
    return not hop.blocked


async def _fetch(url: str, result: ScanResult) -> None:
    current = url
    async with httpx.AsyncClient(
        follow_redirects=False, timeout=FETCH_TIMEOUT, headers={"User-Agent": USER_AGENT}
    ) as client:
        for hop in range(MAX_REDIRECTS + 1):
            if hop > 0 and not await _check_hop(current, result):
                result.final_url = current
                return
            async with client.stream("GET", current) as resp:
                # Defence against DNS rebinding: verify the address we actually connected to.
                stream = resp.extensions.get("network_stream")
                peer = stream.get_extra_info("server_addr") if stream else None
                if peer and not _is_public_ip(ipaddress.ip_address(peer[0])):
                    # Only meaningful when connecting directly (not through an HTTP proxy)
                    if not _using_proxy():
                        result.add(BLOCKED, "The site connected to a private network address.")
                        return

                if resp.is_redirect and "location" in resp.headers:
                    nxt = urljoin(current, resp.headers["location"])
                    try:
                        current = normalize(nxt)
                    except ValueError as e:
                        result.add(BLOCKED, f"Redirects to an invalid address: {e}")
                        return
                    continue

                result.final_url = current
                result.embeddable = _allows_framing(resp.headers, current)
                ctype = resp.headers.get("content-type", "").lower()
                disposition = resp.headers.get("content-disposition", "").lower()
                if ctype.startswith(DOWNLOAD_TYPES) or "attachment" in disposition:
                    result.add(WARN, "Opening it starts a file download.")
                    result.embeddable = False
                if resp.status_code in (404, 410):
                    result.add(WARN, f"The page returned 'not found' ({resp.status_code}).")
                if "html" in ctype:
                    body = b""
                    async for chunk in resp.aiter_bytes():
                        body += chunk
                        if len(body) >= MAX_BYTES:
                            break
                    result.title = _extract_title(body.decode(resp.encoding or "utf-8", errors="ignore"))
                return
        result.add(WARN, "Too many redirects.")
        result.final_url = current


async def check_google_safe_browsing(urls: list[str]) -> list[str]:
    """Returns threat types found, [] if clean or not configured."""
    if not GSB_API_KEY:
        return []
    payload = {
        "client": {"clientId": "linkvault", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                            "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": u} for u in dict.fromkeys(urls)],
        },
    }
    try:
        async with httpx.AsyncClient(timeout=6) as client:
            r = await client.post(
                "https://safebrowsing.googleapis.com/v4/threatMatches:find",
                params={"key": GSB_API_KEY}, json=payload,
            )
            r.raise_for_status()
            return sorted({m.get("threatType", "UNKNOWN") for m in r.json().get("matches", [])})
    except Exception as e:  # service down must not break the app
        log.warning("Safe Browsing lookup failed: %s", e)
        return []


THREAT_NAMES = {
    "MALWARE": "malware", "SOCIAL_ENGINEERING": "phishing / deceptive content",
    "UNWANTED_SOFTWARE": "unwanted software", "POTENTIALLY_HARMFUL_APPLICATION": "harmful apps",
}


async def scan_url(raw: str, fetch: bool | None = None) -> ScanResult:
    fetch = FETCH_PAGE_METADATA if fetch is None else fetch
    try:
        url = normalize(raw)
    except ValueError as e:
        result = ScanResult()
        result.add(BLOCKED, str(e))
        return result

    result = ScanResult(url=url, final_url=url)
    result.domain = structural_check(url, result)
    if result.blocked:
        return result

    parts = urlsplit(url)
    err = await resolve_public(result.domain, parts.port or (443 if parts.scheme == "https" else 80))
    if err:
        result.add(BLOCKED, err)
        return result

    if fetch:
        try:
            await _fetch(url, result)
        except (httpx.HTTPError, OSError, ssl.SSLError) as e:
            log.info("fetch failed for %s: %s", url, e)
            if "certificate" in str(e).lower():
                result.add(WARN, "The site's security certificate is invalid.")
            else:
                result.add(WARN, "The site couldn't be reached to verify it.")
        if result.blocked:
            return result
        if result.final_url.startswith("https://"):
            # http:// links that upgrade themselves to https are fine
            result.drop("Not encrypted")
        # show where the link really goes (important for shorteners)
        result.domain = urlsplit(result.final_url).hostname or result.domain

    threats = await check_google_safe_browsing([result.url, result.final_url])
    if threats:
        names = ", ".join(THREAT_NAMES.get(t, t.lower()) for t in threats)
        result.add(BLOCKED, f"Google Safe Browsing flags this site for {names}.")
    return result
