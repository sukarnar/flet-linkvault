"""Runtime configuration, read from environment variables."""
import os
from pathlib import Path


def _bool(name: str, default: bool) -> bool:
    return os.getenv(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


APP_NAME = os.getenv("APP_TITLE", "LinkVault")

DATA_DIR = Path(os.getenv("DATA_DIR", "/data"))
DB_PATH = DATA_DIR / "linkvault.db"
BLOCKLIST_FILE = DATA_DIR / "blocklist.txt"

# Public address of the site, used to build share links, e.g. https://links.example.com
PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "").rstrip("/")

# Usernames (comma separated) allowed to open /admin
ADMIN_USERNAMES = {
    u.strip().lower() for u in os.getenv("ADMIN_USERNAMES", "").split(",") if u.strip()
}

# Optional: Google Safe Browsing v4 API key (reputation check for malware/phishing)
GSB_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()

# Fetch each page (safely) to read its title, follow redirects and detect embedding rules
FETCH_PAGE_METADATA = _bool("FETCH_PAGE_METADATA", True)

REPORT_HIDE_THRESHOLD = int(os.getenv("REPORT_HIDE_THRESHOLD", "3"))
ANON_SHARE_DAYS = int(os.getenv("ANON_SHARE_DAYS", "30"))
SESSION_DAYS = int(os.getenv("SESSION_DAYS", "30"))
RESCAN_HOURS = int(os.getenv("RESCAN_HOURS", "24"))
