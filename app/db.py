"""SQLite storage. One short-lived connection per operation (safe across threads)."""
from __future__ import annotations

import json
import secrets
import sqlite3
import time
from contextlib import contextmanager
from typing import Iterable, Optional

from config import DB_PATH, REPORT_HIDE_THRESHOLD

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    created_at    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);

-- owner_id NULL = anonymous quick share
CREATE TABLE IF NOT EXISTS links (
    id           INTEGER PRIMARY KEY,
    owner_id     INTEGER REFERENCES users(id) ON DELETE CASCADE,
    url          TEXT NOT NULL,
    final_url    TEXT NOT NULL,
    domain       TEXT NOT NULL,
    title        TEXT NOT NULL DEFAULT '',
    note         TEXT NOT NULL DEFAULT '',
    visibility   TEXT NOT NULL DEFAULT 'private'
                 CHECK (visibility IN ('private', 'friends', 'public', 'unlisted')),
    status       TEXT NOT NULL CHECK (status IN ('safe', 'warn', 'blocked')),
    reasons      TEXT NOT NULL DEFAULT '[]',
    embeddable   INTEGER NOT NULL DEFAULT 0,
    report_count INTEGER NOT NULL DEFAULT 0,
    hidden       INTEGER NOT NULL DEFAULT 0,   -- hidden after too many reports
    admin_locked INTEGER NOT NULL DEFAULT 0,   -- status set by an admin, skip rescans
    checked_at   INTEGER NOT NULL,
    created_at   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_links_owner  ON links(owner_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_links_public ON links(visibility, created_at DESC);

-- per-user categories ("folders") for organising links
CREATE TABLE IF NOT EXISTS categories (
    id         INTEGER PRIMARY KEY,
    owner_id   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    UNIQUE (owner_id, name COLLATE NOCASE)
);

CREATE TABLE IF NOT EXISTS share_codes (
    code       TEXT PRIMARY KEY,
    link_id    INTEGER NOT NULL REFERENCES links(id) ON DELETE CASCADE,
    created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER,
    views      INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS friendships (
    requester_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    addressee_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    status       TEXT NOT NULL CHECK (status IN ('pending', 'accepted')),
    created_at   INTEGER NOT NULL,
    PRIMARY KEY (requester_id, addressee_id)
);

CREATE TABLE IF NOT EXISTS link_shares (
    link_id      INTEGER NOT NULL REFERENCES links(id) ON DELETE CASCADE,
    sender_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    recipient_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at   INTEGER NOT NULL,
    seen         INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (link_id, recipient_id)
);

CREATE TABLE IF NOT EXISTS reports (
    link_id      INTEGER NOT NULL REFERENCES links(id) ON DELETE CASCADE,
    reporter_key TEXT NOT NULL,          -- "u:<id>" or "ip:<address>"
    reason       TEXT NOT NULL,
    created_at   INTEGER NOT NULL,
    PRIMARY KEY (link_id, reporter_key)
);
"""


def now() -> int:
    return int(time.time())


@contextmanager
def connect():
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with connect() as c:
        c.execute("PRAGMA journal_mode = WAL")
        c.executescript(SCHEMA)
        _migrate(c)


def _migrate(c: sqlite3.Connection) -> None:
    """Upgrade databases created by earlier versions (safe to run every start)."""
    cols = {r["name"] for r in c.execute("PRAGMA table_info(links)").fetchall()}
    if "category_id" not in cols:
        c.execute("ALTER TABLE links ADD COLUMN category_id INTEGER "
                  "REFERENCES categories(id) ON DELETE SET NULL")
    c.execute("CREATE INDEX IF NOT EXISTS idx_links_category ON links(owner_id, category_id)")


def _dict(row: Optional[sqlite3.Row]) -> Optional[dict]:
    if row is None:
        return None
    d = dict(row)
    if "reasons" in d:
        d["reasons"] = json.loads(d["reasons"] or "[]")
    return d


def _dicts(rows: Iterable[sqlite3.Row]) -> list[dict]:
    return [_dict(r) for r in rows]


# ------------------------------------------------------------------ users & sessions
def create_user(username: str, password_hash: str) -> int:
    with connect() as c:
        cur = c.execute(
            "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
            (username, password_hash, now()),
        )
        return cur.lastrowid


def get_user(user_id: int) -> Optional[dict]:
    with connect() as c:
        return _dict(c.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone())


def get_user_by_name(username: str) -> Optional[dict]:
    with connect() as c:
        return _dict(c.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone())


def create_session(user_id: int, token_hash: str, ttl_seconds: int) -> None:
    with connect() as c:
        c.execute("DELETE FROM sessions WHERE expires_at < ?", (now(),))
        c.execute(
            "INSERT INTO sessions (token_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
            (token_hash, user_id, now(), now() + ttl_seconds),
        )


def session_user(token_hash: str) -> Optional[dict]:
    with connect() as c:
        return _dict(c.execute(
            """SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id
               WHERE s.token_hash = ? AND s.expires_at > ?""",
            (token_hash, now()),
        ).fetchone())


def delete_session(token_hash: str) -> None:
    with connect() as c:
        c.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))


# ------------------------------------------------------------------ links
LINK_FIELDS = ("url", "final_url", "domain", "title", "note", "visibility", "status",
               "reasons", "embeddable", "checked_at", "hidden", "admin_locked", "report_count")

_LINK_SELECT = """SELECT l.*, u.username AS owner_name, cat.name AS category_name FROM links l
                  LEFT JOIN users u ON u.id = l.owner_id
                  LEFT JOIN categories cat ON cat.id = l.category_id"""

MAX_CATEGORIES = 60
MAX_CATEGORY_NAME = 40


def _owned_category(c: sqlite3.Connection, owner_id: Optional[int], category_id) -> Optional[int]:
    """Only accept a category that belongs to the link's owner."""
    if not category_id or owner_id is None:
        return None
    row = c.execute("SELECT id FROM categories WHERE id = ? AND owner_id = ?",
                    (category_id, owner_id)).fetchone()
    return row["id"] if row else None


def add_link(owner_id: Optional[int], scan, title: str, note: str, visibility: str,
             category_id: Optional[int] = None) -> int:
    with connect() as c:
        cur = c.execute(
            """INSERT INTO links (owner_id, url, final_url, domain, title, note, visibility,
                                  status, reasons, embeddable, checked_at, created_at, category_id)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (owner_id, scan.url, scan.final_url, scan.domain, title, note, visibility,
             scan.status, json.dumps(scan.reasons), int(scan.embeddable), now(), now(),
             _owned_category(c, owner_id, category_id)),
        )
        return cur.lastrowid


def set_link_category(link_id: int, owner_id: int, category_id: Optional[int]) -> None:
    with connect() as c:
        c.execute("UPDATE links SET category_id = ? WHERE id = ? AND owner_id = ?",
                  (_owned_category(c, owner_id, category_id), link_id, owner_id))


# ------------------------------------------------------------------ categories
def clean_category_name(name: str) -> str:
    return " ".join((name or "").split())[:MAX_CATEGORY_NAME]


def list_categories(owner_id: int, visible_only: bool = False, include_friends: bool = False) -> list[dict]:
    """Categories with link counts. visible_only = count only what profile visitors can see."""
    vis_filter = ""
    if visible_only:
        vis = "('public', 'friends')" if include_friends else "('public')"
        vis_filter = f"AND l.visibility IN {vis} AND l.status != 'blocked' AND l.hidden = 0"
    with connect() as c:
        rows = _dicts(c.execute(
            f"""SELECT cat.id, cat.name, COUNT(l.id) AS n FROM categories cat
                LEFT JOIN links l ON l.category_id = cat.id {vis_filter}
                WHERE cat.owner_id = ? GROUP BY cat.id ORDER BY cat.name COLLATE NOCASE""",
            (owner_id,),
        ).fetchall())
    return [r for r in rows if r["n"] > 0] if visible_only else rows


def get_category_name(category_id: int) -> Optional[str]:
    with connect() as c:
        row = c.execute("SELECT name FROM categories WHERE id = ?", (category_id,)).fetchone()
        return row["name"] if row else None


def uncategorized_count(owner_id: int) -> int:
    with connect() as c:
        return c.execute("SELECT COUNT(*) FROM links WHERE owner_id = ? AND category_id IS NULL",
                         (owner_id,)).fetchone()[0]


def create_category(owner_id: int, name: str) -> int:
    """Returns the id (existing one if the name is already used). Raises ValueError."""
    name = clean_category_name(name)
    if not name:
        raise ValueError("Give the category a name.")
    with connect() as c:
        row = c.execute("SELECT id FROM categories WHERE owner_id = ? AND name = ? COLLATE NOCASE",
                        (owner_id, name)).fetchone()
        if row:
            return row["id"]
        if c.execute("SELECT COUNT(*) FROM categories WHERE owner_id = ?", (owner_id,)).fetchone()[0] >= MAX_CATEGORIES:
            raise ValueError(f"You can have up to {MAX_CATEGORIES} categories.")
        return c.execute("INSERT INTO categories (owner_id, name, created_at) VALUES (?, ?, ?)",
                         (owner_id, name, now())).lastrowid


def rename_category(owner_id: int, category_id: int, name: str) -> None:
    name = clean_category_name(name)
    if not name:
        raise ValueError("Give the category a name.")
    with connect() as c:
        try:
            c.execute("UPDATE categories SET name = ? WHERE id = ? AND owner_id = ?",
                      (name, category_id, owner_id))
        except sqlite3.IntegrityError:
            raise ValueError("You already have a category with that name.")


def delete_category(owner_id: int, category_id: int) -> None:
    """Links in it become uncategorized (they are not deleted)."""
    with connect() as c:
        c.execute("UPDATE links SET category_id = NULL WHERE category_id = ? AND owner_id = ?",
                  (category_id, owner_id))
        c.execute("DELETE FROM categories WHERE id = ? AND owner_id = ?", (category_id, owner_id))


def suggest_category(owner_id: int, domain: str) -> Optional[int]:
    """The category most recently used for this domain, to pre-select when saving."""
    with connect() as c:
        row = c.execute(
            """SELECT category_id FROM links WHERE owner_id = ? AND domain = ?
               AND category_id IS NOT NULL ORDER BY created_at DESC LIMIT 1""",
            (owner_id, domain),
        ).fetchone()
        return row["category_id"] if row else None


def update_link(link_id: int, **fields) -> None:
    fields = {k: v for k, v in fields.items() if k in LINK_FIELDS}
    if "reasons" in fields:
        fields["reasons"] = json.dumps(fields["reasons"])
    if not fields:
        return
    sets = ", ".join(f"{k} = ?" for k in fields)
    with connect() as c:
        c.execute(f"UPDATE links SET {sets} WHERE id = ?", (*fields.values(), link_id))


def apply_scan(link_id: int, scan) -> None:
    update_link(link_id, final_url=scan.final_url or scan.url, domain=scan.domain or "",
                status=scan.status, reasons=scan.reasons,
                embeddable=int(scan.embeddable), checked_at=now())


def get_link(link_id: int) -> Optional[dict]:
    with connect() as c:
        return _dict(c.execute(f"{_LINK_SELECT} WHERE l.id = ?", (link_id,)).fetchone())


def find_duplicate(owner_id: int, url: str, final_url: str) -> Optional[dict]:
    with connect() as c:
        return _dict(c.execute(
            "SELECT * FROM links WHERE owner_id = ? AND (url = ? OR final_url = ?)",
            (owner_id, url, final_url),
        ).fetchone())


def delete_link(link_id: int, owner_id: int) -> None:
    with connect() as c:
        c.execute("DELETE FROM links WHERE id = ? AND owner_id = ?", (link_id, owner_id))


def _search_clause(search: str) -> tuple[str, list]:
    if not search:
        return "", []
    like = f"%{search.strip()}%"
    return " AND (l.title LIKE ? OR l.note LIKE ? OR l.domain LIKE ? OR l.url LIKE ?)", [like] * 4


def _category_clause(category) -> tuple[str, list]:
    """category: None = all, "none" = uncategorized, int = that category."""
    if category is None:
        return "", []
    if category == "none":
        return " AND l.category_id IS NULL", []
    return " AND l.category_id = ?", [int(category)]


def list_user_links(owner_id: int, search: str = "", category=None,
                    limit: int = 10_000) -> list[dict]:
    clause, args = _search_clause(search)
    cclause, cargs = _category_clause(category)
    with connect() as c:
        return _dicts(c.execute(
            f"{_LINK_SELECT} WHERE l.owner_id = ?{clause}{cclause} ORDER BY l.created_at DESC LIMIT ?",
            (owner_id, *args, *cargs, limit),
        ).fetchall())


def list_public_links(search: str = "", limit: int = 100) -> list[dict]:
    clause, args = _search_clause(search)
    with connect() as c:
        return _dicts(c.execute(
            f"""{_LINK_SELECT} WHERE l.visibility = 'public' AND l.status != 'blocked'
                AND l.hidden = 0 AND l.owner_id IS NOT NULL{clause}
                ORDER BY l.created_at DESC LIMIT ?""",
            (*args, limit),
        ).fetchall())


def count_user_links(owner_id: int, search: str = "", category=None) -> int:
    clause, args = _search_clause(search)
    cclause, cargs = _category_clause(category)
    with connect() as c:
        return c.execute(f"SELECT COUNT(*) FROM links l WHERE l.owner_id = ?{clause}{cclause}",
                         (owner_id, *args, *cargs)).fetchone()[0]


def list_profile_links(owner_id: int, include_friends: bool, category=None) -> list[dict]:
    vis = ("public", "friends") if include_friends else ("public",)
    marks = ",".join("?" * len(vis))
    cclause, cargs = _category_clause(category)
    with connect() as c:
        return _dicts(c.execute(
            f"""{_LINK_SELECT} WHERE l.owner_id = ? AND l.visibility IN ({marks})
                AND l.status != 'blocked' AND l.hidden = 0{cclause} ORDER BY l.created_at DESC""",
            (owner_id, *vis, *cargs),
        ).fetchall())


def list_links_to_rescan(older_than: int, limit: int = 50) -> list[dict]:
    with connect() as c:
        return _dicts(c.execute(
            """SELECT * FROM links WHERE checked_at < ? AND admin_locked = 0
               AND (visibility != 'private' OR id IN (SELECT link_id FROM link_shares))
               ORDER BY checked_at LIMIT ?""",
            (older_than, limit),
        ).fetchall())


# ------------------------------------------------------------------ direct shares
def share_with(link_id: int, sender_id: int, recipient_ids: list[int]) -> int:
    with connect() as c:
        n = 0
        for rid in recipient_ids:
            cur = c.execute(
                """INSERT INTO link_shares (link_id, sender_id, recipient_id, created_at)
                   VALUES (?, ?, ?, ?)
                   ON CONFLICT (link_id, recipient_id) DO UPDATE SET seen = 0,
                   created_at = excluded.created_at""",
                (link_id, sender_id, rid, now()),
            )
            n += cur.rowcount
        return n


def list_shared_with(user_id: int) -> list[dict]:
    with connect() as c:
        return _dicts(c.execute(
            """SELECT l.*, o.username AS owner_name, s.username AS sender_name, NULL AS category_name,
                      ls.seen, ls.created_at AS shared_at
               FROM link_shares ls
               JOIN links l ON l.id = ls.link_id
               JOIN users s ON s.id = ls.sender_id
               LEFT JOIN users o ON o.id = l.owner_id
               WHERE ls.recipient_id = ? AND l.status != 'blocked' AND l.hidden = 0
               ORDER BY ls.created_at DESC""",
            (user_id,),
        ).fetchall())


def unseen_share_count(user_id: int) -> int:
    with connect() as c:
        return c.execute(
            """SELECT COUNT(*) FROM link_shares ls JOIN links l ON l.id = ls.link_id
               WHERE ls.recipient_id = ? AND ls.seen = 0 AND l.status != 'blocked' AND l.hidden = 0""",
            (user_id,),
        ).fetchone()[0]


def mark_shares_seen(user_id: int) -> None:
    with connect() as c:
        c.execute("UPDATE link_shares SET seen = 1 WHERE recipient_id = ?", (user_id,))


def remove_share(link_id: int, recipient_id: int) -> None:
    with connect() as c:
        c.execute("DELETE FROM link_shares WHERE link_id = ? AND recipient_id = ?", (link_id, recipient_id))


def is_shared_with(link_id: int, user_id: int) -> bool:
    with connect() as c:
        return c.execute("SELECT 1 FROM link_shares WHERE link_id = ? AND recipient_id = ?",
                         (link_id, user_id)).fetchone() is not None


# ------------------------------------------------------------------ share codes (no login needed)
def create_share_code(link_id: int, created_by: Optional[int], expires_at: Optional[int]) -> str:
    with connect() as c:
        if created_by is not None:
            row = c.execute(
                """SELECT code FROM share_codes WHERE link_id = ? AND created_by = ?
                   AND (expires_at IS NULL OR expires_at > ?)""",
                (link_id, created_by, now()),
            ).fetchone()
            if row:
                return row["code"]
        code = secrets.token_urlsafe(9)
        c.execute(
            "INSERT INTO share_codes (code, link_id, created_by, created_at, expires_at) VALUES (?, ?, ?, ?, ?)",
            (code, link_id, created_by, now(), expires_at),
        )
        return code


def get_share(code: str) -> Optional[dict]:
    with connect() as c:
        row = c.execute(
            """SELECT sc.code, sc.expires_at, sc.views, cb.username AS shared_by, l.*,
                      o.username AS owner_name, NULL AS category_name
               FROM share_codes sc
               JOIN links l ON l.id = sc.link_id
               LEFT JOIN users cb ON cb.id = sc.created_by
               LEFT JOIN users o ON o.id = l.owner_id
               WHERE sc.code = ? AND (sc.expires_at IS NULL OR sc.expires_at > ?)""",
            (code, now()),
        ).fetchone()
        if row:
            c.execute("UPDATE share_codes SET views = views + 1 WHERE code = ?", (code,))
        return _dict(row)


def revoke_share_codes(link_id: int) -> None:
    with connect() as c:
        c.execute("DELETE FROM share_codes WHERE link_id = ?", (link_id,))


# ------------------------------------------------------------------ friends
def friendship(a: int, b: int) -> Optional[dict]:
    with connect() as c:
        return _dict(c.execute(
            """SELECT * FROM friendships WHERE (requester_id = ? AND addressee_id = ?)
               OR (requester_id = ? AND addressee_id = ?)""",
            (a, b, b, a),
        ).fetchone())


def are_friends(a: int, b: int) -> bool:
    f = friendship(a, b)
    return bool(f and f["status"] == "accepted")


def send_friend_request(requester_id: int, addressee_id: int) -> str:
    """Returns 'sent', 'accepted' (they had already asked us) or 'exists'."""
    existing = friendship(requester_id, addressee_id)
    with connect() as c:
        if existing is None:
            c.execute(
                "INSERT INTO friendships (requester_id, addressee_id, status, created_at) VALUES (?, ?, 'pending', ?)",
                (requester_id, addressee_id, now()),
            )
            return "sent"
        if existing["status"] == "pending" and existing["requester_id"] == addressee_id:
            c.execute(
                "UPDATE friendships SET status = 'accepted' WHERE requester_id = ? AND addressee_id = ?",
                (addressee_id, requester_id),
            )
            return "accepted"
        return "exists"


def accept_friend(user_id: int, requester_id: int) -> None:
    with connect() as c:
        c.execute(
            "UPDATE friendships SET status = 'accepted' WHERE requester_id = ? AND addressee_id = ?",
            (requester_id, user_id),
        )


def remove_friendship(a: int, b: int) -> None:
    with connect() as c:
        c.execute(
            """DELETE FROM friendships WHERE (requester_id = ? AND addressee_id = ?)
               OR (requester_id = ? AND addressee_id = ?)""",
            (a, b, b, a),
        )
        # stop sharing with each other
        c.execute(
            """DELETE FROM link_shares WHERE (sender_id = ? AND recipient_id = ?)
               OR (sender_id = ? AND recipient_id = ?)""",
            (a, b, b, a),
        )


def list_friends(user_id: int) -> list[dict]:
    with connect() as c:
        return _dicts(c.execute(
            """SELECT u.id, u.username FROM friendships f
               JOIN users u ON u.id = CASE WHEN f.requester_id = ? THEN f.addressee_id ELSE f.requester_id END
               WHERE (f.requester_id = ? OR f.addressee_id = ?) AND f.status = 'accepted'
               ORDER BY u.username COLLATE NOCASE""",
            (user_id, user_id, user_id),
        ).fetchall())


def list_incoming_requests(user_id: int) -> list[dict]:
    with connect() as c:
        return _dicts(c.execute(
            """SELECT u.id, u.username FROM friendships f JOIN users u ON u.id = f.requester_id
               WHERE f.addressee_id = ? AND f.status = 'pending' ORDER BY f.created_at DESC""",
            (user_id,),
        ).fetchall())


def list_outgoing_requests(user_id: int) -> list[dict]:
    with connect() as c:
        return _dicts(c.execute(
            """SELECT u.id, u.username FROM friendships f JOIN users u ON u.id = f.addressee_id
               WHERE f.requester_id = ? AND f.status = 'pending' ORDER BY f.created_at DESC""",
            (user_id,),
        ).fetchall())


# ------------------------------------------------------------------ reports & moderation
def report_link(link_id: int, reporter_key: str, reason: str) -> bool:
    """Returns True if this report was new. Hides the link once the threshold is reached."""
    with connect() as c:
        cur = c.execute(
            "INSERT OR IGNORE INTO reports (link_id, reporter_key, reason, created_at) VALUES (?, ?, ?, ?)",
            (link_id, reporter_key, reason[:500], now()),
        )
        if cur.rowcount == 0:
            return False
        c.execute(
            """UPDATE links SET report_count = report_count + 1,
               hidden = CASE WHEN report_count + 1 >= ? THEN 1 ELSE hidden END
               WHERE id = ?""",
            (REPORT_HIDE_THRESHOLD, link_id),
        )
        return True


def list_reported_links() -> list[dict]:
    with connect() as c:
        rows = _dicts(c.execute(
            f"""{_LINK_SELECT} WHERE l.report_count > 0 OR l.hidden = 1 OR l.admin_locked = 1
                ORDER BY l.hidden DESC, l.report_count DESC, l.created_at DESC LIMIT 200"""
        ).fetchall())
        for r in rows:
            r["report_reasons"] = [x["reason"] for x in c.execute(
                "SELECT reason FROM reports WHERE link_id = ? ORDER BY created_at DESC LIMIT 5", (r["id"],)
            ).fetchall()]
        return rows


def clear_reports(link_id: int) -> None:
    with connect() as c:
        c.execute("DELETE FROM reports WHERE link_id = ?", (link_id,))
        c.execute("UPDATE links SET report_count = 0, hidden = 0, admin_locked = 0 WHERE id = ?", (link_id,))
