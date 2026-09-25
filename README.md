# LinkVault

Save the websites you like, find them later, and share them safely. Built with
[Flet](https://flet.dev) 1.0 (Python), deployed with Docker + Traefik, and updated
automatically from GitHub.

## Features

| | |
|---|---|
| **Save links** | Paste a URL; the title is fetched automatically. Add a note, search your collection. |
| **Visibility per link** | *Only me*, *Friends*, *Public* (shown on your profile and in Explore) or *Anyone with the link*. |
| **Share without login** | `/quick` - anyone can paste a link and get a short share link (expires after 30 days). |
| **Share links for your bookmarks** | "Get share link" on any saved link; revocable. Recipients don't need an account. |
| **Friends** | Send/accept requests by username. Friends see your friends-only links, and you can send links straight to their *Shared* inbox. |
| **Public profiles** | `/u/<username>` shows someone's public links (plus friends-only ones if you're friends). |
| **Built-in viewer or browser** | *View* opens the page inside the app; *Open in browser* opens a new tab. Sites that forbid embedding are detected and open in the browser instead. |
| **Safety checks** | Every link is scanned before it's saved or shared, and re-scanned regularly. See below. |
| **Reporting & moderation** | Anyone can report a link. Three reports hide it automatically; admins review at `/admin`. |

## How links are checked

Code: [`app/security.py`](app/security.py).

1. **Refused outright (blocked)**
   - Anything other than `http://` / `https://`, e.g. `javascript:`, `data:` or `file:`.
   - Credentials in the URL, like `https://paypal.com@evil.site`.
   - Private or internal addresses: `localhost`, `10.x`, `192.168.x`, `169.254.169.254` cloud metadata, `.local`.
   - Domains that don't exist.
   - Domains on your blocklist, and redirects that lead to any of the above.
   - Anything Google Safe Browsing flags as malware or phishing, if you've set a key.
2. **Allowed with a warning (caution)**
   - Look-alike international domains, e.g. `pаypal.com` spelled with a Cyrillic "а".
   - Raw IP addresses, unusual ports, unencrypted `http`, and domain endings often used for scams.
   - Direct `.exe`/`.apk` downloads, invalid certificates, and sites that can't be reached.

   Caution links can't be made public. Anyone opening one sees the reasons and has to confirm first.
3. **Redirects are followed manually**, up to 5 hops, and every hop is re-checked. A URL
   shortener can't hide a bad destination this way, and the card shows the real destination domain.
4. **Page fetches are limited.** They have a 6-second timeout and read at most 256 KB. The
   server checks the IP it actually connected to, which defends against DNS-rebinding attacks.
5. **Links are re-scanned.** Shared and public links are re-checked every 24 hours, when opened
   if stale, and immediately when reported. A site that turns malicious later gets blocked.

The app also hashes passwords with scrypt and stores only a hash of each login token. Logins,
signups, anonymous shares, reports and friend requests are rate-limited per IP or user, using
the real visitor IP passed through by Traefik.

### Recommended: enable Google Safe Browsing

The structural checks catch a lot, but not a brand-new phishing page on an ordinary-looking
domain. For reputation checks:

1. In the Google Cloud Console, create a project and enable the **Safe Browsing API**.
2. Create an API key, restricted to that API.
3. Add `GOOGLE_SAFE_BROWSING_API_KEY=...` to the server's `.env`.

The free Safe Browsing Lookup API is for non-commercial use. For a commercial service, use
Google's paid **Web Risk API** instead.

### Blocklist

Admins can block a domain from `/admin`. You can also edit the blocklist directly:

```bash
docker exec -it linkvault sh -c 'echo "bad-site.example" >> /data/blocklist.txt'
```

Put one domain per line. Subdomains are included, and changes apply immediately.

---

## Project layout

```
app/
  main.py        entry point + background re-scan worker
  ui.py          all screens, dialogs and the in-app viewer
  security.py    URL safety scanner
  db.py          SQLite storage (stored in the /data volume)
  auth.py        passwords, sessions, validation
  ratelimit.py   per-IP / per-user limits
  config.py      environment settings
tests/           run in CI before every deploy
Dockerfile, docker-compose.yml, .env.example
.github/workflows/deploy.yml   test -> build -> push to GHCR -> deploy to VPS
```

## Run locally (Windows)

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:DATA_DIR = ".\data"; $env:ADMIN_USERNAMES = "yourname"
flet run --web --port 8000 app\main.py
```

To run the tests:

```powershell
python tests\test_security.py
python tests\test_ui_render.py
python tests\test_flows.py
```

## Deploying

### Upgrading from the Flet demo (same repo and server)

1. Replace the repo contents with this project, keeping the `.github` folder, then commit and push.
2. On the VPS, add the new settings to `/opt/flet-traefik-demo/.env`. Keep your existing
   `IMAGE`, `APP_DOMAIN` and Traefik values:
   ```
   ADMIN_USERNAMES=yourname
   GOOGLE_SAFE_BROWSING_API_KEY=
   ANON_SHARE_DAYS=30
   ```
3. Push to `main`. The workflow runs the tests, builds the image and deploys it. The
   container is now called `linkvault`, and its data lives in the `linkvault-data` Docker volume.
4. Open the site, register the username you listed in `ADMIN_USERNAMES`, and `/admin` becomes available.

### Fresh setup

1. **DNS:** add an A record, e.g. `links`, pointing to the VPS IP.
2. **Find your Traefik network, entrypoint and cert resolver:**
   ```bash
   docker ps --format '{{.Names}}\t{{.Image}}' | grep -i traefik
   docker inspect <traefik> --format '{{range $k, $v := .NetworkSettings.Networks}}{{$k}}{{"\n"}}{{end}}'
   docker inspect <traefik> --format '{{json .Config.Cmd}}' | tr ',' '\n' | grep -E 'entrypoints\.|certificatesresolvers\.'
   ```
3. **Prepare the VPS:**
   ```bash
   adduser --disabled-password --gecos "" deploy && usermod -aG docker deploy
   mkdir -p /opt/flet-traefik-demo && chown deploy:deploy /opt/flet-traefik-demo
   su - deploy
   ssh-keygen -t ed25519 -f ~/.ssh/gh-actions -N ""
   cat ~/.ssh/gh-actions.pub >> ~/.ssh/authorized_keys
   cat ~/.ssh/gh-actions    # -> GitHub secret VPS_SSH_KEY
   ```
4. **Create the `.env`:** copy `.env.example` to `/opt/flet-traefik-demo/.env` and fill it in.
   `IMAGE` is `ghcr.io/<user>/<repo>` in lower case, without `.git`.
5. **Add GitHub secrets** under Settings → Secrets and variables → Actions:
   - `VPS_HOST`
   - `VPS_USER` (`deploy`)
   - `VPS_SSH_KEY`
   - optionally `VPS_PORT`
6. **Deploy:** push to `main`, or use Actions → Build and deploy → Run workflow.

After that, every push to `main` is tested and deployed automatically. If a test fails,
nothing is deployed.

## Backups

Everything is stored in one SQLite file inside the `linkvault-data` volume:

```bash
docker exec linkvault python -c "import sqlite3; s=sqlite3.connect('/data/linkvault.db'); d=sqlite3.connect('/data/backup.db'); s.backup(d)"
docker cp linkvault:/data/backup.db ./linkvault-$(date +%F).db
```

## Limitations to know about

- **Embedded viewer:** on the web, the viewer is an iframe. Many large sites (GitHub, Google,
  banks, most social networks) refuse to be framed. The app detects this and offers
  *Open in browser* instead.
- **Single instance:** rate limits live in memory, and each browser tab keeps a live WebSocket
  session. Run a single container, or enable sticky sessions and move rate limits to Redis
  before scaling out.
- **No email:** there is no password reset. An admin can reset a password with
  `auth.hash_password()` in a `docker exec` Python shell.
