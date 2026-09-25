"""
Generates assets/index.html = Flet's own index.html + a small connection watchdog.

Why: Flet's browser client only reconnects when the browser reports the WebSocket as
closed. After a laptop sleeps, the network changes, or a proxy silently drops an idle
connection, the socket is "half-open": the browser still says OPEN, clicks are sent into
the void, and nothing happens until the page is reloaded.

The server sends a heartbeat every 20 s (see App._heartbeat). The watchdog below:
  * tracks when the Flet socket last received anything;
  * if it looks open but has been silent for 50 s, closes it -> Flet reconnects to the
    same server session (state is kept);
  * if the connection still isn't healthy ~12 s later (or the client is stuck in a long
    reconnect backoff), reloads the page - but only once the server answers, so users
    never land on a "Bad Gateway" page during a deploy;
  * re-checks immediately when the tab becomes visible again or the network comes back.

Flet serves index.html from the assets directory when one exists there, so this needs
no fork of Flet and keeps working when Flet is upgraded.
"""
import shutil
from pathlib import Path

import flet_web

WATCHDOG = r"""
  <script>
    /* LinkVault connection watchdog - see app/web_patch.py */
    (function () {
      var STALE_MS = 50000, RECOVER_MS = 12000;
      var NativeWS = window.WebSocket, sock = null, lastRx = Date.now();
      var kickedAt = 0, downSince = 0, probing = false;

      function Tracked(url, protocols) {
        var ws = protocols === undefined ? new NativeWS(url) : new NativeWS(url, protocols);
        if (/\/ws(\?|$)/.test(String(url))) {
          sock = ws; lastRx = Date.now();
          ws.addEventListener('message', function () { lastRx = Date.now(); });
          ws.addEventListener('open', function () { lastRx = Date.now(); });
        }
        return ws;
      }
      Tracked.prototype = NativeWS.prototype;
      ['CONNECTING', 'OPEN', 'CLOSING', 'CLOSED'].forEach(function (k) { Tracked[k] = NativeWS[k]; });
      window.WebSocket = Tracked;

      function healthy() {
        return sock && sock.readyState === 1 && Date.now() - lastRx < STALE_MS;
      }

      function reloadWhenServerIsUp() {
        if (probing) return;
        var last = +(sessionStorage.getItem('lv-reload') || 0);
        if (Date.now() - last < 30000) return;           // never loop faster than every 30 s
        probing = true;
        fetch(location.pathname, { cache: 'no-store', credentials: 'same-origin' })
          .then(function (r) {
            if (r.ok) {
              sessionStorage.setItem('lv-reload', String(Date.now()));
              console.warn('[watchdog] connection lost - reloading');
              location.reload();
            }
          })
          .catch(function () { /* server still down - try again on the next check */ })
          .then(function () { probing = false; });
      }

      function check() {
        if (document.hidden || !sock) return;             // background tabs are throttled; wait
        if (healthy()) { kickedAt = 0; downSince = 0; return; }
        var now = Date.now();
        if (!downSince) downSince = now;
        if (sock.readyState === 1 && !kickedAt) {         // "open" but silent = half-open
          kickedAt = now;
          console.warn('[watchdog] no data for ' + Math.round((now - lastRx) / 1000) + 's - reconnecting');
          try { sock.close(4000, 'stale'); } catch (e) {}
          return;
        }
        if (now - downSince > RECOVER_MS) reloadWhenServerIsUp();
      }

      setInterval(check, 5000);
      function soon() { setTimeout(check, 1500); }      // let queued messages arrive first
      document.addEventListener('visibilitychange', function () { if (!document.hidden) soon(); });
      window.addEventListener('online', soon);
      window.addEventListener('focus', soon);
    })();
  </script>
"""

MARKER = "<!-- fletAppConfig -->"


def build_assets(assets_dir: Path) -> Path:
    src = Path(flet_web.get_package_web_dir()) / "index.html"
    html = src.read_text(encoding="utf-8")
    if MARKER in html:
        html = html.replace(MARKER, WATCHDOG + "  " + MARKER, 1)
    else:  # future Flet versions: fall back to end of <head>
        html = html.replace("</head>", WATCHDOG + "</head>", 1)
    assets_dir.mkdir(parents=True, exist_ok=True)
    (assets_dir / "index.html").write_text(html, encoding="utf-8")
    # self-hosted fonts (see palette.FONTS)
    fonts_src = Path(__file__).parent / "fonts"
    if fonts_src.is_dir():
        shutil.copytree(fonts_src, assets_dir / "fonts", dirs_exist_ok=True)
    return assets_dir
