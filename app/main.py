"""LinkVault - save, share and safely open websites. Flet web app entry point."""
import asyncio
import logging

import flet as ft

import db
import security
from config import RESCAN_HOURS
from ui import App

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("linkvault")

db.init_db()
_worker_started = False


async def rescan_worker():
    """Periodically re-checks shared/public links: a site that was fine last month may not be now."""
    while True:
        try:
            stale = db.list_links_to_rescan(db.now() - RESCAN_HOURS * 3600)
            for link in stale:
                result = await security.scan_url(link["url"])
                db.apply_scan(link["id"], result)
                if result.blocked:
                    log.warning("link %s is now blocked: %s", link["id"], result.reasons)
                await asyncio.sleep(1)
        except Exception:
            log.exception("rescan worker error")
        await asyncio.sleep(30 * 60)


async def main(page: ft.Page):
    global _worker_started
    if not _worker_started:
        _worker_started = True
        asyncio.get_running_loop().create_task(rescan_worker())
    await App(page).start()


if __name__ == "__main__":
    # In the container Flet runs as a web server (see FLET_* variables in the Dockerfile)
    ft.run(main, view=ft.AppView.WEB_BROWSER)
