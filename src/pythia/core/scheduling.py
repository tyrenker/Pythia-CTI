"""Background scheduler for automated threat intel sync via APScheduler.

Only active when the `scheduling` extra is installed and
PYTHIA_ENABLE_SCHEDULER=true is set in the environment.
"""

from __future__ import annotations

from typing import Any

try:
    from apscheduler.schedulers.background import BackgroundScheduler
    _HAS_APSCHEDULER = True
except ImportError:
    _HAS_APSCHEDULER = False

_scheduler: Any = None  # BackgroundScheduler instance when running


def _run_seed_fn(fn_name: str) -> None:
    from pythia.core import seed as _seed_mod
    from pythia.core.db import SessionLocal
    fn = getattr(_seed_mod, fn_name)
    with SessionLocal() as session:
        fn(session, dry_run=False)


def start_scheduler() -> None:
    """Start the background scheduler. No-op if APScheduler is not installed."""
    global _scheduler
    if not _HAS_APSCHEDULER:
        return
    if _scheduler is not None and _scheduler.running:
        return

    from pythia.core.config import get_settings
    if not get_settings().enable_scheduler:
        return

    _scheduler = BackgroundScheduler()

    # Daily feeds
    _scheduler.add_job(lambda: _run_seed_fn("seed_abuse_ch"),  "cron", hour=2,  minute=0,  id="abuse_ch")
    _scheduler.add_job(lambda: _run_seed_fn("seed_ipsum"),     "cron", hour=3,  minute=0,  id="ipsum")
    _scheduler.add_job(lambda: _run_seed_fn("seed_phishtank"), "cron", hour=3,  minute=30, id="phishtank")

    # Weekly feeds (Sunday early morning)
    _scheduler.add_job(lambda: _run_seed_fn("seed_apt_sheet"),      "cron", day_of_week="sun", hour=4, id="apt_sheet")
    _scheduler.add_job(lambda: _run_seed_fn("seed_malpedia"),        "cron", day_of_week="sun", hour=5, id="malpedia")
    _scheduler.add_job(lambda: _run_seed_fn("seed_yara_rules"),      "cron", day_of_week="sun", hour=6, id="yara_rules")
    _scheduler.add_job(lambda: _run_seed_fn("seed_icewater"),        "cron", day_of_week="sun", hour=7, id="icewater")
    _scheduler.add_job(lambda: _run_seed_fn("seed_signature_base"),  "cron", day_of_week="sun", hour=8, id="signature_base")

    _scheduler.start()


def stop_scheduler() -> None:
    """Shut down the background scheduler gracefully."""
    global _scheduler
    if _scheduler is not None and _scheduler.running:
        _scheduler.shutdown(wait=False)
    _scheduler = None
