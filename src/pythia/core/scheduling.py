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
    from pythia.core.tasks import run_seed_fn
    run_seed_fn.delay(fn_name)


def _run_feed_fn(fn_name: str) -> None:
    from pythia.core.tasks import poll_all_feeds, process_article_queue

    if fn_name == "process_article_queue":
        process_article_queue.delay()
    else:
        poll_all_feeds.delay()




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
    _scheduler.add_job(
        lambda: _run_seed_fn("seed_abuse_ch"), "cron", hour=2, minute=0, id="abuse_ch"
    )
    _scheduler.add_job(lambda: _run_seed_fn("seed_ipsum"), "cron", hour=3, minute=0, id="ipsum")
    _scheduler.add_job(
        lambda: _run_seed_fn("seed_phishtank"), "cron", hour=3, minute=30, id="phishtank"
    )

    # Weekly feeds (Sunday early morning)
    _scheduler.add_job(
        lambda: _run_seed_fn("seed_apt_sheet"), "cron", day_of_week="sun", hour=4, id="apt_sheet"
    )
    _scheduler.add_job(
        lambda: _run_seed_fn("seed_malpedia"), "cron", day_of_week="sun", hour=5, id="malpedia"
    )
    _scheduler.add_job(
        lambda: _run_seed_fn("seed_yara_rules"), "cron", day_of_week="sun", hour=6, id="yara_rules"
    )
    _scheduler.add_job(
        lambda: _run_seed_fn("seed_icewater"), "cron", day_of_week="sun", hour=7, id="icewater"
    )
    _scheduler.add_job(
        lambda: _run_seed_fn("seed_signature_base"),
        "cron",
        day_of_week="sun",
        hour=8,
        id="signature_base",
    )
    _scheduler.add_job(
        lambda: _run_seed_fn("seed_otx_actors"), "cron", day_of_week="sun", hour=9, id="otx"
    )
    _scheduler.add_job(
        lambda: _run_seed_fn("seed_claude_ttp_inference"),
        "cron",
        day_of_week="sun",
        hour=10,
        id="claude_ttp",
    )
    _scheduler.add_job(
        lambda: _run_seed_fn("seed_sophistication"),
        "cron",
        day_of_week="sun",
        hour=11,
        id="sophistication",
    )

    # Intel feed: poll RSS sources every 4 hours
    _scheduler.add_job(lambda: _run_feed_fn("poll_all_feeds"), "interval", hours=4, id="feed_poll")
    # Intel feed: process queued articles every hour (only fires if auto_ingest sources exist)
    _scheduler.add_job(
        lambda: _run_feed_fn("process_article_queue"), "interval", hours=1, id="feed_ingest"
    )


    # Honeypot: campaign detection every 15 minutes
    _scheduler.add_job(
        _run_campaign_detection,
        "interval",
        minutes=15,
        id="campaign_detection",
    )

    # Honeypot: daily summary report at 00:00 UTC
    _scheduler.add_job(
        _run_daily_honeypot_report,
        "cron",
        hour=0,
        minute=0,
        id="honeypot_daily_report",
    )

    _scheduler.start()


def _run_campaign_detection() -> None:
    from pythia.ingestion.campaign_detector import run_campaign_detection

    run_campaign_detection()


def _run_daily_honeypot_report() -> None:
    from pythia.core.db import SessionLocal
    from pythia.reporting.honeypot_report import generate_daily_honeypot_report

    with SessionLocal() as session:
        generate_daily_honeypot_report(session)


def stop_scheduler() -> None:
    """Shut down the background scheduler gracefully."""
    global _scheduler
    if _scheduler is not None and _scheduler.running:
        _scheduler.shutdown(wait=False)
    _scheduler = None
