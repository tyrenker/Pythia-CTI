import logging
from celery import shared_task
from pythia.core.db import SessionLocal
from pythia.core import seed as _seed_mod
from pythia.ingestion import feed_poller as _poller
from pythia.core.config import get_settings

logger = logging.getLogger(__name__)

@shared_task(name="pythia.tasks.run_seed_fn")
def run_seed_fn(fn_name: str) -> None:
    fn = getattr(_seed_mod, fn_name)
    logger.info(f"Running seed function: {fn_name} via Celery")
    with SessionLocal() as session:
        fn(session, dry_run=False)

@shared_task(name="pythia.tasks.poll_all_feeds")
def poll_all_feeds() -> None:
    logger.info("Polling all feeds via Celery")
    with SessionLocal() as session:
        _poller.poll_all_feeds(session)

@shared_task(name="pythia.tasks.process_article_queue")
def process_article_queue() -> None:
    settings = get_settings()
    logger.info("Processing article queue via Celery")
    with SessionLocal() as session:
        _poller.process_article_queue(session, limit=settings.feed_max_articles_per_run)

# We can also add specific parsing tasks here if we refactor `process_article_queue` to enqueue individual articles.
