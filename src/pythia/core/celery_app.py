from __future__ import annotations

import os
from celery import Celery
from pythia.core.config import get_settings

settings = get_settings()

celery_app = Celery(
    "pythia",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
    include=["pythia.core.tasks"]
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
)
