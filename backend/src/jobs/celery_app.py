"""Celery application configuration."""

from celery import Celery

from src.config import settings

celery_app = Celery(
    "webphomet",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    worker_max_tasks_per_child=100,
    broker_connection_retry_on_startup=True,
)

# Auto-discover tasks from the workers module
celery_app.autodiscover_tasks(["src.jobs"], related_name="workers")
