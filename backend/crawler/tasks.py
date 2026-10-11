from celery import Celery

from ..config import get_settings

celery_app = Celery("upi_shield", broker=get_settings().redis_url)


@celery_app.task
def enqueue_url(url: str) -> str:
    return url
