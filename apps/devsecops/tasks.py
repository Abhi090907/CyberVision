from __future__ import annotations

import logging
import os
from typing import Any

from celery import shared_task

from apps.scanner.services import ScanService

logger = logging.getLogger("devsecops")


@shared_task(name="devsecops.async_scan_task")
def async_scan_task(url: str) -> dict[str, Any]:
    logger.info("Starting async scan task for url=%s", url)
    scan = ScanService.start_scan(target=url, scan_type="full")
    logger.info("Completed async scan task scan_id=%s url=%s", scan.id, url)
    return {"scan_id": scan.id, "url": scan.target, "status": scan.status}


def queue_scan(url: str) -> dict[str, Any]:
    use_celery = os.getenv("ENABLE_CELERY", "true").lower() == "true"
    if use_celery:
        try:
            task = async_scan_task.delay(url)
            return {"scan_id": None, "task_id": task.id, "url": url, "queued": True}
        except Exception as exc:
            logger.warning("Celery unavailable, falling back to sync scan url=%s error=%s", url, exc)

    scan = ScanService.start_scan(target=url, scan_type="full")
    return {"scan_id": scan.id, "task_id": None, "url": scan.target, "queued": False}


def queue_multi_target_scan(urls: list[str]) -> dict[str, list[int]]:
    scan_ids: list[int] = []
    for url in urls:
        result = queue_scan(url)
        if result.get("scan_id"):
            scan_ids.append(int(result["scan_id"]))
    return {"scan_ids": scan_ids}
