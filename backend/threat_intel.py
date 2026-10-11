from __future__ import annotations

import csv
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


SUPPORTED_TYPES = {
    "domain",
    "ip",
    "url",
    "upi",
    "certificate",
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalize_indicator(indicator: str, indicator_type: str) -> str:
    indicator = indicator.strip()

    if indicator_type == "domain":
        return indicator.lower().rstrip(".")

    if indicator_type == "url":
        return indicator.rstrip()

    if indicator_type == "ip":
        return indicator.strip()

    if indicator_type == "upi":
        return indicator.lower().strip()

    if indicator_type == "certificate":
        return indicator.lower().replace(":", "").strip()

    return indicator


def _infer_type(indicator: str) -> str:
    value = indicator.strip()

    # URL
    parsed = urlparse(value)
    if parsed.scheme in {"http", "https"} and parsed.netloc:
        return "url"

    # UPI identifier
    if "@" in value and "/" not in value and " " not in value:
        return "upi"

    # IPv4
    parts = value.split(".")
    if len(parts) == 4:
        try:
            if all(0 <= int(part) <= 255 for part in parts):
                return "ip"
        except ValueError:
            pass

    # SHA-256 certificate fingerprint
    compact = value.replace(":", "").lower()
    if len(compact) in {40, 64}:
        try:
            int(compact, 16)
            return "certificate"
        except ValueError:
            pass

    # Default to domain
    return "domain"


def _indicator_id(indicator_type: str, indicator: str) -> str:
    raw = f"{indicator_type}:{indicator}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def normalize_indicator(
    indicator: str,
    indicator_type: str | None = None,
    source: str = "controlled-feed",
    confidence: float = 0.5,
    first_seen: str | None = None,
    last_seen: str | None = None,
    tags: list[str] | None = None,
) -> dict[str, Any]:
    if not indicator or not indicator.strip():
        raise ValueError("Indicator cannot be empty")

    resolved_type = (indicator_type or _infer_type(indicator)).lower()

    if resolved_type not in SUPPORTED_TYPES:
        raise ValueError(
            f"Unsupported indicator type: {resolved_type}. "
            f"Supported types: {sorted(SUPPORTED_TYPES)}"
        )

    normalized = _normalize_indicator(indicator, resolved_type)

    if not 0 <= float(confidence) <= 1:
        raise ValueError("Confidence must be between 0 and 1")

    return {
        "id": _indicator_id(resolved_type, normalized),
        "type": resolved_type,
        "indicator": normalized,
        "source": source.strip() or "controlled-feed",
        "confidence": round(float(confidence), 4),
        "first_seen": first_seen or _utc_now(),
        "last_seen": last_seen or _utc_now(),
        "tags": sorted(set(tags or [])),
    }


def ingest_records(records: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Normalize a list of threat-intelligence records.

    This function intentionally performs no network requests.
    It is designed for authorized feeds, analyst submissions,
    and controlled datasets.
    """

    accepted: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []

    for index, record in enumerate(records):
        try:
            item = normalize_indicator(
                indicator=str(record.get("indicator", "")),
                indicator_type=record.get("type"),
                source=str(record.get("source", "controlled-feed")),
                confidence=float(record.get("confidence", 0.5)),
                first_seen=record.get("first_seen"),
                last_seen=record.get("last_seen"),
                tags=record.get("tags", []),
            )

            accepted.append(item)

        except Exception as exc:
            rejected.append(
                {
                    "row": index,
                    "record": record,
                    "error": str(exc),
                }
            )

    return {
        "accepted": accepted,
        "accepted_count": len(accepted),
        "rejected": rejected,
        "rejected_count": len(rejected),
        "processed_at": _utc_now(),
    }


def load_json_feed(path: str | Path) -> dict[str, Any]:
    feed_path = Path(path)

    if not feed_path.exists():
        raise FileNotFoundError(f"Threat-intelligence feed not found: {feed_path}")

    with feed_path.open("r", encoding="utf-8") as file:
        data = json.load(file)

    if isinstance(data, dict):
        records = data.get("indicators", [])
    elif isinstance(data, list):
        records = data
    else:
        raise ValueError("JSON feed must contain an array or an 'indicators' array")

    if not isinstance(records, list):
        raise ValueError("'indicators' must be an array")

    return ingest_records(records)


def load_csv_feed(path: str | Path) -> dict[str, Any]:
    feed_path = Path(path)

    if not feed_path.exists():
        raise FileNotFoundError(f"Threat-intelligence feed not found: {feed_path}")

    records: list[dict[str, Any]] = []

    with feed_path.open("r", encoding="utf-8-sig", newline="") as file:
        reader = csv.DictReader(file)

        if not reader.fieldnames or "indicator" not in reader.fieldnames:
            raise ValueError("CSV feed must contain an 'indicator' column")

        for row in reader:
            tags = row.get("tags", "")

            records.append(
                {
                    "indicator": row.get("indicator", ""),
                    "type": row.get("type") or None,
                    "source": row.get("source") or "controlled-feed",
                    "confidence": row.get("confidence") or 0.5,
                    "first_seen": row.get("first_seen") or None,
                    "last_seen": row.get("last_seen") or None,
                    "tags": [
                        tag.strip()
                        for tag in tags.split(",")
                        if tag.strip()
                    ],
                }
            )

    return ingest_records(records)


def match_indicator(
    value: str,
    feed: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Match an observed value against normalized TI indicators.

    Exact matching is intentional for the MVP.
    Fuzzy/domain-family matching should be implemented separately
    so that analysts can distinguish exact evidence from inference.
    """

    if not value:
        return []

    value = value.strip()

    matches = []

    for item in feed:
        if value.lower() == str(item.get("indicator", "")).lower():
            matches.append(item)

    return matches