import csv
import time
from pathlib import Path
from statistics import mean

from .detection.scorer import score


POSITIVE_LABELS = {
    "phishing",
    "malicious",
    "1",
    "true",
    "yes",
}

NEGATIVE_LABELS = {
    "benign",
    "legitimate",
    "safe",
    "0",
    "false",
    "no",
}


def _is_positive(label: str) -> bool:
    value = str(label or "").strip().lower()

    if value in POSITIVE_LABELS:
        return True

    if value in NEGATIVE_LABELS:
        return False

    return False


def _metrics(tp: int, fp: int, fn: int, tn: int) -> dict:
    precision = (
        tp / (tp + fp)
        if (tp + fp)
        else 0.0
    )

    recall = (
        tp / (tp + fn)
        if (tp + fn)
        else 0.0
    )

    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision + recall)
        else 0.0
    )

    false_positive_rate = (
        fp / (fp + tn)
        if (fp + tn)
        else 0.0
    )

    accuracy = (
        (tp + tn) / (tp + fp + fn + tn)
        if (tp + fp + fn + tn)
        else 0.0
    )

    specificity = (
        tn / (tn + fp)
        if (tn + fp)
        else 0.0
    )

    return {
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "false_positive_rate": round(false_positive_rate, 4),
        "specificity": round(specificity, 4),
    }


def evaluate_labels(
    path: str | Path = "data/labels.csv",
) -> dict:

    dataset_path = Path(path)

    if not dataset_path.exists():
        raise FileNotFoundError(
            f"Evaluation dataset not found: {dataset_path}"
        )

    rows = list(
        csv.DictReader(
            dataset_path
            .read_text(encoding="utf-8")
            .splitlines()
        )
    )

    tp = fp = fn = tn = 0

    errors = []
    samples = []

    latencies_ms = []

    for row in rows:

        url = row.get("url", "")
        screenshot = row.get("screenshot", "")
        dom = row.get("dom", "")
        brand = row.get("brand", "")

        started = time.perf_counter()

        try:
            result = score(
                url,
                screenshot,
                dom,
                [brand] if brand else [],
            )

            latency_ms = (
                time.perf_counter() - started
            ) * 1000

            latencies_ms.append(latency_ms)

        except Exception as exc:

            latency_ms = (
                time.perf_counter() - started
            ) * 1000

            errors.append(
                {
                    "url": url,
                    "error": str(exc),
                }
            )

            continue

        predicted = (
            result.get("verdict") == "phishing"
        )

        actual = _is_positive(
            row.get("label", "")
        )

        if predicted and actual:
            tp += 1

        elif predicted and not actual:
            fp += 1

        elif not predicted and actual:
            fn += 1

        else:
            tn += 1

        samples.append(
            {
                "url": url,
                "actual": (
                    "phishing"
                    if actual
                    else "benign"
                ),
                "predicted": result.get(
                    "verdict",
                    "unknown",
                ),
                "score": result.get(
                    "score",
                    0.0,
                ),
                "latency_ms": round(
                    latency_ms,
                    2,
                ),
            }
        )

    evaluated = tp + fp + fn + tn

    metrics = _metrics(
        tp,
        fp,
        fn,
        tn,
    )

    average_latency = (
        mean(latencies_ms)
        if latencies_ms
        else 0.0
    )

    max_latency = (
        max(latencies_ms)
        if latencies_ms
        else 0.0
    )

    min_latency = (
        min(latencies_ms)
        if latencies_ms
        else 0.0
    )

    return {
        "dataset": str(dataset_path),

        "samples": len(rows),

        "evaluated": evaluated,

        "errors_count": len(errors),

        "confusion_matrix": {
            "true_positive": tp,
            "false_positive": fp,
            "false_negative": fn,
            "true_negative": tn,
        },

        "true_positive": tp,
        "false_positive": fp,
        "false_negative": fn,
        "true_negative": tn,

        "metrics": metrics,

        # Backward-compatible fields
        "accuracy": metrics["accuracy"],
        "precision": metrics["precision"],
        "recall": metrics["recall"],
        "f1": metrics["f1"],
        "false_positive_rate": metrics[
            "false_positive_rate"
        ],

        "latency": {
            "average_ms": round(
                average_latency,
                2,
            ),
            "minimum_ms": round(
                min_latency,
                2,
            ),
            "maximum_ms": round(
                max_latency,
                2,
            ),
            "samples_measured": len(
                latencies_ms
            ),
        },

        "errors": errors,

        "samples_detail": samples,
    }