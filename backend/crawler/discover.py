from pathlib import Path
from collections.abc import Callable

BRAND_KEYWORDS = (
    "paytm", "phonepe", "gpay", "googlepay", "sbi", "hdfc", "icici",
    "axis", "upi", "bhim", "amazonpay", "mobikwik",
)


def load_seed_urls(path: str | Path = "data/seeds.txt") -> list[str]:
    """Load non-empty, non-comment URLs from a seed file."""
    seed_path = Path(path)
    if not seed_path.exists():
        return []
    return [
        line.strip()
        for line in seed_path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def matching_certificate_domains(domains: list[str]) -> list[str]:
    """Filter CT-log domains using conservative brand keyword matching."""
    matches: set[str] = set()
    for domain in domains:
        normalized = domain.lower().lstrip("*.")
        if any(keyword in normalized for keyword in BRAND_KEYWORDS):
            matches.add(f"https://{normalized}")
    return sorted(matches)


def certificate_handler(output: Path = Path("data/discovered.txt")) -> Callable:
    """Build a certstream callback that persists only matching domains."""
    output.parent.mkdir(parents=True, exist_ok=True)
    seen: set[str] = set()

    def handler(message: dict, context: object) -> None:
        del context
        if message.get("message_type") != "certificate_update":
            return
        domains = message.get("data", {}).get("leaf_cert", {}).get("all_domains", [])
        for url in matching_certificate_domains(domains):
            if url not in seen:
                seen.add(url)
                with output.open("a", encoding="utf-8") as stream:
                    stream.write(f"{url}\n")

    return handler
