from dataclasses import asdict, dataclass
from urllib.parse import urlparse

from bs4 import BeautifulSoup


SENSITIVE_TERMS = {
    "password", "passcode", "pin", "otp", "cvv", "card", "card_number",
    "upi", "vpa", "bank", "account", "ifsc", "mpin", "verification",
}
SUSPICIOUS_JS = ("window.location", "location.href", "location.replace", "document.location")


@dataclass(frozen=True)
class BehavioralSignals:
    external_form_action: bool = False
    suspicious_redirect: bool = False
    brand_keyword_count: int = 0
    sensitive_inputs: tuple[str, ...] = ()
    external_form_posts: tuple[str, ...] = ()
    external_resources: tuple[str, ...] = ()
    iframe_count: int = 0
    script_count: int = 0
    suspicious_script_markers: tuple[str, ...] = ()
    form_count: int = 0

    def to_dict(self) -> dict:
        return asdict(self)


def inspect_dom(html: str, brand_keywords: list[str], page_url: str | None = None) -> BehavioralSignals:
    soup = BeautifulSoup(html, "html.parser")
    text = soup.get_text(" ", strip=True).lower()
    origin = urlparse(page_url).netloc.lower() if page_url else None

    inputs: list[str] = []
    for field in soup.find_all("input"):
        raw = " ".join(str(field.get(key, "")) for key in ("name", "id", "type", "placeholder", "autocomplete"))
        if raw.strip():
            inputs.append(raw.lower())

    external_posts: set[str] = set()
    for form in soup.find_all("form"):
        action = str(form.get("action", "")).strip()
        if action.startswith(("http://", "https://")) and origin and urlparse(action).netloc.lower() != origin:
            external_posts.add(action)

    external_resources: set[str] = set()
    resource_tags = ("script", "img", "iframe", "link", "source")
    for tag_name in resource_tags:
        for tag in soup.find_all(tag_name):
            candidate = tag.get("src") or tag.get("href")
            if not candidate or not origin:
                continue
            if str(candidate).startswith(("http://", "https://")) and urlparse(str(candidate)).netloc.lower() != origin:
                external_resources.add(str(candidate))

    suspicious_markers = tuple(marker for marker in SUSPICIOUS_JS if marker in html.lower())
    sensitive = tuple(sorted({name for name in inputs if any(term in name for term in SENSITIVE_TERMS)}))
    brand_count = sum(text.count(word.lower()) for word in brand_keywords if word.strip())

    return BehavioralSignals(
        external_form_action=bool(external_posts),
        suspicious_redirect=bool(suspicious_markers),
        brand_keyword_count=brand_count,
        sensitive_inputs=sensitive,
        external_form_posts=tuple(sorted(external_posts)),
        external_resources=tuple(sorted(external_resources))[:50],
        iframe_count=len(soup.find_all("iframe")),
        script_count=len(soup.find_all("script")),
        suspicious_script_markers=suspicious_markers,
        form_count=len(soup.find_all("form")),
    )
