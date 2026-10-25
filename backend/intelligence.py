import asyncio
import hashlib
import ipaddress
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

import httpx


def _hostname(url: str) -> str:
    return (urlparse(url).hostname or "").lower().strip(".")


def _is_private_or_local(host: str) -> bool:
    if host in {"localhost", "127.0.0.1", "::1"}:
        return True
    try:
        return ipaddress.ip_address(host).is_private
    except ValueError:
        return False


def lexical_features(url: str) -> dict:
    parsed = urlparse(url)
    host = _hostname(url)
    path = parsed.path or ""
    query = parsed.query or ""
    suspicious_terms = ("login", "verify", "secure", "payment", "upi", "otp", "pin", "wallet", "bank")
    return {
        "hostname_length": len(host),
        "url_length": len(url),
        "subdomain_count": max(0, host.count(".")),
        "hyphen_count": host.count("-"),
        "digit_count": sum(ch.isdigit() for ch in host),
        "path_depth": len([part for part in path.split("/") if part]),
        "query_length": len(query),
        "uses_https": parsed.scheme == "https",
        "suspicious_term_hits": sum(term in url.lower() for term in suspicious_terms),
        "has_at_symbol": "@" in url,
        "has_punycode": "xn--" in host,
    }


def resolve_dns(host: str) -> dict:
    if not host:
        return {"addresses": [], "error": "missing hostname"}
    try:
        records = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        addresses = sorted({item[4][0] for item in records})
        return {"addresses": addresses[:20], "count": len(addresses)}
    except OSError as exc:
        return {"addresses": [], "error": str(exc)}


def tls_certificate(host: str, port: int = 443) -> dict:
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=4) as raw:
            with context.wrap_socket(raw, server_hostname=host) as sock:
                cert_der = sock.getpeercert(binary_form=True)
                cert = sock.getpeercert()
                return {
                    "subject": dict(x[0] for x in cert.get("subject", [])),
                    "issuer": dict(x[0] for x in cert.get("issuer", [])),
                    "not_before": cert.get("notBefore"),
                    "not_after": cert.get("notAfter"),
                    "sha256": hashlib.sha256(cert_der).hexdigest(),
                    "tls_version": sock.version(),
                }
    except (OSError, ssl.SSLError) as exc:
        return {"error": str(exc)}


async def rdap_domain(host: str) -> dict:
    if not host or _is_private_or_local(host):
        return {"skipped": True, "reason": "local/private hostname"}
    try:
        async with httpx.AsyncClient(timeout=5, follow_redirects=True, headers={"User-Agent": "UPI-Shield/1.0"}) as client:
            response = await client.get(f"https://rdap.org/domain/{host}")
            if response.status_code >= 400:
                return {"status_code": response.status_code}
            data = response.json()
        events = {}
        for event in data.get("events", []):
            if event.get("eventAction") and event.get("eventDate"):
                events[event["eventAction"]] = event["eventDate"]
        created = events.get("registration") or events.get("creation")
        age_days = None
        if created:
            try:
                dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
                age_days = max(0, (datetime.now(timezone.utc) - dt).days)
            except ValueError:
                pass
        return {"registrar": next((e.get("handle") for e in data.get("entities", []) if e.get("roles") and "registrar" in e["roles"]), None), "events": events, "age_days": age_days}
    except (httpx.HTTPError, ValueError) as exc:
        return {"error": str(exc)}


async def analyze_domain(
    url: str,
    active_lookups: bool = False,
) -> dict:
    host = _hostname(url)
    parsed = urlparse(url)

    if active_lookups:
        dns_task = asyncio.to_thread(resolve_dns, host)
        rdap_task = rdap_domain(host)
        if parsed.scheme == "https" and host:
            dns, tls, rdap = await asyncio.gather(
                dns_task,
                asyncio.to_thread(tls_certificate, host),
                rdap_task,
            )
        else:
            dns, rdap = await asyncio.gather(
                dns_task,
                rdap_task,
            )
            tls = {}
    else:
        skipped = {
            "skipped": True,
            "reason": "target is not in the crawl allowlist",
        }
        dns = skipped.copy()
        tls = skipped.copy()
        rdap = skipped.copy()

    return {
        "hostname": host,
        "scheme": parsed.scheme,
        "dns": dns,
        "tls": tls,
        "rdap": rdap,
        "lexical": lexical_features(url),
    }


def domain_risk(intel: dict) -> tuple[float, list[str]]:
    score = 0.0
    reasons: list[str] = []
    lexical = intel.get("lexical", {})
    if lexical.get("has_punycode"):
        score += 0.15; reasons.append("Punycode hostname")
    if lexical.get("has_at_symbol"):
        score += 0.15; reasons.append("URL contains @")
    if lexical.get("suspicious_term_hits", 0) >= 2:
        score += 0.10; reasons.append("Multiple payment/security terms in URL")
    if lexical.get("digit_count", 0) >= 4:
        score += 0.05; reasons.append("Digit-heavy hostname")
    age = intel.get("rdap", {}).get("age_days")
    if isinstance(age, int) and age < 30:
        score += 0.20; reasons.append("Domain registered within 30 days")
    if intel.get("dns", {}).get("addresses") == [] and not intel.get("dns", {}).get("error") is None:
        score += 0.05; reasons.append("DNS resolution failed")
    return round(min(score, 1.0), 4), reasons
