from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from urllib.parse import urlparse

from ..db import (
    get_db_session,
    get_detections,
    neo4j_driver,
)


# ---------------------------------------------------------------------------
# Neo4j schema
# ---------------------------------------------------------------------------

SCHEMA = (
    """
    CREATE CONSTRAINT domain_unique IF NOT EXISTS
    FOR (d:Domain)
    REQUIRE d.name IS UNIQUE
    """,
    """
    CREATE CONSTRAINT ip_unique IF NOT EXISTS
    FOR (i:IP)
    REQUIRE i.addr IS UNIQUE
    """,
    """
    CREATE CONSTRAINT asn_unique IF NOT EXISTS
    FOR (a:ASN)
    REQUIRE a.id IS UNIQUE
    """,
    """
    CREATE CONSTRAINT cert_unique IF NOT EXISTS
    FOR (c:Cert)
    REQUIRE c.sha IS UNIQUE
    """,
    """
    CREATE CONSTRAINT upi_unique IF NOT EXISTS
    FOR (u:UPI)
    REQUIRE u.vpa IS UNIQUE
    """,
    """
    CREATE CONSTRAINT kit_unique IF NOT EXISTS
    FOR (k:Kit)
    REQUIRE k.hash IS UNIQUE
    """,
    """
    CREATE CONSTRAINT brand_unique IF NOT EXISTS
    FOR (b:Brand)
    REQUIRE b.name IS UNIQUE
    """,
    """
    CREATE CONSTRAINT observation_unique IF NOT EXISTS
    FOR (o:Observation)
    REQUIRE o.id IS UNIQUE
    """,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _clean(value: str | None) -> str | None:
    if value is None:
        return None

    value = str(value).strip()

    return value or None


def _observation_id(
    domain: str,
    ip: str | None,
    asn: str | None,
    cert_sha: str | None,
    upi_id: str | None,
    kit_hash: str | None,
    brand: str | None,
    observation_id: str | None = None,
) -> str:
    """
    Generate a deterministic observation identifier.

    If the caller provides an explicit observation_id, use it.

    Otherwise generate a stable ID from the infrastructure
    indicators so repeated ingestion of the same observation
    does not create unlimited duplicate Observation nodes.
    """

    explicit = _clean(observation_id)

    if explicit:
        return explicit

    payload = {
        "domain": _clean(domain),
        "ip": _clean(ip),
        "asn": _clean(asn),
        "cert_sha": _clean(cert_sha),
        "upi_id": _clean(upi_id),
        "kit_hash": _clean(kit_hash),
        "brand": _clean(brand),
    }

    raw = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
    )

    digest = hashlib.sha256(
        raw.encode("utf-8")
    ).hexdigest()[:24]

    return f"OBS-{digest}"


# ---------------------------------------------------------------------------
# Schema initialization
# ---------------------------------------------------------------------------

async def init_schema() -> None:
    import asyncio

    last_error = None

    for _ in range(6):
        try:
            async with neo4j_driver.session() as session:
                for statement in SCHEMA:
                    await session.run(statement)

            return

        except Exception as exc:
            last_error = exc
            await asyncio.sleep(2)

    raise RuntimeError(
        f"Neo4j schema initialization failed: {last_error}"
    )


# ---------------------------------------------------------------------------
# Add infrastructure observation
# ---------------------------------------------------------------------------

async def add_observation(
    domain: str,
    ip: str | None = None,
    asn: str | None = None,
    cert_sha: str | None = None,
    upi_id: str | None = None,
    kit_hash: str | None = None,
    brand: str | None = None,
    observation_id: str | None = None,
    verdict: str | None = None,
    risk_score: float | None = None,
    source: str = "detection",
) -> None:
    """
    Store one infrastructure observation.

    Important design decision:

    Brand attribution is attached to the Observation node,
    NOT directly to the Domain node.

    This prevents a domain from automatically appearing to
    belong to multiple brands simply because several historical
    observations were collected for that domain.
    """

    domain = _clean(domain)

    if not domain:
        raise ValueError(
            "domain is required for graph observation"
        )

    ip = _clean(ip)
    asn = _clean(asn)
    cert_sha = _clean(cert_sha)
    upi_id = _clean(upi_id)
    kit_hash = _clean(kit_hash)
    brand = _clean(brand)
    verdict = _clean(verdict)
    source = _clean(source) or "detection"

    obs_id = _observation_id(
        domain=domain,
        ip=ip,
        asn=asn,
        cert_sha=cert_sha,
        upi_id=upi_id,
        kit_hash=kit_hash,
        brand=brand,
        observation_id=observation_id,
    )

    observed_at = datetime.now(
        timezone.utc
    ).isoformat()

    async with neo4j_driver.session() as session:

        await session.run(
            """
            MERGE (d:Domain {name: $domain})

            MERGE (o:Observation {id: $obs_id})

            SET
                o.observed_at = $observed_at,
                o.verdict = $verdict,
                o.risk_score = $risk_score,
                o.source = $source

            MERGE (d)-[:HAS_OBSERVATION]->(o)

            FOREACH (_ IN CASE
                WHEN $ip IS NULL THEN []
                ELSE [1]
            END |
                MERGE (i:IP {addr: $ip})
                MERGE (o)-[:RESOLVES_TO]->(i)
                MERGE (d)-[:RESOLVES_TO]->(i)
            )

            FOREACH (_ IN CASE
                WHEN $asn IS NULL THEN []
                ELSE [1]
            END |
                MERGE (a:ASN {id: $asn})
                MERGE (o)-[:BELONGS_TO]->(a)
                MERGE (d)-[:BELONGS_TO]->(a)
            )

            FOREACH (_ IN CASE
                WHEN $cert_sha IS NULL THEN []
                ELSE [1]
            END |
                MERGE (c:Cert {sha: $cert_sha})
                MERGE (o)-[:USES_CERT]->(c)
                MERGE (d)-[:USES_CERT]->(c)
            )

            FOREACH (_ IN CASE
                WHEN $upi_id IS NULL THEN []
                ELSE [1]
            END |
                MERGE (u:UPI {vpa: $upi_id})
                MERGE (o)-[:COLLECTS_TO]->(u)
                MERGE (d)-[:COLLECTS_TO]->(u)
            )

            FOREACH (_ IN CASE
                WHEN $kit_hash IS NULL THEN []
                ELSE [1]
            END |
                MERGE (k:Kit {hash: $kit_hash})
                MERGE (o)-[:USES_KIT]->(k)
                MERGE (d)-[:USES_KIT]->(k)
            )

            FOREACH (_ IN CASE
                WHEN $brand IS NULL THEN []
                ELSE [1]
            END |
                MERGE (b:Brand {name: $brand})

                MERGE (o)-[r:MATCHES_BRAND]->(b)

                SET
                    r.observed_at = $observed_at,
                    r.source = $source,
                    r.verdict = $verdict,
                    r.risk_score = $risk_score
            )
            """,
            domain=domain,
            ip=ip,
            asn=asn,
            cert_sha=cert_sha,
            upi_id=upi_id,
            kit_hash=kit_hash,
            brand=brand,
            obs_id=obs_id,
            observed_at=observed_at,
            verdict=verdict,
            risk_score=risk_score,
            source=source,
        )


# ---------------------------------------------------------------------------
# Graph snapshot
# ---------------------------------------------------------------------------

async def graph_snapshot() -> dict:
    """
    Return an analyst-friendly infrastructure graph.

    Observation nodes are intentionally hidden from the public
    graph projection. They are storage/evidence nodes.

    This means the dashboard sees:

        Domain
          |
          +-- IP
          +-- ASN
          +-- Cert
          +-- UPI
          +-- Kit
          |
          +-- Brand

    while Neo4j internally keeps:

        Domain
          |
      Observation
          |
        Brand

    This keeps the graph readable without losing evidence lineage.
    """

    nodes: dict[str, dict] = {}
    links: list[dict[str, str]] = []

    try:
        async with neo4j_driver.session() as session:

            result = await session.run(
                """
                MATCH (a)-[r]->(b)

                WHERE NOT a:Observation
                  AND NOT b:Observation

                RETURN
                    labels(a)[0] AS a_label,

                    coalesce(
                        a.name,
                        a.addr,
                        a.vpa,
                        a.id,
                        a.sha,
                        a.hash
                    ) AS a_id,

                    type(r) AS relation,

                    labels(b)[0] AS b_label,

                    coalesce(
                        b.name,
                        b.addr,
                        b.vpa,
                        b.id,
                        b.sha,
                        b.hash
                    ) AS b_id
                """
            )

            records = await result.data()

        for row in records:

            source_id = row["a_id"]
            target_id = row["b_id"]

            if source_id:
                nodes[str(source_id)] = {
                    "id": str(source_id),
                    "type": row["a_label"],
                    "label": str(source_id),
                }

            if target_id:
                nodes[str(target_id)] = {
                    "id": str(target_id),
                    "type": row["b_label"],
                    "label": str(target_id),
                }

            if source_id and target_id:
                links.append(
                    {
                        "source": str(source_id),
                        "target": str(target_id),
                        "relation": row["relation"],
                    }
                )

    except Exception:
        # If Neo4j is temporarily unavailable,
        # use PostgreSQL as the fallback projection.
        pass

    # -----------------------------------------------------------------------
    # PostgreSQL fallback
    # -----------------------------------------------------------------------

    if nodes:
        return {
            "nodes": list(nodes.values()),
            "links": links,
        }

    async for db_session in get_db_session():

        detections = await get_detections(
            db_session
        )

    # -----------------------------------------------------------------------
    # Build fallback graph
    # -----------------------------------------------------------------------

    for detection in detections:

        domain = (
            urlparse(detection.url).hostname
            or detection.url
        )

        nodes.setdefault(
            domain,
            {
                "id": domain,
                "type": "Domain",
                "label": domain,
            },
        )

        # Only create a brand relationship when the
        # detector actually assigned a brand.
        #
        # Unidentified detections must NOT create an
        # "unidentified" infrastructure node.
        brand = _clean(detection.brand)

        if not brand:
            continue

        brand_id = f"brand:{brand}"

        nodes.setdefault(
            brand_id,
            {
                "id": brand_id,
                "label": brand,
                "type": "Brand",
            },
        )

        links.append(
            {
                "source": domain,
                "target": brand_id,
                "relation": "MATCHES_BRAND",
            }
        )

    return {
        "nodes": list(nodes.values()),
        "links": links,
    }