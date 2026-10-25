from collections.abc import AsyncIterator
from datetime import datetime
import json

from neo4j import AsyncGraphDatabase
from sqlalchemy import DateTime, Float, ForeignKey, Integer, JSON, String, Text, func, select
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from .config import get_settings


settings = get_settings()


engine = create_async_engine(
    settings.database_url,
    pool_pre_ping=True,
)


session_factory = async_sessionmaker(
    engine,
    expire_on_commit=False,
)


neo4j_driver = AsyncGraphDatabase.driver(
    settings.neo4j_uri,
    auth=(
        settings.neo4j_user,
        settings.neo4j_password,
    ),
)


class Base(DeclarativeBase):
    pass


# ============================================================
# Analyst authentication
# ============================================================

class AnalystUser(Base):
    __tablename__ = "analyst_users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(254), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(256))
    full_name: Mapped[str] = mapped_column(String(120), default="")
    mobile_number: Mapped[str] = mapped_column(String(16), default="")
    is_verified: Mapped[bool] = mapped_column(default=False, index=True)
    verified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    login_count: Mapped[int] = mapped_column(Integer, default=0)
    last_login_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
    )


class EmailVerificationToken(Base):
    __tablename__ = "email_verification_tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("analyst_users.id", ondelete="CASCADE"),
        index=True,
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        index=True,
    )
    issued_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
    )


class AnalystSession(Base):
    __tablename__ = "analyst_sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("analyst_users.id", ondelete="CASCADE"),
        index=True,
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        index=True,
    )


class ActivityEvent(Base):
    __tablename__ = "activity_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int | None] = mapped_column(
        ForeignKey("analyst_users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    event_type: Mapped[str] = mapped_column(String(64), index=True)
    event_metadata: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        index=True,
    )


# ============================================================
# Detection table
# ============================================================

class DetectionRecord(Base):
    __tablename__ = "detections"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
    )

    url: Mapped[str] = mapped_column(
        String(2048),
        index=True,
    )

    brand: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    score: Mapped[float] = mapped_column(
        Float,
        default=0.0,
    )

    verdict: Mapped[str] = mapped_column(
        String(32),
        index=True,
    )

    screenshot: Mapped[str] = mapped_column(
        String(2048),
    )

    dom: Mapped[str] = mapped_column(
        String(2048),
    )

    signals: Mapped[dict] = mapped_column(
        JSON,
        default=dict,
    )

    evidence: Mapped[dict] = mapped_column(
        JSON,
        default=dict,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        index=True,
    )


# ============================================================
# Threat Intelligence table
# ============================================================

class ThreatIntelRecord(Base):
    __tablename__ = "threat_intelligence"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    indicator_id: Mapped[str] = mapped_column(
        String(64),
        unique=True,
        index=True,
        nullable=False,
    )

    indicator_type: Mapped[str] = mapped_column(
        String(32),
        index=True,
        nullable=False,
    )

    indicator: Mapped[str] = mapped_column(
        Text,
        index=True,
        nullable=False,
    )

    source: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
    )

    confidence: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        default=0.5,
    )

    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )

    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )

    tags: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        default="[]",
    )


# ============================================================
# JSON safety
# ============================================================

def make_json_safe(value):
    """
    Convert values produced by NumPy/OpenCV/ML libraries
    into values that PostgreSQL JSON can serialize.
    """

    if value is None:
        return None

    if isinstance(value, (str, int, float, bool)):
        return value

    if isinstance(value, dict):
        return {
            str(key): make_json_safe(item)
            for key, item in value.items()
        }

    if isinstance(value, (list, tuple, set)):
        return [
            make_json_safe(item)
            for item in value
        ]

    # NumPy scalar values
    if hasattr(value, "item"):
        try:
            return make_json_safe(value.item())
        except (ValueError, TypeError):
            pass

    # NumPy arrays
    if hasattr(value, "tolist"):
        try:
            return make_json_safe(value.tolist())
        except (ValueError, TypeError):
            pass

    return str(value)


# ============================================================
# Database initialization
# ============================================================

async def init_db() -> None:
    async with engine.begin() as connection:
        await connection.run_sync(
            Base.metadata.create_all
        )
        await connection.run_sync(_migrate_analyst_user_columns)


def _migrate_analyst_user_columns(connection) -> None:
    from sqlalchemy import inspect

    columns = {
        column["name"]
        for column in inspect(connection).get_columns("analyst_users")
    }
    additions = {
        "full_name": "VARCHAR(120) NOT NULL DEFAULT ''",
        "mobile_number": "VARCHAR(16) NOT NULL DEFAULT ''",
        "is_verified": "BOOLEAN NOT NULL DEFAULT FALSE",
        "verified_at": "TIMESTAMP WITH TIME ZONE",
        "login_count": "INTEGER NOT NULL DEFAULT 0",
        "last_login_at": "TIMESTAMP WITH TIME ZONE",
    }
    added_verification_status = "is_verified" not in columns
    for name, definition in additions.items():
        if name not in columns:
            connection.exec_driver_sql(
                f'ALTER TABLE analyst_users ADD COLUMN "{name}" {definition}'
            )
    if added_verification_status:
        connection.exec_driver_sql(
            "UPDATE analyst_users SET is_verified = TRUE"
        )

    verification_columns = {
        column["name"]
        for column in inspect(connection).get_columns("email_verification_tokens")
    }
    if "issued_at" not in verification_columns:
        connection.exec_driver_sql(
            "ALTER TABLE email_verification_tokens ADD COLUMN "
            '"issued_at" TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP'
        )


# ============================================================
# Detection persistence
# ============================================================

async def save_detection(
    session: AsyncSession,
    result: dict,
    screenshot: str,
    dom: str,
) -> DetectionRecord:

    signals = make_json_safe(
        result.get("behavioral", {})
    )

    evidence = make_json_safe(
        {
            "visual": result.get("visual", {}),
            "domain_intel": result.get(
                "domain_intel",
                {},
            ),
            "components": result.get(
                "components",
                {},
            ),
            "reasons": result.get(
                "reasons",
                [],
            ),
            "phash_distance": result.get(
                "phash_distance"
            ),
        }
    )

    record = DetectionRecord(
        url=result["url"],
        brand=result.get("brand"),
        score=float(result["score"]),
        verdict=result["verdict"],
        screenshot=screenshot,
        dom=dom,
        signals=signals,
        evidence=evidence,
    )

    session.add(record)

    await session.commit()

    await session.refresh(record)

    return record


async def get_detections(
    session: AsyncSession,
    verdict: str | None = None,
) -> list[DetectionRecord]:

    query = (
        select(DetectionRecord)
        .order_by(
            DetectionRecord.created_at.desc()
        )
    )

    if verdict:
        query = query.where(
            DetectionRecord.verdict == verdict
        )

    result = await session.execute(query)

    return list(result.scalars())


async def get_detection_by_id(
    session: AsyncSession,
    detection_id: int,
) -> DetectionRecord | None:

    result = await session.execute(
        select(DetectionRecord).where(
            DetectionRecord.id == detection_id
        )
    )

    return result.scalar_one_or_none()


# ============================================================
# Threat Intelligence persistence
# ============================================================

def _parse_datetime(value: str) -> datetime:
    """
    Convert ISO-8601 timestamp into a timezone-aware datetime.
    """

    parsed = datetime.fromisoformat(
        value.replace("Z", "+00:00")
    )

    if parsed.tzinfo is None:
        parsed = parsed.astimezone()

    return parsed


async def save_threat_intel(
    records: list[dict],
) -> int:
    """
    Insert or update normalized threat-intelligence records.

    Existing indicators are updated instead of duplicated.
    """

    saved = 0

    async with session_factory() as session:

        for record in records:

            result = await session.execute(
                select(ThreatIntelRecord).where(
                    ThreatIntelRecord.indicator_id
                    == record["id"]
                )
            )

            existing = result.scalar_one_or_none()

            if existing:

                existing.last_seen = _parse_datetime(
                    record["last_seen"]
                )

                existing.confidence = float(
                    record["confidence"]
                )

                existing.source = record["source"]

                existing.tags = json.dumps(
                    record.get("tags", [])
                )

            else:

                item = ThreatIntelRecord(
                    indicator_id=record["id"],
                    indicator_type=record["type"],
                    indicator=record["indicator"],
                    source=record["source"],
                    confidence=float(
                        record["confidence"]
                    ),
                    first_seen=_parse_datetime(
                        record["first_seen"]
                    ),
                    last_seen=_parse_datetime(
                        record["last_seen"]
                    ),
                    tags=json.dumps(
                        record.get("tags", [])
                    ),
                )

                session.add(item)

                saved += 1

        await session.commit()

    return saved


async def get_threat_intel(
    indicator_type: str | None = None,
) -> list[ThreatIntelRecord]:

    async with session_factory() as session:

        query = (
            select(ThreatIntelRecord)
            .order_by(
                ThreatIntelRecord.last_seen.desc()
            )
        )

        if indicator_type:
            query = query.where(
                ThreatIntelRecord.indicator_type
                == indicator_type
            )

        result = await session.execute(query)

        return list(result.scalars())


async def find_threat_indicator(indicator: str) -> ThreatIntelRecord | None:
    from urllib.parse import urlparse

    raw = indicator.strip().lower()

    candidates = [raw]

    # If input is a URL, also check hostname.
    if "://" in raw:
        parsed = urlparse(raw)
        hostname = (parsed.hostname or "").lower()

        if hostname:
            candidates.append(hostname)

    async with session_factory() as session:
        # 1. Exact URL/domain/IP match
        result = await session.execute(
            select(ThreatIntelRecord)
            .where(ThreatIntelRecord.indicator.in_(candidates))
            .order_by(ThreatIntelRecord.confidence.desc())
        )

        match = result.scalars().first()

        if match:
            return match

        # 2. Domain intelligence:
        # If observed URL is a subdomain, match a known parent domain.
        if "://" in raw:
            parsed = urlparse(raw)
            hostname = (parsed.hostname or "").lower()

            if hostname:
                result = await session.execute(
                    select(ThreatIntelRecord)
                    .where(
                        ThreatIntelRecord.indicator_type == "domain"
                    )
                    .order_by(ThreatIntelRecord.confidence.desc())
                )

                records = result.scalars().all()

                for record in records:
                    known_domain = record.indicator.lower()

                    if (
                        hostname == known_domain
                        or hostname.endswith("." + known_domain)
                    ):
                        return record

    return None

    async with session_factory() as session:

        result = await session.execute(
            select(ThreatIntelRecord).where(
                ThreatIntelRecord.indicator
                == indicator
            )
        )

        return result.scalar_one_or_none()


# ============================================================
# Database session
# ============================================================

async def get_db_session() -> AsyncIterator[AsyncSession]:

    async with session_factory() as session:
        yield session


# ============================================================
# Health checks
# ============================================================

async def db_health() -> bool:

    try:

        async with engine.connect() as connection:

            await connection.exec_driver_sql(
                "SELECT 1"
            )

        return True

    except Exception:

        return False


async def neo4j_health() -> bool:

    try:

        async with neo4j_driver.session() as session:

            result = await session.run(
                "RETURN 1 AS ok"
            )

            await result.single()

        return True

    except Exception:

        return False


# ============================================================
# Shutdown
# ============================================================

async def close_connections() -> None:

    await engine.dispose()

    await neo4j_driver.close()