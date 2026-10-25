import asyncio
import hashlib
import hmac
import secrets
import time
from email.message import EmailMessage
from datetime import datetime, timedelta, timezone
from email.utils import formataddr
from smtplib import SMTP, SMTP_SSL

from sqlalchemy import delete, select, update

from .config import get_settings
from .db import (
    ActivityEvent,
    AnalystSession,
    AnalystUser,
    EmailVerificationToken,
    session_factory,
)


SESSION_COOKIE_NAME = "upi_shield_session"
SESSION_TTL = timedelta(days=7)
VERIFICATION_TTL = timedelta(hours=24)
PASSWORD_SCRYPT_N = 2**14
_last_activity_cleanup = 0.0
_activity_cleanup_lock = asyncio.Lock()


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    password_hash = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=PASSWORD_SCRYPT_N,
        r=8,
        p=1,
        dklen=64,
    )
    return f"scrypt${PASSWORD_SCRYPT_N}$8$1${salt.hex()}${password_hash.hex()}"


def verify_password(password: str, encoded_hash: str) -> bool:
    try:
        algorithm, n, r, p, salt_hex, expected_hex = encoded_hash.split("$")
        if algorithm != "scrypt":
            return False
        actual = hashlib.scrypt(
            password.encode("utf-8"),
            salt=bytes.fromhex(salt_hex),
            n=int(n),
            r=int(r),
            p=int(p),
            dklen=len(bytes.fromhex(expected_hex)),
        )
        return hmac.compare_digest(actual.hex(), expected_hex)
    except (ValueError, TypeError):
        return False


def _hash_session_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _send_email(to_email: str, subject: str, body: str) -> None:
    settings = get_settings()
    if not settings.smtp_host or not settings.report_from_email:
        raise RuntimeError("SMTP_HOST and REPORT_FROM_EMAIL must be configured")

    message = EmailMessage()
    message["From"] = formataddr(("UPI Shield", settings.report_from_email))
    message["To"] = to_email
    message["Subject"] = subject
    message.set_content(body)

    client_type = SMTP_SSL if settings.smtp_use_ssl else SMTP
    with client_type(settings.smtp_host, settings.smtp_port, timeout=15) as client:
        if settings.smtp_starttls and not settings.smtp_use_ssl:
            client.starttls()
        if settings.smtp_username:
            client.login(settings.smtp_username, settings.smtp_password)
        client.send_message(message)


async def send_email(to_email: str, subject: str, body: str) -> None:
    await asyncio.to_thread(_send_email, to_email, subject, body)


async def create_analyst(
    full_name: str,
    email: str,
    mobile_number: str,
    password: str,
) -> AnalystUser:
    async with session_factory() as session:
        user = AnalystUser(
            email=email,
            full_name=full_name,
            mobile_number=mobile_number,
            password_hash=await asyncio.to_thread(hash_password, password),
            is_verified=False,
        )
        session.add(user)
        await session.commit()
        await session.refresh(user)
        await save_activity_event(
            "registration",
            user_id=user.id,
            metadata={"email": user.email},
            session=session,
        )
        return user


async def issue_verification_token(
    user: AnalystUser,
    minimum_interval_seconds: int = 0,
) -> str | None:
    token = secrets.token_urlsafe(40)
    now = datetime.now(timezone.utc)
    async with session_factory() as session:
        result = await session.execute(
            select(EmailVerificationToken).where(
                EmailVerificationToken.user_id == user.id
            )
        )
        existing = result.scalar_one_or_none()
        issued_at = existing.issued_at if existing is not None else None
        if issued_at is not None and issued_at.tzinfo is None:
            issued_at = issued_at.replace(tzinfo=timezone.utc)
        if (
            issued_at is not None
            and minimum_interval_seconds
            and (now - issued_at).total_seconds()
            < minimum_interval_seconds
        ):
            return None
        await session.execute(
            delete(EmailVerificationToken).where(
                EmailVerificationToken.user_id == user.id
            )
        )
        session.add(
            EmailVerificationToken(
                token_hash=_hash_session_token(token),
                user_id=user.id,
                expires_at=now + VERIFICATION_TTL,
            )
        )
        await session.commit()
    return token


async def verify_analyst_email(token: str) -> AnalystUser | None:
    now = datetime.now(timezone.utc)
    async with session_factory() as session:
        result = await session.execute(
            select(EmailVerificationToken).where(
                EmailVerificationToken.token_hash == _hash_session_token(token),
                EmailVerificationToken.expires_at > now,
            )
        )
        verification = result.scalar_one_or_none()
        if verification is None:
            return None

        user = await session.get(AnalystUser, verification.user_id)
        if user is None:
            await session.delete(verification)
            await session.commit()
            return None

        user.is_verified = True
        user.verified_at = now
        await session.delete(verification)
        session.add(
            ActivityEvent(
                user_id=user.id,
                event_type="email_verified",
                event_metadata={},
            )
        )
        await session.commit()
        return user


async def authenticate_analyst(email: str, password: str) -> AnalystUser | None:
    async with session_factory() as session:
        result = await session.execute(
            select(AnalystUser).where(AnalystUser.email == email)
        )
        user = result.scalar_one_or_none()
        if user is None or not await asyncio.to_thread(
            verify_password,
            password,
            user.password_hash,
        ):
            return None
        if not user.is_verified:
            raise PermissionError("Confirm your email address before signing in")
        return user


async def record_login(user: AnalystUser) -> None:
    now = datetime.now(timezone.utc)
    async with session_factory() as session:
        await session.execute(
            update(AnalystUser)
            .where(AnalystUser.id == user.id)
            .values(
                login_count=AnalystUser.login_count + 1,
                last_login_at=now,
            )
        )
        session.add(
            ActivityEvent(
                user_id=user.id,
                event_type="login",
                event_metadata={},
            )
        )
        await session.commit()


async def save_activity_event(
    event_type: str,
    user_id: int | None = None,
    metadata: dict | None = None,
    session=None,
) -> None:
    global _last_activity_cleanup
    now_monotonic = time.monotonic()
    if now_monotonic - _last_activity_cleanup >= 86400:
        async with _activity_cleanup_lock:
            now_monotonic = time.monotonic()
            if now_monotonic - _last_activity_cleanup >= 86400:
                from sqlalchemy import delete

                from .config import get_settings

                cutoff = datetime.now(timezone.utc) - timedelta(
                    days=get_settings().activity_retention_days
                )
                async with session_factory() as cleanup_session:
                    await cleanup_session.execute(
                        delete(ActivityEvent).where(
                            ActivityEvent.created_at < cutoff
                        )
                    )
                    await cleanup_session.commit()
                _last_activity_cleanup = time.monotonic()

    event = ActivityEvent(
        user_id=user_id,
        event_type=event_type,
        event_metadata=metadata or {},
    )
    if session is not None:
        session.add(event)
        await session.commit()
        return
    async with session_factory() as activity_session:
        activity_session.add(event)
        await activity_session.commit()


async def create_session(user_id: int) -> str:
    token = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    async with session_factory() as session:
        await session.execute(
            delete(AnalystSession).where(AnalystSession.expires_at <= now)
        )
        session.add(
            AnalystSession(
                token_hash=_hash_session_token(token),
                user_id=user_id,
                expires_at=now + SESSION_TTL,
            )
        )
        await session.commit()
    return token


async def find_analyst_by_session(token: str | None) -> AnalystUser | None:
    if not token:
        return None
    now = datetime.now(timezone.utc)
    async with session_factory() as session:
        result = await session.execute(
            select(AnalystUser)
            .join(AnalystSession, AnalystSession.user_id == AnalystUser.id)
            .where(
                AnalystSession.token_hash == _hash_session_token(token),
                AnalystSession.expires_at > now,
            )
        )
        return result.scalar_one_or_none()


async def revoke_session(token: str | None) -> None:
    if not token:
        return
    async with session_factory() as session:
        await session.execute(
            delete(AnalystSession).where(
                AnalystSession.token_hash == _hash_session_token(token)
            )
        )
        await session.commit()
