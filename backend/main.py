from contextlib import asynccontextmanager
from html import escape
import hmac
import json
import logging
import smtplib
from urllib.parse import quote
import uuid
from datetime import datetime, timedelta, timezone

from pathlib import Path

from fastapi import (
    Depends,
    FastAPI,
    File,
    Form,
    Header,
    HTTPException,
    Request,
    UploadFile,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.types import Scope
from sqlalchemy.exc import IntegrityError
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from .auth import (
    SESSION_COOKIE_NAME,
    SESSION_TTL,
    authenticate_analyst,
    create_analyst,
    create_session,
    find_analyst_by_session,
    issue_verification_token,
    record_login,
    revoke_session,
    save_activity_event,
    send_email,
    verify_analyst_email,
)
from .config import allowed_target, get_settings
from .crawler.capture import capture, close_capture_browser
from .crawler.app_inspector import inspect_apk

from .db import (
    ActivityEvent,
    AnalystUser,
    close_connections,
    db_health,
    DetectionRecord,
    engine,
    find_threat_indicator,
    get_detection_by_id,
    get_detections,
    init_db,
    neo4j_health,
    save_detection,
    save_threat_intel,
    session_factory,
)

from .detection.scorer import score
from .evaluation import evaluate_labels
from .graph.builder import (
    add_observation,
    graph_snapshot,
    init_schema,
)
from .graph.cluster import cluster_graph
from .intelligence import analyze_domain
from .models import (
    AuthCredentials,
    CaptureRequest,
    DetectionRequest,
    DetectionResponse,
    DiscoverRequest,
    EmailTokenRequest,
    GraphObservation,
    PageVisitRequest,
    RegisterRequest,
    ResendVerificationRequest,
)
from .takedown.report import create_report
from .threat_intel import (
    ingest_records,
    load_csv_feed,
    load_json_feed,
)

FRONTEND_ORIGINS = tuple(
    origin.strip().rstrip("/")
    for origin in get_settings().frontend_origins.split(",")
    if origin.strip()
)
logger = logging.getLogger(__name__)


class ArtifactStaticFiles(StaticFiles):
    async def get_response(self, path: str, scope: Scope) -> Response:
        request = Request(scope)
        user = await find_analyst_by_session(
            request.cookies.get(SESSION_COOKIE_NAME)
        )
        if user is None:
            return PlainTextResponse("Authentication required", status_code=401)

        response = await super().get_response(path, scope)
        if path.lower().endswith(".html"):
            response.headers["content-type"] = "text/plain; charset=utf-8"
            response.headers["x-content-type-options"] = "nosniff"
            response.headers["content-disposition"] = "attachment"
        return response


# ============================================================
# Directories
# ============================================================

for directory in (
    Path("data/captures"),
    Path("data/evidence"),
    Path("data/reports"),
    Path("data/discovered"),
):
    directory.mkdir(parents=True, exist_ok=True)


# ============================================================
# Application lifecycle
# ============================================================

@asynccontextmanager
async def lifespan(_: FastAPI):
    await init_db()
    if await neo4j_health():
        try:
            await init_schema()
        except Exception:
            logger.exception(
                "Neo4j schema initialization failed; graph features may be unavailable"
            )
    else:
        logger.warning(
            "Neo4j is unavailable; starting API without graph schema initialization"
        )

    try:
        yield
    finally:
        try:
            await close_capture_browser()
        finally:
            await close_connections()


# ============================================================
# FastAPI application
# ============================================================

app = FastAPI(
    title="UPI Shield API",
    version="1.0.0",
    description=(
        "Defensive detection and investigation platform "
        "for suspected payment-brand abuse."
    ),
    lifespan=lifespan,
)


app.mount(
    "/artifacts",
    ArtifactStaticFiles(directory="data/captures"),
    name="artifacts",
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        *FRONTEND_ORIGINS,
    ],
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=True,
)


# ============================================================
# Authentication
# ============================================================

async def get_current_user(request: Request):
    user = await find_analyst_by_session(
        request.cookies.get(SESSION_COOKIE_NAME)
    )
    if user is None:
        raise HTTPException(status_code=401, detail="Sign in to continue")
    return user


def require_frontend_origin(request: Request) -> None:
    if request.headers.get("origin") not in FRONTEND_ORIGINS:
        raise HTTPException(status_code=403, detail="Untrusted request origin")


async def require_api_key(
    request: Request,
    x_api_key: str | None = Header(default=None),
) -> None:

    configured_key = get_settings().admin_api_key

    if configured_key and x_api_key and hmac.compare_digest(
        x_api_key,
        configured_key,
    ):
        return

    if request.method not in {"GET", "HEAD", "OPTIONS"}:
        require_frontend_origin(request)

    await get_current_user(request)


# ============================================================
# Response helpers
# ============================================================

def response_from_record(record) -> DetectionResponse:

    return DetectionResponse(
        id=record.id,
        url=record.url,
        brand=record.brand,
        score=record.score,
        verdict=record.verdict,
        behavioral=record.signals or {},
        evidence=record.evidence or {},
        screenshot=record.screenshot,
        dom=record.dom,
        created_at=record.created_at,
    )


# ============================================================
# Health / root
# ============================================================

@app.get("/", include_in_schema=False)
async def root() -> dict:

    return {
        "name": "UPI Shield API",
        "version": "1.0.0",
        "docs": "/docs",
        "status": "online",
    }


@app.get("/health")
async def health() -> dict:
    database_connected = await db_health()

    return {
        "status": "ok" if database_connected else "degraded",
        "database_dialect": engine.dialect.name,
        "services": {
            "database": database_connected,
            "postgres": (
                database_connected
                and engine.dialect.name == "postgresql"
            ),
            "neo4j": await neo4j_health(),
        },
    }


# ============================================================
# Analyst authentication
# ============================================================

def _is_secure_request(request: Request) -> bool:
    forwarded_proto = request.headers.get("x-forwarded-proto", "")
    return (
        request.url.scheme == "https"
        or forwarded_proto.split(",", 1)[0].strip().lower() == "https"
    )


def set_session_cookie(response: Response, request: Request, token: str) -> None:
    secure_request = _is_secure_request(request)
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=token,
        max_age=int(SESSION_TTL.total_seconds()),
        httponly=True,
        secure=secure_request,
        samesite="none" if secure_request else "strict",
        path="/",
    )


def analyst_response(user) -> dict:
    admin_emails = {
        email.strip().lower()
        for email in get_settings().admin_emails.split(",")
        if email.strip()
    }
    return {
        "id": user.id,
        "email": user.email,
        "full_name": user.full_name,
        "is_admin": user.email.lower() in admin_emails,
    }


@app.post("/auth/register", status_code=202)
async def register(
    credentials: RegisterRequest,
    request: Request,
) -> Response:
    require_frontend_origin(request)
    try:
        user = await create_analyst(
            credentials.full_name,
            credentials.email,
            credentials.mobile_number,
            credentials.password,
        )
    except IntegrityError as error:
        raise HTTPException(
            status_code=409,
            detail="An account with this email already exists",
        ) from error

    token = await issue_verification_token(user)
    if token is None:
        raise HTTPException(
            status_code=503,
            detail="Could not issue an email confirmation token. Retry shortly.",
        )
    verification_url = (
        f"{FRONTEND_ORIGINS[0]}/login?token={quote(token)}"
        if FRONTEND_ORIGINS
        else ""
    )
    if not verification_url:
        raise HTTPException(
            status_code=503,
            detail="Configure FRONTEND_ORIGINS before sending verification email",
        )
    try:
        await send_email(
            user.email,
            "Confirm your UPI Shield account",
            (
                f"Hello {user.full_name},\n\n"
                "Confirm your email address to activate your analyst account:\n"
                f"{verification_url}\n\n"
                "This confirmation link expires in 24 hours. If you did not "
                "create this account, you can ignore this message."
            ),
        )
    except (OSError, RuntimeError, smtplib.SMTPException) as error:
        logger.exception("Account confirmation email delivery failed")
        raise HTTPException(
            status_code=503,
            detail=(
                "Your account was created but confirmation email could not be "
                "sent. Check SMTP configuration and request another email."
            ),
        ) from error

    response = Response(
        content=json.dumps(
            {
                "message": "Check your email for a confirmation link.",
                "email": user.email,
            }
        ),
        media_type="application/json",
        status_code=202,
    )
    return response


@app.post("/auth/verify")
async def verify_email(credentials: EmailTokenRequest) -> dict:
    user = await verify_analyst_email(credentials.token)
    if user is None:
        raise HTTPException(
            status_code=400,
            detail="Confirmation link is invalid or has expired",
        )
    return {
        "message": "Email confirmed. You can now sign in.",
        "email": user.email,
    }


@app.post("/auth/resend-verification", status_code=202)
async def resend_verification(
    credentials: ResendVerificationRequest,
    request: Request,
) -> dict:
    require_frontend_origin(request)
    async with session_factory() as session:
        result = await session.execute(
            select(AnalystUser).where(AnalystUser.email == credentials.email)
        )
        user = result.scalar_one_or_none()

    if user is not None and not user.is_verified:
        token = await issue_verification_token(
            user,
            minimum_interval_seconds=60,
        )
        if token is not None:
            verification_url = (
                f"{FRONTEND_ORIGINS[0]}/login?token={quote(token)}"
                if FRONTEND_ORIGINS
                else ""
            )
            if not verification_url:
                raise HTTPException(
                    status_code=503,
                    detail="Configure FRONTEND_ORIGINS before sending verification email",
                )
            try:
                await send_email(
                    user.email,
                    "Confirm your UPI Shield account",
                    (
                        f"Hello {user.full_name},\n\n"
                        "Use this link to confirm your analyst account:\n"
                        f"{verification_url}\n\n"
                        "This link expires in 24 hours."
                    ),
                )
            except (OSError, RuntimeError, smtplib.SMTPException) as error:
                logger.exception("Confirmation email resend failed")
                raise HTTPException(
                    status_code=503,
                    detail="Confirmation email could not be sent. Check SMTP configuration.",
                ) from error

    return {
        "message": (
            "If the account needs confirmation, a confirmation email will be sent. "
            "Wait one minute before requesting another."
        )
    }


@app.post("/auth/login")
async def login(
    credentials: AuthCredentials,
    request: Request,
) -> Response:
    require_frontend_origin(request)
    try:
        user = await authenticate_analyst(
            credentials.email,
            credentials.password,
        )
    except PermissionError as error:
        raise HTTPException(status_code=403, detail=str(error)) from error
    if user is None:
        await save_activity_event("login_failed")
        raise HTTPException(status_code=401, detail="Invalid email or password")

    login_time = datetime.now(timezone.utc).isoformat(timespec="seconds")
    try:
        await send_email(
            user.email,
            "New sign-in to your UPI Shield account",
            (
                f"Hello {user.full_name},\n\n"
                "Your UPI Shield account was signed in at "
                f"{login_time} UTC.\n\n"
                "If this was not you, contact your workspace administrator."
            ),
        )
    except (OSError, RuntimeError, smtplib.SMTPException) as error:
        logger.exception("Login notification email delivery failed")
        await save_activity_event(
            "login_notification_failed",
            user_id=user.id,
        )
        raise HTTPException(
            status_code=503,
            detail="Sign-in notification could not be sent. Check SMTP configuration and retry.",
        ) from error

    await record_login(user)
    token = await create_session(user.id)
    response = Response(
        content=json.dumps({"user": analyst_response(user)}),
        media_type="application/json",
    )
    set_session_cookie(response, request, token)
    return response


@app.get("/auth/me")
async def current_analyst(request: Request) -> dict:
    user = await get_current_user(request)
    return {"user": analyst_response(user)}


@app.post("/auth/logout")
async def logout(request: Request) -> Response:
    require_frontend_origin(request)
    user = await find_analyst_by_session(
        request.cookies.get(SESSION_COOKIE_NAME)
    )
    await revoke_session(request.cookies.get(SESSION_COOKIE_NAME))
    if user is not None:
        await save_activity_event("logout", user_id=user.id)
    response = Response(status_code=204)
    secure_request = _is_secure_request(request)
    response.delete_cookie(
        key=SESSION_COOKIE_NAME,
        httponly=True,
        secure=secure_request,
        samesite="none" if secure_request else "strict",
        path="/",
    )
    return response


@app.post("/analytics/visit", status_code=202)
async def record_page_visit(
    visit: PageVisitRequest,
    request: Request,
) -> dict:
    require_frontend_origin(request)
    await save_activity_event(
        "page_view",
        metadata={"path": visit.path},
    )
    return {"status": "recorded"}


async def require_admin(request: Request) -> AnalystUser:
    user = await get_current_user(request)
    admins = {
        email.strip().lower()
        for email in get_settings().admin_emails.split(",")
        if email.strip()
    }
    if user.email.lower() not in admins:
        raise HTTPException(status_code=403, detail="Admin access is required")
    return user


async def _count_events(
    session: AsyncSession,
    event_type: str,
    since: datetime | None = None,
) -> int:
    query = select(func.count(ActivityEvent.id)).where(
        ActivityEvent.event_type == event_type
    )
    if since is not None:
        query = query.where(ActivityEvent.created_at >= since)
    result = await session.execute(query)
    return int(result.scalar_one())


@app.get("/admin/overview")
async def admin_overview(request: Request) -> dict:
    await require_admin(request)
    now = datetime.now(timezone.utc)
    activity_since = now - timedelta(
        days=get_settings().activity_retention_days
    )
    month_since = now - timedelta(days=30)

    async with session_factory() as session:
        total_users = int(
            (await session.execute(select(func.count(AnalystUser.id)))).scalar_one()
        )
        verified_users = int(
            (
                await session.execute(
                    select(func.count(AnalystUser.id)).where(
                        AnalystUser.is_verified.is_(True)
                    )
                )
            ).scalar_one()
        )
        unverified_users = total_users - verified_users
        detection_count = int(
            (
                await session.execute(
                    select(func.count(DetectionRecord.id))
                )
            ).scalar_one()
        )
        page_views = await _count_events(
            session,
            "page_view",
            since=activity_since,
        )
        recent_visits = await _count_events(
            session,
            "page_view",
            since=month_since,
        )
        logins = await _count_events(
            session,
            "login",
            since=activity_since,
        )
        registrations = await _count_events(
            session,
            "registration",
            since=activity_since,
        )
        feature_events = await session.execute(
            select(ActivityEvent.event_type, func.count(ActivityEvent.id))
            .where(
                ActivityEvent.event_type.like("feature_%"),
                ActivityEvent.created_at >= activity_since,
            )
            .group_by(ActivityEvent.event_type)
            .order_by(ActivityEvent.event_type)
        )
        feature_usage = [
            {"feature": event_type.removeprefix("feature_"), "uses": count}
            for event_type, count in feature_events.all()
        ]
        visits_by_page = await session.execute(
            select(
                ActivityEvent.event_metadata["path"].as_string(),
                func.count(ActivityEvent.id),
            )
            .where(
                ActivityEvent.event_type == "page_view",
                ActivityEvent.created_at >= activity_since,
            )
            .group_by(ActivityEvent.event_metadata["path"].as_string())
            .order_by(func.count(ActivityEvent.id).desc())
        )
        page_counts = [
            {"path": path, "views": count}
            for path, count in visits_by_page.all()
        ]

    return {
        "generated_at": now.isoformat(),
        "activity_retention_days": get_settings().activity_retention_days,
        "accounts": {
            "total": total_users,
            "verified": verified_users,
            "pending_email_confirmation": unverified_users,
            "registrations_in_retention_window": registrations,
        },
        "visits": {
            "page_views_in_retention_window": page_views,
            "page_views_last_30_days": recent_visits,
            "tracked_unique_visitors": False,
            "by_page": page_counts,
        },
        "logins_in_retention_window": logins,
        "detections_stored": detection_count,
        "feature_usage": feature_usage,
    }


@app.get("/admin/users")
async def admin_users(
    request: Request,
    limit: int = 100,
    offset: int = 0,
) -> dict:
    await require_admin(request)
    if not 1 <= limit <= 200 or offset < 0:
        raise HTTPException(
            status_code=422,
            detail="limit must be 1-200 and offset cannot be negative",
        )

    async with session_factory() as session:
        total = int(
            (await session.execute(select(func.count(AnalystUser.id)))).scalar_one()
        )
        result = await session.execute(
            select(AnalystUser)
            .order_by(AnalystUser.created_at.desc())
            .offset(offset)
            .limit(limit)
        )
        users = result.scalars().all()

    return {
        "total": total,
        "users": [
            {
                "id": user.id,
                "full_name": user.full_name,
                "email": user.email,
                "mobile_number": user.mobile_number,
                "email_verified": user.is_verified,
                "created_at": (
                    user.created_at.isoformat() if user.created_at else None
                ),
                "last_login_at": (
                    user.last_login_at.isoformat() if user.last_login_at else None
                ),
                "login_count": user.login_count,
            }
            for user in users
        ],
    }


@app.get("/admin/activity")
async def admin_activity(
    request: Request,
    limit: int = 100,
) -> dict:
    await require_admin(request)
    if not 1 <= limit <= 200:
        raise HTTPException(status_code=422, detail="limit must be 1-200")
    cutoff = datetime.now(timezone.utc) - timedelta(
        days=get_settings().activity_retention_days
    )

    async with session_factory() as session:
        result = await session.execute(
            select(ActivityEvent, AnalystUser.email, AnalystUser.full_name)
            .outerjoin(AnalystUser, ActivityEvent.user_id == AnalystUser.id)
            .where(ActivityEvent.created_at >= cutoff)
            .order_by(ActivityEvent.created_at.desc())
            .limit(limit)
        )
        events = result.all()
        detection_result = await session.execute(
            select(DetectionRecord)
            .order_by(DetectionRecord.created_at.desc())
            .limit(min(limit, 50))
        )
        detections = detection_result.scalars().all()

    return {
        "events": [
            {
                "id": event.id,
                "event_type": event.event_type,
                "created_at": (
                    (
                        event.created_at.isoformat()
                        if isinstance(event.created_at, datetime)
                        else None
                    )
                ),
                "user_email": email,
                "user_name": name,
                "details": event.event_metadata or {},
            }
            for event, email, name in events
        ],
        "detections": [
            {
                "id": detection.id,
                "url": detection.url,
                "brand": detection.brand,
                "score": detection.score,
                "verdict": detection.verdict,
                "created_at": (
                    detection.created_at.isoformat()
                    if detection.created_at
                    else None
                ),
                "screenshot_url": (
                    f"/artifacts/{Path(detection.screenshot).name}"
                ),
                "evidence": detection.evidence or {},
            }
            for detection in detections
        ],
    }


# ============================================================
# Detection APIs
# ============================================================

@app.get(
    "/detections",
    response_model=list[DetectionResponse],
    dependencies=[Depends(require_api_key)],
)
async def list_detections(
    verdict: str | None = None,
) -> list[DetectionResponse]:

    async with session_factory() as session:
        records = await get_detections(
            session,
            verdict=verdict,
        )

    return [
        response_from_record(record)
        for record in records
    ]


@app.post(
    "/detections",
    response_model=DetectionResponse,
    dependencies=[Depends(require_api_key)],
)
async def create_detection(
    payload: DetectionRequest,
    http_request: Request,
) -> DetectionResponse:

    screenshot_path = Path(payload.screenshot)
    dom_path = Path(payload.dom)

    if not screenshot_path.is_absolute():
        screenshot_path = Path.cwd() / screenshot_path

    if not dom_path.is_absolute():
        dom_path = Path.cwd() / dom_path

    if (
        not screenshot_path.is_file()
        or not dom_path.is_file()
    ):
        raise HTTPException(
            status_code=400,
            detail="Screenshot and DOM files must exist",
        )

    settings = get_settings()

    intel = await analyze_domain(
        str(payload.url),
        active_lookups=allowed_target(str(payload.url)),
    )

    # --------------------------------------------------------
    # Threat-intelligence lookup
    # --------------------------------------------------------

    ti_match = await find_threat_indicator(
        str(payload.url)
    )

    if ti_match:

        intel["threat_intel"] = {
            "matched": True,
            "indicator": ti_match.indicator,
            "type": ti_match.indicator_type,
            "source": ti_match.source,
            "confidence": ti_match.confidence,
            "tags": json.loads(ti_match.tags),
        }

    else:

        intel["threat_intel"] = {
            "matched": False,
        }

    detection = score(
        str(payload.url),
        str(screenshot_path),
        str(dom_path),
        payload.brand_keywords,
        settings.phishing_threshold,
        settings.suspicious_threshold,
        intel,
    )

    async with session_factory() as session:
        record = await save_detection(
            session,
            detection,
            str(screenshot_path),
            str(dom_path),
        )

    user = await find_analyst_by_session(
        http_request.cookies.get(SESSION_COOKIE_NAME)
    )
    await save_activity_event(
        "feature_screenshot_analysis",
        user_id=user.id if user else None,
        metadata={
            "detection_id": record.id,
            "url": record.url,
            "verdict": record.verdict,
            "score": record.score,
            "screenshot": str(screenshot_path),
        },
    )

    return response_from_record(record)


# ============================================================
# Authorized capture pipeline
# ============================================================

async def run_capture(
    url: str,
    keywords: list[str],
    user_id: int | None = None,
) -> DetectionResponse:

    if not allowed_target(url):

        raise HTTPException(
            status_code=403,
            detail=(
                "Target is outside CRAWL_ALLOWLIST; "
                "only explicitly authorized targets may be crawled"
            ),
        )

    capture_result = await capture(url)

    if not capture_result["ok"]:

        raise HTTPException(
            status_code=502,
            detail=capture_result.get(
                "error",
                "capture failed",
            ),
        )

    settings = get_settings()

    intel = await analyze_domain(url, active_lookups=True)

    # --------------------------------------------------------
    # Threat-intelligence lookup
    # --------------------------------------------------------

    ti_match = await find_threat_indicator(url)

    if ti_match:

        intel["threat_intel"] = {
            "matched": True,
            "indicator": ti_match.indicator,
            "type": ti_match.indicator_type,
            "source": ti_match.source,
            "confidence": ti_match.confidence,
            "tags": json.loads(ti_match.tags),
        }

    else:

        intel["threat_intel"] = {
            "matched": False,
        }

    # --------------------------------------------------------
    # Detection scoring
    # --------------------------------------------------------

    detection = score(
        url,
        capture_result["screenshot"],
        capture_result["dom"],
        keywords,
        settings.phishing_threshold,
        settings.suspicious_threshold,
        intel,
    )

    detection["capture"] = {
        key: capture_result.get(key)
        for key in (
            "status",
            "final_url",
            "title",
            "network",
            "redirects",
        )
    }

    # --------------------------------------------------------
    # Save detection
    # --------------------------------------------------------

    async with session_factory() as session:
        record = await save_detection(
            session,
            detection,
            capture_result["screenshot"],
            capture_result["dom"],
        )

    await save_activity_event(
        "feature_capture",
        user_id=user_id,
        metadata={
            "detection_id": record.id,
            "url": record.url,
            "verdict": record.verdict,
            "score": record.score,
            "screenshot": capture_result["screenshot"],
            "dom": capture_result["dom"],
        },
    )

    # --------------------------------------------------------
    # Infrastructure graph
    # --------------------------------------------------------

    domain = intel.get("hostname")

    addresses = intel.get(
        "dns",
        {},
    ).get(
        "addresses",
        [],
    )

    cert_sha = intel.get(
        "tls",
        {},
    ).get("sha256")

    if domain:

        try:
            await add_observation(
                domain=domain,
                ip=addresses[0] if addresses else None,
                cert_sha=cert_sha,
                brand=detection.get("brand"),
            )
        except Exception:
            logger.exception("Infrastructure graph observation could not be saved")

    return response_from_record(record)


@app.post(
    "/captures",
    response_model=DetectionResponse,
    dependencies=[Depends(require_api_key)],
)
async def capture_and_detect(
    request: CaptureRequest,
    http_request: Request,
) -> DetectionResponse:
    user = await find_analyst_by_session(
        http_request.cookies.get(SESSION_COOKIE_NAME)
    )

    return await run_capture(
        str(request.url),
        request.brand_keywords,
        user_id=user.id if user else None,
    )


# ============================================================
# Screenshot analysis
# ============================================================

@app.post(
    "/analyze-upload",
    response_model=DetectionResponse,
    dependencies=[Depends(require_api_key)],
)
async def analyze_uploaded_screenshot(
    request: Request,
    url: str = Form(...),
    brand_keywords: str = Form(""),
    screenshot: UploadFile = File(...),
) -> DetectionResponse:

    if not url.startswith(
        ("http://", "https://")
    ):
        raise HTTPException(
            status_code=400,
            detail=(
                "URL must start with "
                "http:// or https://"
            ),
        )

    if screenshot.content_type not in {
        "image/png",
        "image/jpeg",
        "image/webp",
    }:

        raise HTTPException(
            status_code=400,
            detail="Upload a PNG, JPEG, or WebP screenshot",
        )

    content = await screenshot.read()

    if len(content) > (
        get_settings().max_upload_mb
        * 1024
        * 1024
    ):

        raise HTTPException(
            status_code=413,
            detail="Screenshot exceeds upload size limit",
        )

    suffix = Path(
        screenshot.filename or ""
    ).suffix.lower()

    if suffix not in {
        ".png",
        ".jpg",
        ".jpeg",
        ".webp",
    }:
        suffix = ".png"

    output_dir = Path("data/captures")
    output_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    screenshot_path = (
        output_dir
        / f"upload-{uuid.uuid4().hex}{suffix}"
    )

    screenshot_path.write_bytes(content)

    dom_path = (
        output_dir
        / f"{screenshot_path.stem}.html"
    )

    dom_path.write_text(
        (
            "<html>"
            "<head>"
            "<title>Uploaded analyst screenshot</title>"
            "</head>"
            f'<body data-source-url="{escape(url, quote=True)}">'
            "</body>"
            "</html>"
        ),
        encoding="utf-8",
    )

    keywords = [
        item.strip()
        for item in brand_keywords.split(",")
        if item.strip()
    ]

    intel = await analyze_domain(
        url,
        active_lookups=allowed_target(url),
    )

    # TI lookup for analyst-uploaded evidence
    ti_match = await find_threat_indicator(url)

    if ti_match:

        intel["threat_intel"] = {
            "matched": True,
            "indicator": ti_match.indicator,
            "type": ti_match.indicator_type,
            "source": ti_match.source,
            "confidence": ti_match.confidence,
            "tags": json.loads(ti_match.tags),
        }

    else:

        intel["threat_intel"] = {
            "matched": False,
        }

    settings = get_settings()

    detection = score(
        url,
        str(screenshot_path),
        str(dom_path),
        keywords,
        settings.phishing_threshold,
        settings.suspicious_threshold,
        intel,
    )

    async with session_factory() as session:
        record = await save_detection(
            session,
            detection,
            str(screenshot_path),
            str(dom_path),
        )

    user = await find_analyst_by_session(
        request.cookies.get(SESSION_COOKIE_NAME)
    )
    await save_activity_event(
        "feature_screenshot_upload",
        user_id=user.id if user else None,
        metadata={
            "detection_id": record.id,
            "url": record.url,
            "verdict": record.verdict,
            "score": record.score,
            "screenshot": str(screenshot_path),
        },
    )

    return response_from_record(record)


# ============================================================
# Discovery
# ============================================================

@app.post(
    "/discover",
    dependencies=[Depends(require_api_key)],
)
async def discover(
    request: DiscoverRequest,
) -> dict:

    disallowed = [
        str(url)
        for url in request.urls
        if not allowed_target(str(url))
    ]

    if disallowed:

        raise HTTPException(
            status_code=403,
            detail={
                "message": (
                    "Targets must be inside "
                    "CRAWL_ALLOWLIST"
                ),
                "targets": disallowed,
            },
        )

    queue_path = Path(
        "data/discovered/queue.txt"
    )

    queue_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with queue_path.open(
        "a",
        encoding="utf-8",
    ) as stream:

        for url in request.urls:
            stream.write(
                f"{url}\n"
            )

    return {
        "source": request.source,
        "queued": [
            str(url)
            for url in request.urls
        ],
        "count": len(request.urls),
    }


# ============================================================
# APK inspection
# ============================================================

@app.post(
    "/apps/inspect",
    dependencies=[Depends(require_api_key)],
)
async def inspect_app(
    path: str,
    request: Request,
) -> dict:

    try:
        result = inspect_apk(path)
        user = await find_analyst_by_session(
            request.cookies.get(SESSION_COOKIE_NAME)
        )
        await save_activity_event(
            "feature_apk_inspection",
            user_id=user.id if user else None,
            metadata={
                **result,
                "path": str(path),
            },
        )
        return result

    except (
        ValueError,
        FileNotFoundError,
    ) as error:

        raise HTTPException(
            status_code=400,
            detail=str(error),
        ) from error


@app.post(
    "/apps/inspect-upload",
    dependencies=[Depends(require_api_key)],
)
async def inspect_app_upload(
    request: Request,
    apk: UploadFile = File(...),
) -> dict:

    if not (
        apk.filename or ""
    ).lower().endswith(".apk"):

        raise HTTPException(
            status_code=400,
            detail="Upload an .apk file",
        )

    content = await apk.read()

    if len(content) > (
        get_settings().max_upload_mb
        * 5
        * 1024
        * 1024
    ):

        raise HTTPException(
            status_code=413,
            detail="APK exceeds upload size limit",
        )

    path = (
        Path("data/evidence")
        / f"apk-{uuid.uuid4().hex}.apk"
    )
    path.write_bytes(content)

    try:
        result = inspect_apk(path)
        user = await find_analyst_by_session(
            request.cookies.get(SESSION_COOKIE_NAME)
        )
        await save_activity_event(
            "feature_apk_inspection",
            user_id=user.id if user else None,
            metadata={
                **result,
                "path": str(path),
            },
        )
        return result

    except (
        ValueError,
        FileNotFoundError,
    ) as error:

        raise HTTPException(
            status_code=400,
            detail=str(error),
        ) from error


# ============================================================
# Infrastructure graph
# ============================================================

@app.get("/graph", dependencies=[Depends(require_api_key)])
async def get_graph() -> dict:

    return await graph_snapshot()


@app.get("/graph/clusters", dependencies=[Depends(require_api_key)])
async def get_graph_clusters() -> dict:
    """
    Run campaign clustering on the current
    infrastructure graph.

    This is an analytical view only.
    A cluster does not by itself prove that
    all infrastructure belongs to the same
    actor/campaign.
    """

    graph = await graph_snapshot()

    nodes = graph.get(
        "nodes",
        [],
    )

    links = graph.get(
        "links",
        [],
    )

    clusters = cluster_graph(
        nodes=nodes,
        links=links,
    )

    return {
        "clusters": clusters,
        "total_clusters": len(clusters),
        "total_nodes": len(nodes),
        "total_links": len(links),
    }


@app.post(
    "/graph/observations",
    dependencies=[Depends(require_api_key)],
)
async def create_graph_observation(
    observation: GraphObservation,
) -> dict[str, str]:

    await init_schema()

    await add_observation(
        **observation.model_dump()
    )

    return {
        "status": "stored",
        "domain": observation.domain,
    }


# ============================================================
# Evaluation
# ============================================================

@app.get("/evaluation", dependencies=[Depends(require_api_key)])
async def evaluation() -> dict:

    return evaluate_labels()


# ============================================================
# Detection detail
# ============================================================

@app.get(
    "/detections/{detection_id}",
    response_model=DetectionResponse,
    dependencies=[Depends(require_api_key)],
)
async def get_detection(
    detection_id: int,
) -> DetectionResponse:

    async with session_factory() as session:
        record = await get_detection_by_id(
            session,
            detection_id,
        )

    if not record:

        raise HTTPException(
            status_code=404,
            detail="Detection not found",
        )

    return response_from_record(record)


@app.get(
    "/detections/{detection_id}/report",
    dependencies=[Depends(require_api_key)],
)
async def detection_report(
    detection_id: int,
) -> Response:

    detection = await get_detection(
        detection_id
    )

    evidence = detection.evidence

    details = [
        f"URL: {detection.url}",
        f"Verdict: {detection.verdict}",
        f"Risk score: {detection.score:.2f}",
        f"Brand: {detection.brand or 'Unidentified'}",
        "",
        "Reasons:",
    ]

    details.extend(
        f"- {reason}"
        for reason in evidence.get(
            "reasons",
            [],
        )
    )

    details += [
        "",
        "Evidence components:",
        str(
            evidence.get(
                "components",
                {},
            )
        ),
        "",
        "Behavioral signals:",
        str(
            detection.behavioral
        ),
    ]

    return Response(
        content=create_report(
            "UPI Shield - Takedown Evidence",
            "\n".join(details),
        ),
        media_type="application/pdf",
        headers={
            "Content-Disposition": (
                f"attachment; "
                f"filename=detection-{detection_id}.pdf"
            )
        },
    )


# ============================================================
# Threat Intelligence
# ============================================================

@app.post(
    "/threat-intel/ingest",
    dependencies=[Depends(require_api_key)],
)
async def ingest_threat_intelligence(
    payload: dict,
) -> dict:

    records = payload.get(
        "indicators"
    )

    if not isinstance(
        records,
        list,
    ):

        raise HTTPException(
            status_code=400,
            detail="'indicators' must be an array",
        )

    if not records:

        raise HTTPException(
            status_code=400,
            detail="'indicators' cannot be empty",
        )

    result = ingest_records(
        records
    )

    saved_count = await save_threat_intel(
        result["accepted"]
    )

    result["saved_count"] = (
        saved_count
    )

    return result