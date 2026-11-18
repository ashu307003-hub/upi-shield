from collections import Counter
from contextlib import asynccontextmanager
from html import escape
import hmac
import json
import logging
import secrets
import smtplib
from typing import Literal
from urllib.parse import parse_qs, quote, urlsplit
import uuid
from datetime import datetime, timedelta, timezone

from pathlib import Path

from fastapi import (
    BackgroundTasks,
    Depends,
    FastAPI,
    File,
    Form,
    Header,
    HTTPException,
    Request,
    UploadFile,
)
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import ValidationError
from starlette.datastructures import UploadFile as StarletteUploadFile
from starlette.types import Scope
from sqlalchemy.exc import IntegrityError
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from .auth import (
    SESSION_COOKIE_NAME,
    SESSION_TTL,
    authenticate_analyst,
    create_analyst,
    create_session,
    find_analyst_by_email,
    find_analyst_by_session,
    issue_password_reset_token,
    issue_verification_token,
    record_login,
    reset_analyst_password,
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
from .intelligence import analyze_domain, domain_risk
from .models import (
    AuthCredentials,
    BrowserCheckRequest,
    CaptureRequest,
    DetectionRequest,
    DetectionResponse,
    DiscoverRequest,
    EmailTokenRequest,
    GraphObservation,
    PageVisitRequest,
    PasswordResetCompletion,
    PasswordResetRequest,
    RegisterRequest,
    ResendVerificationRequest,
    QrCheckRequest,
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
BROWSER_EXTENSION_ORIGINS = tuple(
    origin.strip().rstrip("/")
    for origin in get_settings().browser_extension_origins.split(",")
    if origin.strip()
)
logger = logging.getLogger(__name__)
PRIVATE_ID_DIRECTORY = Path(__file__).resolve().parents[1] / "data" / "private_ids"
MAX_ID_CARD_SIZE = 5 * 1024 * 1024


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
        *BROWSER_EXTENSION_ORIGINS,
    ],
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=True,
)


# ============================================================
# Authentication
# ============================================================

async def get_current_user(request: Request):
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if token is None:
        authorization = request.headers.get("authorization", "")
        scheme, _, bearer_token = authorization.partition(" ")
        if scheme.lower() == "bearer":
            token = bearer_token
    user = await find_analyst_by_session(
        token
    )
    if user is None:
        raise HTTPException(status_code=401, detail="Sign in to continue")
    return user


async def require_browser_session(request: Request):
    authorization = request.headers.get("authorization", "")
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(status_code=401, detail="Sign in to UPI Shield first")

    user = await find_analyst_by_session(token)
    if user is None:
        raise HTTPException(status_code=401, detail="UPI Shield session expired")
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


def client_ip_address(request: Request) -> str:
    client = request.client
    return client.host if client and client.host else "Unavailable"


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
        "mobile_number": getattr(user, "mobile_number", ""),
        "account_type": getattr(user, "account_type", "professional"),
        "academic_session": getattr(user, "academic_session", ""),
        "institution": getattr(user, "institution", ""),
        "department": getattr(user, "department", ""),
        "course": getattr(user, "course", ""),
        "study_year": getattr(user, "study_year", ""),
        "has_student_id_document": bool(
            getattr(user, "student_id_document", None)
        ),
        "employer": getattr(user, "employer", ""),
        "job_title": getattr(user, "job_title", ""),
        "employment_type": getattr(user, "employment_type", ""),
        "employee_id": getattr(user, "employee_id", ""),
        "is_verified": getattr(user, "is_verified", False),
        "created_at": (
            user.created_at.isoformat()
            if getattr(user, "created_at", None) is not None
            else None
        ),
    }


async def parse_registration_request(
    request: Request,
) -> tuple[RegisterRequest, StarletteUploadFile | None]:
    content_type = request.headers.get("content-type", "").lower()
    student_id_card = None
    try:
        if content_type.startswith("application/json"):
            payload = await request.json()
        elif content_type.startswith("multipart/form-data"):
            form = await request.form()
            payload = {
                key: value
                for key, value in form.multi_items()
                if key != "student_id_card"
            }
            student_id_card = form.get("student_id_card")
            if student_id_card is not None and not isinstance(
                student_id_card,
                StarletteUploadFile,
            ):
                raise HTTPException(
                    status_code=422,
                    detail="Student ID card must be uploaded as a file",
                )
        else:
            raise HTTPException(
                status_code=415,
                detail="Use JSON or multipart form data to register",
            )
        credentials = RegisterRequest.model_validate(payload)
    except ValidationError as error:
        raise RequestValidationError(
            error.errors(include_context=False)
        ) from error
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise HTTPException(status_code=400, detail="Invalid request body") from error

    if credentials.account_type == "student" and student_id_card is None:
        raise HTTPException(status_code=422, detail="Upload your student ID card")
    if credentials.account_type == "professional" and student_id_card is not None:
        raise HTTPException(
            status_code=422,
            detail="Student ID cards are only accepted for student accounts",
        )
    return credentials, student_id_card


async def save_student_id_card(upload: StarletteUploadFile) -> str:
    content = await upload.read(MAX_ID_CARD_SIZE + 1)
    await upload.close()
    if not content:
        raise HTTPException(status_code=422, detail="The uploaded ID card is empty")
    if len(content) > MAX_ID_CARD_SIZE:
        raise HTTPException(
            status_code=413,
            detail="Student ID cards must be 5 MB or smaller",
        )

    file_types = (
        (b"\x89PNG\r\n\x1a\n", ".png"),
        (b"\xff\xd8\xff", ".jpg"),
        (b"%PDF-", ".pdf"),
    )
    extension = next(
        (
            suffix
            for signature, suffix in file_types
            if content.startswith(signature)
        ),
        None,
    )
    if extension is None:
        raise HTTPException(
            status_code=415,
            detail="Upload a PNG, JPEG, or PDF student ID card",
        )

    PRIVATE_ID_DIRECTORY.mkdir(parents=True, exist_ok=True)
    filename = f"{secrets.token_hex(24)}{extension}"
    (PRIVATE_ID_DIRECTORY / filename).write_bytes(content)
    return filename


@app.post("/auth/register", status_code=202)
async def register(request: Request) -> Response:
    require_frontend_origin(request)
    credentials, student_id_card = await parse_registration_request(request)
    document_name = (
        await save_student_id_card(student_id_card)
        if student_id_card is not None
        else None
    )
    try:
        user = await create_analyst(
            credentials.full_name,
            credentials.email,
            credentials.mobile_number,
            credentials.password,
            account_type=credentials.account_type,
            academic_session=credentials.academic_session,
            institution=credentials.institution,
            department=credentials.department,
            course=credentials.course,
            study_year=credentials.study_year,
            student_id_document=document_name,
            employer=credentials.employer,
            job_title=credentials.job_title,
            employment_type=credentials.employment_type,
            employee_id=credentials.employee_id,
        )
    except IntegrityError as error:
        if document_name is not None:
            (PRIVATE_ID_DIRECTORY / document_name).unlink(missing_ok=True)
        raise HTTPException(
            status_code=409,
            detail="An account with this email already exists",
        ) from error
    except Exception:
        if document_name is not None:
            (PRIVATE_ID_DIRECTORY / document_name).unlink(missing_ok=True)
        raise

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
                "sent. Check the email provider configuration and request another email."
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


async def send_password_reset_email(
    email: str,
    full_name: str,
    token: str,
    reset_link_message: str,
) -> None:
    try:
        await send_email(
            email,
            "Reset your UPI Shield password",
            (
                f"Hello {full_name},\n\n"
                f"{reset_link_message}"
                "Android app reset code:\n"
                f"{token}\n\n"
                "This code and any reset link expire in 30 minutes and can only "
                "be used once. If you did not request a password reset, you can "
                "ignore this message."
            ),
        )
    except (OSError, RuntimeError, smtplib.SMTPException):
        logger.exception("Password reset email delivery failed")


@app.post("/auth/forgot-password", status_code=202)
async def forgot_password(
    credentials: PasswordResetRequest,
    background_tasks: BackgroundTasks,
) -> dict:
    user = await find_analyst_by_email(credentials.email)
    if user is not None and user.is_verified:
        token = await issue_password_reset_token(
            user,
            minimum_interval_seconds=60,
        )
        if token is not None:
            if not FRONTEND_ORIGINS:
                logger.warning(
                    "Password reset email will contain an Android code only: "
                    "FRONTEND_ORIGINS is empty"
                )
                reset_link_message = (
                    "Use the code below in the Android app to choose a new password.\n\n"
                )
            else:
                reset_link = (
                    f"{FRONTEND_ORIGINS[0]}/reset-password?token={quote(token)}"
                )
                reset_link_message = (
                    "Use this link to choose a new password:\n"
                    f"{reset_link}\n\n"
                )
            background_tasks.add_task(
                send_password_reset_email,
                user.email,
                user.full_name,
                token,
                reset_link_message,
            )

    return {
        "message": (
            "If an account exists for that email, a password reset link will "
            "be sent. You can request another link after one minute."
        )
    }


@app.post("/auth/reset-password")
async def reset_password(credentials: PasswordResetCompletion) -> dict:
    if not await reset_analyst_password(credentials.token, credentials.password):
        raise HTTPException(
            status_code=400,
            detail="Password reset link is invalid or has expired",
        )
    return {
        "message": "Your password has been updated. Sign in with your new password."
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
                    detail="Confirmation email could not be sent. Check the email provider configuration.",
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
    if credentials.account_type != getattr(user, "account_type", "professional"):
        await save_activity_event("login_failed", user_id=user.id)
        raise HTTPException(
            status_code=401,
            detail="Invalid account type, email, or password",
        )

    login_time = datetime.now(timezone.utc).isoformat(timespec="seconds")
    client_ip = client_ip_address(request)
    try:
        await send_email(
            user.email,
            "New sign-in to your UPI Shield account",
            (
                f"Hello {user.full_name},\n\n"
                "Your UPI Shield account was signed in.\n\n"
                f"Login time: {login_time} UTC\n"
                f"IP address: {client_ip}\n\n"
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
            detail="Sign-in notification could not be sent. Check the email provider configuration and retry.",
        ) from error

    await record_login(user)
    token = await create_session(user.id)
    response = Response(
        content=json.dumps({"user": analyst_response(user)}),
        media_type="application/json",
    )
    set_session_cookie(response, request, token)
    return response


@app.post("/mobile/auth/login")
async def mobile_login(
    credentials: AuthCredentials,
    request: Request,
) -> dict:
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
    if credentials.account_type != getattr(user, "account_type", "professional"):
        await save_activity_event("login_failed", user_id=user.id)
        raise HTTPException(
            status_code=401,
            detail="Invalid account type, email, or password",
        )

    login_time = datetime.now(timezone.utc).isoformat(timespec="seconds")
    try:
        await send_email(
            user.email,
            "New sign-in to your UPI Shield account",
            (
                f"Hello {user.full_name},\n\n"
                "Your UPI Shield mobile app signed in.\n\n"
                f"Login time: {login_time} UTC\n"
                f"IP address: {client_ip_address(request)}\n\n"
                "If this was not you, contact your workspace administrator."
            ),
        )
    except (OSError, RuntimeError, smtplib.SMTPException) as error:
        logger.exception("Mobile login notification email delivery failed")
        await save_activity_event(
            "login_notification_failed",
            user_id=user.id,
        )
        raise HTTPException(
            status_code=503,
            detail="Sign-in notification could not be sent. Check the email provider configuration and retry.",
        ) from error

    await record_login(user)
    token = await create_session(user.id)
    return {
        "user": analyst_response(user),
        "session_token": token,
    }


@app.post("/mobile/auth/logout", status_code=204)
async def mobile_logout(
    request: Request,
    user: AnalystUser = Depends(require_browser_session),
) -> Response:
    _, _, token = request.headers.get("authorization", "").partition(" ")
    await revoke_session(token)
    await save_activity_event("logout", user_id=user.id)
    return Response(status_code=204)


@app.get("/mobile/dashboard")
async def mobile_dashboard(
    user: AnalystUser = Depends(get_current_user),
) -> dict:
    async with session_factory() as session:
        counts = await session.execute(
            select(DetectionRecord.verdict, func.count(DetectionRecord.id))
            .group_by(DetectionRecord.verdict)
        )
        recent_result = await session.execute(
            select(DetectionRecord)
            .order_by(DetectionRecord.created_at.desc())
            .limit(5)
        )
        recent = recent_result.scalars().all()

    verdict_counts = {
        verdict: count
        for verdict, count in counts.all()
    }
    return {
        "user": analyst_response(user),
        "totals": {
            "detections": sum(verdict_counts.values()),
            "phishing": verdict_counts.get("phishing", 0),
            "suspicious": verdict_counts.get("suspicious", 0),
        },
        "recent": [
            {
                "id": record.id,
                "url": record.url,
                "brand": record.brand,
                "score": record.score,
                "verdict": record.verdict,
                "created_at": (
                    record.created_at.isoformat()
                    if record.created_at
                    else None
                ),
            }
            for record in recent
        ],
    }


@app.get("/auth/me")
async def current_analyst(request: Request) -> dict:
    user = await get_current_user(request)
    return {"user": analyst_response(user)}


@app.get("/auth/profile/student-id-card")
async def student_id_card(request: Request) -> FileResponse:
    user = await get_current_user(request)
    filename = getattr(user, "student_id_document", None)
    if not filename:
        raise HTTPException(status_code=404, detail="No student ID card is on file")

    document_path = PRIVATE_ID_DIRECTORY / filename
    if not document_path.is_file():
        logger.error("Student ID document is missing for analyst %s", user.id)
        raise HTTPException(status_code=404, detail="Student ID card is unavailable")

    return FileResponse(
        document_path,
        media_type={
            ".jpg": "image/jpeg",
            ".png": "image/png",
            ".pdf": "application/pdf",
        }.get(document_path.suffix.lower(), "application/octet-stream"),
        filename=f"student-id-card{document_path.suffix.lower()}",
        headers={
            "Cache-Control": "private, no-store",
            "X-Content-Type-Options": "nosniff",
        },
    )


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


@app.post("/browser/check")
async def check_browser_url(
    payload: BrowserCheckRequest,
    _: AnalystUser = Depends(require_browser_session),
) -> dict:
    target = str(payload.url)
    settings = get_settings()

    domain_intel = await analyze_domain(target, active_lookups=False)
    lexical_score, lexical_reasons = domain_risk(domain_intel)

    def report_result(
        *,
        status: str,
        score_value: float,
        verdict: str | None,
        reason: str | None,
        signals: list[str],
        method: str,
        known_threat: bool = False,
    ) -> dict:
        normalized_score = max(0.0, min(1.0, float(score_value)))
        risk_level = (
            "high"
            if normalized_score >= settings.phishing_threshold
            else "elevated"
            if normalized_score >= settings.suspicious_threshold
            else "low"
        )
        return {
            "status": status,
            "verdict": verdict,
            "score": normalized_score,
            "score_label": "URL risk score (not probability)",
            "risk_level": risk_level,
            "reason": reason,
            "report": {
                "url": target,
                "risk_score": normalized_score,
                "risk_level": risk_level,
                "known_threat": known_threat,
                "method": method,
                "signals": signals,
                "checked_at": datetime.now(timezone.utc).isoformat(),
                "scope": (
                    "This click-time check uses threat data, prior analyses, "
                    "and URL text only. It does not inspect the page, payment "
                    "request, QR code, or recipient."
                ),
            },
        }

    intel = await find_threat_indicator(target)
    if intel:
        intel_confidence = max(0.0, min(1.0, float(intel.confidence)))
        signals = [
            f"Matches a threat-intelligence indicator from {intel.source}."
        ]
        signals.extend(lexical_reasons)
        if intel_confidence >= settings.suspicious_threshold:
            verdict = (
                "phishing"
                if intel_confidence >= settings.phishing_threshold
                else "suspicious"
            )
            return report_result(
                status="blocked",
                verdict=verdict,
                score_value=max(intel_confidence, lexical_score),
                reason=signals[0],
                signals=signals,
                method="threat-intelligence match and URL text",
                known_threat=True,
            )

    async with session_factory() as session:
        authority = urlsplit(target).netloc.lower()
        result = await session.execute(
            select(DetectionRecord)
            .where(
                or_(
                    DetectionRecord.url == target,
                    func.lower(DetectionRecord.url).like(
                        f"http://{authority}/%"
                    ),
                    func.lower(DetectionRecord.url).like(
                        f"https://{authority}/%"
                    ),
                ),
                DetectionRecord.verdict.in_(("phishing", "suspicious")),
            )
            .order_by(DetectionRecord.score.desc())
            .limit(1)
        )
        detection = result.scalar_one_or_none()

    if detection is not None:
        signals = [
            "This URL or host was previously flagged by UPI Shield analysis."
        ]
        signals.extend(
            (getattr(detection, "evidence", None) or {}).get("reasons", [])
        )
        signals.extend(lexical_reasons)
        return report_result(
            status="blocked",
            verdict=detection.verdict,
            score_value=max(float(detection.score), lexical_score),
            reason=signals[0],
            signals=signals,
            method="prior UPI Shield analysis and URL text",
            known_threat=True,
        )

    risk_signals = list(lexical_reasons)
    if intel and intel.confidence > 0:
        risk_signals.insert(
            0,
            f"Low-confidence threat-intelligence match from {intel.source}.",
        )
    preliminary_score = max(
        lexical_score,
        float(intel.confidence) if intel else 0.0,
    )
    heuristic_flagged = preliminary_score >= settings.suspicious_threshold
    heuristic_verdict = "suspicious" if heuristic_flagged else None
    reason = (
        "URL text contains multiple risk indicators."
        if heuristic_flagged
        else "A low-confidence threat match or limited URL signal was found."
        if intel
        else "No known threat match; this is not proof that the link is safe."
    )
    return report_result(
        status="blocked" if heuristic_flagged else "unknown",
        verdict=heuristic_verdict,
        score_value=preliminary_score,
        reason=reason,
        signals=risk_signals,
        method=(
            "low-confidence threat intelligence and URL text"
            if intel
            else "URL text heuristics only"
        ),
    )


@app.post("/mobile/check-qr")
async def check_mobile_qr(
    payload: QrCheckRequest,
    user: AnalystUser = Depends(get_current_user),
) -> dict:
    raw_payload = payload.payload.strip()
    parsed = urlsplit(raw_payload)
    if parsed.scheme.lower() in {"http", "https"}:
        result = await check_browser_url(
            BrowserCheckRequest(url=raw_payload),
            user,
        )
        result["report"]["input_type"] = "qr_web_link"
        return result

    query = parse_qs(parsed.query, keep_blank_values=True)
    vpa = query.get("pa", [""])[0].strip().lower()
    if parsed.scheme.lower() != "upi" or parsed.netloc.lower() != "pay":
        return {
            "status": "unknown",
            "verdict": None,
            "score": None,
            "score_label": None,
            "risk_level": "unknown",
            "reason": (
                "This QR code is not a supported web link or UPI payment QR. "
                "It has not been verified."
            ),
            "report": {
                "input_type": "unsupported_qr",
                "signals": [],
                "known_threat": False,
                "scope": "The QR payload format is not supported.",
            },
        }

    if (
        not vpa
        or len(vpa) > 256
        or "@" not in vpa
        or vpa.startswith("@")
        or vpa.endswith("@")
        or any(ord(character) < 32 for character in vpa)
    ):
        raise HTTPException(
            status_code=422,
            detail="The UPI QR code does not contain a valid payee address",
        )

    settings = get_settings()
    intel = await find_threat_indicator(vpa)
    confidence = (
        max(0.0, min(1.0, float(intel.confidence)))
        if intel
        else 0.0
    )
    risk_level = (
        "high"
        if confidence >= settings.phishing_threshold
        else "elevated"
        if confidence >= settings.suspicious_threshold
        else "low"
    )
    flagged = confidence >= settings.suspicious_threshold
    verdict = (
        "phishing"
        if confidence >= settings.phishing_threshold
        else "suspicious"
        if flagged
        else None
    )
    signals = (
        [
            f"Payee address matches a threat-intelligence indicator from {intel.source}."
        ]
        if intel
        else []
    )
    payee_name = query.get("pn", [""])[0].strip()[:160]
    amount = query.get("am", [""])[0].strip()[:32]
    reason = (
        signals[0]
        if flagged
        else "No known threat match for this payee. This does not verify the recipient."
        if not intel
        else "A low-confidence threat match exists; verify the recipient independently."
    )

    return {
        "status": "blocked" if flagged else "unknown",
        "verdict": verdict,
        "score": confidence,
        "score_label": "reputation signal score (not probability)",
        "risk_level": risk_level,
        "reason": reason,
        "report": {
            "input_type": "upi_payment_qr",
            "payee_vpa": vpa,
            "payee_name": payee_name or None,
            "amount": amount or None,
            "currency": query.get("cu", [""])[0].strip()[:8] or None,
            "risk_score": confidence,
            "risk_level": risk_level,
            "known_threat": intel is not None,
            "method": "exact payee address threat-intelligence lookup",
            "signals": signals,
            "checked_at": datetime.now(timezone.utc).isoformat(),
            "scope": (
                "This checks the QR's payee address against available threat "
                "data. The displayed payee name and amount are not independently "
                "verified, and a missing match is not proof of safety."
            ),
        },
    }


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
# Dashboard reports
# ============================================================

@app.get("/reports", dependencies=[Depends(require_api_key)])
async def dashboard_report(
    section: Literal[
        "all",
        "summary",
        "checks",
        "brands",
        "evaluation",
        "connections",
    ] = "all",
) -> Response:
    async with session_factory() as session:
        detections = await get_detections(session)

    verdict_counts = Counter(
        detection.verdict
        for detection in detections
    )
    brand_counts = Counter(
        (detection.brand or "Unidentified").strip().casefold()
        or "Unidentified"
        for detection in detections
    )
    average_score = (
        sum(detection.score for detection in detections) / len(detections)
        if detections
        else 0
    )

    sections: list[str] = [
        f"Created: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        "",
    ]

    if section in {"all", "summary"}:
        sections.extend(
            [
                "OVERVIEW",
                f"Website checks saved: {len(detections)}",
                f"Likely scams: {verdict_counts.get('phishing', 0)}",
                f"Needs a closer look: {verdict_counts.get('suspicious', 0)}",
                f"No clear warning signs: {verdict_counts.get('benign', 0)}",
                f"Average risk score: {average_score:.0%}",
                "",
            ]
        )

    if section in {"all", "checks"}:
        sections.append("WEBSITE CHECKS")
        if not detections:
            sections.append("No website checks have been saved yet.")
        for detection in detections:
            verdict = {
                "phishing": "Likely a scam",
                "suspicious": "Needs a closer look",
                "benign": "No clear warning signs",
            }.get(detection.verdict, detection.verdict)
            created_at = (
                detection.created_at.strftime("%Y-%m-%d %H:%M")
                if detection.created_at
                else "Unknown date"
            )
            sections.extend(
                [
                    f"Check #{detection.id}: {detection.url}",
                    f"Result: {verdict} | Risk score: {detection.score:.0%}",
                    f"Brand: {detection.brand or 'Unidentified'} | Checked: {created_at}",
                ]
            )
            reasons = (detection.evidence or {}).get("reasons", [])
            if isinstance(reasons, list):
                sections.extend(f"Reason: {reason}" for reason in reasons)
            sections.append("")

    if section in {"all", "brands"}:
        sections.append("BRAND RESULTS")
        if not brand_counts:
            sections.append("No brand results are available yet.")
        else:
            sections.extend(
                f"{brand}: {count} check(s)"
                for brand, count in sorted(
                    brand_counts.items(),
                    key=lambda item: (-item[1], item[0]),
                )
            )
        sections.append("")

    if section in {"all", "evaluation"}:
        try:
            evaluation_data = evaluate_labels()
        except FileNotFoundError as error:
            if section == "evaluation":
                raise HTTPException(
                    status_code=503,
                    detail="Test results are not available right now.",
                ) from error
            sections.extend(
                [
                    "TEST RESULTS",
                    "Test results could not be included because the test data is unavailable.",
                    "",
                ]
            )
        else:
            metrics = evaluation_data.get("metrics", evaluation_data)
            sections.extend(
                [
                    "TEST RESULTS",
                    f"Test samples: {evaluation_data.get('samples', 0)}",
                    f"Accuracy: {float(metrics.get('accuracy', 0)):.0%}",
                    f"Precision: {float(metrics.get('precision', 0)):.0%}",
                    f"Recall: {float(metrics.get('recall', 0)):.0%}",
                    f"F1 score: {float(metrics.get('f1', 0)):.0%}",
                    f"Test errors: {evaluation_data.get('errors_count', 0)}",
                    "",
                ]
            )

    if section in {"all", "connections"}:
        graph = await graph_snapshot()
        nodes = graph.get("nodes", [])
        links = graph.get("links", [])
        clusters = cluster_graph(nodes=nodes, links=links)
        sections.extend(
            [
                "WEBSITE CONNECTIONS",
                f"Items found: {len(nodes)}",
                f"Connections found: {len(links)}",
                f"Related groups: {len(clusters)}",
                "A related group is an estimate and does not prove a shared owner.",
            ]
        )
        for node in nodes:
            sections.append(
                f"Item: {node.get('label') or node.get('id', 'Unknown')} "
                f"({node.get('type', 'unknown')})"
            )
        for link in links:
            sections.append(
                f"Connection: {link.get('source', 'Unknown')} "
                f"{link.get('relation', 'related to')} "
                f"{link.get('target', 'Unknown')}"
            )
        for cluster in clusters:
            sections.append(
                f"Group {cluster.get('cluster_id', 'unknown')}: "
                f"{cluster.get('size', 0)} items, "
                f"{cluster.get('confidence_percent', 0)}% estimated match"
            )
            sections.extend(
                f"Evidence: {item}"
                for item in cluster.get("evidence", [])
            )
        sections.append("")

    return Response(
        content=create_report(
            "UPI Shield - Full Report"
            if section == "all"
            else f"UPI Shield - {section.title()} Report",
            "\n".join(sections),
        ),
        media_type="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename=upi-shield-{section}.pdf"
        },
    )


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