import asyncio
import hashlib
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from backend.auth import (
    hash_password,
    issue_password_reset_token,
    reset_analyst_password,
    verify_password,
)
from backend.db import (
    ActivityEvent,
    AnalystSession,
    AnalystUser,
    Base,
    PasswordResetToken,
    _migrate_analyst_user_columns,
    close_connections,
)
from backend.main import app, client_ip_address
from backend.models import AuthCredentials, PasswordResetCompletion
from starlette.requests import Request


class PasswordTests(unittest.TestCase):
    def test_password_hash_verifies_without_storing_plaintext(self):
        password = "correct horse battery staple"
        encoded = hash_password(password)

        self.assertTrue(encoded.startswith("scrypt$"))
        self.assertNotIn(password, encoded)
        self.assertTrue(verify_password(password, encoded))
        self.assertFalse(verify_password("incorrect password", encoded))

    def test_credentials_normalize_email_and_require_long_password(self):
        credentials = AuthCredentials(
            email="  Analyst@Example.com ",
            password="a-strong-password",
            account_type="professional",
        )

        self.assertEqual(credentials.email, "analyst@example.com")
        with self.assertRaises(ValueError):
            AuthCredentials(
                email="analyst@example.com",
                password="short",
                account_type="professional",
            )
        with self.assertRaises(ValueError):
            PasswordResetCompletion(
                token="t" * 40,
                password="too-short",
            )


class DatabaseMigrationTests(unittest.TestCase):
    def test_existing_analyst_accounts_remain_verified(self):
        engine = create_engine("sqlite://")
        with engine.begin() as connection:
            connection.execute(
                text(
                    "CREATE TABLE analyst_users ("
                    "id INTEGER PRIMARY KEY, email VARCHAR(254), "
                    "password_hash VARCHAR(256))"
                )
            )
            connection.execute(
                text(
                    "CREATE TABLE email_verification_tokens ("
                    "id INTEGER PRIMARY KEY, token_hash VARCHAR(64), "
                    "user_id INTEGER, expires_at TIMESTAMP)"
                )
            )
            connection.execute(
                text(
                    "INSERT INTO analyst_users (id, email, password_hash) "
                    "VALUES (1, 'existing@example.com', 'old-hash')"
                )
            )

            _migrate_analyst_user_columns(connection)
            verified = connection.execute(
                text("SELECT is_verified FROM analyst_users WHERE id = 1")
            ).scalar_one()
            account_type = connection.execute(
                text("SELECT account_type FROM analyst_users WHERE id = 1")
            ).scalar_one()

        engine.dispose()
        self.assertTrue(verified)
        self.assertEqual(account_type, "professional")


class PasswordResetServiceTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_async_engine("sqlite+aiosqlite://")
        self.session_factory = async_sessionmaker(
            self.engine,
            expire_on_commit=False,
        )

        async def create_tables():
            async with self.engine.begin() as connection:
                await connection.run_sync(
                    lambda sync_connection: Base.metadata.create_all(
                        sync_connection,
                        tables=[
                            AnalystUser.__table__,
                            PasswordResetToken.__table__,
                            AnalystSession.__table__,
                            ActivityEvent.__table__,
                        ],
                    )
                )

        asyncio.run(create_tables())

    def tearDown(self):
        asyncio.run(self.engine.dispose())

    def test_reset_token_is_hashed_expiring_and_rate_limited(self):
        async def run_test():
            async with self.session_factory() as session:
                user = AnalystUser(
                    email="reset@example.com",
                    password_hash=hash_password("old-strong-password"),
                    is_verified=True,
                )
                session.add(user)
                await session.commit()

            with patch("backend.auth.session_factory", self.session_factory):
                token = await issue_password_reset_token(
                    user,
                    minimum_interval_seconds=60,
                )
                throttled_token = await issue_password_reset_token(
                    user,
                    minimum_interval_seconds=60,
                )

            self.assertIsNotNone(token)
            self.assertIsNone(throttled_token)
            async with self.session_factory() as session:
                reset_token = (
                    await session.execute(select(PasswordResetToken))
                ).scalar_one()
                self.assertEqual(
                    reset_token.token_hash,
                    hashlib.sha256(token.encode("utf-8")).hexdigest(),
                )
                self.assertNotEqual(reset_token.token_hash, token)
                expires_at = reset_token.expires_at
                if expires_at.tzinfo is None:
                    expires_at = expires_at.replace(tzinfo=timezone.utc)
                self.assertGreater(
                    expires_at,
                    datetime.now(timezone.utc),
                )

        asyncio.run(run_test())

    def test_reset_changes_password_consumes_token_and_revokes_sessions(self):
        async def run_test():
            raw_token = "one-time-reset-token"
            async with self.session_factory() as session:
                user = AnalystUser(
                    email="reset@example.com",
                    password_hash=hash_password("old-strong-password"),
                    is_verified=True,
                )
                session.add(user)
                await session.flush()
                session.add_all(
                    [
                        PasswordResetToken(
                            token_hash=hashlib.sha256(
                                raw_token.encode("utf-8")
                            ).hexdigest(),
                            user_id=user.id,
                            expires_at=datetime.now(timezone.utc)
                            + timedelta(minutes=30),
                        ),
                        AnalystSession(
                            token_hash="s" * 64,
                            user_id=user.id,
                            expires_at=datetime.now(timezone.utc)
                            + timedelta(days=1),
                        ),
                    ]
                )
                await session.commit()
                user_id = user.id

            with patch("backend.auth.session_factory", self.session_factory):
                reset = await reset_analyst_password(
                    raw_token,
                    "new-strong-password",
                )
                reused = await reset_analyst_password(
                    raw_token,
                    "another-strong-password",
                )

            self.assertTrue(reset)
            self.assertFalse(reused)
            async with self.session_factory() as session:
                user = await session.get(AnalystUser, user_id)
                self.assertTrue(
                    verify_password("new-strong-password", user.password_hash)
                )
                self.assertFalse(
                    verify_password("old-strong-password", user.password_hash)
                )
                self.assertEqual(
                    await session.scalar(
                        select(func.count()).select_from(PasswordResetToken)
                    ),
                    0,
                )
                self.assertEqual(
                    await session.scalar(
                        select(func.count()).select_from(AnalystSession)
                    ),
                    0,
                )
                self.assertEqual(
                    await session.scalar(
                        select(func.count())
                        .select_from(ActivityEvent)
                        .where(ActivityEvent.event_type == "password_reset")
                    ),
                    1,
                )

        asyncio.run(run_test())

    def test_expired_reset_token_cannot_change_password(self):
        async def run_test():
            raw_token = "expired-reset-token"
            async with self.session_factory() as session:
                user = AnalystUser(
                    email="reset@example.com",
                    password_hash=hash_password("old-strong-password"),
                    is_verified=True,
                )
                session.add(user)
                await session.flush()
                session.add(
                    PasswordResetToken(
                        token_hash=hashlib.sha256(
                            raw_token.encode("utf-8")
                        ).hexdigest(),
                        user_id=user.id,
                        expires_at=datetime.now(timezone.utc)
                        - timedelta(minutes=1),
                    )
                )
                await session.commit()
                user_id = user.id

            with patch("backend.auth.session_factory", self.session_factory):
                reset = await reset_analyst_password(
                    raw_token,
                    "new-strong-password",
                )

            self.assertFalse(reset)
            async with self.session_factory() as session:
                user = await session.get(AnalystUser, user_id)
                self.assertTrue(
                    verify_password("old-strong-password", user.password_hash)
                )

        asyncio.run(run_test())


class AuthenticationRouteTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def tearDown(self):
        self.client.close()

    @classmethod
    def tearDownClass(cls):
        asyncio.run(close_connections())

    def test_register_sends_confirmation_without_creating_session(self):
        user = SimpleNamespace(
            id=7,
            email="analyst@example.com",
            full_name="Analyst One",
        )
        with (
            patch("backend.main.create_analyst", new_callable=AsyncMock, return_value=user),
            patch("backend.main.issue_verification_token", new_callable=AsyncMock, return_value="verification-token"),
            patch("backend.main.send_email", new_callable=AsyncMock) as send_email,
            patch("backend.main.create_session", new_callable=AsyncMock) as create_session,
        ):
            response = self.client.post(
                "/auth/register",
                headers={"Origin": "http://localhost:3000"},
                json={
                    "full_name": "Analyst One",
                    "mobile_number": "+919876543210",
                    "email": "analyst@example.com",
                    "password": "a-strong-password",
                    "account_type": "professional",
                    "employer": "Example Corp",
                    "department": "Security",
                    "job_title": "Analyst",
                    "employment_type": "Full-time",
                    "employee_id": "EMP-7",
                },
            )

        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.json()["email"], user.email)
        self.assertIn("confirmation link", response.json()["message"])
        send_email.assert_awaited_once()
        create_session.assert_not_awaited()

    def test_register_requires_name_and_country_coded_mobile_number(self):
        response = self.client.post(
            "/auth/register",
            headers={"Origin": "http://localhost:3000"},
            json={
                "email": "analyst@example.com",
                "password": "a-strong-password",
                "account_type": "professional",
            },
        )
        self.assertEqual(response.status_code, 422)

    def test_student_registration_requires_an_id_card_upload(self):
        response = self.client.post(
            "/auth/register",
            headers={"Origin": "http://localhost:3000"},
            json={
                "full_name": "Student One",
                "mobile_number": "+919876543210",
                "email": "student@example.com",
                "password": "a-strong-password",
                "account_type": "student",
                "academic_session": "2026-2027",
                "institution": "Example University",
                "department": "Computer Science",
                "course": "BSc",
                "study_year": "2nd year",
            },
        )
        self.assertEqual(response.status_code, 422)
        self.assertEqual(response.json()["detail"], "Upload your student ID card")

    def test_student_registration_stores_the_uploaded_card_privately(self):
        user = SimpleNamespace(
            id=8,
            email="student@example.com",
            full_name="Student One",
        )
        with tempfile.TemporaryDirectory() as upload_directory:
            with (
                patch(
                    "backend.main.PRIVATE_ID_DIRECTORY",
                    Path(upload_directory),
                ),
                patch(
                    "backend.main.create_analyst",
                    new_callable=AsyncMock,
                    return_value=user,
                ) as create_user,
                patch(
                    "backend.main.issue_verification_token",
                    new_callable=AsyncMock,
                    return_value="verification-token",
                ),
                patch("backend.main.send_email", new_callable=AsyncMock),
                patch(
                    "backend.main.get_current_user",
                    new_callable=AsyncMock,
                    return_value=user,
                ),
            ):
                response = self.client.post(
                    "/auth/register",
                    headers={"Origin": "http://localhost:3000"},
                    data={
                        "full_name": "Student One",
                        "mobile_number": "+919876543210",
                        "email": "student@example.com",
                        "password": "a-strong-password",
                        "account_type": "student",
                        "academic_session": "2026-2027",
                        "institution": "Example University",
                        "department": "Computer Science",
                        "course": "BSc",
                        "study_year": "2nd year",
                    },
                    files={
                        "student_id_card": (
                            "student-id.pdf",
                            b"%PDF-1.7 private student card",
                            "application/pdf",
                        )
                    },
                )

                stored_name = create_user.await_args.kwargs["student_id_document"]
                stored_file = Path(upload_directory) / stored_name
                self.assertTrue(stored_file.is_file())
                self.assertEqual(
                    stored_file.read_bytes(),
                    b"%PDF-1.7 private student card",
                )
                user.student_id_document = stored_name
                download = self.client.get("/auth/profile/student-id-card")
                self.assertEqual(download.status_code, 200)
                self.assertEqual(
                    download.content,
                    b"%PDF-1.7 private student card",
                )
                self.assertEqual(download.headers["cache-control"], "private, no-store")

        self.assertEqual(response.status_code, 202)

        response = self.client.post(
            "/auth/register",
            headers={"Origin": "http://localhost:3000"},
            json={
                "full_name": "Analyst One",
                "mobile_number": "9876543210",
                "email": "analyst@example.com",
                "password": "a-strong-password",
                "account_type": "professional",
            },
        )
        self.assertEqual(response.status_code, 422)

    def test_login_creates_session_cookie(self):
        user = SimpleNamespace(
            id=7,
            email="analyst@example.com",
            full_name="Analyst One",
        )
        with (
            patch(
                "backend.main.authenticate_analyst",
                new_callable=AsyncMock,
                return_value=user,
            ),
            patch(
                "backend.main.create_session",
                new_callable=AsyncMock,
                return_value="session-token",
            ),
            patch("backend.main.send_email", new_callable=AsyncMock) as send_email,
            patch("backend.main.record_login", new_callable=AsyncMock) as record_login,
        ):
            response = self.client.post(
                "/auth/login",
                headers={
                    "Origin": "http://localhost:3000",
                    "X-Forwarded-For": "203.0.113.42",
                },
                json={
                    "email": "analyst@example.com",
                    "password": "a-strong-password",
                    "account_type": "professional",
                },
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.cookies["upi_shield_session"], "session-token")
        self.assertEqual(response.json()["user"]["id"], user.id)
        send_email.assert_awaited_once()
        notification_body = send_email.await_args.args[2]
        self.assertIn("Login time:", notification_body)
        self.assertIn(" UTC", notification_body)
        self.assertIn("IP address: Unavailable", notification_body)
        self.assertNotIn("203.0.113.42", notification_body)
        record_login.assert_awaited_once_with(user)

    def test_logout_revokes_session_and_expires_cookie(self):
        user = SimpleNamespace(id=7)
        self.client.cookies.set("upi_shield_session", "valid-session")
        with (
            patch(
                "backend.main.find_analyst_by_session",
                new_callable=AsyncMock,
                return_value=user,
            ),
            patch(
                "backend.main.revoke_session",
                new_callable=AsyncMock,
            ) as revoke_session,
            patch(
                "backend.main.save_activity_event",
                new_callable=AsyncMock,
            ) as save_event,
        ):
            response = self.client.post(
                "/auth/logout",
                headers={"Origin": "http://localhost:3000"},
                json={},
            )

        self.assertEqual(response.status_code, 204)
        self.assertIn("max-age=0", response.headers["set-cookie"].lower())
        revoke_session.assert_awaited_once_with("valid-session")
        save_event.assert_awaited_once_with("logout", user_id=7)

    def test_login_ip_uses_connection_address_not_forwarded_header(self):
        request = Request(
            {
                "type": "http",
                "asgi": {"version": "3.0"},
                "http_version": "1.1",
                "method": "POST",
                "scheme": "http",
                "path": "/auth/login",
                "raw_path": b"/auth/login",
                "query_string": b"",
                "root_path": "",
                "server": ("localhost", 8000),
                "client": ("198.51.100.27", 54321),
                "headers": [(b"x-forwarded-for", b"203.0.113.42")],
            }
        )

        self.assertEqual(client_ip_address(request), "198.51.100.27")

    def test_login_uses_secure_cross_origin_cookie_behind_https_proxy(self):
        user = SimpleNamespace(
            id=7,
            email="analyst@example.com",
            full_name="Analyst One",
        )
        with (
            patch("backend.main.FRONTEND_ORIGINS", ("https://public.example",)),
            patch(
                "backend.main.authenticate_analyst",
                new_callable=AsyncMock,
                return_value=user,
            ),
            patch(
                "backend.main.create_session",
                new_callable=AsyncMock,
                return_value="session-token",
            ),
            patch("backend.main.send_email", new_callable=AsyncMock),
            patch("backend.main.record_login", new_callable=AsyncMock),
        ):
            response = self.client.post(
                "/auth/login",
                headers={
                    "Origin": "https://public.example",
                    "X-Forwarded-Proto": "https",
                },
                json={
                    "email": "analyst@example.com",
                    "password": "a-strong-password",
                    "account_type": "professional",
                },
            )

        self.assertEqual(response.status_code, 200)
        cookie = response.headers["set-cookie"].lower()
        self.assertIn("secure", cookie)
        self.assertIn("samesite=none", cookie)

    def test_login_rejects_invalid_credentials(self):
        with patch(
            "backend.main.authenticate_analyst",
            new_callable=AsyncMock,
            return_value=None,
        ), patch(
            "backend.main.save_activity_event",
            new_callable=AsyncMock,
        ):
            response = self.client.post(
                "/auth/login",
                headers={"Origin": "http://localhost:3000"},
                json={
                    "email": "analyst@example.com",
                    "password": "a-strong-password",
                    "account_type": "professional",
                },
            )

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()["detail"], "Invalid email or password")

    def test_login_rejects_a_mismatched_account_type(self):
        user = SimpleNamespace(
            id=7,
            email="student@example.com",
            account_type="student",
        )
        with (
            patch(
                "backend.main.authenticate_analyst",
                new_callable=AsyncMock,
                return_value=user,
            ),
            patch("backend.main.save_activity_event", new_callable=AsyncMock),
            patch("backend.main.create_session", new_callable=AsyncMock) as create_session,
        ):
            response = self.client.post(
                "/auth/login",
                headers={"Origin": "http://localhost:3000"},
                json={
                    "email": "student@example.com",
                    "password": "a-strong-password",
                    "account_type": "professional",
                },
            )

        self.assertEqual(response.status_code, 401)
        create_session.assert_not_awaited()

    def test_dashboard_evidence_requires_an_analyst_session(self):
        with patch(
            "backend.main.find_analyst_by_session",
            new_callable=AsyncMock,
            return_value=None,
        ):
            response = self.client.get("/artifacts/evidence.png")

        self.assertEqual(response.status_code, 401)

    def test_student_id_card_requires_an_analyst_session(self):
        with patch(
            "backend.main.find_analyst_by_session",
            new_callable=AsyncMock,
            return_value=None,
        ):
            response = self.client.get("/auth/profile/student-id-card")

        self.assertEqual(response.status_code, 401)

    def test_registration_rejects_untrusted_origins(self):
        with patch("backend.main.create_analyst", new_callable=AsyncMock) as create_user:
            response = self.client.post(
                "/auth/register",
                headers={"Origin": "https://untrusted.example"},
                json={
                    "full_name": "Analyst One",
                    "mobile_number": "+919876543210",
                    "email": "analyst@example.com",
                    "password": "a-strong-password",
                },
            )

        self.assertEqual(response.status_code, 403)
        create_user.assert_not_awaited()

    def test_dashboard_api_requires_an_analyst_session(self):
        with patch(
            "backend.main.find_analyst_by_session",
            new_callable=AsyncMock,
            return_value=None,
        ):
            response = self.client.get("/detections")

        self.assertEqual(response.status_code, 401)

    def test_current_analyst_requires_and_reads_session_cookie(self):
        user = SimpleNamespace(
            id=7,
            email="analyst@example.com",
            full_name="Analyst One",
            mobile_number="+919876543210",
            account_type="student",
            academic_session="2026-2027",
            institution="Example University",
            department="Computer Science",
            course="BSc",
            study_year="2nd year",
            student_id_document="private-card.pdf",
            employer="",
            job_title="",
            employment_type="",
            employee_id="",
            is_verified=True,
            created_at=None,
        )
        self.client.cookies.set("upi_shield_session", "valid-session")
        with patch(
            "backend.main.find_analyst_by_session",
            new_callable=AsyncMock,
            return_value=user,
        ) as find_user:
            response = self.client.get("/auth/me")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["user"]["id"], 7)
        self.assertEqual(response.json()["user"]["account_type"], "student")
        self.assertEqual(response.json()["user"]["institution"], "Example University")
        self.assertTrue(response.json()["user"]["has_student_id_document"])
        find_user.assert_awaited_once_with("valid-session")

    def test_login_rejects_unverified_accounts(self):
        with patch(
            "backend.main.authenticate_analyst",
            new_callable=AsyncMock,
            side_effect=PermissionError("Confirm your email address before signing in"),
        ):
            response = self.client.post(
                "/auth/login",
                headers={"Origin": "http://localhost:3000"},
                json={
                    "email": "analyst@example.com",
                    "password": "a-strong-password",
                    "account_type": "professional",
                },
            )

        self.assertEqual(response.status_code, 403)
        self.assertEqual(
            response.json()["detail"],
            "Confirm your email address before signing in",
        )

    def test_confirmation_token_activates_account(self):
        user = SimpleNamespace(email="analyst@example.com")
        with patch(
            "backend.main.verify_analyst_email",
            new_callable=AsyncMock,
            return_value=user,
        ):
            response = self.client.post(
                "/auth/verify",
                json={"token": "v" * 40},
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["email"], user.email)

    def test_password_reset_request_is_generic_and_emails_only_verified_accounts(self):
        user = SimpleNamespace(
            id=7,
            email="analyst@example.com",
            full_name="Analyst One",
            is_verified=True,
        )
        with (
            patch(
                "backend.main.find_analyst_by_email",
                new_callable=AsyncMock,
                side_effect=[user, None],
            ),
            patch(
                "backend.main.issue_password_reset_token",
                new_callable=AsyncMock,
                return_value="r" * 54,
            ) as issue_token,
            patch("backend.main.FRONTEND_ORIGINS", ("https://dashboard.example",)),
            patch("backend.main.send_email", new_callable=AsyncMock) as send_email,
        ):
            existing_response = self.client.post(
                "/auth/forgot-password",
                json={"email": "analyst@example.com"},
            )
            missing_response = self.client.post(
                "/auth/forgot-password",
                json={"email": "unknown@example.com"},
            )

        self.assertEqual(existing_response.status_code, 202)
        self.assertEqual(existing_response.json(), missing_response.json())
        self.assertNotIn("r" * 54, existing_response.text)
        issue_token.assert_awaited_once_with(
            user,
            minimum_interval_seconds=60,
        )
        send_email.assert_awaited_once()
        self.assertIn(
            "https://dashboard.example/reset-password?token=" + "r" * 54,
            send_email.await_args.args[2],
        )
        self.assertIn(
            "Android app reset code:\n" + "r" * 54,
            send_email.await_args.args[2],
        )

    def test_password_reset_updates_only_with_a_valid_reset_token(self):
        with patch(
            "backend.main.reset_analyst_password",
            new_callable=AsyncMock,
            side_effect=[True, False],
        ) as reset_password:
            response = self.client.post(
                "/auth/reset-password",
                json={"token": "r" * 40, "password": "a-new-strong-password"},
            )
            reused_response = self.client.post(
                "/auth/reset-password",
                json={"token": "r" * 40, "password": "another-strong-password"},
            )

        self.assertEqual(response.status_code, 200)
        self.assertIn("updated", response.json()["message"])
        self.assertEqual(reused_response.status_code, 400)
        reset_password.assert_any_await("r" * 40, "a-new-strong-password")
        reset_password.assert_any_await("r" * 40, "another-strong-password")

    def test_password_reset_email_still_supports_android_without_frontend_origin(self):
        user = SimpleNamespace(
            id=7,
            email="analyst@example.com",
            full_name="Analyst One",
            is_verified=True,
        )
        with (
            patch(
                "backend.main.find_analyst_by_email",
                new_callable=AsyncMock,
                return_value=user,
            ),
            patch(
                "backend.main.issue_password_reset_token",
                new_callable=AsyncMock,
                return_value="r" * 54,
            ),
            patch("backend.main.FRONTEND_ORIGINS", ()),
            patch("backend.main.send_email", new_callable=AsyncMock) as send_email,
        ):
            response = self.client.post(
                "/auth/forgot-password",
                json={"email": "analyst@example.com"},
            )

        self.assertEqual(response.status_code, 202)
        body = send_email.await_args.args[2]
        self.assertIn("Android app reset code:\n" + "r" * 54, body)
        self.assertNotIn("/reset-password?token=", body)

    def test_login_requires_successful_notification_before_creating_session(self):
        user = SimpleNamespace(
            id=7,
            email="analyst@example.com",
            full_name="Analyst One",
        )
        with (
            patch(
                "backend.main.authenticate_analyst",
                new_callable=AsyncMock,
                return_value=user,
            ),
            patch(
                "backend.main.send_email",
                new_callable=AsyncMock,
                side_effect=RuntimeError("SMTP unavailable"),
            ),
            patch(
                "backend.main.save_activity_event",
                new_callable=AsyncMock,
            ),
            patch(
                "backend.main.create_session",
                new_callable=AsyncMock,
            ) as create_session,
        ):
            response = self.client.post(
                "/auth/login",
                headers={"Origin": "http://localhost:3000"},
                json={
                    "email": "analyst@example.com",
                    "password": "a-strong-password",
                    "account_type": "professional",
                },
            )

        self.assertEqual(response.status_code, 503)
        self.assertNotIn("upi_shield_session", response.cookies)
        create_session.assert_not_awaited()

    def test_page_view_records_only_the_route_path(self):
        with patch(
            "backend.main.save_activity_event",
            new_callable=AsyncMock,
        ) as save_event:
            response = self.client.post(
                "/analytics/visit?tracking=ignored",
                headers={"Origin": "http://localhost:3000"},
                json={"path": "/admin"},
            )

        self.assertEqual(response.status_code, 202)
        save_event.assert_awaited_once_with(
            "page_view",
            metadata={"path": "/admin"},
        )

    def test_admin_endpoints_reject_non_allowlisted_users(self):
        user = SimpleNamespace(email="analyst@example.com")
        with (
            patch("backend.main.get_current_user", new_callable=AsyncMock, return_value=user),
            patch(
                "backend.main.get_settings",
                return_value=SimpleNamespace(admin_emails="admin@example.com"),
            ),
        ):
            response = self.client.get("/admin/overview")

        self.assertEqual(response.status_code, 403)

    def test_health_reports_database_outage_as_degraded(self):
        with (
            patch("backend.main.db_health", new_callable=AsyncMock, return_value=False),
            patch("backend.main.neo4j_health", new_callable=AsyncMock, return_value=False),
        ):
            response = self.client.get("/health")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "degraded")
        self.assertFalse(response.json()["services"]["database"])
        self.assertFalse(response.json()["services"]["postgres"])


if __name__ == "__main__":
    unittest.main()
