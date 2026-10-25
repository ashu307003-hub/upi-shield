import asyncio
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text

from backend.auth import hash_password, verify_password
from backend.db import _migrate_analyst_user_columns, close_connections
from backend.main import app
from backend.models import AuthCredentials


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
        )

        self.assertEqual(credentials.email, "analyst@example.com")
        with self.assertRaises(ValueError):
            AuthCredentials(email="analyst@example.com", password="short")


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

        engine.dispose()
        self.assertTrue(verified)


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
            },
        )
        self.assertEqual(response.status_code, 422)

        response = self.client.post(
            "/auth/register",
            headers={"Origin": "http://localhost:3000"},
            json={
                "full_name": "Analyst One",
                "mobile_number": "9876543210",
                "email": "analyst@example.com",
                "password": "a-strong-password",
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
                headers={"Origin": "http://localhost:3000"},
                json={
                    "email": "analyst@example.com",
                    "password": "a-strong-password",
                },
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.cookies["upi_shield_session"], "session-token")
        self.assertEqual(response.json()["user"]["id"], user.id)
        send_email.assert_awaited_once()
        record_login.assert_awaited_once_with(user)

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
                },
            )

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()["detail"], "Invalid email or password")

    def test_dashboard_evidence_requires_an_analyst_session(self):
        with patch(
            "backend.main.find_analyst_by_session",
            new_callable=AsyncMock,
            return_value=None,
        ):
            response = self.client.get("/artifacts/evidence.png")

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
