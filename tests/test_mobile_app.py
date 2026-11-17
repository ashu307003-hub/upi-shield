import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from backend.main import check_mobile_qr, mobile_login
from backend.models import AuthCredentials, QrCheckRequest


class MobileAppTests(unittest.IsolatedAsyncioTestCase):
    async def test_upi_qr_match_returns_recipient_risk_report(self):
        user = SimpleNamespace(id=1)
        intel = SimpleNamespace(confidence=0.82, source="test-feed")
        with (
            patch(
                "backend.main.get_settings",
                return_value=SimpleNamespace(
                    suspicious_threshold=0.35,
                    phishing_threshold=0.6,
                ),
            ),
            patch(
                "backend.main.find_threat_indicator",
                new_callable=AsyncMock,
                return_value=intel,
            ),
        ):
            result = await check_mobile_qr(
                QrCheckRequest(
                    payload=(
                        "upi://pay?pa=merchant%40upi&pn=Test%20Shop"
                        "&am=25.00&cu=INR"
                    )
                ),
                user,
            )

        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["verdict"], "phishing")
        self.assertEqual(result["score"], 0.82)
        self.assertEqual(result["report"]["payee_vpa"], "merchant@upi")
        self.assertEqual(result["report"]["payee_name"], "Test Shop")
        self.assertEqual(result["report"]["amount"], "25.00")

    async def test_unmatched_upi_qr_is_not_labeled_safe(self):
        with (
            patch(
                "backend.main.get_settings",
                return_value=SimpleNamespace(
                    suspicious_threshold=0.35,
                    phishing_threshold=0.6,
                ),
            ),
            patch(
                "backend.main.find_threat_indicator",
                new_callable=AsyncMock,
                return_value=None,
            ),
        ):
            result = await check_mobile_qr(
                QrCheckRequest(payload="upi://pay?pa=merchant%40upi&pn=Shop"),
                SimpleNamespace(id=1),
            )

        self.assertEqual(result["status"], "unknown")
        self.assertIsNone(result["verdict"])
        self.assertFalse(result["report"]["known_threat"])
        self.assertIn("not proof of safety", result["report"]["scope"])

    async def test_web_link_in_qr_reuses_click_time_url_check(self):
        expected = {
            "status": "unknown",
            "verdict": None,
            "report": {"signals": []},
        }
        with patch(
            "backend.main.check_browser_url",
            new_callable=AsyncMock,
            return_value=expected,
        ) as check_url:
            result = await check_mobile_qr(
                QrCheckRequest(payload="https://merchant.example/pay"),
                SimpleNamespace(id=1),
            )

        self.assertEqual(result["report"]["input_type"], "qr_web_link")
        check_url.assert_awaited_once()

    async def test_mobile_login_returns_a_bearer_session(self):
        user = SimpleNamespace(
            id=3,
            email="analyst@example.com",
            full_name="Test Analyst",
            account_type="professional",
        )
        credentials = AuthCredentials(
            email="analyst@example.com",
            password="long-password-123",
            account_type="professional",
        )
        with (
            patch(
                "backend.main.authenticate_analyst",
                new_callable=AsyncMock,
                return_value=user,
            ),
            patch("backend.main.client_ip_address", return_value="127.0.0.1"),
            patch("backend.main.send_email", new_callable=AsyncMock),
            patch("backend.main.record_login", new_callable=AsyncMock),
            patch(
                "backend.main.create_session",
                new_callable=AsyncMock,
                return_value="test-session-token",
            ),
            patch(
                "backend.main.get_settings",
                return_value=SimpleNamespace(admin_emails=""),
            ),
        ):
            result = await mobile_login(credentials, SimpleNamespace())

        self.assertEqual(result["session_token"], "test-session-token")
        self.assertEqual(result["user"]["email"], user.email)


if __name__ == "__main__":
    unittest.main()
