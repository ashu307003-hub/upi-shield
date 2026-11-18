import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

import httpx

from backend.auth import _send_email


class BrevoEmailDeliveryTests(unittest.TestCase):
    def setUp(self):
        self.settings = SimpleNamespace(
            email_provider="brevo",
            brevo_api_key="test-api-key",
            report_from_email="sender@example.com",
            smtp_host="localhost",
            smtp_port=2525,
            smtp_username="",
            smtp_password="",
            smtp_starttls=False,
            smtp_use_ssl=False,
        )

    def test_sends_plain_text_and_html_through_brevo_https_api(self):
        response = Mock()
        with (
            patch("backend.auth.get_settings", return_value=self.settings),
            patch("backend.auth.httpx.post", return_value=response) as post,
        ):
            _send_email("recipient@example.com", "Subject", "Hello <there>")

        post.assert_called_once_with(
            "https://api.brevo.com/v3/smtp/email",
            headers={"api-key": "test-api-key"},
            json={
                "sender": {
                    "name": "UPI Shield",
                    "email": "sender@example.com",
                },
                "to": [{"email": "recipient@example.com"}],
                "subject": "Subject",
                "textContent": "Hello <there>",
                "htmlContent": "<pre>Hello &lt;there&gt;</pre>",
            },
            timeout=15,
        )
        response.raise_for_status.assert_called_once_with()

    def test_requires_api_key_without_attempting_a_request(self):
        self.settings.brevo_api_key = ""
        with (
            patch("backend.auth.get_settings", return_value=self.settings),
            patch("backend.auth.httpx.post") as post,
        ):
            with self.assertRaisesRegex(RuntimeError, "BREVO_API_KEY"):
                _send_email("recipient@example.com", "Subject", "Body")

        post.assert_not_called()

    def test_reports_brevo_http_status_without_exposing_credentials(self):
        response = httpx.Response(
            401,
            request=httpx.Request("POST", "https://api.brevo.com/v3/smtp/email"),
        )
        with (
            patch("backend.auth.get_settings", return_value=self.settings),
            patch(
                "backend.auth.httpx.post",
                side_effect=httpx.HTTPStatusError(
                    "unauthorized",
                    request=response.request,
                    response=response,
                ),
            ),
        ):
            with self.assertRaisesRegex(RuntimeError, "HTTP 401") as error:
                _send_email("recipient@example.com", "Subject", "Body")

        self.assertNotIn(self.settings.brevo_api_key, str(error.exception))

    def test_smtp_provider_remains_supported(self):
        self.settings.email_provider = "smtp"
        with (
            patch("backend.auth.get_settings", return_value=self.settings),
            patch("backend.auth.SMTP") as smtp,
        ):
            _send_email("recipient@example.com", "Subject", "Body")

        smtp.assert_called_once_with("localhost", 2525, timeout=15)
        message = smtp.return_value.__enter__.return_value.send_message.call_args.args[0]
        self.assertEqual(message["To"], "recipient@example.com")
        self.assertEqual(message.get_content(), "Body\n")


if __name__ == "__main__":
    unittest.main()
