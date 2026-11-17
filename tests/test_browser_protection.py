import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from pydantic import HttpUrl, TypeAdapter

from backend.main import check_browser_url
from backend.models import BrowserCheckRequest


class FakeSession:
    def __init__(self, detection):
        self.detection = detection

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        return None

    async def execute(self, _query):
        return SimpleNamespace(scalar_one_or_none=lambda: self.detection)


class BrowserProtectionTests(unittest.IsolatedAsyncioTestCase):
    async def test_threat_intelligence_match_is_blocked(self):
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
            result = await check_browser_url(
                BrowserCheckRequest(
                    url=TypeAdapter(HttpUrl).validate_python(
                        "https://payment.test"
                    )
                ),
                None,
            )

        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["verdict"], "phishing")

    async def test_prior_detection_on_same_host_is_blocked(self):
        detection = SimpleNamespace(
            verdict="suspicious",
            score=0.48,
        )
        with (
            patch(
                "backend.main.find_threat_indicator",
                new_callable=AsyncMock,
                return_value=None,
            ),
            patch(
                "backend.main.session_factory",
                side_effect=lambda: FakeSession(detection),
            ),
        ):
            result = await check_browser_url(
                BrowserCheckRequest(
                    url=TypeAdapter(HttpUrl).validate_python(
                        "https://payment.test/checkout"
                    )
                ),
                None,
            )

        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["verdict"], "suspicious")

    async def test_unknown_url_is_not_mislabeled_as_safe(self):
        with (
            patch(
                "backend.main.find_threat_indicator",
                new_callable=AsyncMock,
                return_value=None,
            ),
            patch(
                "backend.main.session_factory",
                side_effect=lambda: FakeSession(None),
            ),
        ):
            result = await check_browser_url(
                BrowserCheckRequest(
                    url=TypeAdapter(HttpUrl).validate_python(
                        "https://unknown.test"
                    )
                ),
                None,
            )

        self.assertEqual(result["status"], "unknown")
        self.assertIsNone(result["verdict"])
        self.assertEqual(result["score"], 0.0)
        self.assertEqual(result["risk_level"], "low")
        self.assertFalse(result["report"]["known_threat"])
        self.assertIn("does not inspect the page", result["report"]["scope"])

    async def test_url_risk_heuristic_returns_a_report_and_warning_verdict(self):
        with (
            patch(
                "backend.main.get_settings",
                return_value=SimpleNamespace(
                    suspicious_threshold=0.35,
                    phishing_threshold=0.6,
                ),
            ),
            patch(
                "backend.main.analyze_domain",
                new_callable=AsyncMock,
                return_value={"lexical": {"has_punycode": True}},
            ),
            patch(
                "backend.main.domain_risk",
                return_value=(0.45, ["Punycode hostname", "Payment words in URL"]),
            ),
            patch(
                "backend.main.find_threat_indicator",
                new_callable=AsyncMock,
                return_value=None,
            ),
            patch(
                "backend.main.session_factory",
                side_effect=lambda: FakeSession(None),
            ),
        ):
            result = await check_browser_url(
                BrowserCheckRequest(
                    url=TypeAdapter(HttpUrl).validate_python(
                        "https://xn--bcher-kva.example/payment/login"
                    )
                ),
                None,
            )

        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["verdict"], "suspicious")
        self.assertEqual(result["score"], 0.45)
        self.assertEqual(result["score_label"], "URL risk score (not probability)")
        self.assertEqual(result["report"]["signals"], [
            "Punycode hostname",
            "Payment words in URL",
        ])
        self.assertFalse(result["report"]["known_threat"])


if __name__ == "__main__":
    unittest.main()
