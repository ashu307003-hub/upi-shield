import unittest
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

from backend.main import app
from backend.takedown.report import create_report


class _SessionContext:
    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        return False


class DashboardReportTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def tearDown(self):
        self.client.close()

    def _detection(self):
        return SimpleNamespace(
            id=4,
            url="https://" + "example-" * 20 + "site.test",
            verdict="phishing",
            score=0.91,
            brand="Example",
            created_at=datetime(2025, 1, 1, tzinfo=timezone.utc),
            evidence={"reasons": ["A test warning"]},
        )

    def test_full_report_includes_dashboard_data_and_is_a_downloadable_pdf(self):
        with (
            patch(
                "backend.main.get_current_user",
                new_callable=AsyncMock,
                return_value=SimpleNamespace(id=1),
            ),
            patch(
                "backend.main.session_factory",
                return_value=_SessionContext(),
            ),
            patch(
                "backend.main.get_detections",
                new_callable=AsyncMock,
                return_value=[self._detection()],
            ),
            patch(
                "backend.main.evaluate_labels",
                return_value={
                    "samples": 5,
                    "metrics": {
                        "accuracy": 0.8,
                        "precision": 0.7,
                        "recall": 0.6,
                        "f1": 0.65,
                    },
                    "errors_count": 0,
                },
            ) as evaluate_labels,
            patch(
                "backend.main.graph_snapshot",
                new_callable=AsyncMock,
                return_value={"nodes": [], "links": []},
            ) as graph_snapshot,
            patch("backend.main.cluster_graph", return_value=[]),
        ):
            response = self.client.get("/reports?section=all")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["content-type"], "application/pdf")
        self.assertIn("attachment;", response.headers["content-disposition"])
        self.assertIn("upi-shield-all.pdf", response.headers["content-disposition"])
        self.assertTrue(response.content.startswith(b"%PDF"))
        evaluate_labels.assert_called_once_with()
        graph_snapshot.assert_awaited_once_with()

    def test_section_report_skips_unselected_dashboard_data(self):
        with (
            patch(
                "backend.main.get_current_user",
                new_callable=AsyncMock,
                return_value=SimpleNamespace(id=1),
            ),
            patch(
                "backend.main.session_factory",
                return_value=_SessionContext(),
            ),
            patch(
                "backend.main.get_detections",
                new_callable=AsyncMock,
                return_value=[self._detection()],
            ),
            patch("backend.main.evaluate_labels") as evaluate_labels,
            patch(
                "backend.main.graph_snapshot",
                new_callable=AsyncMock,
            ) as graph_snapshot,
        ):
            response = self.client.get("/reports?section=brands")

        self.assertEqual(response.status_code, 200)
        self.assertIn("upi-shield-brands.pdf", response.headers["content-disposition"])
        evaluate_labels.assert_not_called()
        graph_snapshot.assert_not_awaited()

    def test_report_requires_a_signed_in_user(self):
        with patch(
            "backend.main.find_analyst_by_session",
            new_callable=AsyncMock,
            return_value=None,
        ):
            response = self.client.get("/reports")

        self.assertEqual(response.status_code, 401)

    def test_test_results_report_explains_when_test_data_is_missing(self):
        with (
            patch(
                "backend.main.get_current_user",
                new_callable=AsyncMock,
                return_value=SimpleNamespace(id=1),
            ),
            patch(
                "backend.main.session_factory",
                return_value=_SessionContext(),
            ),
            patch(
                "backend.main.get_detections",
                new_callable=AsyncMock,
                return_value=[],
            ),
            patch(
                "backend.main.evaluate_labels",
                side_effect=FileNotFoundError,
            ),
        ):
            response = self.client.get("/reports?section=evaluation")

        self.assertEqual(response.status_code, 503)
        self.assertEqual(
            response.json()["detail"],
            "Test results are not available right now.",
        )

    def test_pdf_generation_handles_long_and_non_latin_text(self):
        report = create_report(
            "UPI Shield",
            "https://" + "example" * 50 + "site.test — 日本語",
        )

        self.assertTrue(report.startswith(b"%PDF"))


if __name__ == "__main__":
    unittest.main()
