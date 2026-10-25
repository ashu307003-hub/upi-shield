import unittest
from unittest.mock import AsyncMock, patch

from backend.intelligence import analyze_domain


class AnalyzeDomainTests(unittest.IsolatedAsyncioTestCase):
    async def test_non_allowlisted_analysis_skips_network_lookups(self):
        with (
            patch(
                "backend.intelligence.resolve_dns",
                side_effect=AssertionError("DNS lookup should be skipped"),
            ),
            patch(
                "backend.intelligence.tls_certificate",
                side_effect=AssertionError("TLS lookup should be skipped"),
            ),
            patch(
                "backend.intelligence.rdap_domain",
                new_callable=AsyncMock,
                side_effect=AssertionError("RDAP lookup should be skipped"),
            ),
        ):
            result = await analyze_domain("https://example.test")

        self.assertTrue(result["dns"]["skipped"])
        self.assertTrue(result["tls"]["skipped"])
        self.assertTrue(result["rdap"]["skipped"])
        self.assertEqual(result["hostname"], "example.test")

    async def test_allowlisted_analysis_runs_network_lookups(self):
        with (
            patch(
                "backend.intelligence.resolve_dns",
                return_value={"addresses": ["127.0.0.1"]},
            ) as resolve_dns,
            patch(
                "backend.intelligence.tls_certificate",
                return_value={"sha256": "test"},
            ) as tls_certificate,
            patch(
                "backend.intelligence.rdap_domain",
                new_callable=AsyncMock,
                return_value={"age_days": 10},
            ) as rdap_domain,
        ):
            result = await analyze_domain(
                "https://localhost",
                active_lookups=True,
            )

        resolve_dns.assert_called_once_with("localhost")
        tls_certificate.assert_called_once_with("localhost")
        rdap_domain.assert_awaited_once_with("localhost")
        self.assertEqual(result["dns"]["addresses"], ["127.0.0.1"])
        self.assertEqual(result["tls"]["sha256"], "test")
        self.assertEqual(result["rdap"]["age_days"], 10)


if __name__ == "__main__":
    unittest.main()
