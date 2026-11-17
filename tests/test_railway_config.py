import unittest

from backend.config import Settings


class RailwayConfigTests(unittest.TestCase):
    def test_postgres_urls_use_asyncpg_driver(self):
        for prefix in ("postgres://", "postgresql://"):
            with self.subTest(prefix=prefix):
                settings = Settings(
                    _env_file=None,
                    database_url=f"{prefix}user:pass@db.example:5432/upi_shield",
                )
                self.assertEqual(
                    settings.database_url,
                    "postgresql+asyncpg://user:pass@db.example:5432/upi_shield",
                )

    def test_asyncpg_url_is_not_rewritten(self):
        url = "postgresql+asyncpg://user:pass@db.example:5432/upi_shield"
        self.assertEqual(
            Settings(_env_file=None, database_url=url).database_url,
            url,
        )
