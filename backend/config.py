from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    database_url: str = "postgresql+asyncpg://upi_shield:change-me@localhost:5432/upi_shield"
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = "change-me"
    redis_url: str = "redis://localhost:6379/0"
    smtp_host: str = "localhost"
    smtp_port: int = 1025
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_starttls: bool = False
    smtp_use_ssl: bool = False
    report_from_email: str = "alerts@example.com"
    admin_api_key: str = ""
    admin_emails: str = ""
    frontend_origins: str = "http://localhost:3000,http://127.0.0.1:3000"
    activity_retention_days: int = Field(default=180, gt=0)
    crawl_allowlist: str = "127.0.0.1,localhost"
    phishing_threshold: float = 0.6
    suspicious_threshold: float = 0.35
    max_upload_mb: int = 8

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


@lru_cache
def get_settings() -> Settings:
    return Settings()


def allowed_target(url: str) -> bool:
    allowlist = [item.strip().lower() for item in get_settings().crawl_allowlist.split(",") if item.strip()]
    if not allowlist:
        return False
    from urllib.parse import urlparse
    hostname = (urlparse(url).hostname or "").lower()
    return any(hostname == domain or hostname.endswith(f".{domain}") for domain in allowlist)
