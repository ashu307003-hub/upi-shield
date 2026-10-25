from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field, HttpUrl, field_validator


class FindingStatus(StrEnum):
    NEW = "new"
    REVIEWED = "reviewed"
    DISMISSED = "dismissed"


class Finding(BaseModel):
    id: str
    url: HttpUrl
    brand: str | None = None
    score: float = 0.0
    status: FindingStatus = FindingStatus.NEW
    created_at: datetime


class DetectionRequest(BaseModel):
    url: HttpUrl
    screenshot: str
    dom: str
    brand_keywords: list[str] = Field(default_factory=list)


class DiscoverRequest(BaseModel):
    urls: list[HttpUrl] = Field(min_length=1, max_length=100)
    source: str = "analyst_report"

    @field_validator("source")
    @classmethod
    def validate_source(cls, source: str) -> str:
        source = source.strip()
        if not source:
            raise ValueError("source must not be empty")
        if len(source) > 100:
            raise ValueError("source must be at most 100 characters")
        if any(ord(character) < 32 or ord(character) == 127 for character in source):
            raise ValueError("source must not contain control characters")
        return source


class CaptureRequest(BaseModel):
    url: HttpUrl
    brand_keywords: list[str] = Field(default_factory=list)


class AuthCredentials(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=12, max_length=128)

    @field_validator("email")
    @classmethod
    def normalize_email(cls, email: str) -> str:
        email = email.strip().lower()
        local, separator, domain = email.partition("@")
        if (
            not separator
            or not local
            or "@" in domain
            or domain.startswith(".")
            or domain.endswith(".")
            or ".." in email
            or "." not in domain
            or any(character.isspace() for character in email)
        ):
            raise ValueError("Enter a valid email address")
        return email


class RegisterRequest(AuthCredentials):
    full_name: str = Field(min_length=2, max_length=120)
    mobile_number: str = Field(min_length=8, max_length=16)

    @field_validator("full_name")
    @classmethod
    def normalize_full_name(cls, name: str) -> str:
        name = " ".join(name.split())
        if any(ord(character) < 32 for character in name):
            raise ValueError("Name must not contain control characters")
        return name

    @field_validator("mobile_number")
    @classmethod
    def normalize_mobile_number(cls, phone: str) -> str:
        phone = phone.strip().replace(" ", "").replace("-", "").replace("(", "").replace(")", "")
        if phone.startswith("00"):
            phone = f"+{phone[2:]}"
        if not phone.startswith("+"):
            raise ValueError("Include your country code, starting with +")
        digits = phone[1:]
        if not digits.isdigit() or not 7 <= len(digits) <= 15 or digits.startswith("0"):
            raise ValueError("Enter a valid mobile number with country code")
        return phone


class EmailTokenRequest(BaseModel):
    token: str = Field(min_length=32, max_length=128)


class ResendVerificationRequest(BaseModel):
    email: str = Field(min_length=3, max_length=254)

    @field_validator("email")
    @classmethod
    def normalize_email(cls, email: str) -> str:
        return AuthCredentials.normalize_email(email)


class PageVisitRequest(BaseModel):
    path: str = Field(min_length=1, max_length=200)

    @field_validator("path")
    @classmethod
    def validate_path(cls, path: str) -> str:
        if (
            not path.startswith("/")
            or "?" in path
            or "#" in path
            or any(ord(character) < 32 for character in path)
        ):
            raise ValueError("path must be a clean site route")
        return path


class GraphObservation(BaseModel):
    domain: str
    ip: str | None = None
    asn: str | None = None
    cert_sha: str | None = None
    upi_id: str | None = None
    kit_hash: str | None = None


class DetectionResponse(BaseModel):
    id: int
    url: str
    brand: str | None
    score: float
    verdict: str
    behavioral: dict
    evidence: dict = Field(default_factory=dict)
    screenshot: str
    dom: str
    created_at: datetime | None = None
