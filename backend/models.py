from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field, HttpUrl


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
    source: str = Field(default="analyst_report", pattern="^(analyst_report|ct_log|message)$")


class CaptureRequest(BaseModel):
    url: HttpUrl
    brand_keywords: list[str] = Field(default_factory=list)


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
