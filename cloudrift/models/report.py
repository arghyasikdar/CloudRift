"""Pydantic data models for CloudRift intelligence reports."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field, HttpUrl

from cloudrift.models.enums import CloudProvider, ExposureStatus, RiskLevel


class ProviderFingerprint(BaseModel):
    """A provider detection signal extracted from a URL or response."""

    provider: CloudProvider
    confidence: float = Field(ge=0, le=1)
    indicator: str
    source: str


class ExposedFile(BaseModel):
    """A potentially exposed object or file in cloud storage."""

    path: str
    url: str | None = None
    category: str
    risk: RiskLevel
    confidence: float = Field(default=0.75, ge=0, le=1)
    evidence: str | None = None


class BucketCandidate(BaseModel):
    """A generated or extracted bucket/container candidate."""

    name: str
    provider: CloudProvider = CloudProvider.UNKNOWN
    source: str
    confidence: float = Field(default=0.5, ge=0, le=1)
    metadata: dict[str, Any] = Field(default_factory=dict)


class BucketObservation(BaseModel):
    """Validation and exposure observations for one bucket candidate."""

    candidate: BucketCandidate
    endpoint: str | None = None
    provider: CloudProvider = CloudProvider.UNKNOWN
    status_code: int | None = None
    exposure: ExposureStatus = ExposureStatus.UNKNOWN
    confidence: float = Field(default=0.0, ge=0, le=1)
    region: str | None = None
    evidence: list[str] = Field(default_factory=list)
    exposed_files: list[ExposedFile] = Field(default_factory=list)


class Finding(BaseModel):
    """A correlated security finding."""

    title: str
    risk: RiskLevel
    provider: CloudProvider
    bucket: str
    confidence: float = Field(ge=0, le=1)
    evidence: list[str] = Field(default_factory=list)
    exposed_files: list[ExposedFile] = Field(default_factory=list)
    recommendation: str


class Relationship(BaseModel):
    """A relationship between a source artifact and a cloud asset."""

    source: str
    target: str
    relation: str
    confidence: float = Field(default=0.7, ge=0, le=1)


class ScanStatistics(BaseModel):
    """High-level execution metrics."""

    candidates_generated: int = 0
    buckets_validated: int = 0
    public_buckets: int = 0
    sensitive_files: int = 0
    providers_seen: dict[CloudProvider, int] = Field(default_factory=dict)


class IntelligenceReport(BaseModel):
    """Final CloudRift report emitted by the engine."""

    target: str
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    candidates: list[BucketCandidate] = Field(default_factory=list)
    observations: list[BucketObservation] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    relationships: list[Relationship] = Field(default_factory=list)
    fingerprints: list[ProviderFingerprint] = Field(default_factory=list)
    statistics: ScanStatistics = Field(default_factory=ScanStatistics)
    js_sources: list[HttpUrl | str] = Field(default_factory=list)

    @property
    def highest_risk(self) -> RiskLevel:
        """Return the highest risk represented in the report."""

        order = {
            RiskLevel.HIGH: 3,
            RiskLevel.MEDIUM: 2,
            RiskLevel.LOW: 1,
            RiskLevel.INFO: 0,
        }
        if not self.findings:
            return RiskLevel.INFO
        return max((finding.risk for finding in self.findings), key=order.get)
