"""Provider abstraction for cloud storage validation."""

from __future__ import annotations

from abc import ABC, abstractmethod

import httpx

from cloudrift.analyzers.exposure import ExposureAnalyzer
from cloudrift.analyzers.sensitive import SensitiveFileAnalyzer
from cloudrift.models.enums import CloudProvider
from cloudrift.models.report import BucketCandidate, BucketObservation


class CloudStorageProvider(ABC):
    """Base class for async storage provider checks."""

    provider: CloudProvider

    def __init__(self, client: httpx.AsyncClient) -> None:
        self.client = client
        self.exposure_analyzer = ExposureAnalyzer()
        self.sensitive_analyzer = SensitiveFileAnalyzer()

    @abstractmethod
    def endpoints_for(self, bucket: str) -> list[str]:
        """Return provider endpoints to validate a bucket candidate."""

    async def validate(self, candidate: BucketCandidate) -> BucketObservation:
        """Validate a candidate against provider endpoints."""

        best = BucketObservation(candidate=candidate, provider=self.provider)
        for endpoint in self.endpoints_for(candidate.name):
            observation = await self._probe(candidate, endpoint)
            if observation.exposure.value in {"listable", "public", "exists_private"}:
                return observation
            if observation.status_code and observation.status_code != 404:
                best = observation
        return best

    async def _probe(self, candidate: BucketCandidate, endpoint: str) -> BucketObservation:
        """Probe one endpoint and convert the response to an observation."""

        try:
            response = await self.client.get(endpoint)
            body = response.text[:2_000_000]
            headers = {key.lower(): value for key, value in response.headers.items()}
            exposure, evidence = self.exposure_analyzer.classify(response.status_code, body, headers)
            paths = self.exposure_analyzer.extract_listing_paths(body)
            exposed_files = self.sensitive_analyzer.analyze_paths(paths, endpoint)
            confidence = self._confidence(response.status_code, exposure.value, evidence)
            region = headers.get("x-amz-bucket-region") or headers.get("x-goog-stored-content-encoding")
            return BucketObservation(
                candidate=candidate,
                endpoint=endpoint,
                provider=self.provider,
                status_code=response.status_code,
                exposure=exposure,
                confidence=confidence,
                region=region,
                evidence=evidence,
                exposed_files=exposed_files,
            )
        except httpx.HTTPError as exc:
            return BucketObservation(
                candidate=candidate,
                endpoint=endpoint,
                provider=self.provider,
                evidence=[f"Request failed: {exc.__class__.__name__}"],
            )

    @staticmethod
    def _confidence(status_code: int | None, exposure: str, evidence: list[str]) -> float:
        """Compute a bounded confidence score for an observation."""

        if exposure in {"listable", "public"}:
            return 0.94
        if exposure == "exists_private":
            return 0.72
        if status_code == 404:
            return 0.2
        return 0.35 + min(len(evidence) * 0.08, 0.3)
