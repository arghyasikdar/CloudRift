"""Risk scoring and finding generation."""

from __future__ import annotations

from cloudrift.models.enums import ExposureStatus, RiskLevel
from cloudrift.models.report import BucketObservation, Finding


class RiskScorer:
    """Convert observations into normalized exposure findings."""

    def score(self, observation: BucketObservation) -> Finding | None:
        """Create a finding from a bucket observation when meaningful."""

        if observation.exposure in {ExposureStatus.NOT_FOUND, ExposureStatus.UNKNOWN}:
            return None
        highest_file_risk = self._highest_file_risk(observation)
        if highest_file_risk == RiskLevel.HIGH:
            risk = RiskLevel.HIGH
            title = "Sensitive cloud storage object exposed"
        elif observation.exposure == ExposureStatus.LISTABLE:
            risk = RiskLevel.MEDIUM
            title = "Open cloud storage object listing"
        elif observation.exposure == ExposureStatus.PUBLIC:
            risk = RiskLevel.MEDIUM
            title = "Publicly readable cloud storage bucket"
        else:
            risk = RiskLevel.LOW
            title = "Cloud storage bucket exists but requires authorization"

        if self._looks_like_public_media(observation.candidate.name) and risk == RiskLevel.MEDIUM:
            risk = RiskLevel.LOW
            title = "Likely public media or CDN storage exposure"

        return Finding(
            title=title,
            risk=risk,
            provider=observation.provider,
            bucket=observation.candidate.name,
            confidence=max(observation.confidence, observation.candidate.confidence),
            evidence=observation.evidence,
            exposed_files=observation.exposed_files,
            recommendation=self._recommendation(risk),
        )

    @staticmethod
    def _highest_file_risk(observation: BucketObservation) -> RiskLevel | None:
        """Return the highest sensitive file risk for an observation."""

        if any(file.risk == RiskLevel.HIGH for file in observation.exposed_files):
            return RiskLevel.HIGH
        if any(file.risk == RiskLevel.MEDIUM for file in observation.exposed_files):
            return RiskLevel.MEDIUM
        return None

    @staticmethod
    def _looks_like_public_media(name: str) -> bool:
        """Identify names commonly used for intentionally public content."""

        return any(token in name for token in ("cdn", "assets", "static", "media", "public"))

    @staticmethod
    def _recommendation(risk: RiskLevel) -> str:
        """Return concise remediation guidance."""

        if risk == RiskLevel.HIGH:
            return "Remove sensitive objects, rotate exposed credentials, and enforce least-privilege bucket policies."
        if risk == RiskLevel.MEDIUM:
            return "Review intended public access, disable anonymous listing, and restrict object ACLs where possible."
        return "Confirm business intent, document ownership, and monitor for sensitive object drift."
