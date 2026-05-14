"""Relationship and report correlation logic."""

from __future__ import annotations

from collections import Counter

from cloudrift.models.enums import ExposureStatus
from cloudrift.models.report import BucketObservation, IntelligenceReport, Relationship


class CorrelationEngine:
    """Deduplicate and correlate storage observations into a report."""

    def correlate(
        self,
        report: IntelligenceReport,
        observations: list[BucketObservation],
        relationships: list[Relationship],
    ) -> IntelligenceReport:
        """Attach observations, relationships, and statistics to a report."""

        seen: set[tuple[str, str]] = set()
        deduped: list[BucketObservation] = []
        for observation in observations:
            key = (observation.provider.value, observation.candidate.name)
            if key not in seen:
                seen.add(key)
                deduped.append(observation)

        report.observations = deduped
        report.relationships = self._dedupe_relationships(relationships)
        report.statistics.candidates_generated = len(report.candidates)
        report.statistics.buckets_validated = len(deduped)
        report.statistics.public_buckets = sum(
            observation.exposure in {ExposureStatus.PUBLIC, ExposureStatus.LISTABLE}
            for observation in deduped
        )
        report.statistics.sensitive_files = sum(len(observation.exposed_files) for observation in deduped)
        report.statistics.providers_seen = dict(Counter(observation.provider for observation in deduped))
        return report

    @staticmethod
    def _dedupe_relationships(relationships: list[Relationship]) -> list[Relationship]:
        """Deduplicate relationship edges."""

        seen: set[tuple[str, str, str]] = set()
        output: list[Relationship] = []
        for relationship in relationships:
            key = (relationship.source, relationship.target, relationship.relation)
            if key not in seen:
                seen.add(key)
                output.append(relationship)
        return output
