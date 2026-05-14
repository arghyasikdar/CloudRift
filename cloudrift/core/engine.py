"""CloudRift async intelligence engine."""

from __future__ import annotations

import asyncio

import httpx

from cloudrift.core.config import ScanConfig
from cloudrift.discovery.jsintel import JavaScriptIntelExtractor
from cloudrift.discovery.permutations import BucketPermutationGenerator
from cloudrift.fingerprints.engine import FingerprintEngine
from cloudrift.intelligence.correlation import CorrelationEngine
from cloudrift.intelligence.scoring import RiskScorer
from cloudrift.models.enums import CloudProvider
from cloudrift.models.report import BucketCandidate, BucketObservation, IntelligenceReport, Relationship
from cloudrift.providers.registry import build_providers


class CloudRiftEngine:
    """Coordinate discovery, validation, exposure analysis, and reporting."""

    def __init__(self, config: ScanConfig | None = None) -> None:
        self.config = config or ScanConfig()
        self.permutations = BucketPermutationGenerator(self.config.wordlist)
        self.fingerprints = FingerprintEngine()
        self.scorer = RiskScorer()
        self.correlation = CorrelationEngine()

    async def scan(self, target: str) -> IntelligenceReport:
        """Run a complete CloudRift intelligence scan."""

        report = IntelligenceReport(target=target)
        js_names: set[str] = set()
        relationships: list[Relationship] = [Relationship(source=target, target=target, relation="scan-root", confidence=1.0)]

        if self.config.js_analysis:
            js_result = await JavaScriptIntelExtractor(self.config.timeout, self.config.proxy).analyze_target(
                target,
                include_sourcemaps=self.config.sourcemaps,
            )
            js_names = js_result.bucket_names
            relationships.extend(js_result.relationships)
            for url in js_result.urls:
                report.fingerprints.extend(self.fingerprints.detect(url, source="javascript"))

        provider = self.config.provider or CloudProvider.UNKNOWN
        candidates = self.permutations.generate(
            target=target,
            provider=provider,
            js_names=js_names,
            limit=self.config.max_candidates,
        )
        report.candidates = candidates
        relationships.extend(self._candidate_relationships(target, candidates))

        if self.config.passive_only:
            return self.correlation.correlate(report, [], relationships)

        observations = await self._validate_candidates(candidates)
        report = self.correlation.correlate(report, observations, relationships)
        report.findings = [finding for observation in observations if (finding := self.scorer.score(observation))]
        return report

    async def _validate_candidates(self, candidates: list[BucketCandidate]) -> list[BucketObservation]:
        """Validate generated candidates with bounded concurrency."""

        limits = httpx.Limits(max_connections=self.config.concurrency)
        async with httpx.AsyncClient(
            timeout=self.config.timeout,
            proxy=self.config.proxy,
            follow_redirects=False,
            limits=limits,
            headers={"User-Agent": "CloudRift/0.1 authorized-research"},
        ) as client:
            providers = build_providers(client, self.config.provider)
            semaphore = asyncio.Semaphore(self.config.concurrency)

            async def validate(candidate: BucketCandidate) -> BucketObservation:
                async with semaphore:
                    selected = providers
                    if candidate.provider != CloudProvider.UNKNOWN and self.config.provider is None:
                        selected = [provider for provider in providers if provider.provider == candidate.provider] or providers
                    results = await asyncio.gather(*(provider.validate(candidate) for provider in selected))
                    return max(results, key=lambda item: item.confidence)

            return list(await asyncio.gather(*(validate(candidate) for candidate in candidates)))

    @staticmethod
    def _candidate_relationships(target: str, candidates: list[BucketCandidate]) -> list[Relationship]:
        """Create root-to-candidate relationship edges."""

        return [
            Relationship(
                source=target,
                target=candidate.name,
                relation=candidate.source,
                confidence=candidate.confidence,
            )
            for candidate in candidates
        ]
