"""Cloud storage provider fingerprinting."""

from __future__ import annotations

import re

from cloudrift.models.enums import CloudProvider
from cloudrift.models.report import ProviderFingerprint


class FingerprintEngine:
    """Infer providers from URLs, endpoints, and response metadata."""

    PATTERNS: tuple[tuple[CloudProvider, re.Pattern[str]], ...] = (
        (CloudProvider.AWS, re.compile(r"(?:s3[.-][a-z0-9-]+|s3)\.amazonaws\.com", re.I)),
        (CloudProvider.GCP, re.compile(r"storage\.(?:googleapis|cloud\.google)\.com", re.I)),
        (CloudProvider.AZURE, re.compile(r"blob\.core\.windows\.net", re.I)),
        (CloudProvider.FIREBASE, re.compile(r"firebasestorage\.googleapis\.com", re.I)),
        (CloudProvider.DIGITALOCEAN, re.compile(r"digitaloceanspaces\.com", re.I)),
        (CloudProvider.CLOUDFLARE_R2, re.compile(r"r2\.cloudflarestorage\.com", re.I)),
    )

    def detect(self, value: str, source: str = "input") -> list[ProviderFingerprint]:
        """Return provider fingerprints found in a string."""

        fingerprints: list[ProviderFingerprint] = []
        for provider, pattern in self.PATTERNS:
            match = pattern.search(value)
            if match:
                fingerprints.append(
                    ProviderFingerprint(
                        provider=provider,
                        confidence=0.95,
                        indicator=match.group(0),
                        source=source,
                    )
                )
        return fingerprints

    def provider_for_url(self, value: str) -> CloudProvider:
        """Return the strongest provider match for a URL-like string."""

        matches = self.detect(value)
        return matches[0].provider if matches else CloudProvider.UNKNOWN
