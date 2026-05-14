"""Intelligent bucket and container candidate generation."""

from __future__ import annotations

from pathlib import Path

from cloudrift.models.enums import CloudProvider
from cloudrift.models.report import BucketCandidate
from cloudrift.utils.text import is_valid_bucket_name, target_tokens

DEFAULT_KEYWORDS = (
    "assets",
    "backup",
    "backups",
    "cdn",
    "config",
    "data",
    "dev",
    "files",
    "logs",
    "media",
    "private",
    "prod",
    "production",
    "public",
    "qa",
    "stage",
    "staging",
    "static",
    "uploads",
)

PREFIXES = ("cdn", "static", "media", "assets", "files", "backup", "staging", "dev")
SUFFIXES = DEFAULT_KEYWORDS


class BucketPermutationGenerator:
    """Generate realistic storage candidates from target intelligence."""

    def __init__(self, wordlist: Path | None = None) -> None:
        self.extra_words = self._load_wordlist(wordlist)

    def generate(
        self,
        target: str,
        provider: CloudProvider = CloudProvider.UNKNOWN,
        js_names: set[str] | None = None,
        limit: int = 500,
    ) -> list[BucketCandidate]:
        """Generate deduplicated, AWS-compatible candidate names."""

        names: dict[str, BucketCandidate] = {}
        tokens = target_tokens(target)
        keywords = sorted(set(DEFAULT_KEYWORDS).union(self.extra_words))

        def add(name: str, source: str, confidence: float) -> None:
            normalized = name.lower().replace("_", "-").strip(".-")
            if is_valid_bucket_name(normalized) and normalized not in names:
                names[normalized] = BucketCandidate(
                    name=normalized,
                    provider=provider,
                    source=source,
                    confidence=confidence,
                )

        for token in tokens:
            add(token, "target-token", 0.45)
            for keyword in keywords:
                add(f"{token}-{keyword}", "target-keyword-suffix", 0.72)
                add(f"{keyword}-{token}", "target-keyword-prefix", 0.68)
                add(f"{token}.{keyword}", "target-dot-keyword", 0.52)

            for env in ("dev", "stage", "staging", "prod", "qa"):
                for app in ("api", "web", "app", "admin"):
                    add(f"{token}-{env}-{app}", "environment-heuristic", 0.66)
                    add(f"{env}-{token}-{app}", "environment-heuristic", 0.64)

        for name in js_names or set():
            add(name, "javascript-intelligence", 0.9)

        return list(names.values())[:limit]

    @staticmethod
    def _load_wordlist(wordlist: Path | None) -> set[str]:
        """Load optional user-provided wordlist values."""

        if not wordlist:
            return set()
        return {
            line.strip().lower()
            for line in wordlist.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("#")
        }
