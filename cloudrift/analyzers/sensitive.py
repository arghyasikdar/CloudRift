"""Sensitive object name detection."""

from __future__ import annotations

import re

from cloudrift.models.enums import RiskLevel
from cloudrift.models.report import ExposedFile


class SensitiveFileAnalyzer:
    """Classify object paths that commonly indicate sensitive exposure."""

    RULES: tuple[tuple[re.Pattern[str], str, RiskLevel], ...] = (
        (re.compile(r"(^|/)\.env(\.|$)?", re.I), "environment-secret", RiskLevel.HIGH),
        (re.compile(r"(database|db|dump).*\.(sql|sqlite|dump)$", re.I), "database-dump", RiskLevel.HIGH),
        (re.compile(r"(backup|archive).*\.(zip|tar|gz|7z|bak)$", re.I), "backup-archive", RiskLevel.HIGH),
        (re.compile(r"(private|id_rsa|secret|key).*(\.pem|\.key|$)", re.I), "private-key", RiskLevel.HIGH),
        (re.compile(r"terraform\.tfstate", re.I), "infrastructure-state", RiskLevel.HIGH),
        (re.compile(r"(^|/)(config|settings)\.(json|yaml|yml|ini)$", re.I), "configuration", RiskLevel.MEDIUM),
        (re.compile(r"(^|/)(users|customers|employees)\.csv$", re.I), "identity-data", RiskLevel.HIGH),
        (re.compile(r"\.(log|trace)$", re.I), "logs", RiskLevel.MEDIUM),
        (re.compile(r"(^|/)\.(github|gitlab-ci|circleci|travis)", re.I), "ci-cd-artifact", RiskLevel.MEDIUM),
    )

    def analyze_paths(self, paths: list[str], base_url: str | None = None) -> list[ExposedFile]:
        """Return sensitive file findings for object paths."""

        findings: list[ExposedFile] = []
        for path in paths:
            for pattern, category, risk in self.RULES:
                if pattern.search(path):
                    findings.append(
                        ExposedFile(
                            path=path,
                            url=f"{base_url.rstrip('/')}/{path.lstrip('/')}" if base_url else None,
                            category=category,
                            risk=risk,
                            confidence=0.88 if risk == RiskLevel.HIGH else 0.72,
                            evidence=f"Object path matched {category} exposure rule",
                        )
                    )
                    break
        return findings
