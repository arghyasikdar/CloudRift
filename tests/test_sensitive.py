from cloudrift.analyzers.sensitive import SensitiveFileAnalyzer
from cloudrift.models.enums import RiskLevel


def test_sensitive_file_detection() -> None:
    findings = SensitiveFileAnalyzer().analyze_paths(["public/app.js", ".env", "dumps/database.sql"])

    assert len(findings) == 2
    assert all(finding.risk == RiskLevel.HIGH for finding in findings)
