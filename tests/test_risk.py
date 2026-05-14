from cloudrift.intelligence.scoring import RiskScorer
from cloudrift.models.enums import CloudProvider, ExposureStatus, RiskLevel
from cloudrift.models.report import BucketCandidate, BucketObservation, ExposedFile


def test_high_risk_for_sensitive_file() -> None:
    observation = BucketObservation(
        candidate=BucketCandidate(name="target-backups", source="test"),
        provider=CloudProvider.AWS,
        exposure=ExposureStatus.LISTABLE,
        confidence=0.95,
        exposed_files=[ExposedFile(path=".env", category="environment-secret", risk=RiskLevel.HIGH)],
    )

    finding = RiskScorer().score(observation)

    assert finding is not None
    assert finding.risk == RiskLevel.HIGH
