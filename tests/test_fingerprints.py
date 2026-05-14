from cloudrift.fingerprints.engine import FingerprintEngine
from cloudrift.models.enums import CloudProvider


def test_provider_detection_for_s3_url() -> None:
    engine = FingerprintEngine()

    assert engine.provider_for_url("https://bucket.s3.amazonaws.com/config.json") == CloudProvider.AWS


def test_provider_detection_for_azure_url() -> None:
    engine = FingerprintEngine()

    assert engine.provider_for_url("https://acct.blob.core.windows.net/container") == CloudProvider.AZURE
