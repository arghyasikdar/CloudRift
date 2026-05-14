from cloudrift.analyzers.exposure import ExposureAnalyzer
from cloudrift.models.enums import ExposureStatus


def test_xml_listing_detection() -> None:
    body = "<ListBucketResult><Contents><Key>database.sql</Key></Contents></ListBucketResult>"
    status, evidence = ExposureAnalyzer().classify(200, body, {})

    assert status == ExposureStatus.LISTABLE
    assert evidence


def test_extract_listing_paths() -> None:
    body = "<ListBucketResult><Contents><Key>database.sql</Key></Contents></ListBucketResult>"

    assert ExposureAnalyzer().extract_listing_paths(body) == ["database.sql"]
