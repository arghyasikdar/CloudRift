"""HTTP response analysis for cloud storage exposure."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET

from cloudrift.models.enums import ExposureStatus


class ExposureAnalyzer:
    """Infer bucket exposure state from status codes, headers, and bodies."""

    LISTING_MARKERS = ("<ListBucketResult", "<EnumerationResults", "<Contents>", "<Blob>")
    DENIED_MARKERS = ("AccessDenied", "Access Denied", "AuthenticationFailed", "Anonymous caller")
    NOT_FOUND_MARKERS = ("NoSuchBucket", "The specified bucket does not exist", "ContainerNotFound")

    def classify(self, status_code: int | None, body: str, headers: dict[str, str]) -> tuple[ExposureStatus, list[str]]:
        """Classify a storage endpoint response."""

        evidence: list[str] = []
        if status_code is None:
            return ExposureStatus.UNKNOWN, ["No response received"]
        if any(marker in body for marker in self.LISTING_MARKERS):
            evidence.append("Response body contains object listing markers")
            return ExposureStatus.LISTABLE, evidence
        if status_code in {200, 206}:
            evidence.append(f"HTTP {status_code} indicates public readability")
            return ExposureStatus.PUBLIC, evidence
        if status_code in {401, 403} or any(marker in body for marker in self.DENIED_MARKERS):
            evidence.append("Provider returned authentication or access denied response")
            return ExposureStatus.EXISTS_PRIVATE, evidence
        if status_code == 404 or any(marker in body for marker in self.NOT_FOUND_MARKERS):
            evidence.append("Provider returned not found response")
            return ExposureStatus.NOT_FOUND, evidence
        if headers.get("x-amz-bucket-region") or headers.get("x-goog-metageneration"):
            evidence.append("Provider-specific headers indicate bucket existence")
            return ExposureStatus.EXISTS_PRIVATE, evidence
        return ExposureStatus.UNKNOWN, [f"Unhandled HTTP status {status_code}"]

    def extract_listing_paths(self, body: str) -> list[str]:
        """Extract object paths from XML listing responses."""

        paths: set[str] = set()
        try:
            root = ET.fromstring(body)
            for element in root.iter():
                if element.tag.endswith("Key") or element.tag.endswith("Name"):
                    if element.text:
                        paths.add(element.text)
        except ET.ParseError:
            for match in re.finditer(r"<Key>([^<]+)</Key>|<Name>([^<]+)</Name>", body):
                paths.add(next(group for group in match.groups() if group))
        return sorted(paths)
