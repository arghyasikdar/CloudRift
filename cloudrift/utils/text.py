"""Text normalization helpers."""

from __future__ import annotations

import math
import re
from collections import Counter
from urllib.parse import urlparse


def normalize_target(target: str) -> str:
    """Normalize a domain, URL, or organization string into a base token."""

    cleaned = target.strip().lower()
    parsed = urlparse(cleaned if "://" in cleaned else f"https://{cleaned}")
    host = parsed.netloc or parsed.path
    host = host.split("@")[-1].split(":")[0]
    host = host.removeprefix("www.")
    return host.strip("/")


def target_tokens(target: str) -> list[str]:
    """Create useful naming tokens from a target."""

    host = normalize_target(target)
    common_tlds = {"com", "net", "org", "edu", "gov", "io", "co", "ai", "dev", "app"}
    parts = [part for part in re.split(r"[^a-z0-9]+", host) if part and part not in common_tlds]
    if len(parts) > 1:
        parts.append(parts[0])
        parts.append("-".join(parts))
    return sorted(set(parts), key=lambda value: (0 if value == parts[0] else 1, len(value), value))


def is_valid_bucket_name(name: str) -> bool:
    """Validate a candidate against AWS-compatible bucket naming constraints."""

    if not 3 <= len(name) <= 63:
        return False
    if not re.fullmatch(r"[a-z0-9][a-z0-9.-]+[a-z0-9]", name):
        return False
    if ".." in name or ".-" in name or "-." in name:
        return False
    if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", name):
        return False
    reserved_prefixes = ("xn--", "sthree-", "amzn-s3-demo-")
    reserved_suffixes = ("-s3alias", "--ol-s3", ".mrap", "--x-s3", "--table-s3")
    return not name.startswith(reserved_prefixes) and not name.endswith(reserved_suffixes)


def shannon_entropy(value: str) -> float:
    """Calculate Shannon entropy for a string."""

    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())
