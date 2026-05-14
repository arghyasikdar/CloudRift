"""Shared enumerations used by CloudRift models."""

from enum import StrEnum


class CloudProvider(StrEnum):
    """Supported cloud storage providers."""

    AWS = "aws"
    GCP = "gcp"
    AZURE = "azure"
    FIREBASE = "firebase"
    DIGITALOCEAN = "digitalocean"
    CLOUDFLARE_R2 = "cloudflare_r2"
    UNKNOWN = "unknown"


class RiskLevel(StrEnum):
    """Normalized finding risk levels."""

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ExposureStatus(StrEnum):
    """Observed storage exposure state."""

    PUBLIC = "public"
    LISTABLE = "listable"
    AUTH_REQUIRED = "auth_required"
    EXISTS_PRIVATE = "exists_private"
    NOT_FOUND = "not_found"
    UNKNOWN = "unknown"
