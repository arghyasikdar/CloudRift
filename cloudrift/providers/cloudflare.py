"""Cloudflare R2 provider implementation."""

from cloudrift.models.enums import CloudProvider
from cloudrift.providers.base import CloudStorageProvider


class CloudflareR2Provider(CloudStorageProvider):
    """Validate Cloudflare R2 public endpoints."""

    provider = CloudProvider.CLOUDFLARE_R2

    def endpoints_for(self, bucket: str) -> list[str]:
        """Return Cloudflare R2 endpoints."""

        return [f"https://{bucket}.r2.cloudflarestorage.com"]
