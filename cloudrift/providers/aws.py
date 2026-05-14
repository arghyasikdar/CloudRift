"""AWS S3 provider implementation."""

from cloudrift.models.enums import CloudProvider
from cloudrift.providers.base import CloudStorageProvider


class AWSS3Provider(CloudStorageProvider):
    """Validate AWS S3 virtual-hosted, path-style, and regional endpoints."""

    provider = CloudProvider.AWS

    def endpoints_for(self, bucket: str) -> list[str]:
        """Return AWS S3 endpoints for a bucket name."""

        return [
            f"https://{bucket}.s3.amazonaws.com",
            f"https://s3.amazonaws.com/{bucket}",
            f"https://{bucket}.s3.us-east-1.amazonaws.com",
        ]
