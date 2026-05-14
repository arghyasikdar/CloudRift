"""Google Cloud Storage provider implementation."""

from cloudrift.models.enums import CloudProvider
from cloudrift.providers.base import CloudStorageProvider


class GCSProvider(CloudStorageProvider):
    """Validate Google Cloud Storage endpoints."""

    provider = CloudProvider.GCP

    def endpoints_for(self, bucket: str) -> list[str]:
        """Return GCS endpoints for a bucket name."""

        return [
            f"https://storage.googleapis.com/{bucket}",
            f"https://{bucket}.storage.googleapis.com",
        ]
