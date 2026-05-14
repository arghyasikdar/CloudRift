"""Azure Blob Storage provider implementation."""

from cloudrift.models.enums import CloudProvider
from cloudrift.providers.base import CloudStorageProvider


class AzureBlobProvider(CloudStorageProvider):
    """Validate Azure Blob Storage container endpoints."""

    provider = CloudProvider.AZURE

    def endpoints_for(self, bucket: str) -> list[str]:
        """Return Azure Blob endpoints for a storage account candidate."""

        account = bucket.replace(".", "").replace("-", "")
        return [f"https://{account}.blob.core.windows.net"]
