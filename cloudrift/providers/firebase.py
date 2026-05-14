"""Firebase Storage provider implementation."""

from cloudrift.models.enums import CloudProvider
from cloudrift.providers.base import CloudStorageProvider


class FirebaseStorageProvider(CloudStorageProvider):
    """Validate Firebase Storage endpoints."""

    provider = CloudProvider.FIREBASE

    def endpoints_for(self, bucket: str) -> list[str]:
        """Return Firebase Storage endpoints for a project bucket."""

        return [f"https://firebasestorage.googleapis.com/v0/b/{bucket}/o"]
