"""DigitalOcean Spaces provider implementation."""

from cloudrift.models.enums import CloudProvider
from cloudrift.providers.base import CloudStorageProvider


class DigitalOceanSpacesProvider(CloudStorageProvider):
    """Validate common DigitalOcean Spaces endpoints."""

    provider = CloudProvider.DIGITALOCEAN

    def endpoints_for(self, bucket: str) -> list[str]:
        """Return DigitalOcean Spaces endpoints for common regions."""

        return [
            f"https://{bucket}.nyc3.digitaloceanspaces.com",
            f"https://{bucket}.sfo3.digitaloceanspaces.com",
            f"https://{bucket}.ams3.digitaloceanspaces.com",
        ]
