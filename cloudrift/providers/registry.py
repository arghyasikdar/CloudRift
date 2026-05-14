"""Provider registry helpers."""

from __future__ import annotations

import httpx

from cloudrift.models.enums import CloudProvider
from cloudrift.providers.aws import AWSS3Provider
from cloudrift.providers.azure import AzureBlobProvider
from cloudrift.providers.base import CloudStorageProvider
from cloudrift.providers.cloudflare import CloudflareR2Provider
from cloudrift.providers.digitalocean import DigitalOceanSpacesProvider
from cloudrift.providers.firebase import FirebaseStorageProvider
from cloudrift.providers.gcp import GCSProvider

PROVIDER_TYPES: dict[CloudProvider, type[CloudStorageProvider]] = {
    CloudProvider.AWS: AWSS3Provider,
    CloudProvider.GCP: GCSProvider,
    CloudProvider.AZURE: AzureBlobProvider,
    CloudProvider.FIREBASE: FirebaseStorageProvider,
    CloudProvider.DIGITALOCEAN: DigitalOceanSpacesProvider,
    CloudProvider.CLOUDFLARE_R2: CloudflareR2Provider,
}


def build_providers(client: httpx.AsyncClient, selected: CloudProvider | None = None) -> list[CloudStorageProvider]:
    """Build provider instances for a scan."""

    if selected and selected != CloudProvider.UNKNOWN:
        return [PROVIDER_TYPES[selected](client)]
    return [provider_type(client) for provider_type in PROVIDER_TYPES.values()]
