import httpx
import pytest

from cloudrift.models.report import BucketCandidate
from cloudrift.models.enums import ExposureStatus
from cloudrift.providers.aws import AWSS3Provider


@pytest.mark.asyncio
async def test_bucket_validation_with_mock_transport() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            text="<ListBucketResult><Contents><Key>.env</Key></Contents></ListBucketResult>",
            request=request,
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        observation = await AWSS3Provider(client).validate(BucketCandidate(name="target-backups", source="test"))

    assert observation.exposure == ExposureStatus.LISTABLE
    assert observation.exposed_files[0].path == ".env"
