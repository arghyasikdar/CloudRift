"""JavaScript and source map intelligence extraction."""

from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from cloudrift.fingerprints.engine import FingerprintEngine
from cloudrift.models.report import Relationship

BUCKET_NAME_PATTERNS = (
    re.compile(r"https?://([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])\.s3[.-][a-z0-9-]*\.amazonaws\.com", re.I),
    re.compile(r"https?://s3[.-][a-z0-9-]*\.amazonaws\.com/([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])", re.I),
    re.compile(r"https?://storage\.googleapis\.com/([a-z0-9][a-z0-9._-]{1,221}[a-z0-9])", re.I),
    re.compile(r"https?://([a-z0-9-]+)\.blob\.core\.windows\.net", re.I),
    re.compile(r"https?://[^\"']*firebasestorage\.googleapis\.com/[^\"']*", re.I),
    re.compile(r"([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])\.digitaloceanspaces\.com", re.I),
    re.compile(r"([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])\.r2\.cloudflarestorage\.com", re.I),
)


@dataclass(frozen=True)
class JSIntelResult:
    """Storage intelligence extracted from frontend artifacts."""

    bucket_names: set[str]
    urls: set[str]
    relationships: list[Relationship]


class JavaScriptIntelExtractor:
    """Fetch and parse JavaScript assets for cloud storage indicators."""

    def __init__(self, timeout: float = 8.0, proxy: str | None = None) -> None:
        self.timeout = timeout
        self.proxy = proxy
        self.fingerprints = FingerprintEngine()

    async def analyze_target(self, target: str, include_sourcemaps: bool = False) -> JSIntelResult:
        """Discover JS files from a page and extract storage references."""

        base_url = target if "://" in target else f"https://{target}"
        async with httpx.AsyncClient(timeout=self.timeout, proxy=self.proxy, follow_redirects=True) as client:
            html = await self._safe_get_text(client, base_url)
            js_urls = self._extract_script_urls(html, base_url)
            if include_sourcemaps:
                js_urls.update({f"{url}.map" for url in js_urls if not url.endswith(".map")})
            bodies = await asyncio.gather(*(self._safe_get_text(client, url) for url in js_urls))

        bucket_names: set[str] = set()
        urls: set[str] = set()
        relationships: list[Relationship] = []
        for source_url, body in zip(js_urls, bodies, strict=False):
            extracted_names, extracted_urls = self.extract_from_text(body)
            bucket_names.update(extracted_names)
            urls.update(extracted_urls)
            for name in extracted_names:
                relationships.append(
                    Relationship(source=source_url, target=name, relation="frontend-reference", confidence=0.85)
                )
        return JSIntelResult(bucket_names=bucket_names, urls=urls, relationships=relationships)

    def extract_from_text(self, text: str) -> tuple[set[str], set[str]]:
        """Extract bucket names and cloud URLs from text."""

        names: set[str] = set()
        urls = set(re.findall(r"https?://[^\s\"'<>)}]+", text))
        for pattern in BUCKET_NAME_PATTERNS:
            for match in pattern.finditer(text):
                value = match.group(1) if match.groups() else match.group(0)
                if "firebasestorage" in value:
                    parsed = urlparse(value)
                    names.add(parsed.netloc)
                else:
                    names.add(value.lower())
        cloud_urls: set[str] = set()
        for raw in list(urls):
            if self.fingerprints.provider_for_url(raw).value != "unknown":
                cloud_urls.add(raw.rstrip(".,;"))
        return names, cloud_urls

    @staticmethod
    def _extract_script_urls(html: str, base_url: str) -> set[str]:
        """Extract absolute JavaScript URLs from HTML."""

        soup = BeautifulSoup(html or "", "html.parser")
        urls: set[str] = set()
        for script in soup.find_all("script"):
            src = script.get("src")
            if src:
                urls.add(urljoin(base_url, src))
        return urls

    @staticmethod
    async def _safe_get_text(client: httpx.AsyncClient, url: str) -> str:
        """Fetch text content, returning an empty string on network errors."""

        try:
            response = await client.get(url)
            if "application/json" in response.headers.get("content-type", ""):
                return json.dumps(response.json())
            return response.text
        except Exception:
            return ""
