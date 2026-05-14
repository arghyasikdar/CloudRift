"""Runtime configuration for CloudRift scans."""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, Field

from cloudrift.models.enums import CloudProvider


class ScanConfig(BaseModel):
    """User-controlled scan options."""

    provider: CloudProvider | None = None
    wordlist: Path | None = None
    concurrency: int = Field(default=25, ge=1, le=200)
    timeout: float = Field(default=8.0, gt=0)
    proxy: str | None = None
    verbose: bool = False
    js_analysis: bool = False
    sourcemaps: bool = False
    max_candidates: int = Field(default=500, ge=1)
    passive_only: bool = False
