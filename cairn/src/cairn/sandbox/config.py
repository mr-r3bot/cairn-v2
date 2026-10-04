"""Sandbox configuration knobs (Cairn v2, Phase 1).

The sandbox is Docker-native: containment comes from per-run *internal*
networks (no external route — the collector is the only reachable peer),
read-only root filesystems, dropped capabilities, no-new-privileges, and
cgroup limits.  See docs/specs/verification.md for the threat model.
"""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, Field


class SandboxConfig(BaseModel):
    """All knobs needed to stand up isolated verification sandboxes."""

    # image that executes the PoC; must contain the runtime the PoC needs
    # (python3 for script-type PoCs)
    image: str = "python:3.13-slim"

    # image the nonce collector service runs in (stdlib python is enough)
    collector_image: str = "python:3.13-slim"
    collector_port: int = Field(default=9931, ge=1, le=65535)
    collector_startup_timeout_s: int = Field(default=30, ge=1)

    # per-payload container caps (cgroup-backed)
    mem_mb: int = Field(default=512, ge=32)
    pids_limit: int = Field(default=128, ge=16)
    cpus: float = Field(default=1.0, gt=0, le=64)
    payload_timeout_s: int = Field(default=120, ge=1)

    # host-side directories (bind-mounted into containers)
    scratch_root: Path = Path("datas/cairn/sandbox/scratch")
    hits_root: Path = Path("datas/cairn/sandbox/collector")

    # keep failed containers around for debugging (never in CI)
    keep_on_failure: bool = False
