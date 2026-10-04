"""Sandbox configuration knobs (Cairn v2, Phase 1).

The sandbox is Docker-native: containment comes from per-run *internal*
networks (no external route — the collector is the only reachable peer),
read-only root filesystems, dropped capabilities, no-new-privileges, and
cgroup limits.  See docs/specs/verification.md for the threat model.

Path duality: Cairn itself runs in a Docker container (docker-compose) while
the Docker daemon lives on the host.  Bind-mount sources are interpreted by
the **daemon** (host paths); file reads/writes by the dispatcher use its
**own** view.  When both are the same process (dispatcher on the host),
leave ``host_data_home`` unset.  Inside docker-compose, set
``host_data_home`` to the host-side path of the shared ``datas/cairn``
volume.
"""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, Field

DEFAULT_DATA_HOME = Path.home() / ".local" / "share" / "cairn"


class SandboxConfig(BaseModel):
    """All knobs needed to stand up isolated verification sandboxes."""

    # dispatcher-side root for sandbox data (scratch, collector hits)
    data_home: Path = DEFAULT_DATA_HOME

    # daemon-side root for the same data when the dispatcher itself runs in
    # a container; None means "same paths as data_home"
    host_data_home: Path | None = None

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

    # keep failed containers around for debugging (never in CI)
    keep_on_failure: bool = False

    @property
    def scratch_root(self) -> Path:
        return self.data_home / "sandbox" / "scratch"

    @property
    def hits_root(self) -> Path:
        return self.data_home / "sandbox" / "collector"

    def host_path(self, path: Path) -> Path:
        """Translate a dispatcher-side path under data_home to the daemon's view."""
        if self.host_data_home is None:
            return path
        try:
            relative = path.relative_to(self.data_home)
        except ValueError:
            return path
        return self.host_data_home / relative
