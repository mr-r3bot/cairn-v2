"""Untrusted claim ingestion contract (Cairn v2, Phase 0).

A claim is the Strix -> Cairn handoff: a finding, its PoC, and everything
needed to stand the target up.  Every field arrives from an external system
and is treated as untrusted input:

- fields are strictly validated (unknown fields rejected, sizes capped),
- the PoC payload is *sealed*: the board (fact descriptions) only ever
  carries its digest, never the payload itself,
- ``strix_claimed_oracle`` is recorded verbatim for audit/export, but is
  never rendered onto the board and MUST never be read as proof by verdict
  logic (see docs/specs/verification.md, "effect, not echo").

The claim maps onto the blackboard as the project's *origin* fact; the
verification goal maps onto the *goal* fact.  Nothing here introduces a
fourth primitive.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from cairn.server.models import ProjectDetail

REPO_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
COMMIT_PATTERN = re.compile(r"^[0-9a-fA-F]{7,40}$")

VULN_CLASSES = (
    "rce",
    "sqli",
    "ssrf",
    "authbypass",
    "pathtraversal",
    "xss",
    "file-upload",
    "deserialization",
    "other",
)

_MAX_TEXT = 4096
_MAX_POC_BYTES = 256 * 1024
_MAX_DICT_KEYS = 32


def _cap_text(value: str) -> str:
    text = value.strip()
    if not text:
        raise ValueError("must not be empty")
    if len(value) > _MAX_TEXT:
        raise ValueError(f"must be at most {_MAX_TEXT} characters")
    return text


def _cap_dict(value: dict | None, *, what: str) -> dict:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError(f"{what} must be an object")
    if len(value) > _MAX_DICT_KEYS:
        raise ValueError(f"{what} must have at most {_MAX_DICT_KEYS} keys")
    return value


class PocScript(BaseModel):
    """PoC given as a runnable script body."""

    model_config = ConfigDict(extra="forbid")

    type: Literal["script"]
    language: Literal["python", "bash", "sh"] = "bash"
    payload: str = Field(min_length=1)

    @field_validator("payload")
    @classmethod
    def cap_payload(cls, value: str) -> str:
        if len(value.encode("utf-8")) > _MAX_POC_BYTES:
            raise ValueError(f"payload must be at most {_MAX_POC_BYTES} bytes")
        return value


class PocHttp(BaseModel):
    """PoC given as an HTTP request (method, url, headers, body)."""

    model_config = ConfigDict(extra="forbid")

    type: Literal["http"]
    method: str = Field(min_length=1, max_length=16)
    url: str = Field(min_length=1, max_length=2048)
    headers: dict[str, str] = Field(default_factory=dict)
    body: str | None = None

    @field_validator("method")
    @classmethod
    def normalize_method(cls, value: str) -> str:
        method = value.strip().upper()
        if not re.fullmatch(r"[A-Z]+", method):
            raise ValueError("method must be an HTTP token")
        return method

    @field_validator("headers")
    @classmethod
    def cap_headers(cls, value: dict[str, str]) -> dict[str, str]:
        return _cap_dict(value, what="headers")

    @field_validator("body")
    @classmethod
    def cap_body(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if len(value.encode("utf-8")) > _MAX_POC_BYTES:
            raise ValueError(f"body must be at most {_MAX_POC_BYTES} bytes")
        return value


class PocCommand(BaseModel):
    """PoC given as an argv to execute (e.g. a curl one-liner)."""

    model_config = ConfigDict(extra="forbid")

    type: Literal["command"]
    argv: list[str] = Field(min_length=1, max_length=64)

    @field_validator("argv")
    @classmethod
    def clean_argv(cls, value: list[str]) -> list[str]:
        total = 0
        for item in value:
            if not item.strip():
                raise ValueError("argv items must not be empty")
            total += len(item.encode("utf-8"))
        if total > _MAX_POC_BYTES:
            raise ValueError(f"argv must be at most {_MAX_POC_BYTES} bytes total")
        return value


Poc = PocScript | PocHttp | PocCommand


class ClaimPayload(BaseModel):
    """The untrusted Strix finding, exactly as it crosses the boundary."""

    model_config = ConfigDict(extra="forbid")

    source: str = Field(default="strix", max_length=64)
    target_repo: str
    target_commit: str
    target_image: str | None = None
    run_hints: dict = Field(default_factory=dict)
    poc: Annotated[Poc, Field(discriminator="type")]
    vuln_class: str
    strix_claimed_oracle: dict = Field(default_factory=dict)

    @field_validator("source")
    @classmethod
    def clean_source(cls, value: str) -> str:
        return _cap_text(value)

    @field_validator("target_repo")
    @classmethod
    def validate_repo(cls, value: str) -> str:
        if not REPO_PATTERN.fullmatch(value):
            raise ValueError("target_repo must look like owner/name")
        return value

    @field_validator("target_commit")
    @classmethod
    def validate_commit(cls, value: str) -> str:
        if not COMMIT_PATTERN.fullmatch(value):
            raise ValueError("target_commit must be a 7-40 char hex sha")
        return value.lower()

    @field_validator("target_image")
    @classmethod
    def validate_image(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _cap_text(value)

    @field_validator("run_hints", "strix_claimed_oracle")
    @classmethod
    def cap_dicts(cls, value: dict, info) -> dict:
        return _cap_dict(value, what=info.field_name)

    @field_validator("vuln_class")
    @classmethod
    def validate_vuln_class(cls, value: str) -> str:
        text = value.strip().lower()
        if text not in VULN_CLASSES:
            raise ValueError(f"vuln_class must be one of {', '.join(VULN_CLASSES)}")
        return text

    def seal(self) -> str:
        """Digest of the canonical PoC — the only PoC reference the board sees."""
        canonical = json.dumps(
            self.poc.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
        )
        return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def to_origin_description(self, claim_id: str) -> str:
        """Render the claim as the project origin fact.

        Deliberately excludes the PoC payload (digest only) and the contents
        of ``strix_claimed_oracle`` — neither ever reaches the board.
        """
        digest = self.seal()
        lines = [
            f"[claim {claim_id}] untrusted finding from {self.source}",
            f"target: {self.target_repo} @ {self.target_commit}",
            f"class: {self.vuln_class}",
            f"poc: {self.poc.type} · sealed ({digest[:14]}…)",
        ]
        if self.target_image:
            lines.append(f"image: {self.target_image}")
        if self.run_hints:
            hints = "; ".join(f"{k}={json.dumps(v)}" for k, v in sorted(self.run_hints.items()))
            lines.append(f"run_hints: {hints[:_MAX_TEXT]}")
        lines.append(
            "strix_claimed_oracle: recorded for audit only — never treated as proof"
        )
        return "\n".join(lines)

    def to_goal_description(self, claim_id: str) -> str:
        """Render the verification goal as the project goal fact."""
        return (
            f"[claim {claim_id}] independent verdict: reproduced | not_reproduced | "
            "inconclusive (+sub_reason), backed by a Cairn-controlled marker observed "
            "out-of-band. Strix's claimed success signal is not evidence."
        )


class ClaimRecord(BaseModel):
    """Claim metadata safe to expose back out (payload stays sealed)."""

    id: str
    project_id: str
    source: str
    target_repo: str
    target_commit: str
    target_image: str | None
    vuln_class: str
    poc_digest: str
    created_at: str


class ClaimIngestResponse(BaseModel):
    claim: ClaimRecord
    project: ProjectDetail
    project_id: str
    origin_fact_id: str = "origin"
    goal_fact_id: str = "goal"
