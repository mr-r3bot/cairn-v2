"""Effect oracles (Cairn v2, Phase 4) — effect, not echo.

Each oracle plants an unforgeable runtime marker — a nonce chosen *after*
boot, never reused — and confirms the effect itself through a
Cairn-controlled channel:

- ``rce/nonce-callback`` — the PoC is parameterised via ``CAIRN_CMD``: the
  command the claimed RCE executes on the target.  Cairn sets it to a
  beacon; the nonce reaching the collector is the ONLY proof of code
  execution.
- ``ssrf/nonce-callback`` — same channel, the PoC is parameterised via
  ``CAIRN_URL``: the URL the claimed SSRF forces the target to fetch.
- ``sqli/seeded-row`` — a Cairn-chosen secret is seeded into the target
  (run_hints.seed_command runs inside the target container); reproduction =
  the PoC returns that exact value.  Without a seeding hook this leans
  ``ambiguous``, never guesses.
- ``sentinel`` (authbypass / pathtraversal) — Cairn plants a marker file
  (run_hints.plant_command) at a protected location; reproduction = the
  PoC returns its content.
- anything else (xss, client-side, ...) — no honest automated oracle yet;
  ``ambiguous`` so the run stays inconclusive.

Strix's claimed oracle is never consulted here — that field is forbidden
as proof (see docs/specs/verification.md).
"""

from __future__ import annotations

import logging
import secrets
from dataclasses import dataclass, field
from typing import Any, Literal

from cairn.sandbox.manager import SandboxManager

LOG = logging.getLogger(__name__)

OracleStatus = Literal["confirmed", "not_confirmed", "ambiguous"]


@dataclass
class OracleOutcome:
    status: OracleStatus
    marker: str | None = None
    reason: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)


def new_nonce() -> str:
    """Fresh marker, chosen post-boot, never reused."""
    return secrets.token_hex(8)


def beacon_command(collector_url: str, nonce: str) -> str:
    """A best-effort beacon runnable wherever the PoC lands it (target or payload side)."""
    url = f"{collector_url}/beacon/{nonce}"
    return (
        f'(command -v curl >/dev/null 2>&1 && curl -s -m 6 "{url}") || '
        f'(command -v wget >/dev/null 2>&1 && wget -q -T 6 -O /dev/null "{url}") || '
        f'python3 -c "import urllib.request; urllib.request.urlopen(\'{url}\', timeout=6)" '
        "|| true"
    )


class BaseOracle:
    id: str = "base"
    classes: tuple[str, ...] = ()

    def instrument(self, context: dict) -> dict[str, str]:
        """Extra env the payload gets; context: run_id, sandbox, claim, recipe."""
        return {}

    def observe(self, context: dict) -> OracleOutcome:
        raise NotImplementedError


class NonceCallbackOracle(BaseOracle):
    """Shared nonce-callback logic for rce (CAIRN_CMD) and ssrf (CAIRN_URL)."""

    param: str = "CAIRN_CMD"

    def instrument(self, context: dict) -> dict[str, str]:
        sandbox: SandboxManager = context["sandbox"]
        nonce = new_nonce()
        context.setdefault("state", {})["nonce"] = nonce
        url = f"{sandbox.collector_url()}/beacon/{nonce}"
        if self.param == "CAIRN_URL":
            value = url
        else:
            value = beacon_command(sandbox.collector_url(), nonce)
        return {self.param: value, "CAIRN_NONCE": nonce}

    def observe(self, context: dict) -> OracleOutcome:
        nonce = context.get("state", {}).get("nonce")
        sandbox: SandboxManager = context["sandbox"]
        run_id = context["run_id"]
        if not nonce:
            return OracleOutcome("ambiguous", reason="oracle was never armed")
        # short residual window for beacons still in flight after payload exit
        hit = sandbox.wait_for_nonce(nonce, run_id=run_id, timeout_s=5.0)
        if hit is not None:
            return OracleOutcome(
                "confirmed",
                marker=nonce,
                reason="nonce observed in collector (out-of-band)",
                evidence={"hit": hit},
            )
        return OracleOutcome(
            "not_confirmed",
            reason="clean run; marker never fired within bounds",
        )


class RceNonceOracle(NonceCallbackOracle):
    id = "rce/nonce-callback"
    classes = ("rce", "deserialization")
    param = "CAIRN_CMD"


class SsrfNonceOracle(NonceCallbackOracle):
    id = "ssrf/nonce-callback"
    classes = ("ssrf",)
    param = "CAIRN_URL"


class SeededRowOracle(BaseOracle):
    """sqli — seed a Cairn-chosen secret; reproduction = PoC returns it."""

    id = "sqli/seeded-row"
    classes = ("sqli",)

    def instrument(self, context: dict) -> dict[str, str]:
        seed = "CAIRN_SEED_" + new_nonce()
        context.setdefault("state", {})["seed"] = seed
        claim = context.get("claim") or {}
        seed_command = (claim.get("run_hints") or {}).get("seed_command")
        if not seed_command:
            return {"CAIRN_SEED": seed}
        recipe = context.get("recipe") or {}
        target = recipe.get("target_container") or next(iter(recipe.get("services", {}).values()), None)
        if not target:
            context["state"]["seed_error"] = "no target container to seed"
            return {"CAIRN_SEED": seed}
        try:
            argv = seed_command if isinstance(seed_command, list) else ["sh", "-c", str(seed_command)]
            container = sandbox_container(context)
            rc, out = container.exec_run([str(a).replace("{SEED}", seed) for a in argv])
            context["state"]["seed_rc"] = int(rc or 0)
            context["state"]["seed_log"] = out.decode("utf-8", "replace")[-2000:]
        except Exception as exc:  # noqa: BLE001 - seeding failure must lean ambiguous
            context["state"]["seed_error"] = str(exc)
        return {"CAIRN_SEED": seed}

    def observe(self, context: dict) -> OracleOutcome:
        state = context.get("state", {})
        seed = state.get("seed")
        if not seed:
            return OracleOutcome("ambiguous", reason="oracle was never armed")
        if state.get("seed_error") or state.get("seed_rc") not in (None, 0):
            return OracleOutcome(
                "ambiguous",
                reason=f"seeding failed: {state.get('seed_error') or 'rc=' + str(state.get('seed_rc'))}",
            )
        if (context.get("claim") or {}).get("run_hints", {}).get("seed_command") is None:
            return OracleOutcome(
                "ambiguous",
                reason="no seeding hook (run_hints.seed_command); cannot seed a secret row fairly",
            )
        stdout = (context.get("execution_stdout") or "")
        if seed in stdout:
            return OracleOutcome(
                "confirmed",
                marker=seed,
                reason="PoC returned the exact Cairn-seeded value (unforgeable post-boot secret)",
            )
        return OracleOutcome("not_confirmed", reason="clean run; seeded value never returned")


class SentinelOracle(BaseOracle):
    """authbypass/pathtraversal — read a Cairn-planted marker the path must not reach."""

    id = "sentinel/planted-file"
    classes = ("authbypass", "pathtraversal")

    def instrument(self, context: dict) -> dict[str, str]:
        claim = context.get("claim") or {}
        hints = claim.get("run_hints") or {}
        plant = hints.get("plant_command")
        sentinel_path = hints.get("sentinel_path")
        nonce = new_nonce()
        context.setdefault("state", {})["nonce"] = nonce
        if not (plant and sentinel_path):
            return {"CAIRN_SENTINEL_PATH": sentinel_path or "", "CAIRN_NONCE": nonce}
        recipe = context.get("recipe") or {}
        target = recipe.get("target_container")
        if target:
            try:
                argv = plant if isinstance(plant, list) else ["sh", "-c", str(plant)]
                container = sandbox_container(context)
                rc, out = container.exec_run([str(a).replace("{NONCE}", nonce) for a in argv])
                context["state"]["plant_rc"] = int(rc or 0)
                context["state"]["plant_log"] = out.decode("utf-8", "replace")[-2000:]
            except Exception as exc:  # noqa: BLE001
                context["state"]["plant_error"] = str(exc)
        return {"CAIRN_SENTINEL_PATH": str(sentinel_path), "CAIRN_NONCE": nonce}

    def observe(self, context: dict) -> OracleOutcome:
        state = context.get("state", {})
        nonce = state.get("nonce")
        claim = context.get("claim") or {}
        hints = claim.get("run_hints") or {}
        if not (hints.get("plant_command") and hints.get("sentinel_path")):
            return OracleOutcome(
                "ambiguous",
                reason="no sentinel hook (run_hints.plant_command + sentinel_path); cannot plant a marker fairly",
            )
        if state.get("plant_error") or state.get("plant_rc") not in (None, 0):
            return OracleOutcome(
                "ambiguous",
                reason=f"planting failed: {state.get('plant_error') or state.get('plant_rc')}",
            )
        stdout = context.get("execution_stdout") or ""
        if nonce and nonce in stdout:
            return OracleOutcome(
                "confirmed",
                marker=nonce,
                reason="PoC reached the Cairn-planted sentinel content",
            )
        return OracleOutcome("not_confirmed", reason="clean run; sentinel content never returned")


class NoopOracle(BaseOracle):
    """Classes without an honest automated oracle (xss, other): lean inconclusive."""

    id = "none/manual-review"

    def __init__(self, vuln_class: str):
        self.vuln_class = vuln_class

    def instrument(self, context: dict) -> dict[str, str]:
        return {}

    def observe(self, context: dict) -> OracleOutcome:
        return OracleOutcome(
            "ambiguous",
            reason=f"class {self.vuln_class!r} has no automated oracle; needs human review",
        )


def sandbox_container(context: dict):
    recipe = context.get("recipe") or {}
    name = recipe.get("target_container")
    if not name:
        raise RuntimeError("no target container in recipe")
    client = context["sandbox"].client
    return client.containers.get(name)


_REGISTRY: list[BaseOracle] = [
    RceNonceOracle(),
    SsrfNonceOracle(),
    SeededRowOracle(),
    SentinelOracle(),
]


def oracle_for(vuln_class: str) -> BaseOracle:
    for oracle in _REGISTRY:
        if vuln_class in oracle.classes:
            return oracle
    return NoopOracle(vuln_class)
