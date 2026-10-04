"""Cairn v2 sandbox — mandatory containment for untrusted PoC execution.

Attacker-authored code from Strix claims never runs outside this sandbox.
Containment is Docker-native (agreed deviation from plan.md's hand-rolled
Landlock/seccomp sketch — same invariants, implemented with primitives the
dispatcher already orchestrates):

1. *No egress except the collector* — payloads run on a per-run **internal**
   Docker network with no external route; the nonce collector is the only
   meaningful peer on it.
2. *No writes outside scratch* — read-only rootfs; the scratch bind mount is
   the single writable path and doubles as the evidence directory.
3. *Resource-capped* — cgroup memory/pids/cpu limits, dropped capabilities,
   no-new-privileges, non-root uid.

The collector is the product's oracle channel: a nonce observed there is
the only signal that can ever upgrade a claim to ``reproduced``
(effect-not-echo; see docs/specs/verification.md).
"""

from cairn.sandbox.collector_script import nonce_seen, parse_hits
from cairn.sandbox.config import SandboxConfig
from cairn.sandbox.manager import PayloadResult, SandboxManager

__all__ = [
    "PayloadResult",
    "SandboxConfig",
    "SandboxManager",
    "nonce_seen",
    "parse_hits",
]
