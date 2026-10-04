"""Budget caps + stop conditions (Cairn v2, Phase 6).

One ledger per verification run.  The deterministic pipeline spends no
tokens and no dollars, so those caps are advisory; wall clock, step count,
and payload runs are hard.  On breach the run pauses and concludes
``inconclusive / BUDGET_EXHAUSTED`` unless a verdict is already derivable
(an already-confirmed marker still wins — the proof is in hand).

Stop conditions for the loop: goal reached (verdict), budget hit, or stall
(N cycles without progress) — runs always terminate.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from cairn.verification.config import BudgetConfig


@dataclass
class BudgetLedger:
    caps: BudgetConfig = field(default_factory=BudgetConfig)
    started_at: float = field(default_factory=time.monotonic)
    steps: int = 0
    payload_runs: int = 0
    cost_usd: float = 0.0
    tokens: int = 0
    stall_cycles: int = 0

    def start(self) -> None:
        self.started_at = time.monotonic()

    def step(self) -> None:
        self.steps += 1

    def payload_run(self) -> None:
        self.payload_runs += 1

    def spend(self, cost_usd: float = 0.0, tokens: int = 0) -> None:
        self.cost_usd += cost_usd
        self.tokens += tokens

    # ------------------------------------------------------------------

    def elapsed_s(self) -> float:
        return time.monotonic() - self.started_at

    def breach(self) -> str | None:
        """Human-readable breach reason, or None while inside the caps."""
        if self.elapsed_s() > self.caps.wall_clock_s:
            return f"wall clock {self.elapsed_s():.0f}s > {self.caps.wall_clock_s}s"
        if self.steps >= self.caps.max_steps:
            return f"steps {self.steps} >= {self.caps.max_steps}"
        if self.payload_runs >= self.caps.max_payload_runs:
            return f"payload runs {self.payload_runs} >= {self.caps.max_payload_runs}"
        if self.cost_usd >= self.caps.max_cost_usd:
            return f"cost ${self.cost_usd:.2f} >= ${self.caps.max_cost_usd:.2f}"
        if self.tokens >= self.caps.max_tokens:
            return f"tokens {self.tokens} >= {self.caps.max_tokens}"
        return None

    def snapshot(self) -> dict:
        return {
            "elapsed_s": round(self.elapsed_s(), 1),
            "wall_clock_cap_s": self.caps.wall_clock_s,
            "steps": self.steps,
            "max_steps": self.caps.max_steps,
            "payload_runs": self.payload_runs,
            "max_payload_runs": self.caps.max_payload_runs,
            "cost_usd": round(self.cost_usd, 4),
            "max_cost_usd": self.caps.max_cost_usd,
            "tokens": self.tokens,
            "max_tokens": self.caps.max_tokens,
            "breach": self.breach(),
        }
