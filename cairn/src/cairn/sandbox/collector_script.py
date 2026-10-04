"""Source of the in-container nonce collector service (Cairn v2, Phase 1).

The collector is the *only* permitted egress from a sandbox network: it is
attached to the run's internal Docker network under the alias ``collector``
and records every request it receives to a JSONL file on a bind mount the
dispatcher reads.  Oracle logic (Phase 4) treats a recorded nonce hit as
the sole out-of-band proof of effect.

The script below runs inside the collector container with nothing but the
Python standard library.
"""

from __future__ import annotations

import json

COLLECTOR_SERVER_SOURCE = '''\
#!/usr/bin/env python3
"""Cairn nonce collector: records every inbound request as a JSONL hit."""
import argparse
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

_lock = threading.Lock()
_hits_path = None


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _respond(self, body: bytes = b"ok") -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _record(self) -> None:
        hit = {
            "ts": round(time.time(), 3),
            "method": self.command,
            "path": self.path,
            "src": self.client_address[0],
        }
        with _lock:
            with open(_hits_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(hit, sort_keys=True) + "\\n")

    def do_GET(self) -> None:
        if self.path == "/healthz":
            self._respond(b"healthy")
            return
        self._record()
        self._respond()

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        if length > 0:
            self.rfile.read(min(length, 1 << 20))
        self._record()
        self._respond()

    do_PUT = do_POST
    do_DELETE = do_GET

    def log_message(self, *_args) -> None:  # keep container logs quiet
        return


def main() -> None:
    global _hits_path
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=9931)
    parser.add_argument("--hits", required=True)
    args = parser.parse_args()
    _hits_path = args.hits

    server = ThreadingHTTPServer(("0.0.0.0", args.port), Handler)
    print(f"collector listening on :{args.port}, hits -> {_hits_path}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
'''


def collector_command(port: int) -> list[str]:
    # the source ships inline via `python3 -c`: the collector container is
    # read-only (put_archive is refused by the daemon), so no file is ever
    # written — only the hits file is a bind mount
    return [
        "python3",
        "-c",
        COLLECTOR_SERVER_SOURCE,
        "--port",
        str(port),
        "--hits",
        "/collector/hits.jsonl",
    ]


def parse_hits(raw: str) -> list[dict]:
    """Parse the JSONL hits file (dispatcher side)."""
    hits = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            hits.append(json.loads(line))
        except json.JSONDecodeError:
            continue  # a torn line never blocks the evidence stream
    return hits


def nonce_seen(hits: list[dict], nonce: str) -> dict | None:
    """Return the first hit carrying `nonce`, if any.

    A hit counts when the nonce appears as a non-empty path segment —
    `/beacon/<nonce>`, `/<nonce>`, `/?x=<nonce>` all qualify — but a bare
    health probe (`/healthz`) never does.
    """
    for hit in hits:
        path = hit.get("path") or ""
        if path.startswith("/healthz"):
            continue
        segments = [seg for seg in path.replace("?", "/").split("/") if seg]
        if nonce in segments:
            return hit
    return None


__all__ = [
    "COLLECTOR_SERVER_SOURCE",
    "collector_command",
    "parse_hits",
    "nonce_seen",
]
