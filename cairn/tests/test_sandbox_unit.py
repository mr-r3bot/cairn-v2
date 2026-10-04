"""Host-only unit tests for the sandbox package (no Docker required)."""

from __future__ import annotations

import io
import json
import tarfile
import time
from pathlib import Path

import pytest

from cairn.sandbox.archives import text_file_archive
from cairn.sandbox.collector_script import (
    COLLECTOR_SERVER_SOURCE,
    collector_command,
    nonce_seen,
    parse_hits,
)
from cairn.sandbox.config import SandboxConfig
from cairn.sandbox.manager import SandboxManager, _sanitize


# ---------------------------------------------------------------- archives


def test_text_file_archive_places_file_at_nested_path() -> None:
    archive_dir, raw = text_file_archive("/collector/collector.py", "print('hi')")
    assert archive_dir == "/collector"
    with tarfile.open(fileobj=io.BytesIO(raw)) as tar:
        members = tar.getmembers()
        assert [m.name for m in members] == ["collector.py"]
        assert members[0].size == len(b"print('hi')")
        assert tar.extractfile("collector.py").read() == b"print('hi')"


def test_text_file_archive_rejects_bad_paths() -> None:
    with pytest.raises(ValueError):
        text_file_archive("collector.py", "x")
    with pytest.raises(ValueError):
        text_file_archive("/a/../b", "x")


# ---------------------------------------------------------------- collector


def test_collector_source_is_self_contained_stdlib() -> None:
    # the embedded service must only import stdlib modules
    for line in COLLECTOR_SERVER_SOURCE.splitlines():
        stripped = line.strip()
        if stripped.startswith(("import ", "from ")):
            module = stripped.split()[1].split(".")[0]
            assert module in {
                "argparse",
                "json",
                "threading",
                "time",
                "http",
            }, f"unexpected import in collector source: {module}"


def test_collector_command_shape() -> None:
    cmd = collector_command(9931)
    # inline source via -c: nothing is ever written to the read-only rootfs
    assert cmd[0:2] == ["python3", "-c"]
    assert "ThreadingHTTPServer" in cmd[2]
    assert cmd[3:] == ["--port", "9931", "--hits", "/collector/hits.jsonl"]


def test_parse_hits_skips_torn_lines() -> None:
    raw = (
        json.dumps({"ts": 1, "method": "GET", "path": "/beacon/aa", "src": "10.0.0.2"})
        + "\n"
        + '{"ts": 2, "path": "/be"  # torn mid-write\n'
        + "\n"
        + json.dumps({"ts": 3, "method": "GET", "path": "/beacon/bb", "src": "10.0.0.2"})
        + "\n"
    )
    hits = parse_hits(raw)
    assert [h["path"] for h in hits] == ["/beacon/aa", "/beacon/bb"]


def test_nonce_seen_matches_path_segments_not_substrings() -> None:
    hits = [
        {"path": "/healthz"},
        {"path": "/beacon/7f3c9d20"},
        {"path": "/7f3c9d20?x=1"},
    ]
    assert nonce_seen(hits, "7f3c9d20") == hits[1]
    # substring-only overlap must NOT count
    assert nonce_seen(hits, "7f3c") is None
    assert nonce_seen(hits, "healthz") is None
    # leading query style still matches via segment split
    assert nonce_seen([{"path": "/x/abcd1234"}], "abcd1234") is not None


# ---------------------------------------------------------------- config / naming


def test_config_defaults_are_conservative() -> None:
    cfg = SandboxConfig()
    assert cfg.mem_mb >= 128
    assert cfg.pids_limit >= 16
    assert cfg.image.startswith("python:")
    assert not cfg.keep_on_failure


def test_sanitize_run_ids() -> None:
    assert _sanitize("run/with/slashes") == "run-with-slashes"
    assert _sanitize("abc-123_x") == "abc-123_x"
    with pytest.raises(ValueError):
        _sanitize("///")


def test_manager_paths_are_per_run(tmp_path) -> None:
    manager = SandboxManager(SandboxConfig(data_home=tmp_path / "d"))
    assert manager.network_name("r1") == "cairn-sbxnet-r1"
    assert manager.collector_name("r1") == "cairn-sbxcollector-r1"
    scratch = manager.scratch_dir("r1")
    assert scratch == tmp_path / "d" / "sandbox" / "scratch" / "r1"
    assert scratch.exists()
    assert manager.hits_path("r1") == tmp_path / "d" / "sandbox" / "collector" / "r1"
    assert manager.collector_url() == "http://collector:9931"


def test_host_path_translation_for_containerized_dispatcher(tmp_path) -> None:
    cfg_same = SandboxConfig(data_home=tmp_path / "d")
    assert cfg_same.host_path(tmp_path / "d" / "sandbox" / "scratch" / "r1") == (
        tmp_path / "d" / "sandbox" / "scratch" / "r1"
    )
    cfg_docker = SandboxConfig(
        data_home=Path("/root/.local/share/cairn"),
        host_data_home=Path("/srv/cairn/datas/cairn"),
    )
    assert cfg_docker.host_path(
        Path("/root/.local/share/cairn/sandbox/scratch/r1")
    ) == Path("/srv/cairn/datas/cairn/sandbox/scratch/r1")
    # paths outside data_home pass through untouched
    assert cfg_docker.host_path(Path("/etc/passwd")) == Path("/etc/passwd")


def test_wait_for_nonce_polls_until_hit_lands(tmp_path, monkeypatch) -> None:
    manager = SandboxManager(SandboxConfig(data_home=tmp_path))
    hits_path = manager.hits_path("r1")
    hits_path.parent.mkdir(parents=True, exist_ok=True)
    hits_path.write_text("")

    # a hit arrives after 1.2s of polling
    import threading

    def later() -> None:
        time.sleep(1.2)
        with open(hits_path, "a") as fh:
            fh.write(json.dumps({"ts": 1, "method": "GET", "path": "/beacon/nonc3", "src": "x"}) + "\n")

    threading.Timer(1.2, later).start()
    hit = manager.wait_for_nonce("nonc3", run_id="r1", timeout_s=5)
    assert hit is not None and hit["path"] == "/beacon/nonc3"

    assert manager.wait_for_nonce("absent", run_id="r1", timeout_s=0.2) is None
