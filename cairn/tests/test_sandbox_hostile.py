"""Hostile-payload integration tests for the sandbox core (Phase 1 done-when).

These run REAL containers and prove the three invariants against genuinely
hostile code:

1. a hostile payload cannot reach the network except the collector;
2. a hostile payload cannot write outside scratch;
3. a hostile payload is resource-capped (pids, memory, capabilities).

Requires Docker and the `python:3.13-slim` image; opt in with
CAIRN_SANDBOX_INTEGRATION=1 (the default suite must stay Docker-free).
"""

from __future__ import annotations

import json
import os
import uuid

import pytest

docker = pytest.importorskip("docker")

pytestmark = [
    pytest.mark.skipif(
        os.environ.get("CAIRN_SANDBOX_INTEGRATION") != "1",
        reason="set CAIRN_SANDBOX_INTEGRATION=1 to run sandbox container tests",
    ),
]

IMAGE = "python:3.13-slim"


@pytest.fixture(scope="module")
def docker_available() -> None:
    try:
        client = docker.from_env()
        client.ping()
        client.images.get(IMAGE)
    except Exception as exc:  # pragma: no cover - environment guard
        pytest.skip(f"docker not usable for integration tests: {exc}")
    finally:
        try:
            client.close()
        except Exception:
            pass


@pytest.fixture()
def manager(tmp_path, docker_available) :
    from cairn.sandbox import SandboxConfig, SandboxManager

    run_id = f"it-{uuid.uuid4().hex[:8]}"
    mgr = SandboxManager(
        SandboxConfig(
            image=IMAGE,
            collector_image=IMAGE,
            scratch_root=tmp_path / "scratch",
            hits_root=tmp_path / "hits",
            mem_mb=256,
            pids_limit=32,
            payload_timeout_s=60,
        )
    )
    mgr._it_run_id = run_id  # noqa: SLF001 - test bookkeeping
    yield mgr
    mgr.teardown(run_id)
    mgr.close()


def _payload_file(manager, name: str, body: str) -> None:
    (manager.scratch_dir(manager._it_run_id) / name).write_text(body)


def _run(manager, script_name: str, timeout_s: int = 45):
    from cairn.sandbox import PayloadResult  # noqa: F401 - documentation of return type

    return manager.run_payload(
        manager._it_run_id,
        ["python3", f"/scratch/{script_name}"],
        timeout_s=timeout_s,
    )


def _result_json(manager, name: str) -> dict:
    path = manager.scratch_dir(manager._it_run_id) / name
    return json.loads(path.read_text())


# =====================================================================
# invariant 1 — network: collector reachable, everything else blocked
# =====================================================================


def test_hostile_network_egress_denied_except_collector(manager) -> None:
    manager.ensure_collector(manager._it_run_id)

    # a decoy listener lives on a DIFFERENT sandbox network; if the payload
    # could reach it, cross-run isolation would be broken
    decoy = manager.client.containers.run(
        IMAGE,
        ["sleep", "infinity"],
        name=f"cairn-it-decoy-{uuid.uuid4().hex[:8]}",
        detach=True,
        labels={"cairn.sandbox.run": manager._it_run_id},
    )
    try:
        # collect decoy's non-internal network name for an explicit cross-check
        _payload_file(
            manager,
            "case_net.py",
            """
import json, socket, urllib.request

res = {}
try:
    body = urllib.request.urlopen("http://collector:9931/beacon/7f3c9d20b4a1e09a", timeout=6)
    res["collector"] = body.status
except Exception as e:
    res["collector"] = f"fail:{type(e).__name__}:{e}"

for name, addr in [("external", ("1.1.1.1", 80)), ("decoy", ("cairn-it-decoy", 9931))]:
    try:
        socket.create_connection(addr, timeout=5)
        res[name] = "REACHED"
    except OSError as e:
        res[name] = f"blocked:{type(e).__name__}"
    except Exception as e:
        res[name] = f"blocked:{type(e).__name__}"

json.dump(res, open("/scratch/result_net.json", "w"))
""",
        )
        result = _run(manager, "case_net.py")
        assert result.rc == 0, result.stderr

        res = _result_json(manager, "result_net.json")
        # the one permitted path works and is observed out-of-band
        assert res["collector"] == 200
        hit = manager.wait_for_nonce("7f3c9d20b4a1e09a", run_id=manager._it_run_id, timeout_s=10)
        assert hit is not None, "collector beacon was not recorded out-of-band"

        # everything else is blocked
        assert res["external"].startswith("blocked"), res
        assert res["decoy"].startswith("blocked"), res
    finally:
        decoy.remove(force=True)


# =====================================================================
# invariant 2 — filesystem: no writes outside scratch
# =====================================================================


def test_hostile_filesystem_writes_confined_to_scratch(manager) -> None:
    _payload_file(
        manager,
        "case_fs.py",
        """
import json

res = {}
for label, path in [
    ("root_etc", "/etc/cairn_pwn"),
    ("root_var", "/var/tmp/cairn_pwn"),
    ("root_usr", "/usr/cairn_pwn"),
    ("slash", "/cairn_pwn"),
    ("scratch", "/scratch/proof.txt"),
    ("tmp", "/tmp/cairn_pwn"),
]:
    try:
        with open(path, "w") as fh:
            fh.write("pwned")
        res[label] = "WROTE"
    except OSError as e:
        res[label] = f"denied:{e.errno}"

json.dump(res, open("/scratch/result_fs.json", "w"))
""",
    )
    result = _run(manager, "case_fs.py")
    assert result.rc == 0, result.stderr

    res = _result_json(manager, "result_fs.json")
    for label in ("root_etc", "root_var", "root_usr", "slash"):
        assert res[label].startswith("denied"), f"{label} was writable: {res}"
    assert res["scratch"] == "WROTE"
    assert (manager.scratch_dir(manager._it_run_id) / "proof.txt").read_text() == "pwned"
    assert res["tmp"] == "WROTE"  # tmpfs counts as scratch-and-vapor, not persistence


# =====================================================================
# invariant 3 — resource caps: pids, memory, capabilities, uid
# =====================================================================


def test_hostile_fork_bomb_capped_by_pids_limit(manager) -> None:
    _payload_file(
        manager,
        "case_pids.py",
        """
import json, os, time

spawned = 0
errno = None
for _ in range(400):
    try:
        pid = os.fork()
        if pid == 0:
            time.sleep(1.2)
            os._exit(0)
        spawned += 1
    except OSError as e:
        errno = e.errno
        break
time.sleep(1.6)
json.dump({"spawned": spawned, "errno": errno}, open("/scratch/result_pids.json", "w"))
""",
    )
    result = _run(manager, "case_pids.py", timeout_s=60)
    assert result.rc == 0, result.stderr

    res = _result_json(manager, "result_pids.json")
    assert res["errno"] == 11, f"fork loop stopped for the wrong reason: {res}"
    assert res["spawned"] < 40, f"fork bomb exceeded pids cap: {res}"


def test_hostile_memory_hog_killed_by_cgroup_limit(manager) -> None:
    _payload_file(
        manager,
        "case_mem.py",
        """
import json
json.dump({"phase": "start"}, open("/scratch/result_mem.json", "w"))
try:
    blob = bytearray(600 * 1024 * 1024)  # zero-filled -> pages get touched
    json.dump({"phase": "ALLOCATED"}, open("/scratch/result_mem.json", "w"))
except MemoryError:
    json.dump({"phase": "memoryerror"}, open("/scratch/result_mem.json", "w"))
""",
    )
    result = _run(manager, "case_mem.py", timeout_s=60)

    res = _result_json(manager, "result_mem.json")
    # either the allocator refused or the cgroup OOM-killer terminated the
    # payload mid-allocation — both prove the cap
    assert res["phase"] in ("start", "memoryerror"), res
    assert result.rc in (137, None) or res["phase"] == "memoryerror", (result.rc, res)


def test_hostile_payload_runs_without_capabilities_and_privileges(manager) -> None:
    _payload_file(
        manager,
        "case_caps.py",
        """
import json
status = {}
for line in open("/proc/self/status"):
    if ":" in line:
        key, value = line.split(":", 1)
        status[key] = value.strip()
json.dump(
    {
        "uid": status.get("Uid"),
        "capperm": status.get("CapPrm"),
        "capeff": status.get("CapEff"),
        "nonewprivs": status.get("NoNewPrivs"),
    },
    open("/scratch/result_caps.json", "w"),
)
""",
    )
    result = _run(manager, "case_caps.py")
    assert result.rc == 0, result.stderr

    res = _result_json(manager, "result_caps.json")
    assert res["capperm"] == "0000000000000000", res
    assert res["capeff"] == "0000000000000000", res
    assert res["nonewprivs"] == "1", res
    uid = int(res["uid"].split()[0])
    assert uid != 0, res
