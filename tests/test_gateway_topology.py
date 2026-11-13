"""Transactional route handling; kernel commands are simulated, never sudo."""

import json
import os
from types import SimpleNamespace

import pytest

from defense.gateway_topology import (GatewayTopology, ROUTES, parse_routes,
                                      scoped_routes, topology_lock, validate_virtual_interfaces, command)


@pytest.mark.parametrize("listing", ["", "cangw -A -s vcan1 -d vcan0 -e # 12 handled 0 dropped 0 deleted\n"])
def test_cangw_2023_successful_list_status_36(monkeypatch, listing):
    monkeypatch.setattr("defense.gateway_topology.subprocess.run",
                        lambda *a, **k: SimpleNamespace(returncode=36, stdout=listing, stderr=""))
    assert command(["cangw", "-L"]) == listing


@pytest.mark.parametrize("listing", ["NLMSG_ERROR\n", "Unknown attribute 90!", "garbage"])
def test_legacy_list_status_does_not_hide_invalid_netlink_response(monkeypatch, listing):
    monkeypatch.setattr("defense.gateway_topology.subprocess.run",
                        lambda *a, **k: SimpleNamespace(returncode=36, stdout=listing, stderr=""))
    with pytest.raises(ValueError):
        command(["cangw", "-L"])


@pytest.mark.parametrize("args,status,stderr", [
    (["cangw", "-L"], 255, "netlink sendto: Operation not permitted"),
    (["cangw", "-L"], 36, "netlink recv: interrupted"),
    (["cangw", "-A", "-s", "vcan1", "-d", "vcan0", "-e"], 36, ""),
    (["cangw", "-L"], 0, "netlink error"),
])
def test_network_command_failures_remain_fatal_and_include_diagnostics(monkeypatch, args, status, stderr):
    monkeypatch.setattr("defense.gateway_topology.subprocess.run",
                        lambda *a, **k: SimpleNamespace(returncode=status, stdout="", stderr=stderr))
    with pytest.raises(RuntimeError) as error:
        command(args)
    assert f"exit {status}" in str(error.value)
    if stderr:
        assert stderr in str(error.value)


class Kernel:
    def __init__(self):
        self.routes = list(ROUTES)
        self.unrelated = ("-A", "-s", "other0", "-d", "other1", "-e")
        self.routes.append(self.unrelated)
        self.calls = []
        self.kind = "vcan"
        self.fail_delete = None
        self.fail_add = False

    def __call__(self, args):
        self.calls.append(args)
        if args[0] == "ip":
            return json.dumps([{"ifname": args[-1], "flags": ["UP"],
                                "linkinfo": {"info_kind": self.kind}}])
        assert args[0] == "cangw"
        if args[1] == "-L":
            return "\n".join("cangw " + " ".join(r) + " # 23 handled 0 dropped 0 deleted" for r in self.routes)
        if args[1] == "-D":
            route = ("-A", *args[2:])
            if route == self.fail_delete:
                raise RuntimeError("simulated deletion failure")
            self.routes.remove(route)
        elif args[1] == "-A":
            if self.fail_add:
                raise RuntimeError("simulated restoration failure")
            self.routes.append(tuple(args[1:]))
        else:
            pytest.fail("Unexpected command, including forbidden flush")
        return ""


def test_activation_restore_only_changes_exact_lab_routes(tmp_path):
    kernel = Kernel()
    path = tmp_path / "state.json"
    topology = GatewayTopology(path, run=kernel)
    topology.activate()
    assert kernel.routes == [kernel.unrelated]
    topology.assert_isolated()
    assert path.exists()
    topology.restore()
    assert set(kernel.routes) == {*ROUTES, kernel.unrelated}
    assert not path.exists()
    before = list(kernel.routes)
    assert not topology.restore()
    assert kernel.routes == before
    assert all("-F" not in call for call in kernel.calls)


@pytest.mark.parametrize("failure_index", [0, 1])
def test_write_ahead_journal_restores_after_partial_activation(tmp_path, failure_index):
    kernel = Kernel()
    kernel.fail_delete = ROUTES[failure_index]
    topology = GatewayTopology(tmp_path / "state.json", run=kernel)
    with pytest.raises(RuntimeError, match="deletion"):
        topology.activate()
    assert topology.path.exists()
    topology.restore()
    assert sorted(kernel.routes) == sorted([*ROUTES, kernel.unrelated])


def test_failed_restore_keeps_journal_and_can_be_retried(tmp_path):
    kernel = Kernel()
    topology = GatewayTopology(tmp_path / "state.json", run=kernel)
    topology.activate()
    kernel.fail_add = True
    with pytest.raises(RuntimeError, match="restoration"):
        topology.restore()
    assert topology.path.exists()
    kernel.fail_add = False
    topology.restore()
    assert set(kernel.routes) == {*ROUTES, kernel.unrelated}


@pytest.mark.parametrize("extra", [
    ("-A", "-s", "vcan1", "-d", "third", "-e"),
    ("-A", "-s", "third", "-d", "vcan0", "-e"),
    ("-A", "-s", "vcan1", "-d", "vcan0", "-e", "-f", "604:7FF"),
    ROUTES[0],
])
def test_refuse_unsupported_bypass_or_duplicate_without_changes(tmp_path, extra):
    kernel = Kernel()
    kernel.routes.append(extra)
    before = list(kernel.routes)
    topology = GatewayTopology(tmp_path / "state.json", run=kernel)
    with pytest.raises(ValueError):
        topology.activate()
    assert kernel.routes == before
    assert not topology.path.exists()
    assert not any(call[1] == "-D" for call in kernel.calls if call[0] == "cangw")


def test_missing_original_route_refused(tmp_path):
    kernel = Kernel()
    kernel.routes.remove(ROUTES[0])
    with pytest.raises(ValueError, match="Expected"):
        GatewayTopology(tmp_path / "state.json", kernel).activate()


def test_existing_journal_prevents_second_activation(tmp_path):
    kernel = Kernel()
    topology = GatewayTopology(tmp_path / "state.json", kernel)
    topology.activate()
    with pytest.raises(RuntimeError, match="journal"):
        topology.activate()


def test_injected_route_is_detected_while_running(tmp_path):
    kernel = Kernel()
    topology = GatewayTopology(tmp_path / "state.json", kernel)
    topology.activate()
    kernel.routes.append(ROUTES[0])
    with pytest.raises(RuntimeError, match="Direct"):
        topology.assert_isolated()


@pytest.mark.parametrize("kind", ["can", "vxcan", "veth"])
def test_physical_or_other_interface_rejected_even_if_named_vcan(kind):
    kernel = Kernel()
    kernel.kind = kind
    with pytest.raises(ValueError, match="kernel vcan"):
        validate_virtual_interfaces(kernel)


def test_journal_cannot_execute_arbitrary_commands(tmp_path):
    kernel = Kernel()
    topology = GatewayTopology(tmp_path / "state.json", kernel)
    topology.path.write_text(json.dumps({"version": 1, "netns": os.stat("/proc/self/ns/net").st_ino,
                                        "routes": [["-F"], list(ROUTES[1])]}))
    with pytest.raises(ValueError, match="Invalid recovery"):
        topology.restore()
    assert not any(call[0] == "cangw" for call in kernel.calls)


def test_namespace_mismatch_refused(tmp_path):
    kernel = Kernel()
    topology = GatewayTopology(tmp_path / "state.json", kernel)
    topology.activate()
    data = json.loads(topology.path.read_text())
    data["netns"] = -1
    topology.path.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="namespace"):
        topology.restore()


def test_lock_prevents_live_restore(tmp_path):
    path = tmp_path / "state.json"
    with topology_lock(path):
        with pytest.raises(RuntimeError, match="running"):
            with topology_lock(path):
                pytest.fail("Concurrent lock acquired")
    with topology_lock(path):
        pass


@pytest.mark.parametrize("listing", ["NLMSG_ERROR", "garbage", "cangw -A -s vcan1 -d"])
def test_unrecognized_listing_not_treated_as_empty(listing):
    with pytest.raises(ValueError):
        parse_routes(listing)


def test_comments_in_real_cangw_format_are_ignored():
    routes = parse_routes("cangw -A -s vcan1 -d vcan0 -e # 12 handled 0 dropped 0 deleted\n")
    assert scoped_routes(routes) == [ROUTES[0]]
