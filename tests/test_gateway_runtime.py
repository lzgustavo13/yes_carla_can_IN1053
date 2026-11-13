"""CLI lifecycle and failure behavior without any kernel network operations."""

import can
import pytest

import security_gateway_module as cli
from scripts import demo_can_defense
from scripts.can_defense_report import summarize
from scripts.demo_can_defense_virtual import simulate


def test_demo_repeated_output_preserves_evidence_without_starting_network(monkeypatch, tmp_path, capsys):
    output = tmp_path / "normal"
    output.mkdir()
    evidence = output / "gateway.txt"
    evidence.write_text("previous experiment evidence")

    def unexpected_network():
        pytest.fail("Repeated output must be rejected before network access")

    monkeypatch.setattr(demo_can_defense, "validate_virtual_interfaces", unexpected_network)
    assert demo_can_defense.main(["normal", "--output", str(output)]) == 2
    assert evidence.read_text() == "previous experiment evidence"
    assert list(output.iterdir()) == [evidence]
    error = capsys.readouterr().err
    assert str(output) in error
    assert "new --output" in error
    assert "Traceback" not in error


def test_demo_missing_candump_does_not_create_partial_evidence(monkeypatch, tmp_path, capsys):
    output = tmp_path / "new_run"
    monkeypatch.setattr(demo_can_defense.shutil, "which", lambda name: None)
    assert demo_can_defense.main(["normal", "--output", str(output)]) == 1
    assert not output.exists()
    assert "install can-utils" in capsys.readouterr().err


@pytest.mark.parametrize("send_error", [False, True])
def test_runtime_closes_sockets_before_restore_and_fails_closed(monkeypatch, tmp_path, send_error):
    events = []

    class Topology:
        def __init__(self, path):
            pass

        def activate(self):
            events.append("activate")

        def assert_isolated(self):
            pass

        def restore(self):
            events.append("restore")

    class Bus:
        def __init__(self, interface, channel, **kwargs):
            assert interface == "socketcan"
            assert kwargs["receive_own_messages"] is False
            assert kwargs["ignore_config"] is True
            self.channel = channel
            self.messages = [can.Message(arbitration_id=0x604, data=[1], is_extended_id=False)] if channel == "vcan1" else []
            events.append("open_" + channel)

        def recv(self, timeout):
            return self.messages.pop(0) if self.messages else None

        def send(self, frame, timeout):
            events.append("send_" + self.channel)
            if send_error:
                raise can.CanOperationError("test send error")

        def shutdown(self):
            events.append("close_" + self.channel)

    monkeypatch.setattr(cli, "GatewayTopology", Topology)
    monkeypatch.setattr(cli, "validate_virtual_interfaces", lambda: None)
    monkeypatch.setattr(cli.can, "Bus", Bus)
    counter = [0]

    def clock():
        counter[0] += 1
        return counter[0] * .1

    monkeypatch.setattr(cli.time, "monotonic", clock)
    monkeypatch.setattr(cli.select, "select", lambda buses, *args: (buses, [], []))
    exit_code = cli.main(["--mode", "MONITOR", "--log", str(tmp_path / "runtime.csv"),
                          "--state", str(tmp_path / "state.json"), "--duration", "1"])
    assert events.index("activate") < events.index("open_vcan0")
    assert "close_vcan0" in events and "close_vcan1" in events
    if send_error:
        assert exit_code == 1
        assert "restore" not in events
    else:
        assert exit_code == 0
        assert events.index("close_vcan0") < events.index("restore")
        assert events.index("close_vcan1") < events.index("restore")


@pytest.mark.parametrize("scenario", ["normal", "unprotected", "monitor", "protect"])
def test_existing_spoofing_attack_four_virtual_scenarios_and_report(tmp_path, scenario):
    output = tmp_path / scenario
    evidence = simulate(scenario, output)
    counts = summarize(output / "decisions.csv")
    assert evidence["synthetic"]
    assert evidence["legitimate_frames_at_vehicle"] == 31
    assert counts["send_errors"] == 0
    if scenario == "normal":
        assert evidence["injected"] == 0
    else:
        assert evidence["injected"] == 100
        assert evidence["attack_frames_at_vehicle"] == (0 if scenario == "protect" else 100)
    assert counts["blocked"] == (100 if scenario == "protect" else 0)
    assert counts["alerts"] == (100 if scenario in {"protect", "monitor"} else 0)
    assert counts["forwarded"] == evidence["statistics"]["forwarded"]
    if scenario in {"protect", "monitor"}:
        untrusted = summarize(output / "decisions.csv", "vcan1")
        assert untrusted["analyzed"] == 100
        assert untrusted["blocked"] == (100 if scenario == "protect" else 0)
        assert untrusted["forwarded"] == (0 if scenario == "protect" else 100)


def test_passive_experiment_refuses_isolated_environment(monkeypatch, tmp_path):
    from defense.gateway_topology import GatewayTopology
    monkeypatch.setattr(cli, "validate_virtual_interfaces", lambda: None)
    monkeypatch.setattr(GatewayTopology, "current", lambda self: [])
    result = cli.main(["--passive", "--state", str(tmp_path / "state.json"),
                       "--log", str(tmp_path / "unused.csv")])
    assert result == 1
    assert not (tmp_path / "unused.csv").exists()
