"""Security policies and actual virtual transport, without CARLA or root."""

import csv
import json
from pathlib import Path
import subprocess
import uuid

import can
import pytest

from defense.can_gateway import DecisionLog, GatewayPolicy, SecurityGateway

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def config():
    return json.loads((ROOT / "data/can_gateway_policy.json").read_text())


@pytest.fixture
def policy(config):
    return GatewayPolicy(ROOT / "data/carla.dbc", config)


def frame(can_id=0x604, data=b"\x01", **kwargs):
    return can.Message(arbitration_id=can_id, data=data, is_extended_id=False, **kwargs)


def test_source_policy_uses_dbc_and_keeps_legitimate_handbrake(policy):
    assert policy.database.get_message_by_name("HAND_BRAKE").frame_id == 0x604
    assert policy.periods["HAND_BRAKE"] == .2
    assert policy.inspect(frame(), "vcan0", 0).allowed
    result = policy.inspect(frame(), "vcan1", 0)
    assert not result.allowed
    assert result.reasons == ("source_denied",)


def test_allowlist(config):
    config["segments"]["vcan1"]["allow"] = ["BRAKE"]
    policy = GatewayPolicy(ROOT / "data/carla.dbc", config)
    assert policy.inspect(frame(0x601, b"\0" * 4), "vcan1", 0).allowed
    assert "source_not_allowlisted" in policy.inspect(frame(0x602, b"\0" * 4), "vcan1", 0).reasons


@pytest.mark.parametrize("message", [
    frame(0x123), frame(data=b"\0\0"), frame(is_remote_frame=True),
    frame(is_error_frame=True), frame(is_fd=True),
    can.Message(arbitration_id=0x604, data=[1], is_extended_id=True),
    frame(dlc=8),
])
def test_unknown_malformed_and_extended_id_bypass_rejected(policy, message):
    assert not policy.inspect(message, "vcan1", 0).allowed


def test_periodic_traffic_frequency_and_exact_window_boundary(policy):
    # THROTTLE: 100 ms, 1 s window => ceil(10 * 1.5) + 1 = 16.
    message = frame(0x600, b"\0" * 4)
    for i in range(30):
        decision = policy.inspect(message, "vcan1", i * .1)
        assert decision.allowed
        assert decision.window_limit == 16
    assert policy.inspect(message, "vcan1", 10).window_count == 1


def test_flood_counts_blocked_attempts_and_recovers_after_window(policy):
    message = frame(0x600, b"\0" * 4)
    for _ in range(16):
        assert policy.inspect(message, "vcan1", 0).allowed
    for _ in range(1000):
        decision = policy.inspect(message, "vcan1", 0)
        assert decision.reasons == ("frequency_exceeded",)
        assert decision.window_count == 17
    assert len(next(iter(policy.windows.values()))) == 17
    assert policy.inspect(message, "vcan1", 1).allowed


def test_handbrake_attack_has_both_alerts(policy):
    # Existing attack default: 100 ms; DBC: 200 ms => 9 frames/window allowed.
    for i in range(10):
        decision = policy.inspect(frame(), "vcan1", i * .1)
    assert decision.window_limit == 9
    assert decision.reasons == ("source_denied", "frequency_exceeded")


def test_event_messages_have_no_invented_frequency_limit(policy):
    for _ in range(100):
        result = policy.inspect(frame(0x60C), "vcan1", 0)
        assert result.allowed
        assert result.window_limit == 0


def test_experimental_period_override(config):
    config["period_overrides_ms"] = {"DOORS": 200}
    policy = GatewayPolicy(ROOT / "data/carla.dbc", config)
    for _ in range(10):
        decision = policy.inspect(frame(0x60C), "vcan1", 0)
    assert decision.reasons == ("frequency_exceeded",)


def test_clock_and_source_validation(policy):
    policy.inspect(frame(), "vcan1", 2)
    with pytest.raises(ValueError, match="monotonic"):
        policy.inspect(frame(), "vcan1", 1)
    with pytest.raises(ValueError, match="Unknown source"):
        policy.inspect(frame(), "can0", 2)


@pytest.mark.parametrize("key,value", [
    ("window_seconds", 0), ("window_seconds", float("nan")),
    ("window_seconds", True), ("rate_multiplier", .9),
    ("burst_allowance", -1), ("burst_allowance", 1.1),
    ("period_overrides_ms", {"UNKNOWN": 100}),
    ("period_overrides_ms", {"HAND_BRAKE": 0}),
])
def test_invalid_config_rejected(config, key, value):
    config[key] = value
    with pytest.raises(ValueError):
        GatewayPolicy(ROOT / "data/carla.dbc", config)


@pytest.mark.parametrize("mode,blocked,forwarded", [("MONITOR", 0, 1), ("PROTECT", 1, 0)])
def test_decisions_logs_and_transport(policy, tmp_path, mode, blocked, forwarded):
    class Destination:
        sent = []

        def send(self, message, timeout):
            self.sent.append(message)

    destination = Destination()
    path = tmp_path / "decisions.csv"
    log = DecisionLog(path)
    output = []
    gateway = SecurityGateway(policy, mode, log, clock=lambda: 0, output=output.append)
    gateway.process(frame(), "vcan1", destination)
    assert len(destination.sent) == forwarded
    assert gateway.stats.analyzed == 1
    assert gateway.stats.allowed == 1 - blocked
    assert gateway.stats.blocked == blocked
    assert gateway.stats.alerts == 1
    assert gateway.stats.forwarded == forwarded
    assert "0x604" in output[0] and "source_denied" in output[0]
    log.close()
    row = list(csv.DictReader(path.open()))[0]
    assert row["can_id"] == "0x604"
    assert row["action"] == ("BLOCK" if blocked else "ALLOW")
    assert row["forwarded"] == str(forwarded)
    with pytest.raises(FileExistsError):
        DecisionLog(path)


def test_send_error_recorded_and_propagated(policy, tmp_path):
    class BrokenBus:
        def send(self, message, timeout):
            raise can.CanOperationError("test error")

    log = DecisionLog(tmp_path / "error.csv")
    gateway = SecurityGateway(policy, "MONITOR", log, clock=lambda: 0, output=lambda _: None)
    with pytest.raises(can.CanOperationError):
        gateway.process(frame(), "vcan1", BrokenBus())
    log.close()
    assert gateway.stats.send_errors == 1
    assert gateway.stats.forwarded == 0
    row = list(csv.DictReader((tmp_path / "error.csv").open()))[0]
    assert row["action"] == "SEND_ERROR"


@pytest.mark.parametrize("mode", ["MONITOR", "PROTECT"])
def test_bidirectional_virtual_transport_no_loops_duplicates_or_control_loss(policy, tmp_path, mode):
    """Exercise python-can transport with the same socket ownership as runtime."""
    prefix = str(uuid.uuid4())
    attacker = can.Bus(interface="virtual", channel=prefix + "1")
    untrusted = can.Bus(interface="virtual", channel=prefix + "1", receive_own_messages=False)
    trusted = can.Bus(interface="virtual", channel=prefix + "0", receive_own_messages=False)
    vehicle = can.Bus(interface="virtual", channel=prefix + "0")
    log = DecisionLog(tmp_path / "virtual.csv")
    gateway = SecurityGateway(policy, mode, log, clock=lambda: 0, output=lambda _: None)
    try:
        attacker.send(frame())
        gateway.process(untrusted.recv(.1), "vcan1", trusted)
        received = vehicle.recv(.02)
        assert (received is not None) == (mode == "MONITOR")
        assert trusted.recv(0) is None  # no reflected copy for reverse forwarding
        # Local control reaches the vehicle independently of gateway decisions.
        vehicle.send(frame(data=b"\0"))
        local = trusted.recv(.1)
        assert bytes(local.data) == b"\0"
        gateway.process(local, "vcan0", untrusted)
        telemetry = attacker.recv(.1)
        assert bytes(telemetry.data) == b"\0"
        assert untrusted.recv(0) is None
        assert attacker.recv(0) is None
        assert vehicle.recv(0) is None
        # An authorized untrusted frame is forwarded exactly once in both modes.
        attacker.send(frame(0x600, b"\x40\0\0\0"))
        gateway.process(untrusted.recv(.1), "vcan1", trusted)
        assert vehicle.recv(.1).arbitration_id == 0x600
        assert vehicle.recv(0) is None and trusted.recv(0) is None
    finally:
        log.close()
        for bus in (attacker, untrusted, trusted, vehicle):
            bus.shutdown()


def test_gateway_import_and_cli_without_carla():
    code = "import sys; import security_gateway_module; assert 'carla' not in sys.modules"
    subprocess.run([__import__("sys").executable, "-c", code], cwd=ROOT, check=True)
