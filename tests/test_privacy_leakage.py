"""DBC-driven privacy leakage tests; no CARLA server or kernel CAN required."""

import csv
import json
import threading
from types import SimpleNamespace
from unittest.mock import MagicMock

import can
import cantools
import pytest

import attacks.privacy_leakage as privacy
import cyberattacks_module as cli


@pytest.fixture
def attack():
    return privacy.PrivacyLeakageAttack("data/carla.dbc")


def gnss_frame(attack, latitude=-8.1234567, longitude=-34.1234567):
    message = attack.gnss_message
    return can.Message(
        arbitration_id=message.frame_id, is_extended_id=message.is_extended_frame,
        data=message.encode({attack.latitude_signal: latitude, attack.longitude_signal: longitude}),
    )


class FakeClock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


class ReceiveOnlyBus:
    """A bus with a failing send method makes accidental transmission detectable."""
    def __init__(self, clock, events=()):
        self.clock = clock
        self.events = list(events)
        self.send = MagicMock(side_effect=AssertionError("A passive attack cannot send"))

    def recv(self, timeout):
        if not self.events:
            self.clock.now += timeout
            return None
        delay, frame = self.events[0]
        if delay > timeout:
            self.events[0] = (delay - timeout, frame)
            self.clock.now += timeout
            return None
        self.events.pop(0)
        self.clock.now += delay
        return frame


def test_identifies_real_gnss_message_and_signals(attack):
    assert attack.gnss_message.name == "GNSS"
    assert attack.gnss_message.frame_id == 1550 == 0x60E
    assert attack.gnss_message.length == 8
    assert [signal.name for signal in attack.gnss_message.signals] == ["GNSS_LAT_signal", "GNSS_LON_signal"]
    assert [signal.unit for signal in attack.gnss_message.signals] == ["deg", "deg"]


def test_id_is_discovered_from_custom_dbc(tmp_path):
    database = cantools.database.load_file("data/carla.dbc")
    database.get_message_by_name("GNSS").frame_id = 0x620
    database.refresh()
    path = tmp_path / "custom.dbc"
    cantools.database.dump_file(database, path)
    attack = privacy.PrivacyLeakageAttack(str(path))
    location = attack.decode_location(gnss_frame(attack), 1.25)
    assert attack.gnss_message.frame_id == 0x620
    assert location.latitude == pytest.approx(-8.1234567)


def test_decode_uses_dbc_physical_values(attack):
    location = attack.decode_location(gnss_frame(attack), 1.25)
    assert location.timestamp == 1.25
    assert location.latitude == pytest.approx(-8.1234567, abs=1e-7)
    assert location.longitude == pytest.approx(-34.1234567, abs=1e-7)


@pytest.mark.parametrize("kind", ["other", "extended", "remote", "error", "short", "out_of_range"])
def test_unrelated_or_invalid_frames_are_ignored(attack, kind):
    frame = gnss_frame(attack)
    if kind == "other":
        frame.arbitration_id = attack.database.get_message_by_name("STEER").frame_id
    elif kind == "extended":
        frame.is_extended_id = True
    elif kind == "remote":
        frame.is_remote_frame = True
    elif kind == "error":
        frame.is_error_frame = True
    elif kind == "short":
        frame.data = frame.data[:2]
    else:
        frame.data = attack.gnss_message.encode({attack.latitude_signal: 91, attack.longitude_signal: 0}, strict=False)
    assert attack.decode_location(frame, 0) is None


def test_capture_stores_locations_and_respects_deadline_without_sending(attack):
    clock = FakeClock()
    wrong = can.Message(arbitration_id=0x600, is_extended_id=False, data=b"\x00" * 4)
    bus = ReceiveOnlyBus(clock, [(0.01, wrong), (0.02, gnss_frame(attack)),
                                 (0.05, gnss_frame(attack, -8.2, -34.2)),
                                 (0.5, gnss_frame(attack))])
    attack.listen(bus, 0.2, clock=clock)
    points = attack.locations()
    assert len(points) == 2
    assert [p.timestamp for p in points] == pytest.approx([0.03, 0.08])
    assert points[-1].latitude == pytest.approx(-8.2)
    assert points[-1].longitude == pytest.approx(-34.2)
    assert attack.observation_seconds == pytest.approx(0.2)
    bus.send.assert_not_called()


def test_empty_bus_observation_is_bounded(attack):
    clock = FakeClock()
    bus = ReceiveOnlyBus(clock)
    attack.listen(bus, 0.35, clock=clock)
    assert clock.now == pytest.approx(0.35)
    assert not attack.locations()
    bus.send.assert_not_called()


@pytest.mark.parametrize("duration", [0, -1, float("nan"), float("inf")])
def test_invalid_durations_are_rejected(attack, duration):
    with pytest.raises(ValueError, match="duration"):
        attack.listen(MagicMock(), duration)


def test_csv_columns_and_coordinate_precision(attack, tmp_path):
    attack.store_location(privacy.CapturedLocation(0.123456, -8.1234567, -34.1234567))
    path = attack.export_csv(str(tmp_path / "results" / "trip.csv"))
    with path.open(newline="") as stream:
        reader = csv.DictReader(stream)
        rows = list(reader)
        assert reader.fieldnames == ["timestamp", "latitude", "longitude"]
    assert rows == [{"timestamp": "0.123456", "latitude": "-8.1234567", "longitude": "-34.1234567"}]
    snapshot = attack.locations()
    snapshot.clear()
    assert len(attack.locations()) == 1


def test_empty_csv_has_header(attack, tmp_path):
    path = attack.export_csv(str(tmp_path / "empty.csv"))
    assert path.read_text().strip() == "timestamp,latitude,longitude"


@pytest.mark.parametrize("failure", [KeyboardInterrupt, can.CanOperationError])
def test_interrupt_or_receive_error_exports_partial_capture(monkeypatch, tmp_path, failure):
    def listen(self, bus, duration, **kwargs):
        self.store_location(privacy.CapturedLocation(0.1, -8, -34))
        raise failure()
    monkeypatch.setattr(privacy.PrivacyLeakageAttack, "listen", listen)
    path = tmp_path / "partial.csv"
    bus = MagicMock()
    if failure is KeyboardInterrupt:
        points = privacy.run_privacy_leakage_attack(bus, "vcan0", "data/carla.dbc", 30, str(path), output=lambda _: None)
        assert len(points) == 1
    else:
        with pytest.raises(can.CanOperationError):
            privacy.run_privacy_leakage_attack(bus, "vcan0", "data/carla.dbc", 30, str(path), output=lambda _: None)
    assert len(path.read_text().splitlines()) == 2
    bus.send.assert_not_called()


@pytest.mark.parametrize("kind", ["vcan", "can"])
def test_interface_device_type_is_verified(monkeypatch, kind):
    result = SimpleNamespace(returncode=0, stdout=json.dumps([{"linkinfo": {"info_kind": kind}}]))
    monkeypatch.setattr(privacy.subprocess, "run", MagicMock(return_value=result))
    if kind == "vcan":
        privacy.validate_virtual_interface("vcan0")
    else:
        with pytest.raises(ValueError, match="physical CAN"):
            privacy.validate_virtual_interface("vcan0")


@pytest.mark.parametrize("interface", ["can0", "vcan2", "usbcan0"])
def test_physical_or_other_interface_names_are_rejected(interface):
    with pytest.raises(ValueError, match="restricted"):
        privacy.validate_virtual_interface(interface)


def test_plot_uses_longitude_x_latitude_y(tmp_path, monkeypatch):
    monkeypatch.setenv("MPLCONFIGDIR", str(tmp_path / "mpl"))
    import matplotlib
    matplotlib.use("Agg", force=True)
    plot = privacy.LiveRoutePlot(interactive=False)
    try:
        plot.update_plot([privacy.CapturedLocation(0, -8, -34), privacy.CapturedLocation(1, -8.1, -34.2)])
        assert list(plot.route.get_xdata()) == [-34, -34.2]
        assert list(plot.route.get_ydata()) == [-8, -8.1]
        plot.figure.savefig(tmp_path / "route.png")
        assert (tmp_path / "route.png").stat().st_size > 0
    finally:
        plot.close()


def test_cli_dispatches_privacy_to_receive_only_path(monkeypatch):
    monkeypatch.setattr("sys.argv", ["cyberattacks_module.py", "--feature", "privacy_leakage", "--duration", "30", "--plot"])
    validate = MagicMock()
    monkeypatch.setattr(cli, "validate_virtual_interface", validate)
    run = MagicMock()
    monkeypatch.setattr(cli, "run_privacy_leakage_attack", run)
    bus = MagicMock()
    factory = MagicMock(return_value=bus)
    monkeypatch.setattr(cli.can.interface, "Bus", factory)
    assert cli.main() == 0
    validate.assert_called_once_with("vcan0")
    factory.assert_called_once_with(channel="vcan0", interface="socketcan")
    assert run.call_args.kwargs["duration"] == 30
    assert run.call_args.kwargs["plot"] is True
    bus.send.assert_not_called()
    bus.shutdown.assert_called_once()


def test_live_plot_and_capture_use_separate_threads_and_export(monkeypatch, tmp_path):
    main_thread = threading.get_ident()
    draw_started = threading.Event()
    capture_finished = threading.Event()
    capture_threads = []
    plot_threads = []

    def listen(self, bus, duration, **kwargs):
        capture_threads.append(threading.get_ident())
        assert draw_started.wait(timeout=2)
        point = privacy.CapturedLocation(0.1, -8, -34)
        self.store_location(point)
        kwargs["on_location"](point)
        capture_finished.set()

    class FakePlot:
        def __init__(self):
            self.plt = SimpleNamespace(pause=lambda _: capture_finished.wait(timeout=2))
            self.figure = SimpleNamespace(savefig=lambda path: path.write_bytes(b"test figure"))

        def is_open(self):
            return True

        def update_plot(self, points):
            plot_threads.append(threading.get_ident())
            draw_started.set()

        def close(self):
            pass

    monkeypatch.setattr(privacy.PrivacyLeakageAttack, "listen", listen)
    monkeypatch.setattr(privacy, "LiveRoutePlot", FakePlot)
    bus = MagicMock()
    points = privacy.run_privacy_leakage_attack(
        bus, "vcan0", "data/carla.dbc", 30, str(tmp_path / "trip.csv"), True,
        output=lambda _: None,
    )
    assert len(points) == 1
    assert capture_threads[0] != main_thread
    assert plot_threads and all(thread_id == main_thread for thread_id in plot_threads)
    assert (tmp_path / "trip.csv").exists()
    assert (tmp_path / "trip_route.png").exists()
    bus.send.assert_not_called()


@pytest.mark.parametrize("feature,runner,arguments", [
    ("replay", "run_replay_attack", ["--can-id", "0x602"]),
    ("fabrication", "run_fabrication_attack", ["--message", "STEER", "--value", "255"]),
    ("fuzzy", "fuzzy_attack_func", []),
    ("denial_of_service", "denial_of_service_func", []),
    ("hand_brake", "spoofing_attacks_func", []),
])
def test_existing_attack_dispatch_and_default_interface_are_preserved(monkeypatch, feature, runner, arguments):
    if runner == "spoofing_attacks_func":
        feature = next(iter(cli.FEATURE_CAN_ID_PAYLOAD_MAPPER))
    monkeypatch.setattr("sys.argv", ["cyberattacks_module.py", "--feature", feature] + arguments)
    run = MagicMock()
    monkeypatch.setattr(cli, runner, run)
    bus = MagicMock()
    factory = MagicMock(return_value=bus)
    monkeypatch.setattr(cli.can.interface, "Bus", factory)
    validate = MagicMock()
    monkeypatch.setattr(cli, "validate_virtual_interface", validate)
    assert cli.main() == 0
    factory.assert_called_once_with(channel="vcan1", interface="socketcan")
    run.assert_called_once()
    validate.assert_not_called()
    bus.shutdown.assert_called_once()
