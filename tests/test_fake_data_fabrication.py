"""Unit tests for DBC-driven fake data fabrication."""

import cantools
import pytest

from attacks.fake_data_fabrication import (
    build_fabricated_frame,
    inject_periodically,
)


class FakeClock:
    def __init__(self):
        self.now = 0.0

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


class RecordingBus:
    def __init__(self, clock):
        self.clock = clock
        self.sent = []

    def send(self, message):
        self.sent.append((self.clock.now, message))


@pytest.mark.parametrize(
    "message_name,signal_name,value,expected_id",
    [
        ("STEER", "STEER_signal", 255, 0x602),
        ("THROTTLE", "THROTTLE_signal", 200, 0x600),
        ("BRAKE", "BRAKE_signal", 128, 0x601),
    ],
)
def test_fabrication_uses_dbc_for_id_and_payload(
    message_name, signal_name, value, expected_id
):
    fabricated = build_fabricated_frame(
        "data/carla.dbc",
        value,
        message_name=message_name,
        signal_name=signal_name,
    )
    database = cantools.database.load_file("data/carla.dbc")
    decoded = database.decode_message(
        fabricated.message.arbitration_id,
        fabricated.message.data,
    )

    assert fabricated.message.arbitration_id == expected_id
    assert decoded[signal_name] == value


def test_signal_alone_resolves_its_message():
    fabricated = build_fabricated_frame(
        "data/carla.dbc",
        0,
        signal_name="STEER_signal",
    )
    assert fabricated.message_name == "STEER"
    assert fabricated.message.arbitration_id == 0x602


@pytest.mark.parametrize("value", [-1, 256])
def test_fabrication_rejects_value_outside_dbc_range(value):
    with pytest.raises(ValueError, match="minimum|maximum"):
        build_fabricated_frame(
            "data/carla.dbc",
            value,
            message_name="STEER",
        )


def test_fabrication_rejects_unknown_signal():
    with pytest.raises(ValueError, match="not found"):
        build_fabricated_frame(
            "data/carla.dbc",
            1,
            signal_name="NOT_A_SIGNAL",
        )


def test_fabrication_rejects_mismatched_message_and_signal():
    with pytest.raises(ValueError, match="does not belong"):
        build_fabricated_frame(
            "data/carla.dbc",
            1,
            message_name="BRAKE",
            signal_name="STEER_signal",
        )


def test_periodic_injection_uses_configured_schedule():
    fabricated = build_fabricated_frame(
        "data/carla.dbc",
        255,
        message_name="STEER",
    )
    clock = FakeClock()
    bus = RecordingBus(clock)

    sent = inject_periodically(
        bus,
        fabricated,
        period=0.1,
        duration=0.26,
        clock=clock.monotonic,
        sleep=clock.sleep,
    )

    assert sent == 3
    assert [timestamp for timestamp, _ in bus.sent] == pytest.approx([0.0, 0.1, 0.2])
    assert all(message.arbitration_id == 0x602 for _, message in bus.sent)
