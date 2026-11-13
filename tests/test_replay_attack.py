"""Unit tests for capture filtering and timing-preserving CAN replay."""

import can
import pytest

from attacks.replay_attack import CapturedCANFrame, capture_frames, replay_frames


class FakeClock:
    """Deterministic monotonic clock shared by fake receive/send buses."""

    def __init__(self, initial=0.0):
        self.now = initial
        self.sleep_calls = []

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.sleep_calls.append(seconds)
        self.now += seconds


class TimedReceiveBus:
    """Return queued messages after their configured receive delays."""

    def __init__(self, clock, events):
        self.clock = clock
        self.events = list(events)

    def recv(self, timeout):
        if not self.events:
            self.clock.now += timeout
            return None
        delay, message = self.events[0]
        if delay > timeout:
            self.events[0] = (delay - timeout, message)
            self.clock.now += timeout
            return None
        self.events.pop(0)
        self.clock.now += delay
        return message


class RecordingSendBus:
    def __init__(self, clock):
        self.clock = clock
        self.sent = []

    def send(self, message):
        self.sent.append((self.clock.now, message))


def test_capture_filters_id_and_preserves_order_data_and_relative_time():
    clock = FakeClock()
    wrong_id = can.Message(arbitration_id=0x601, data=[0xAA])
    first = can.Message(arbitration_id=0x602, data=[0x10, 0, 0, 0])
    second = can.Message(arbitration_id=0x602, data=[0x20, 0, 0, 0])
    bus = TimedReceiveBus(
        clock,
        [(0.02, wrong_id), (0.08, first), (0.12, second)],
    )

    captured = capture_frames(bus, 0x602, 0.4, clock=clock.monotonic)

    assert [frame.arbitration_id for frame in captured] == [0x602, 0x602]
    assert [frame.data for frame in captured] == [bytes(first.data), bytes(second.data)]
    assert [frame.dlc for frame in captured] == [4, 4]
    assert [frame.timestamp for frame in captured] == pytest.approx([0.0, 0.12])


def test_replay_retransmits_frames_in_order_at_original_relative_times():
    clock = FakeClock(initial=10.0)
    bus = RecordingSendBus(clock)
    frames = [
        CapturedCANFrame(0.0, 0x602, 1, b"\x10"),
        CapturedCANFrame(0.1, 0x602, 1, b"\x20"),
        CapturedCANFrame(0.25, 0x602, 1, b"\x30"),
    ]

    sent = replay_frames(
        bus,
        frames,
        clock=clock.monotonic,
        sleep=clock.sleep,
    )

    assert sent == 3
    assert [bytes(message.data) for _, message in bus.sent] == [b"\x10", b"\x20", b"\x30"]
    relative_send_times = [timestamp - bus.sent[0][0] for timestamp, _ in bus.sent]
    assert relative_send_times == pytest.approx([0.0, 0.1, 0.25])


def test_replay_can_repeat_the_same_sequence():
    clock = FakeClock()
    bus = RecordingSendBus(clock)
    frames = [
        CapturedCANFrame(0.0, 0x602, 1, b"\x01"),
        CapturedCANFrame(0.05, 0x602, 1, b"\x02"),
    ]

    sent = replay_frames(
        bus,
        frames,
        repetitions=3,
        clock=clock.monotonic,
        sleep=clock.sleep,
    )

    assert sent == 6
    assert [bytes(message.data) for _, message in bus.sent] == [
        b"\x01", b"\x02", b"\x01", b"\x02", b"\x01", b"\x02"
    ]


def test_empty_capture_replays_nothing():
    clock = FakeClock()
    bus = RecordingSendBus(clock)
    assert replay_frames(bus, [], clock=clock.monotonic, sleep=clock.sleep) == 0
    assert bus.sent == []
