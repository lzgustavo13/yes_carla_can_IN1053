"""C2: observe CAN trace + GNSS sensor data to reconstruct a simulated trip.

The CLI owns the SocketCAN connection. This module only receives frames;
it never sends, fabricates, replays, or changes vehicle controls.
"""

import csv
from dataclasses import dataclass
import json
import math
from pathlib import Path
import subprocess
import threading
import time
from typing import Callable, List, Optional

import can
import cantools

from can_network import VCAN_CHANNEL, VCAN_ATTACKER_CHANNEL
from can_network.dbc import SENSOR_MESSAGES, load_and_validate


def validate_virtual_interface(interface: str) -> None:
    """Reject physical CAN, including a device renamed to look like vcan."""
    if interface not in (VCAN_CHANNEL, VCAN_ATTACKER_CHANNEL):
        raise ValueError("Privacy leakage is restricted to vcan0/vcan1")
    result = subprocess.run(
        ["ip", "-details", "-json", "link", "show", "dev", interface],
        capture_output=True, text=True, timeout=5, check=False,
    )
    if result.returncode != 0:
        raise ValueError(f"Virtual interface {interface} is unavailable; start 1_up_environment.sh")
    links = json.loads(result.stdout)
    if not links or links[0].get("linkinfo", {}).get("info_kind") != "vcan":
        raise ValueError(f"{interface} must be a kernel vcan device; physical CAN is unsupported")


@dataclass(frozen=True)
class CapturedLocation:
    """Observed coordinates in degrees and seconds since observation began."""

    timestamp: float
    latitude: float
    longitude: float


class PrivacyLeakageAttack:
    """Separate DBC decoding, passive capture, storage, and CSV export."""

    def __init__(self, dbc_path: str):
        self.database, _ = load_and_validate(dbc_path)
        self.gnss_message = self.identify_gnss_message()
        self.latitude_signal, self.longitude_signal = SENSOR_MESSAGES["GNSS"][0]
        self._locations: List[CapturedLocation] = []
        self._lock = threading.Lock()
        self.observation_seconds = 0.0
        self.invalid_frames = 0

    def identify_gnss_message(self):
        """Resolve the existing GNSS schema; its arbitration ID comes from DBC."""
        try:
            message = self.database.get_message_by_name("GNSS")
        except KeyError as exc:
            raise ValueError("The selected DBC must contain the project's GNSS message") from exc
        expected = SENSOR_MESSAGES["GNSS"][0]
        signals = {signal.name: signal for signal in message.signals}
        if any(name not in signals or signals[name].unit != "deg" for name in expected):
            raise ValueError("GNSS must contain the project's latitude/longitude signals in deg")
        return message

    def decode_location(self, frame: can.Message, timestamp: float) -> Optional[CapturedLocation]:
        """Ignore unrelated/invalid frames and decode physical values with DBC."""
        if (frame.arbitration_id != self.gnss_message.frame_id
                or frame.is_extended_id != self.gnss_message.is_extended_frame
                or frame.is_remote_frame or frame.is_error_frame):
            return None
        try:
            if len(frame.data) != self.gnss_message.length:
                raise ValueError("Unexpected GNSS payload length")
            decoded = self.gnss_message.decode(frame.data, decode_choices=False)
            latitude = float(decoded[self.latitude_signal])
            longitude = float(decoded[self.longitude_signal])
            if (not math.isfinite(latitude) or not math.isfinite(longitude)
                    or not -90 <= latitude <= 90 or not -180 <= longitude <= 180):
                raise ValueError("Invalid geographic coordinates")
        except (cantools.database.errors.DecodeError, ValueError, KeyError):
            self.invalid_frames += 1
            return None
        return CapturedLocation(timestamp, latitude, longitude)

    def store_location(self, location: CapturedLocation) -> None:
        with self._lock:
            self._locations.append(location)

    def locations(self) -> List[CapturedLocation]:
        """Copy a consistent snapshot; plotting never holds the capture lock."""
        with self._lock:
            return list(self._locations)

    def listen(
        self, bus: can.BusABC, duration: float, *,
        stop: Optional[threading.Event] = None,
        clock: Callable[[], float] = time.monotonic,
        on_location: Optional[Callable[[CapturedLocation], None]] = None,
    ) -> None:
        """Receive until the monotonic deadline or cancellation, without sending."""
        if not math.isfinite(duration) or duration <= 0:
            raise ValueError("Capture duration must be finite and greater than zero")
        started = clock()
        deadline = started + duration
        try:
            while stop is None or not stop.is_set():
                remaining = deadline - clock()
                if remaining <= 0:
                    break
                # Short bounded waits allow shutdown even when GNSS is absent.
                frame = bus.recv(timeout=min(remaining, 0.1))
                arrival = clock()
                if arrival >= deadline:
                    break
                if frame is None:
                    continue
                location = self.decode_location(frame, arrival - started)
                if location is not None:
                    self.store_location(location)
                    if on_location is not None:
                        on_location(location)
        finally:
            self.observation_seconds = clock() - started

    def export_csv(self, output_path: str) -> Path:
        """Export coordinates in capture order, including a header for empty trips."""
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.writer(stream)
            writer.writerow(["timestamp", "latitude", "longitude"])
            for location in self.locations():
                writer.writerow([f"{location.timestamp:.6f}",
                                 f"{location.latitude:.7f}", f"{location.longitude:.7f}"])
        return path


class LiveRoutePlot:
    """Render longitude/latitude on the main thread, independently of CAN recv."""

    def __init__(self, *, interactive: bool = True):
        # Terminal-only capture does not import or require a GUI backend.
        import matplotlib.pyplot as plt

        self.plt = plt
        self.figure, self.axes = plt.subplots(layout="constrained")
        if interactive and not self.figure.canvas.required_interactive_framework:
            plt.close(self.figure)
            raise RuntimeError("--plot requires a graphical matplotlib backend; omit --plot on headless hosts")
        self.axes.set_title("Vehicle Route - Privacy Leakage Attack")
        self.axes.set_xlabel("Longitude / GNSS_LON_signal (deg)")
        self.axes.set_ylabel("Latitude / GNSS_LAT_signal (deg)")
        self.axes.ticklabel_format(useOffset=False, style="plain")
        self.axes.grid(True)
        self.route, = self.axes.plot([], [], ".-", label="Observed trajectory")
        self.current, = self.axes.plot([], [], "ro", label="Latest location")
        self.axes.legend()
        if interactive:
            plt.show(block=False)

    def update_plot(self, locations: List[CapturedLocation]) -> None:
        if locations:
            self.route.set_data([p.longitude for p in locations], [p.latitude for p in locations])
            self.current.set_data([locations[-1].longitude], [locations[-1].latitude])
            self.axes.relim()
            self.axes.autoscale_view()
        self.figure.canvas.draw_idle()

    def is_open(self) -> bool:
        return self.plt.fignum_exists(self.figure.number)

    def close(self) -> None:
        self.plt.close(self.figure)


def run_privacy_leakage_attack(
    bus: can.BusABC, interface: str, dbc_path: str, duration: float,
    output_path: str = "results/privacy_leakage_trace.csv", plot: bool = False, *,
    output: Callable[[str], None] = print,
) -> List[CapturedLocation]:
    """Run passive observation, live reporting, and export even on Ctrl+C."""
    if interface not in (VCAN_CHANNEL, VCAN_ATTACKER_CHANNEL):
        raise ValueError("Privacy leakage is restricted to vcan0/vcan1")
    if not math.isfinite(duration) or duration <= 0:
        raise ValueError("Capture duration must be finite and greater than zero")
    attack = PrivacyLeakageAttack(dbc_path)
    route_plot = LiveRoutePlot() if plot else None
    separator = "=" * 60
    output(separator)
    output("C2 - CAN Privacy Leakage Attack")
    output(separator)
    output(f"Interface : {interface}")
    output(f"Target    : {attack.gnss_message.name} (0x{attack.gnss_message.frame_id:03X})")
    output("Mode      : Passive monitoring (receive only)")
    output(f"Duration  : {duration:g} s")
    output("Listening for vehicle location...")

    def report(location: CapturedLocation) -> None:
        output(f"[LEAK] t={location.timestamp:.2f}s\n"
               f"       {attack.latitude_signal} = {location.latitude:.7f} deg\n"
               f"       {attack.longitude_signal} = {location.longitude:.7f} deg")

    stop = threading.Event()
    errors: List[Exception] = []
    worker = None

    def capture() -> None:
        try:
            attack.listen(bus, duration, stop=stop, on_location=report)
        except Exception as exc:
            errors.append(exc)

    try:
        if route_plot is None:
            capture()
        else:
            # Only the worker calls recv. All matplotlib operations stay on
            # the main thread, so drawing does not pause CAN capture.
            worker = threading.Thread(target=capture, name="privacy-leakage-capture")
            worker.start()
            while worker.is_alive() and route_plot.is_open():
                route_plot.update_plot(attack.locations())
                route_plot.plt.pause(0.1)
    except KeyboardInterrupt:
        output("\nObservation stopped by user; saving captured locations.")
    finally:
        stop.set()
        if worker is not None:
            worker.join()
        try:
            path = attack.export_csv(output_path)
            points = attack.locations()
            output(f"\nCaptured locations: {len(points)}")
            output(f"Observation duration: {attack.observation_seconds:.2f} s")
            output(f"Invalid GNSS frames ignored: {attack.invalid_frames}")
            if points:
                output(f"Initial position: {points[0].latitude:.7f}, {points[0].longitude:.7f} deg")
                output(f"Final position:   {points[-1].latitude:.7f}, {points[-1].longitude:.7f} deg")
            else:
                output("No GNSS location observed; check CARLA, the selected interface and DBC.")
            output(f"Trajectory saved to:\n{path}")
            if route_plot is not None:
                route_plot.update_plot(points)
                image_path = path.with_name(f"{path.stem}_route.png")
                route_plot.figure.savefig(image_path)
                output(f"Route image saved to:\n{image_path}")
            output("Attack finished.")
            output(separator)
        finally:
            if route_plot is not None:
                route_plot.close()
    if errors:
        raise errors[0]
    return attack.locations()
