#!/usr/bin/env python3
"""Deterministic python-can VirtualBus demonstration, WITHOUT CARLA/SocketCAN.

Uses the existing spoofing function with a simulated clock. This produces
synthetic evidence only; it does not validate kernel can-gw or vehicle motion.
"""

import argparse
import json
from pathlib import Path
import sys
from types import SimpleNamespace
from unittest.mock import patch
import uuid

import can

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import cyberattacks_module as attacks  # noqa: E402
from defense.can_gateway import DecisionLog, GatewayPolicy, SecurityGateway  # noqa: E402


def simulate(scenario, output):
    output.mkdir(parents=True, exist_ok=False)
    unique = str(uuid.uuid4())
    buses = [can.Bus(interface="virtual", channel=unique + channel, receive_own_messages=False)
             for channel in ("0", "0", "1", "1", "0")]
    controls, trusted, attacker, untrusted, vehicle = buses
    log = DecisionLog(output / "decisions.csv")
    clock = [0.0]
    mode = "PROTECT" if scenario == "protect" else "MONITOR"
    policy = GatewayPolicy.load(ROOT / "data/carla.dbc", ROOT / "data/can_gateway_policy.json")
    gateway = SecurityGateway(policy, mode, log, clock=lambda: clock[0], output=lambda _: None)
    injected = received_attack = legitimate_received = 0

    def drain_vehicle():
        nonlocal received_attack, legitimate_received
        while True:
            message = vehicle.recv(0)
            if message is None:
                break
            if message.arbitration_id == 0x604 and bytes(message.data) == b"\x01":
                received_attack += 1
            else:
                legitimate_received += 1

    def tick(now):
        clock[0] = now
        controls.send(can.Message(arbitration_id=0x604, data=[0], is_extended_id=False))
        message = trusted.recv(.1)
        gateway.process(message, "vcan0", None if scenario in {"normal", "unprotected"} else untrusted)
        while attacker.recv(0) is not None:
            pass
        drain_vehicle()

    class Inject:
        def send(self, message):
            nonlocal injected
            injected += 1
            attacker.send(message)
            message = untrusted.recv(.1)
            if scenario == "unprotected":
                # Emulate the original kernel bridge, then passively observe.
                trusted.send(message)
                gateway.process(message, "vcan0")
            else:
                gateway.process(message, "vcan1", trusted)
            drain_vehicle()

    class EndAttack(Exception):
        pass

    def advance(seconds):
        clock[0] = round(clock[0] + seconds, 6)
        if round(clock[0] * 100) % 20 == 0:
            tick(clock[0])
        if clock[0] >= 4:
            raise EndAttack

    try:
        for step in range(10):
            tick(step * .2)
        tick(2.0)
        if scenario != "normal":
            simulated_time = SimpleNamespace(monotonic=lambda: clock[0], sleep=advance)
            with patch.object(attacks, "time", simulated_time), patch.object(attacks, "_print_status"):
                try:
                    attacks.spoofing_attacks_func(Inject(), "hand_brake", .02)
                except EndAttack:
                    pass
        else:
            for step in range(11, 21):
                tick(step * .2)
        for step in range(21, 31):
            tick(step * .2)
        drain_vehicle()
        assert received_attack == (0 if scenario in {"normal", "protect"} else injected)
        assert legitimate_received == 31
        metadata = {"synthetic": True, "transport": "python-can VirtualBus",
                    "scenario": scenario, "injected": injected,
                    "attack_frames_at_vehicle": received_attack,
                    "legitimate_frames_at_vehicle": legitimate_received,
                    "vehicle_motion": "NOT_VALIDATED", "statistics": json.loads(gateway.summary())}
        (output / "experiment.json").write_text(json.dumps(metadata, indent=2) + "\n")
        return metadata
    finally:
        log.close()
        for bus in buses:
            bus.shutdown()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    if args.output.exists():
        parser.error(f"Output already exists: {args.output}. Choose a new directory to preserve previous evidence.")
    for scenario in ("normal", "unprotected", "monitor", "protect"):
        print(json.dumps(simulate(scenario, args.output / scenario)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
