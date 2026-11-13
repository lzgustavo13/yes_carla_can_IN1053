#!/usr/bin/env python3
"""Virtual CAN security gateway CLI; see README.md for execution and recovery."""

import argparse
from contextlib import ExitStack
from pathlib import Path
import signal
import select
import sys
import time

import can

from defense.can_gateway import DecisionLog, GatewayPolicy, SecurityGateway
from defense.gateway_topology import GatewayTopology, ROUTES, topology_lock, validate_virtual_interfaces

ROOT = Path(__file__).resolve().parent


def positive(value):
    try:
        return GatewayPolicy._positive(float(value))
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def run(args):
    topology = GatewayTopology(args.state)
    with topology_lock(args.state):
        if args.restore:
            changed = topology.restore()
            print("Original can-gw routes restored." if changed else "No recovery journal.")
            return 0
        policy = GatewayPolicy.load(args.dbc, args.policy)
        validate_virtual_interfaces()
        if args.passive and args.mode != "MONITOR":
            raise ValueError("--passive requires MONITOR")
        if args.passive and (topology.path.exists() or set(topology.current()) != set(ROUTES)):
            raise ValueError("Passive experiments require the original can-gw routes; restore first")
        stopped = False

        def stop(signum, frame):
            nonlocal stopped
            stopped = True

        with ExitStack() as stack:
            for signum in (signal.SIGINT, signal.SIGTERM):
                previous = signal.signal(signum, stop)
                stack.callback(signal.signal, signum, previous)
            log = DecisionLog(args.log)
            stack.callback(log.close)
            gateway = SecurityGateway(policy, args.mode, log)
            try:
                if not args.passive:
                    topology.activate()
                # Bind only after kernel routes are removed: no pre-activation
                # forwarded frames remain queued for duplicate forwarding.
                with ExitStack() as buses_stack:
                    channels = ("vcan0",) if args.passive else ("vcan0", "vcan1")
                    buses = {}
                    for channel in channels:
                        bus = can.Bus(interface="socketcan", channel=channel,
                                      receive_own_messages=False, local_loopback=True,
                                      ignore_config=True)
                        buses_stack.callback(bus.shutdown)
                        buses[channel] = bus
                    print(f"READY mode={args.mode} passive={args.passive} log={args.log}", flush=True)
                    started = last_stats = last_audit = time.monotonic()
                    while not stopped and (args.duration is None or time.monotonic() - started < args.duration):
                        now = time.monotonic()
                        if not args.passive and now - last_audit >= 0.5:
                            topology.assert_isolated()
                            last_audit = now
                        # Bounded fair polling; flooding one side cannot starve
                        # telemetry in the other direction or signal handling.
                        ready, _, _ = select.select(list(buses.values()), [], [], 0.05)
                        for source, bus in buses.items():
                            if bus not in ready:
                                continue
                            frame = bus.recv(timeout=0)
                            if frame is not None:
                                destination = None if args.passive else buses["vcan1" if source == "vcan0" else "vcan0"]
                                gateway.process(frame, source, destination)
                        if now - last_stats >= 1:
                            print(gateway.summary(), flush=True)
                            last_stats = now
                # Sockets are closed before restoring can-gw; no overlap.
                if not args.passive:
                    topology.restore()
            finally:
                print(gateway.summary(), flush=True)
        return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("MONITOR", "PROTECT"), default="MONITOR")
    parser.add_argument("--dbc", type=Path, default=ROOT / "data/carla.dbc")
    parser.add_argument("--policy", type=Path, default=ROOT / "data/can_gateway_policy.json")
    parser.add_argument("--log", type=Path, default=ROOT / "results/can_gateway.csv")
    parser.add_argument("--state", type=Path, default=ROOT / "results/can_gateway_state.json")
    parser.add_argument("--duration", type=positive, help="Stop cleanly after N seconds")
    parser.add_argument("--passive", action="store_true", help="Observe vcan0 without changing routes or forwarding")
    parser.add_argument("--restore", action="store_true", help="Recover original routes after a failed/abrupt run")
    args = parser.parse_args(argv)
    try:
        return run(args)
    except (Exception, KeyboardInterrupt) as exc:
        print(f"Gateway stopped: {exc}\nIf a recovery journal exists, forwarding remains disabled. "
              f"Stop attacks, then run --restore with --state {args.state}.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
