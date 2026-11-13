#!/usr/bin/env python3
"""Record one reproducible scenario using the existing hand_brake attack.

Start CARLA separately. Run this script through sudo with the project's
Python interpreter; all interfaces are validated as kernel vcan devices.
"""

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import signal
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from defense.gateway_topology import validate_virtual_interfaces  # noqa: E402


def stop(process):
    if process is not None and process.poll() is None:
        process.send_signal(signal.SIGTERM)
        try:
            process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            raise RuntimeError("Process needed SIGKILL; check gateway recovery journal")


def existing_output(path):
    print(f"Output already exists: {path}\n"
          "Previous logs were preserved. Use a new --output directory "
          "or create a new DEMO_DIR for the four scenarios.", file=sys.stderr)
    return 2


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario", choices=("normal", "unprotected", "monitor", "protect"))
    parser.add_argument("--output", type=Path, required=True, help="New directory for this run")
    args = parser.parse_args(argv)
    if args.output.exists():
        return existing_output(args.output)
    try:
        if shutil.which("candump") is None:
            raise RuntimeError("candump not found; install can-utils before recording an experiment")
        validate_virtual_interfaces()
        args.output.mkdir(parents=True, exist_ok=False)
    except FileExistsError:
        return existing_output(args.output)
    except Exception as exc:
        print(f"Experiment setup failed: {exc}", file=sys.stderr)
        return 1
    output = args.output.resolve()
    attack_command = [sys.executable, str(ROOT / "cyberattacks_module.py"),
                      "--feature", "hand_brake", "--period", "0.02", "--vcan", "vcan1"]
    gateway_command = [sys.executable, "-u", str(ROOT / "security_gateway_module.py"),
                       "--mode", "PROTECT" if args.scenario == "protect" else "MONITOR",
                       "--log", str(output / "decisions.csv")]
    if args.scenario in {"normal", "unprotected"}:
        gateway_command.append("--passive")
    metadata = {"scenario": args.scenario, "started_utc": datetime.now(timezone.utc).isoformat(),
                "attack_command": attack_command if args.scenario != "normal" else None,
                "attack_seconds": 10, "gateway_command": gateway_command,
                "vehicle_effect": "PENDING_MANUAL_OBSERVATION", "completed": False}
    metadata_path = output / "experiment.json"
    metadata_path.write_text(json.dumps(metadata, indent=2) + "\n")
    capture = gateway = attack = None

    def interrupted(signum, frame):
        raise KeyboardInterrupt

    previous = signal.signal(signal.SIGTERM, interrupted)
    try:
        with (output / "traffic.log").open("w") as traffic, (output / "gateway.txt").open("w") as terminal, \
                (output / "attack.txt").open("w") as attack_log:
            try:
                capture = subprocess.Popen(["candump", "-L", "vcan0", "vcan1"], stdout=traffic, stderr=subprocess.STDOUT)
                gateway = subprocess.Popen(gateway_command, cwd=ROOT, stdout=terminal, stderr=subprocess.STDOUT)
                deadline = time.monotonic() + 10
                while "READY " not in (output / "gateway.txt").read_text():
                    if gateway.poll() is not None or time.monotonic() > deadline:
                        raise RuntimeError("Gateway failed to become ready; inspect gateway.txt")
                    time.sleep(.05)
                print(f"READY {args.scenario}: 3 s baseline, 10 s attack/normal, 3 s recovery.", flush=True)
                time.sleep(3)
                if args.scenario != "normal":
                    attack = subprocess.Popen(attack_command, cwd=ROOT, stdout=attack_log, stderr=subprocess.STDOUT)
                end = time.monotonic() + 10
                while time.monotonic() < end:
                    if gateway.poll() is not None or capture.poll() is not None:
                        raise RuntimeError("Gateway or candump exited during the experiment")
                    if attack is not None and attack.poll() is not None:
                        raise RuntimeError("Attack exited early; inspect attack.txt")
                    time.sleep(.1)
                stop(attack)
                time.sleep(3)
            finally:
                # Stop the attacker first; only then restore the original routes.
                try:
                    stop(attack)
                finally:
                    try:
                        stop(gateway)
                    finally:
                        stop(capture)
            if gateway.returncode != 0:
                raise RuntimeError("Gateway failed; inspect journal and gateway.txt")
        metadata["completed"] = True
        print(f"Recorded {output}. Add the observed CARLA behavior to experiment.json.")
        return 0
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        return 1
    finally:
        signal.signal(signal.SIGTERM, previous)
        metadata_path.write_text(json.dumps(metadata, indent=2) + "\n")


if __name__ == "__main__":
    sys.exit(main())
