"""Scoped can-gw replacement for the project's two virtual segments.

Only the exact pair of unmodified echo routes created by 1_up_environment.sh
is supported. Other rules touching either interface cause a refusal; rules
between unrelated interfaces are never changed. Commands never use a shell.
"""

from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import shlex
import subprocess

from can_network.constants import VCAN_CHANNEL, VCAN_ATTACKER_CHANNEL

INTERFACES = (VCAN_CHANNEL, VCAN_ATTACKER_CHANNEL)
ROUTES = (("-A", "-s", "vcan1", "-d", "vcan0", "-e"),
          ("-A", "-s", "vcan0", "-d", "vcan1", "-e"))


def command(args):
    result = subprocess.run(args, check=False, capture_output=True, text=True, timeout=5)
    # can-utils v2023.03 leaves err equal to sendto's request length (36)
    # after a successful LIST. Accept only that specific read-only command
    # and status, with no stderr and a completely parseable route listing.
    # NLMSG_ERROR on stdout must never be mistaken for an empty topology.
    legacy_list = args == ["cangw", "-L"] and result.returncode == 36 and not result.stderr.strip()
    if legacy_list:
        parse_routes(result.stdout)
    elif result.returncode or result.stderr.strip():
        details = "\n".join(part.strip() for part in (result.stderr, result.stdout) if part.strip())
        raise RuntimeError(f"{shlex.join(args)} failed (exit {result.returncode}): "
                           f"{details or 'no diagnostic output'}")
    return result.stdout


def validate_virtual_interfaces(run=command):
    for name in INTERFACES:
        links = json.loads(run(["ip", "-details", "-json", "link", "show", "dev", name]))
        if (len(links) != 1 or links[0].get("ifname") != name
                or links[0].get("linkinfo", {}).get("info_kind") != "vcan"
                or "UP" not in links[0].get("flags", [])):
            raise ValueError(f"{name} must be an UP kernel vcan interface")


def parse_routes(listing):
    routes = []
    for line in listing.splitlines():
        args = shlex.split(line, comments=True)
        if not args:
            continue
        if Path(args[0]).name != "cangw" or args[1:2] != ["-A"]:
            raise ValueError(f"Unrecognized cangw output: {line}")
        args = tuple(args[1:])
        if args.count("-s") != 1 or args.count("-d") != 1:
            raise ValueError("Missing can-gw route endpoints")
        # Ensure malformed listings are never treated as an empty topology.
        try:
            args[args.index("-s") + 1], args[args.index("-d") + 1]
        except IndexError as exc:
            raise ValueError("Missing can-gw interface name") from exc
        routes.append(args)
    return routes


def scoped_routes(routes):
    selected = []
    for args in routes:
        source, destination = args[args.index("-s") + 1], args[args.index("-d") + 1]
        if source in INTERFACES or destination in INTERFACES:
            if args not in ROUTES:
                raise ValueError("Unsupported route touching vcan0/vcan1; no rules changed")
            selected.append(args)
    if len(set(selected)) != len(selected):
        raise ValueError("Duplicate lab routes; no rules changed")
    return selected


@contextmanager
def topology_lock(state_path):
    """Lock across run/restore; keep the lock inode stable after release."""
    fd = os.open(str(state_path) + ".lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeError("Gateway is running; stop it before restoring") from exc
        yield
    finally:
        os.close(fd)


class GatewayTopology:
    def __init__(self, state_path, run=command):
        self.path = Path(state_path)
        self.run = run

    def current(self):
        return scoped_routes(parse_routes(self.run(["cangw", "-L"])))

    def activate(self):
        validate_virtual_interfaces(self.run)
        if self.path.exists():
            raise RuntimeError("Recovery journal exists; run --restore first")
        before = self.current()
        if set(before) != set(ROUTES):
            raise ValueError("Expected the original two can-gw echo routes; no rules changed")
        # Durable write-ahead journal: restore compares actual rules, so a crash
        # before/after either deletion is recoverable without adding duplicates.
        journal = {"version": 1, "netns": os.stat("/proc/self/ns/net").st_ino,
                   "routes": [list(route) for route in before]}
        fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(journal, stream)
            stream.flush()
            os.fsync(stream.fileno())
        for route in before:
            self.run(["cangw", "-D", *route[1:]])
        self.assert_isolated()

    def assert_isolated(self):
        if self.current():
            raise RuntimeError("Direct can-gw route detected; gateway stopped")

    def restore(self):
        validate_virtual_interfaces(self.run)
        if not self.path.exists():
            return False
        with self.path.open(encoding="utf-8") as stream:
            journal = json.load(stream)
        # Never execute arguments from a journal without checking the exact
        # supported topology, even when restore is invoked through sudo.
        if (set(journal) != {"version", "netns", "routes"} or journal["version"] != 1
                or journal["netns"] != os.stat("/proc/self/ns/net").st_ino
                or len(journal["routes"]) != 2
                or {tuple(r) for r in journal["routes"]} != set(ROUTES)):
            raise ValueError("Invalid recovery journal or different network namespace")
        current = self.current()
        for route in ROUTES:
            if route not in current:
                self.run(["cangw", *route])
        if set(self.current()) != set(ROUTES):
            raise RuntimeError("Restoration incomplete; journal retained")
        self.path.unlink()
        return True
