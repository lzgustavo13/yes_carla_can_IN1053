"""Pure DBC policies, bounded temporal detection and auditable forwarding.

The source is the receiving interface, never an authenticated ECU identity.
No SocketCAN, CARLA or privileged setup is needed to exercise this module.
"""

from collections import deque
from dataclasses import asdict, dataclass
import csv
import json
import math
import time

from can_network.dbc import load_and_validate


@dataclass(frozen=True)
class Decision:
    source: str
    can_id: int
    message_name: str
    allowed: bool
    reasons: tuple
    window_count: int
    window_limit: int


@dataclass
class Statistics:
    analyzed: int = 0
    allowed: int = 0
    blocked: int = 0
    alerts: int = 0
    forwarded: int = 0
    send_errors: int = 0


class GatewayPolicy:
    """Validate policy once; count attempted traffic in a sliding window.

    Limit = ceil(window / period * multiplier) + burst. The extra burst
    tolerates window boundary jitter; multiplier tolerates scheduler bursts.
    Counts saturate at limit+1, bounding memory even during a flood.
    """

    def __init__(self, dbc_path, config):
        self.database, _ = load_and_validate(dbc_path)
        self.messages = {(m.frame_id, m.is_extended_frame): m for m in self.database.messages}
        names = {m.name for m in self.database.messages}
        if set(config) != {"window_seconds", "rate_multiplier", "burst_allowance",
                           "period_overrides_ms", "segments"}:
            raise ValueError("Invalid policy keys")
        self.window = self._positive(config["window_seconds"])
        self.multiplier = self._positive(config["rate_multiplier"])
        if self.multiplier < 1:
            raise ValueError("rate_multiplier must be >= 1")
        self.burst = config["burst_allowance"]
        if type(self.burst) is not int or self.burst < 0:
            raise ValueError("burst_allowance must be a nonnegative integer")
        overrides = config["period_overrides_ms"]
        if not isinstance(overrides, dict) or set(overrides) - names:
            raise ValueError("Period overrides must reference DBC message names")
        self.periods = {}
        for m in self.database.messages:
            period = self._positive(overrides[m.name]) if m.name in overrides else m.cycle_time
            if period:
                self.periods[m.name] = period / 1000
        self.segments = config["segments"]
        if set(self.segments) != {"vcan0", "vcan1"}:
            raise ValueError("Policies must describe vcan0 and vcan1")
        for segment in self.segments.values():
            if set(segment) != {"allow", "deny", "check_frequency"}:
                raise ValueError("Invalid segment policy keys")
            allow, deny = segment["allow"], segment["deny"]
            if allow != "dbc" and (not isinstance(allow, list) or set(allow) - names):
                raise ValueError("allow must be 'dbc' or a list of DBC names")
            if not isinstance(deny, list) or set(deny) - names:
                raise ValueError("deny must list DBC names")
            if type(segment["check_frequency"]) is not bool:
                raise ValueError("check_frequency must be boolean")
        self.windows = {}
        self.last_time = None

    @staticmethod
    def _positive(value):
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError("Expected a finite positive number")
        if not math.isfinite(value) or value <= 0:
            raise ValueError("Expected a finite positive number")
        return float(value)

    @classmethod
    def load(cls, dbc_path, policy_path):
        with open(policy_path, encoding="utf-8") as stream:
            return cls(dbc_path, json.load(stream))

    def inspect(self, frame, source, now):
        if source not in self.segments:
            raise ValueError("Unknown source segment")
        if not math.isfinite(now) or (self.last_time is not None and now < self.last_time):
            raise ValueError("Use a monotonic clock")
        self.last_time = now
        segment = self.segments[source]
        message = self.messages.get((frame.arbitration_id, frame.is_extended_id))
        reasons = []
        count = limit = 0
        if message is None:
            reasons.append("unknown_id_or_format")
        else:
            if message.name in segment["deny"]:
                reasons.append("source_denied")
            if segment["allow"] != "dbc" and message.name not in segment["allow"]:
                reasons.append("source_not_allowlisted")
            if (frame.is_remote_frame or frame.is_error_frame or frame.is_fd
                    or frame.dlc != message.length or len(frame.data) != message.length):
                reasons.append("invalid_frame")
            period = self.periods.get(message.name)
            if segment["check_frequency"] and period:
                limit = math.ceil(self.window / period * self.multiplier) + self.burst
                key = (source, frame.arbitration_id, frame.is_extended_id)
                timestamps = self.windows.setdefault(key, deque(maxlen=limit + 1))
                while timestamps and timestamps[0] <= now - self.window:
                    timestamps.popleft()
                timestamps.append(now)
                count = len(timestamps)
                if count > limit:
                    reasons.append("frequency_exceeded")
        return Decision(source, frame.arbitration_id, message.name if message else "UNKNOWN",
                        not reasons, tuple(reasons), count, limit)


class DecisionLog:
    FIELDS = ("timestamp", "mode", "source", "can_id", "message_name", "data", "dlc",
              "action", "forwarded", "reasons", "window_count", "window_limit",
              "analyzed", "allowed", "blocked", "alerts", "forwarded_total", "send_errors")

    def __init__(self, path):
        # Never truncate previous experiment evidence.
        self.stream = open(path, "x", newline="", encoding="utf-8")
        self.writer = csv.DictWriter(self.stream, fieldnames=self.FIELDS)
        self.writer.writeheader()
        self.stream.flush()

    def write(self, mode, frame, decision, action, forwarded, stats, extra=""):
        row = dict(timestamp=time.time(), mode=mode, source=decision.source,
                   can_id=f"0x{decision.can_id:X}", message_name=decision.message_name,
                   data=bytes(frame.data).hex(), dlc=frame.dlc, action=action,
                   forwarded=int(forwarded), reasons=";".join((*decision.reasons, extra)).strip(";"),
                   window_count=decision.window_count, window_limit=decision.window_limit)
        row.update({key: value for key, value in asdict(stats).items()
                    if key in self.FIELDS and key != "forwarded"})
        row["forwarded_total"] = stats.forwarded
        self.writer.writerow(row)
        self.stream.flush()

    def close(self):
        self.stream.close()


class SecurityGateway:
    def __init__(self, policy, mode, log, clock=time.monotonic, output=print):
        if mode not in {"MONITOR", "PROTECT"}:
            raise ValueError("Mode must be MONITOR or PROTECT")
        self.policy, self.mode, self.log = policy, mode, log
        self.clock, self.output = clock, output
        self.stats = Statistics()

    def process(self, frame, source, destination=None):
        """Apply a decision and send once. None destination means passive capture."""
        decision = self.policy.inspect(frame, source, self.clock())
        stats = self.stats
        stats.analyzed += 1
        stats.alerts += bool(decision.reasons)
        permitted = decision.allowed or self.mode == "MONITOR"
        stats.allowed += permitted
        stats.blocked += not permitted
        action = "ALLOW" if permitted else "BLOCK"
        forwarded = False
        try:
            if permitted and destination is not None:
                # Same bus object is also the destination receive socket; its
                # receive_own_messages=False prevents feedback in either direction.
                destination.send(frame, timeout=0.1)
                forwarded = True
                stats.forwarded += 1
        except Exception:
            stats.send_errors += 1
            self.log.write(self.mode, frame, decision, "SEND_ERROR", False, stats, "send_failed")
            self.output(f"SEND_ERROR source={source} ID=0x{decision.can_id:X}")
            raise
        self.log.write(self.mode, frame, decision, action, forwarded, stats)
        if decision.reasons:
            self.output(f"{action} source={source} ID=0x{decision.can_id:X} "
                        f"reason={';'.join(decision.reasons)} "
                        f"window={decision.window_count}/{decision.window_limit}")
        return decision

    def summary(self):
        return json.dumps(asdict(self.stats), sort_keys=True)
