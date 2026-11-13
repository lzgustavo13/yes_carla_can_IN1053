#!/usr/bin/env python3
"""Compare measured gateway decisions from experiment directories."""

import argparse
import csv
import json
from pathlib import Path


def summarize(path, source=None):
    counts = dict(analyzed=0, allowed=0, blocked=0, alerts=0, forwarded=0, send_errors=0)
    with Path(path).open(newline="", encoding="utf-8") as stream:
        for row in csv.DictReader(stream):
            if source is not None and row["source"] != source:
                continue
            counts["analyzed"] += 1
            counts["allowed"] += row["action"] == "ALLOW"
            counts["blocked"] += row["action"] == "BLOCK"
            counts["alerts"] += bool(row["reasons"])
            counts["forwarded"] += int(row["forwarded"])
            counts["send_errors"] += row["action"] == "SEND_ERROR"
    return counts


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("runs", nargs="+", type=Path)
    parser.add_argument("--output", type=Path, default=Path("results/can_defense/comparison.png"))
    parser.add_argument("--source", choices=("vcan0", "vcan1"), help="Filter by receiving segment")
    args = parser.parse_args(argv)
    for path in args.runs:
        if not (path / "decisions.csv").is_file():
            parser.error(f"Missing decisions.csv in {path}; run the experiment before generating its report")
    import matplotlib
    matplotlib.use("Agg")
    from matplotlib import pyplot as plt
    summaries = {path.name: summarize(path / "decisions.csv", args.source) for path in args.runs}
    synthetic = any((path / "experiment.json").exists()
                    and json.loads((path / "experiment.json").read_text()).get("synthetic", False)
                    for path in args.runs)
    labels = list(summaries)
    allowed = [row["allowed"] for row in summaries.values()]
    blocked = [row["blocked"] for row in summaries.values()]
    fig, axis = plt.subplots(figsize=(9, 4))
    axis.bar(labels, allowed, label="Permitidas / observadas", color="#25816b")
    axis.bar(labels, blocked, bottom=allowed, label="Bloqueadas", color="#c24545")
    axis.set_ylabel("Quadros")
    title = "Demonstração sintética — python-can VirtualBus" if synthetic else "Decisões CAN"
    axis.set_title(title + (f" — origem {args.source}" if args.source else ""))
    for index, (permitted, rejected) in enumerate(zip(allowed, blocked)):
        if permitted:
            axis.text(index, permitted / 2, str(permitted), ha="center", va="center", color="white")
        if rejected:
            axis.text(index, permitted + rejected / 2, str(rejected), ha="center", va="center", color="white")
    axis.legend()
    fig.tight_layout()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(args.output, dpi=160)
    plt.close(fig)
    args.output.with_suffix(".json").write_text(json.dumps(summaries, indent=2) + "\n")
    print(json.dumps(summaries, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
