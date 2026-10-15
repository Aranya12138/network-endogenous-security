#!/usr/bin/env python3
"""Convert read-counters.py output into a simple three-mode health report."""

import argparse
import re
import sys


def evaluate(line):
    switch = line.split(maxsplit=1)[0]
    values = {key: int(value) for key, value in re.findall(r"(\w+)=([0-9]+)", line)}
    print("GATEWAY %s" % switch)
    for mode in (1, 2, 3):
        good = values.get("mode%d_good" % mode, 0)
        bad = values.get("mode%d_bad" % mode, 0)
        if bad > 0:
            status = "SUSPECT"
        elif good > 0:
            status = "HEALTHY"
        else:
            status = "NO_DATA"
        print("mode%d status=%s good=%d bad=%d" % (mode, status, good, bad))
    no_majority = values.get("no_majority", 0)
    print("no_majority status=%s count=%d" % (
        "ALERT" if no_majority > 0 else "CLEAR",
        no_majority,
    ))
    print("schedule_policy=ALL_THREE_MODES")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("file", nargs="?", help="read counter text from file; default stdin")
    args = parser.parse_args()
    source = open(args.file, encoding="utf-8") if args.file else sys.stdin
    try:
        lines = [line.strip() for line in source if line.strip()]
    finally:
        if args.file:
            source.close()
    if not lines:
        parser.error("no counter lines supplied")
    for line in lines:
        evaluate(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

