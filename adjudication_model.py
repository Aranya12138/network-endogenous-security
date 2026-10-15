#!/usr/bin/env python3
"""Executable reference model for order-independent 2-of-3 adjudication.

This program helps test the state machine before students translate it to P4
register reads and writes.  It does not replace the P4 data-plane solution.
"""

import argparse
import collections
import zlib


class Adjudicator:
    def __init__(self):
        self.states = {}
        self.good = collections.Counter()
        self.bad = collections.Counter()
        self.no_majority = 0

    def process(self, sequence, mode, protected):
        observed_crc = zlib.crc32(protected) & 0xFFFFFFFF
        state = self.states.setdefault(sequence, {
            "seen": set(),
            "candidates": [],
            "decided": False,
            "winner": None,
        })

        if mode in state["seen"]:
            return "DROP duplicate-mode", None
        state["seen"].add(mode)

        if state["decided"]:
            if state["winner"] is not None:
                target = self.good if observed_crc == state["winner"] else self.bad
                target[mode] += 1
            return "DROP already-decided", None

        candidates = state["candidates"]
        if not candidates:
            candidates.append((observed_crc, mode))
            return "DROP first-candidate", None

        if len(candidates) == 1:
            first_crc, first_mode = candidates[0]
            if observed_crc == first_crc:
                state["decided"] = True
                state["winner"] = observed_crc
                self.good[first_mode] += 1
                self.good[mode] += 1
                return "ACCEPT majority", protected
            candidates.append((observed_crc, mode))
            return "DROP second-candidate", None

        first_crc, first_mode = candidates[0]
        second_crc, second_mode = candidates[1]
        state["decided"] = True
        if observed_crc == first_crc:
            state["winner"] = observed_crc
            self.good[first_mode] += 1
            self.bad[second_mode] += 1
            self.good[mode] += 1
            return "ACCEPT majority", protected
        if observed_crc == second_crc:
            state["winner"] = observed_crc
            self.bad[first_mode] += 1
            self.good[second_mode] += 1
            self.good[mode] += 1
            return "ACCEPT majority", protected

        state["winner"] = None
        self.no_majority += 1
        return "DROP no-majority", None

    def summary(self):
        parts = []
        for mode in (1, 2, 3):
            parts.append(
                "mode%d_good=%d mode%d_bad=%d"
                % (mode, self.good[mode], mode, self.bad[mode])
            )
        parts.append("no_majority=%d" % self.no_majority)
        return " ".join(parts)


SCENARIOS = {
    "no-fault": ((2, b"correct"), (1, b"correct"), (3, b"correct")),
    "corrupt-mode1": ((1, b"wrong"), (2, b"correct"), (3, b"correct")),
    "drop-mode2": ((1, b"correct"), (3, b"correct")),
    "no-majority": ((1, b"value-a"), (2, b"value-b"), (3, b"value-c")),
}


def run_scenario(name):
    adjudicator = Adjudicator()
    outputs = []
    print("SCENARIO %s" % name)
    for mode, value in SCENARIOS[name]:
        action, output = adjudicator.process(1, mode, value.ljust(16, b"\x00"))
        print("mode=%d value=%s action=%s" % (mode, value.decode(), action))
        if output is not None:
            outputs.append(output)
    print("OUTPUT count=%d" % len(outputs))
    print("COUNTERS %s" % adjudicator.summary())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("scenario", choices=("all",) + tuple(SCENARIOS), default="all", nargs="?")
    args = parser.parse_args()
    names = SCENARIOS if args.scenario == "all" else (args.scenario,)
    for name in names:
        run_scenario(name)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

