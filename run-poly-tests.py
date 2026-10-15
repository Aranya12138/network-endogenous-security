#!/usr/bin/env python3
"""Restart Mininet and run reproducible polymorphic adjudication scenarios."""

import argparse
import os
from pathlib import Path
import subprocess
import sys
import time

import pexpect

ROOT = Path(__file__).resolve().parent
P4_SETUP = "/home/p4/p4setup.bash"

SCENARIOS = {
    "no-fault": {
        "faults": [],
        "sender": "h1",
        "receiver": "h2",
        "destination": "10.0.2.2",
        "message": "auto-ok",
        "expected": 1,
        "counter_switch": "s2",
        "counter_tokens": (
            "mode1_good=1 mode1_bad=0",
            "mode2_good=1 mode2_bad=0",
            "mode3_good=1 mode3_bad=0",
            "no_majority=0",
        ),
    },
    "reverse": {
        "faults": [],
        "sender": "h2",
        "receiver": "h1",
        "destination": "10.0.1.1",
        "message": "auto-reverse",
        "expected": 1,
        "counter_switch": "s1",
        "counter_tokens": (
            "mode1_good=1 mode1_bad=0",
            "mode2_good=1 mode2_bad=0",
            "mode3_good=1 mode3_bad=0",
            "no_majority=0",
        ),
    },
    "corrupt-mode1": {
        "faults": ["corrupt:1:1:0x1"],
        "sender": "h1",
        "receiver": "h2",
        "destination": "10.0.2.2",
        "message": "auto-corrupt",
        "expected": 1,
        "counter_switch": "s2",
        "counter_tokens": (
            "mode1_good=0 mode1_bad=1",
            "mode2_good=1 mode2_bad=0",
            "mode3_good=1 mode3_bad=0",
            "no_majority=0",
        ),
    },
    "drop-mode2": {
        "faults": ["drop:2:1"],
        "sender": "h1",
        "receiver": "h2",
        "destination": "10.0.2.2",
        "message": "auto-drop",
        "expected": 1,
        "counter_switch": "s2",
        "counter_tokens": (
            "mode1_good=1 mode1_bad=0",
            "mode2_good=0 mode2_bad=0",
            "mode3_good=1 mode3_bad=0",
            "no_majority=0",
        ),
    },
    "no-majority": {
        "faults": [
            "corrupt:1:1:0x1",
            "corrupt:2:1:0x2",
            "corrupt:3:1:0x4",
        ],
        "sender": "h1",
        "receiver": "h2",
        "destination": "10.0.2.2",
        "message": "auto-no-major",
        "expected": 0,
        "counter_switch": "s2",
        "counter_tokens": ("no_majority=1",),
    },
}


def shell(command, *, check=True):
    return subprocess.run(
        ["bash", "-lc", "source %s && %s" % (P4_SETUP, command)],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=check,
    )


def wait_for(path, marker, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists() and marker in path.read_text(errors="replace"):
            return path.read_text(errors="replace")
        time.sleep(0.1)
    content = path.read_text(errors="replace") if path.exists() else "<missing>"
    raise RuntimeError("timeout waiting for %r in %s\n%s" % (marker, path, content))


def mininet_command(child, command):
    child.sendline(command)
    child.expect_exact("mininet> ", timeout=30)


def run_scenario(name):
    scenario = SCENARIOS[name]
    print("\n=== scenario: %s ===" % name, flush=True)
    child = None
    log_path = Path("/tmp/poly-auto-%s-%d.log" % (name, os.getpid()))

    try:
        child = pexpect.spawn(
            "bash",
            ["-lc", "source %s && make" % P4_SETUP],
            cwd=str(ROOT),
            encoding="utf-8",
            timeout=90,
        )
        child.expect_exact("mininet> ")

        fault_args = " ".join("--fault %s" % value for value in scenario["faults"])
        controller = shell("python3 mycontroller.py %s" % fault_args)
        print(controller.stdout, end="")

        timeout = 4 if scenario["expected"] == 0 else 10
        receiver_cmd = (
            "%s sh -c 'python3 receive-poly.py --timeout %d --expect %d > %s 2>&1 &'"
            % (scenario["receiver"], timeout, scenario["expected"], log_path)
        )
        mininet_command(child, receiver_cmd)
        wait_for(log_path, "POLY_LISTEN", 3)

        send_cmd = "%s python3 send-poly.py %s %s" % (
            scenario["sender"],
            scenario["destination"],
            scenario["message"],
        )
        mininet_command(child, send_cmd)
        receiver_output = wait_for(log_path, "POLY_SUMMARY", timeout + 3)
        expected_summary = "POLY_SUMMARY received=%d expected=%d" % (
            scenario["expected"],
            scenario["expected"],
        )
        if expected_summary not in receiver_output:
            raise AssertionError(receiver_output)
        print(receiver_output, end="")

        # Allow the third, late modality to update statistics without outputting.
        time.sleep(0.5)
        counters = shell("python3 read-counters.py").stdout
        print(counters, end="")
        counter_line = next(
            line for line in counters.splitlines()
            if line.startswith(scenario["counter_switch"] + " ")
        )
        for token in scenario["counter_tokens"]:
            if token not in counter_line:
                raise AssertionError("missing %r in %r" % (token, counter_line))

        print("SCENARIO_PASS %s" % name, flush=True)
        return True
    finally:
        if child is not None and child.isalive():
            child.sendline("exit")
            try:
                child.expect(pexpect.EOF, timeout=20)
            except pexpect.ExceptionPexpect:
                child.close(force=True)
        shell("make stop", check=False)
        shell("make clean", check=False)
        if log_path.exists():
            log_path.unlink()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "scenario",
        nargs="*",
        choices=tuple(SCENARIOS),
        help="default: run every scenario",
    )
    args = parser.parse_args()
    selected = args.scenario or list(SCENARIOS)

    failures = []
    for name in selected:
        try:
            run_scenario(name)
        except Exception as exc:
            failures.append((name, exc))
            print("SCENARIO_FAIL %s: %s" % (name, exc), file=sys.stderr, flush=True)

    if failures:
        return 1
    print("\nALL_SCENARIOS_PASS %d" % len(selected))
    return 0


if __name__ == "__main__":
    sys.exit(main())
