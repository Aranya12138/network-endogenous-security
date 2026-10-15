#!/usr/bin/env python3
"""Read per-modality adjudication counters from S1 and S2."""

import argparse
import os
import sys

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "utils"))

import p4runtime_lib.bmv2
import p4runtime_lib.helper
from p4runtime_lib.switch import ShutdownAllSwitchConnections

COUNTER_NAMES = (
    "MyIngress.good_count",
    "MyIngress.bad_count",
    "MyIngress.no_majority_count",
)


def read_counter(sw, helper, name, index):
    counter_id = helper.get_counters_id(name)
    for response in sw.ReadCounters(counter_id, index):
        for entity in response.entities:
            entry = entity.counter_entry
            if entry.counter_id == counter_id and entry.index.index == index:
                return entry.data.packet_count
    return 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--p4info",
        default="./build/polymorphic.p4.p4info.txtpb",
        help="P4Info text protobuf",
    )
    args = parser.parse_args()

    helper = p4runtime_lib.helper.P4InfoHelper(args.p4info)
    switches = {
        "s1": p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name="counter-s1", address="127.0.0.1:50051", device_id=0
        ),
        "s2": p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name="counter-s2", address="127.0.0.1:50052", device_id=1
        ),
    }

    try:
        for sw in switches.values():
            sw.MasterArbitrationUpdate()

        for switch_name, sw in switches.items():
            values = []
            for mode in (1, 2, 3):
                good = read_counter(sw, helper, COUNTER_NAMES[0], mode)
                bad = read_counter(sw, helper, COUNTER_NAMES[1], mode)
                values.append("mode%d_good=%d mode%d_bad=%d" % (mode, good, mode, bad))
            no_majority = read_counter(sw, helper, COUNTER_NAMES[2], 0)
            print("%s %s no_majority=%d" % (switch_name, " ".join(values), no_majority))
    finally:
        ShutdownAllSwitchConnections()

    return 0


if __name__ == "__main__":
    sys.exit(main())
