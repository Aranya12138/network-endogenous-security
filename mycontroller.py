#!/usr/bin/env python3
"""Verified three-path baseline controller used as the student starter.

The baseline installs ordinary IPv4 and IPv6 forwarding only. Follow the
milestones in STUDENT_TODO.md to add multicast scheduling, gateway roles,
fault injection and counter reads. Keep this file runnable after every step.
"""

import argparse
import grpc
import os
import sys
from time import sleep

# Import P4Runtime lib from parent utils dir
# Probably there's a better way of doing this.
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 'utils/'))
import p4runtime_lib.bmv2
from p4runtime_lib.error_utils import printGrpcError
from p4runtime_lib.switch import ShutdownAllSwitchConnections
import p4runtime_lib.helper

def writeMulticastGroup(p4info_helper, sw, group_id, replicas):
    """Install a multicast group; replicas is a list of (egress_port, instance)."""
    entry = p4info_helper.buildMulticastGroupEntry(
        group_id,
        [{"egress_port": port, "instance": instance} for port, instance in replicas],
    )
    sw.WritePREEntry(entry)


def writePolymorphicScheduleRule(p4info_helper, sw, destination, direction):
    """Match host-facing UDP/5000 experiment traffic and mark it for scheduling."""
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.polymorphic_schedule",
        match_fields={
            "standard_metadata.ingress_port": 1,
            "hdr.ipv4.dstAddr": destination,
            "hdr.udp.dstPort": 5000,
        },
        action_name="MyIngress.start_polymorphic",
        action_params={"packet_direction": direction},
    )
    sw.WriteTableEntry(table_entry)

def writeDestGatewayRole(p4info_helper, sw, direction):
    """Give a gateway the adjudication role for one direction.

    h1 -> h2: s1 schedules, s2 adjudicates (direction 0).
    h2 -> h1: s2 schedules, s1 adjudicates (direction 1).
    Intermediate switches keep the default NoAction.
    """
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.dest_gateway_role",
        match_fields={
            "hdr.polyShim.direction": direction,
        },
        action_name="MyIngress.set_dest_gateway",
        action_params={},
    )
    sw.WriteTableEntry(table_entry)

def writeArp_matchRules(p4info_helper, sw, match_fields_1, match_fields_2, action_params):

    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.arp_match",
        match_fields={
            "hdr.arp.oper": match_fields_1,
            "hdr.arp.tpa" : match_fields_2
        },
        action_name="MyIngress.send_arp_reply",
        action_params=action_params
        )
    sw.WriteTableEntry(table_entry)
    
def writeIpv4_lpmRules(p4info_helper, sw, match_fields, action_params):

    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.ipv4_lpm",
        match_fields={
            "hdr.ipv4.dstAddr": match_fields
        },
        action_name="MyIngress.ipv4_forward",
        action_params=action_params
        )
    sw.WriteTableEntry(table_entry)
    
def writeIpv6_lpmRules(p4info_helper, sw, match_fields, action_params):

    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.ipv6_lpm",
        match_fields={
            "hdr.ipv6.dstAddr": match_fields
        },
        action_name="MyIngress.ipv6_forward",
        action_params=action_params
        )
    sw.WriteTableEntry(table_entry)

def install_faults(p4info_helper, mode_to_switch, faults):
    """Install fault entries on s11/s21/s31 based on --fault args."""
    for fault in faults:
        parts = fault.split(":")
        kind = parts[0]
        if kind == "corrupt" and len(parts) == 4:
            mode = int(parts[1])
            seq = int(parts[2])
            mask = int(parts[3], 16)
            sw = mode_to_switch.get(mode)
            if sw is None:
                print("unknown mode %d for fault %s" % (mode, fault))
                continue
            table_entry = p4info_helper.buildTableEntry(
                table_name="MyIngress.fault_corrupt",
                match_fields={
                    "hdr.polyShim.modality_id": mode,
                    "hdr.polyShim.sequence_number": seq,
                },
                action_name="MyIngress.do_corrupt",
                action_params={"mask": mask},
            )
            try:
                response = sw.WriteTableEntry(table_entry)
                print("DEBUG: write corrupt response = %s" % response, flush=True)
            except Exception as e:
                print("DEBUG: write corrupt raised: %r" % e, flush=True)
                raise
            print("Installed corrupt fault on %s: mode=%d seq=%d mask=0x%x"
                  % (sw.name, mode, seq, mask))
        elif kind == "drop" and len(parts) == 3:
            mode = int(parts[1])
            seq = int(parts[2])
            sw = mode_to_switch.get(mode)
            if sw is None:
                print("unknown mode %d for fault %s" % (mode, fault))
                continue
            table_entry = p4info_helper.buildTableEntry(
                table_name="MyIngress.fault_drop",
                match_fields={
                    "hdr.polyShim.modality_id": mode,
                    "hdr.polyShim.sequence_number": seq,
                },
                action_name="MyIngress.do_drop",
                action_params={},
            )
            try:
                response = sw.WriteTableEntry(table_entry)
                print("DEBUG: write drop response = %s" % response, flush=True)
            except Exception as e:
                print("DEBUG: write drop raised: %r" % e, flush=True)
                raise
            print("Installed drop fault on %s: mode=%d seq=%d"
                  % (sw.name, mode, seq))
        else:
            print("unknown fault: %s" % fault)


def main(p4info_file_path, bmv2_file_path, faults=None):
    print("DEBUG: main() entered, p4info=%s, bmv2=%s" % (p4info_file_path, bmv2_file_path), flush=True)
    if faults is None:
        faults = []
    # Instantiate a P4Runtime helper from the p4info file
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)

    try:
        # Create a switch connection object for switches;
        # this is backed by a P4Runtime gRPC connection.
        # Also, dump all P4Runtime messages sent to switch to given txt files.
        s1 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s1',
            address='127.0.0.1:50051',
            device_id=0,
            proto_dump_file='logs/s1-p4runtime-requests.txt')
        s2 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s2',
            address='127.0.0.1:50052',
            device_id=1,
            proto_dump_file='logs/s2-p4runtime-requests.txt')
        s11 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s11',
            address='127.0.0.1:50053',
            device_id=2,
            proto_dump_file='logs/s11-p4runtime-requests.txt')
        s12 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s12',
            address='127.0.0.1:50054',
            device_id=3,
            proto_dump_file='logs/s12-p4runtime-requests.txt')
        s21 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s21',
            address='127.0.0.1:50055',
            device_id=4,
            proto_dump_file='logs/s21-p4runtime-requests.txt')
        s22 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s22',
            address='127.0.0.1:50056',
            device_id=5,
            proto_dump_file='logs/s22-p4runtime-requests.txt')
        s31 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s31',
            address='127.0.0.1:50057',
            device_id=6,
            proto_dump_file='logs/s31-p4runtime-requests.txt')
        s32 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s32',
            address='127.0.0.1:50058',
            device_id=7,
            proto_dump_file='logs/s32-p4runtime-requests.txt')
        s41 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s41',
            address='127.0.0.1:50059',
            device_id=8,
            proto_dump_file='logs/s41-p4runtime-requests.txt')
        s42 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s42',
            address='127.0.0.1:50060',
            device_id=9,
            proto_dump_file='logs/s42-p4runtime-requests.txt')


        # Send master arbitration update message to establish this controller as
        # master (required by P4Runtime before performing any other write operation)
        s1.MasterArbitrationUpdate()
        s2.MasterArbitrationUpdate()
        s11.MasterArbitrationUpdate()
        s12.MasterArbitrationUpdate()
        s21.MasterArbitrationUpdate()
        s22.MasterArbitrationUpdate()
        s31.MasterArbitrationUpdate()
        s32.MasterArbitrationUpdate()
        s41.MasterArbitrationUpdate()
        s42.MasterArbitrationUpdate()

        # Install the P4 program on the switches
        s1.SetForwardingPipelineConfig(p4info=p4info_helper.p4info, bmv2_json_file_path=bmv2_file_path)
        s2.SetForwardingPipelineConfig(p4info=p4info_helper.p4info, bmv2_json_file_path=bmv2_file_path)
        s11.SetForwardingPipelineConfig(p4info=p4info_helper.p4info, bmv2_json_file_path=bmv2_file_path)
        s12.SetForwardingPipelineConfig(p4info=p4info_helper.p4info, bmv2_json_file_path=bmv2_file_path)
        s21.SetForwardingPipelineConfig(p4info=p4info_helper.p4info, bmv2_json_file_path=bmv2_file_path)
        s22.SetForwardingPipelineConfig(p4info=p4info_helper.p4info, bmv2_json_file_path=bmv2_file_path)
        s31.SetForwardingPipelineConfig(p4info=p4info_helper.p4info, bmv2_json_file_path=bmv2_file_path)
        s32.SetForwardingPipelineConfig(p4info=p4info_helper.p4info, bmv2_json_file_path=bmv2_file_path)
        s41.SetForwardingPipelineConfig(p4info=p4info_helper.p4info, bmv2_json_file_path=bmv2_file_path)
        s42.SetForwardingPipelineConfig(p4info=p4info_helper.p4info, bmv2_json_file_path=bmv2_file_path)
        
        writeArp_matchRules(p4info_helper, s1, [1], ["10.0.1.10", 32], {"macAddr": "08:00:00:00:01:00"})
        writeArp_matchRules(p4info_helper, s2, [1], ["10.0.2.20", 32], {"macAddr": "08:00:00:00:02:00"})
        

        # Table entries for ipv4
        # h1 -> h2
        writeIpv4_lpmRules(p4info_helper, s1, ["10.0.2.2", 32], {"dstAddr": "08:00:00:00:11:00", "port": 2})
        writeIpv4_lpmRules(p4info_helper, s11, ["10.0.2.2", 32], {"dstAddr": "08:00:00:00:12:00", "port": 2})
        writeIpv4_lpmRules(p4info_helper, s12, ["10.0.2.2", 32], {"dstAddr": "08:00:00:00:02:00", "port": 2})
        writeIpv4_lpmRules(p4info_helper, s2, ["10.0.2.2", 32], {"dstAddr": "08:00:00:00:02:02", "port": 1})
        
        # h2 -> h1
        writeIpv4_lpmRules(p4info_helper, s2, ["10.0.1.1", 32], {"dstAddr": "08:00:00:00:12:00", "port": 2})
        writeIpv4_lpmRules(p4info_helper, s12, ["10.0.1.1", 32], {"dstAddr": "08:00:00:00:11:00", "port": 1})
        writeIpv4_lpmRules(p4info_helper, s11, ["10.0.1.1", 32], {"dstAddr": "08:00:00:00:01:00", "port": 1})
        writeIpv4_lpmRules(p4info_helper, s1, ["10.0.1.1", 32], {"dstAddr": "08:00:00:00:01:01", "port": 1})
        
        # Table entries for ipv6
        # h1 -> h2
        writeIpv6_lpmRules(p4info_helper, s1, ["fe80::5678", 128], {"dstAddr": "08:00:00:00:11:00", "port": 3})
        writeIpv6_lpmRules(p4info_helper, s21, ["fe80::5678", 128], {"dstAddr": "08:00:00:00:12:00", "port": 2})
        writeIpv6_lpmRules(p4info_helper, s22, ["fe80::5678", 128], {"dstAddr": "08:00:00:00:02:00", "port": 2})
        writeIpv6_lpmRules(p4info_helper, s2, ["fe80::5678", 128], {"dstAddr": "08:00:00:00:02:02", "port": 1})
        
        # h2 -> h1
        writeIpv6_lpmRules(p4info_helper, s2, ["fe80::1234", 128], {"dstAddr": "08:00:00:00:12:00", "port": 3})
        writeIpv6_lpmRules(p4info_helper, s22, ["fe80::1234", 128], {"dstAddr": "08:00:00:00:11:00", "port": 1})
        writeIpv6_lpmRules(p4info_helper, s21, ["fe80::1234", 128], {"dstAddr": "08:00:00:00:01:00", "port": 1})
        writeIpv6_lpmRules(p4info_helper, s1, ["fe80::1234", 128], {"dstAddr": "08:00:00:00:01:01", "port": 1})

        # STUDENT TODO M3: multicast replication on both gateways.
        # One original packet -> three replicas out ports 2/3/4 with
        # replica instances 1/2/3, independent on s1 and s2.
        writeMulticastGroup(p4info_helper, s1, group_id=10,
                            replicas=[(2, 1), (3, 2), (4, 3)])
        writeMulticastGroup(p4info_helper, s2, group_id=10,
                            replicas=[(2, 1), (3, 2), (4, 3)])

        # STUDENT TODO M3: source-gateway scheduling rules, one per direction.
        # direction 0: h1 -> h2 (scheduled at s1); 1: h2 -> h1 (at s2).
        writePolymorphicScheduleRule(p4info_helper, s1, "10.0.2.2", 0)
        writePolymorphicScheduleRule(p4info_helper, s2, "10.0.1.1", 1)
        # STUDENT TODO M5: destination-gateway roles, one per direction.
        # direction 0: s2 adjudicates; direction 1: s1 adjudicates.
        writeDestGatewayRole(p4info_helper, s2, 0)
        writeDestGatewayRole(p4info_helper, s1, 1)
        # STUDENT TODO M5-M6: install faults on intermediate switches
        mode_to_switch = {
        1: s11,   # IPv4 模态中间交换机
        2: s21,   # IPv6 模态中间交换机
        3: s31,   # Source Routing 模态中间交换机
        }
        install_faults(p4info_helper, mode_to_switch, faults)
        # STUDENT TODO M5-M6: destination-gateway roles, fault-table entries
        # and counter reads are added in the next lesson.
        

    except KeyboardInterrupt:
        print(" Shutting down.")
    except grpc.RpcError as e:
        printGrpcError(e)

    ShutdownAllSwitchConnections()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='P4Runtime Controller')
    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                        type=str, action="store", required=False,
                        default='./build/polymorphic.p4.p4info.txtpb')
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
                        type=str, action="store", required=False,
                        default='./build/polymorphic.json')
    parser.add_argument("--fault", action="append", default=[],
                        help="corrupt:MODE:SEQ:MASK or drop:MODE:SEQ")
    args = parser.parse_args()
    
    print("DEBUG: args parsed, p4info=%s, bmv2=%s" % (args.p4info, args.bmv2_json), flush=True)

    print("DEBUG: checking p4info exists =", os.path.exists(args.p4info), flush=True)
    if not os.path.exists(args.p4info):
        parser.print_help()
        print("\np4info file not found: %s\nHave you run 'make'?" % args.p4info)
        parser.exit(1)
    print("DEBUG: checking bmv2 exists =", os.path.exists(args.bmv2_json), flush=True)
    if not os.path.exists(args.bmv2_json):
        parser.print_help()
        print("\nBMv2 JSON file not found: %s\nHave you run 'make'?" % args.bmv2_json)
        parser.exit(1)
        print("DEBUG: about to call main()", flush=True)
    main(args.p4info, args.bmv2_json, args.fault)
