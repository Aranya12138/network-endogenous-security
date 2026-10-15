/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_SRCROUTING    = 0x1234;

const bit<16> TYPE_IPV4          = 0x800;
const bit<16> TYPE_ARP           = 0x0806;

const bit<16> TYPE_IPV6          = 0x86DD;

const bit<16> ARP_HTYPE_ETHERNET = 0x0001;
const bit<16> ARP_PTYPE_IPV4     = 0x0800;
const bit<8>  ARP_HLEN_ETHERNET  = 6;
const bit<8>  ARP_PLEN_IPV4      = 4;
const bit<16> ARP_OPER_REQUEST   = 1;
const bit<16> ARP_OPER_REPLY     = 2;

// M1: PolyShim experiment constants (field contract in STUDENT_TODO.md).
const bit<16> POLY_MAGIC        = 0x504f; // ASCII "PO"
const bit<8>  POLY_IP_PROTOCOL  = 253;
const bit<16> POLY_UDP_PORT     = 5000;
const bit<16> POLY_MCAST_GROUP  = 10;

const bit<8> MODE_IPV4 = 1;
const bit<8> MODE_IPV6 = 2;
const bit<8> MODE_SR   = 3;

#define MAX_HOPS 9

/*
 * STUDENT TODO ROADMAP
 *
 * This starter intentionally remains the verified three-path baseline. It
 * compiles before any experiment code is added. Complete the extension in
 * stages and keep every stage compilable:
 *
 *   M1: define PolyShim, protected_data and saved inner-IPv4 headers;
 *   M2: parse UDP dport 5000 with exactly 16 protected bytes;
 *   M3: add sequence/CRC metadata and an ingress scheduling table;
 *   M4: set mcast_grp and build IPv4/IPv6/SR outer headers in MyEgress;
 *   M5: add destination-gateway register state and 2-out-of-3 adjudication;
 *   M6: restore the original IPv4 packet and emit it at host-facing port 1.
 *
 * The field contract and pseudocode are in STUDENT_TODO.md. Do not paste a
 * complete solution here first: implement and validate one milestone at a
 * time so a failing stage can be located from pcap and counter evidence.
 */

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<128> ip6Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header srcRoute_t {
    bit<1>    bos;
    bit<15>   port;
}

header arp_t {
    bit<16> htype; // format of hardware address
    bit<16> ptype; // format of protocol address
    bit<8>  hlen; // length of hardware address
    bit<8>  plen; // length of protocol address
    bit<16> oper; // request or reply operation
    macAddr_t sha; //src mac address
    ip4Addr_t spa; //src ip address
    macAddr_t tha; // dst mac address
    ip4Addr_t tpa; // dst ip address
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header ipv6_t{
    bit<4>    version;
    bit<8>    trafficClass;
    bit<20>   flowLabel;
    bit<16>   payLoadLen;
    bit<8>    nextHdr;
    bit<8>    hopLimit;
    ip6Addr_t srcAddr;
    ip6Addr_t dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> pkt_length;
    bit<16> checksum;
}

// M1: PolyShim sits between the outer modality header and the inner IPv4.
header polyShim_t {
    bit<16> magic;
    bit<8>  direction;        // 0: h1 -> h2, 1: h2 -> h1
    bit<32> sequence_number;
    bit<8>  modality_id;
    bit<32> source_crc32;
    bit<16> inner_ether_type;
}

// M1: fixed 16-byte payload so the Parser can extract a known-width field.
header protectedData_t {
    bit<128> value;
}

struct metadata {
    ip4Addr_t   dst_ipv4; // dst ip

    // M3: scheduling state, set once per original packet in Ingress and
    // inherited by every replica.
    bit<1>      is_polymorphic;
    bit<8>      packet_direction; // 0: h1 -> h2, 1: h2 -> h1
    bit<32>     sequence_number;
    bit<32>     source_crc32;
    // M5-M6: adjudication temp values
    bit<32> current_slot;
    bit<32> observed_crc;
    bit<32> read_seq_tag;
    bit<32> read_crc_candidate_1;
    bit<32> read_crc_candidate_2;
    bit<8>  read_mode_candidate_1;
    bit<8>  read_mode_candidate_2;
    bit<8>  read_seen_modes;
    bit<2>  read_candidate_counts;
    bit<1>  read_decided;
    bit<32> read_decided_crc;
    bit<1>  allow_output;
    bit<1>  is_dest_gateway;
    // M5: set when the fault_drop table hits on an intermediate switch; the
    // apply block must then return so ordinary forwarding cannot overwrite
    // the drop-port egress_spec written by mark_to_drop.
    bit<1>  fault_dropped;
}

struct headers {
    ethernet_t  ethernet;
    srcRoute_t[MAX_HOPS]    srcRoutes;
    arp_t       arp;
    ipv4_t      ipv4;
    ipv6_t      ipv6;
    tcp_t       tcp;
    udp_t       udp;
    polyShim_t  polyShim;
    ipv4_t      inner_ipv4; // M1: the saved original IPv4, kept apart from hdr.ipv4
    protectedData_t protected_data;
}

// M3: per-gateway sequence generator. Read + increment happens once per
// original scheduled packet in Ingress, never once per replica in Egress.
register<bit<32>>(1) sequence_counter;

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }
    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_SRCROUTING: parse_srcRouting;
            TYPE_IPV4: parse_ipv4;
            TYPE_ARP : parse_arp;
            TYPE_IPV6: parse_ipv6;
            default: accept;
        }
    }
    
    state parse_srcRouting {
        packet.extract(hdr.srcRoutes.next);
        transition select(hdr.srcRoutes.last.bos) {
            1: parse_srcRoute_payload;
            default: parse_srcRouting;
        }
    }

    state parse_srcRoute_payload {
        // M2: SR replicas carry PolyShim right after the stack; the original
        // SR demo carries plain IPv4 after the stack.
        transition select(packet.lookahead<bit<16>>()) {
            POLY_MAGIC: parse_polyShim;
            default: parse_ipv4;
        }
    }
    
    state parse_arp {
        packet.extract(hdr.arp);
        meta.dst_ipv4 = hdr.arp.tpa;  //save dst ip
        transition accept;
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            6: parse_tcp;
            17: parse_udp;
            POLY_IP_PROTOCOL: parse_polyShim; // M2: outer IPv4 replica
            default: accept;
        }
    }
    
    state parse_ipv6{
        packet.extract(hdr.ipv6);
        transition select(hdr.ipv6.nextHdr) {
            POLY_IP_PROTOCOL: parse_polyShim; // M2: outer IPv6 replica
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        // M2: only the fixed UDP/5000 experiment format continues to the
        // 16-byte protected data. Ordinary UDP stays accepted as before.
        transition select(hdr.udp.dstPort) {
            POLY_UDP_PORT: parse_protected_data;
            default: accept;
        }
    }

    state parse_polyShim {
        packet.extract(hdr.polyShim);
        transition select(hdr.polyShim.magic) {
            POLY_MAGIC: parse_polyShim_inner;
            default: accept;
        }
    }

    state parse_polyShim_inner {
        transition select(hdr.polyShim.inner_ether_type) {
            TYPE_IPV4: parse_inner_ipv4;
            default: accept;
        }
    }

    state parse_inner_ipv4 {
        packet.extract(hdr.inner_ipv4);
        transition select(hdr.inner_ipv4.protocol) {
            6: parse_tcp;
            17: parse_udp;
            default: accept;
        }
    }

    state parse_protected_data {
        packet.extract(hdr.protected_data);
        transition accept;
    }

}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

        /* M5: adjudication state */
    #define STATE_SLOTS 1024
    #define MODE_COUNTER_SLOTS 5

    register<bit<32>>(STATE_SLOTS) seq_tag;
    register<bit<32>>(STATE_SLOTS) crc_candidate_1;
    register<bit<32>>(STATE_SLOTS) crc_candidate_2;
    register<bit<8>>(STATE_SLOTS)  mode_candidate_1;
    register<bit<8>>(STATE_SLOTS)  mode_candidate_2;
    register<bit<8>>(STATE_SLOTS)  seen_modes;
    register<bit<2>>(STATE_SLOTS)  candidate_counts;
    register<bit<1>>(STATE_SLOTS)  decided;
    register<bit<32>>(STATE_SLOTS) decided_crc;

    counter(MODE_COUNTER_SLOTS, CounterType.packets) good_count;
    counter(MODE_COUNTER_SLOTS, CounterType.packets) bad_count;
    counter(1, CounterType.packets) no_majority_count;

    action adjudicate() {
        meta.current_slot = hdr.polyShim.sequence_number & 0x3FF;

        seq_tag.read(meta.read_seq_tag, meta.current_slot);
        if (meta.read_seq_tag != hdr.polyShim.sequence_number) {
            seq_tag.write(meta.current_slot, hdr.polyShim.sequence_number);
            crc_candidate_1.write(meta.current_slot, 0);
            crc_candidate_2.write(meta.current_slot, 0);
            mode_candidate_1.write(meta.current_slot, 0);
            mode_candidate_2.write(meta.current_slot, 0);
            seen_modes.write(meta.current_slot, 0);
            candidate_counts.write(meta.current_slot, 0);
            decided.write(meta.current_slot, 0);
            decided_crc.write(meta.current_slot, 0);
        }

        seen_modes.read(meta.read_seen_modes, meta.current_slot);
        candidate_counts.read(meta.read_candidate_counts, meta.current_slot);
        decided.read(meta.read_decided, meta.current_slot);
        crc_candidate_1.read(meta.read_crc_candidate_1, meta.current_slot);
        crc_candidate_2.read(meta.read_crc_candidate_2, meta.current_slot);
        mode_candidate_1.read(meta.read_mode_candidate_1, meta.current_slot);
        mode_candidate_2.read(meta.read_mode_candidate_2, meta.current_slot);
        decided_crc.read(meta.read_decided_crc, meta.current_slot);

        bit<8> mode_bit = 8w1 << hdr.polyShim.modality_id;
        if ((meta.read_seen_modes & mode_bit) != 0) {
            mark_to_drop(standard_metadata);
        }
        else {
            seen_modes.write(meta.current_slot, meta.read_seen_modes | mode_bit);

            hash(meta.observed_crc,
                 HashAlgorithm.crc32,
                 (bit<32>)0,
                 { hdr.inner_ipv4.srcAddr,
                   hdr.inner_ipv4.dstAddr,
                   hdr.inner_ipv4.protocol,
                   hdr.udp.srcPort,
                   hdr.udp.dstPort,
                   hdr.protected_data.value },
                 (bit<32>)0xFFFFFFFF);

            if (meta.read_decided == 1) {
                if (meta.observed_crc == meta.read_decided_crc) {
                    good_count.count((bit<32>)hdr.polyShim.modality_id);
                } else {
                    bad_count.count((bit<32>)hdr.polyShim.modality_id);
                }
                mark_to_drop(standard_metadata);
            }
            else if (meta.read_candidate_counts == 0) {
                crc_candidate_1.write(meta.current_slot, meta.observed_crc);
                mode_candidate_1.write(meta.current_slot, hdr.polyShim.modality_id);
                candidate_counts.write(meta.current_slot, 1);
                mark_to_drop(standard_metadata);
            }
            else if (meta.read_candidate_counts == 1) {
                if (meta.observed_crc == meta.read_crc_candidate_1) {
                    decided.write(meta.current_slot, 1);
                    decided_crc.write(meta.current_slot, meta.observed_crc);
                    good_count.count((bit<32>)meta.read_mode_candidate_1);
                    good_count.count((bit<32>)hdr.polyShim.modality_id);
                    meta.allow_output = 1;
                } else {
                    crc_candidate_2.write(meta.current_slot, meta.observed_crc);
                    mode_candidate_2.write(meta.current_slot, hdr.polyShim.modality_id);
                    candidate_counts.write(meta.current_slot, 2);
                    mark_to_drop(standard_metadata);
                }
            }
            else {
                decided.write(meta.current_slot, 1);
                if (meta.observed_crc == meta.read_crc_candidate_1) {
                    decided_crc.write(meta.current_slot, meta.read_crc_candidate_1);
                    good_count.count((bit<32>)meta.read_mode_candidate_1);
                    bad_count.count((bit<32>)meta.read_mode_candidate_2);
                    good_count.count((bit<32>)hdr.polyShim.modality_id);
                    meta.allow_output = 1;
                }
                else if (meta.observed_crc == meta.read_crc_candidate_2) {
                    decided_crc.write(meta.current_slot, meta.read_crc_candidate_2);
                    bad_count.count((bit<32>)meta.read_mode_candidate_1);
                    good_count.count((bit<32>)meta.read_mode_candidate_2);
                    good_count.count((bit<32>)hdr.polyShim.modality_id);
                    meta.allow_output = 1;
                }
                else {
                    no_majority_count.count(0);
                    mark_to_drop(standard_metadata);
                }
            }
        }
    }

    action drop() {
        mark_to_drop(standard_metadata);
    }
    
    action srcRoute_nhop() {
        standard_metadata.egress_spec = (bit<9>)hdr.srcRoutes[0].port;
        hdr.srcRoutes.pop_front(1);
    }

    action srcRoute_finish() {
        hdr.ethernet.etherType = TYPE_IPV4;
    }

    action update_ttl(){
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
	
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl         = hdr.ipv4.ttl - 1;
    }
    
    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }
    
    action ipv6_forward(macAddr_t dstAddr,egressSpec_t port){
	standard_metadata.egress_spec = port;
	hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
	hdr.ethernet.dstAddr = dstAddr;
	hdr.ipv6.hopLimit = hdr.ipv6.hopLimit - 1;
    }
    
    table ipv6_lpm{
    	key = {
	    hdr.ipv6.dstAddr: lpm;
	}
	actions = {
	    ipv6_forward;
	    drop;
	    NoAction;
	}		
	size = 1024;	
	default_action = drop();
    }

    action send_arp_reply(macAddr_t macAddr) {
        hdr.ethernet.dstAddr = hdr.arp.sha;      // Ethernet target address = ARP source MAC address
        hdr.ethernet.srcAddr = macAddr; 	  // Ethernet source address = the action argument macAddr

        hdr.arp.oper         = ARP_OPER_REPLY;   // modify the ARP packet type to reply
        // set the fields to reply
        hdr.arp.tha          = hdr.arp.sha;      // ARP target MAC address = ARP source MAC address
        hdr.arp.tpa          = hdr.arp.spa;      // ARP target IP address = ARP source IP address
        hdr.arp.sha          = macAddr;          // ARP source MAC address = the action argument macAddr
        hdr.arp.spa          = meta.dst_ipv4;           // ARP source IP address = ARP target IP address

        // 出口端口：还原后从主机侧端口发出（h1/h2 都接在网关 eth1）
        standard_metadata.egress_spec = 1;
    }

    table arp_match {
        key = {
            hdr.arp.oper           : exact;
            hdr.arp.tpa            : lpm;
        }
        actions = {
            send_arp_reply;
            drop;
        }
        const default_action = drop();
    }

    action start_polymorphic(bit<8> packet_direction) {
        meta.is_polymorphic   = 1;
        meta.packet_direction = packet_direction;
    }

    table polymorphic_schedule {
        key = {
            standard_metadata.ingress_port: exact;
            hdr.ipv4.dstAddr: exact;
            hdr.udp.dstPort: exact;
        }
        actions = {
            start_polymorphic;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    /* M5: 目的网关角色表。控制器按方向下发：S2 在方向 0、S1 在方向 1
       执行裁决；中间交换机保持默认 NoAction，只查故障表并转发。
       不能用 ingress_port 判断角色：反向时副本到达中间交换机的 2 号口，
       与目的网关的 2 号口无法区分。 */
    action set_dest_gateway() {
        meta.is_dest_gateway = 1;
    }
    table dest_gateway_role {
        key = {
            hdr.polyShim.direction: exact;
        }
        actions = {
            set_dest_gateway;
            NoAction;
        }
        size = 2;
        default_action = NoAction();
    }

    /* M5-M6: 故障注入表（中间交换机使用） */
    action do_corrupt(bit<32> mask) {
        hdr.protected_data.value = hdr.protected_data.value ^ (bit<128>)mask;
    }
    table fault_corrupt {
        key = {
            hdr.polyShim.modality_id: exact;
            hdr.polyShim.sequence_number: exact;
        }
        actions = {
            do_corrupt;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    action do_drop() {
        meta.fault_dropped = 1;
        mark_to_drop(standard_metadata);
    }
    table fault_drop {
        key = {
            hdr.polyShim.modality_id: exact;
            hdr.polyShim.sequence_number: exact;
        }
        actions = {
            do_drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    apply {
        /*
         * TODO M5: destination-gateway adjudication must run before ordinary
         * routing and either emit exactly one restored packet or drop; outer
         * packets must never reach a host unchanged.
         */

        if (hdr.polyShim.isValid()) {
            standard_metadata.mcast_grp = 0;
            dest_gateway_role.apply();
            if (meta.is_dest_gateway == 1) {
                // 目的网关：做裁决
                adjudicate();
                if (meta.allow_output == 1) {
                    // The destination gateway has fresh metadata, so take the
                    // direction and the original addresses from the packet
                    // itself before the internal headers are invalidated.
                    meta.packet_direction = hdr.polyShim.direction;
                    hdr.ethernet.etherType = TYPE_IPV4;
                    // setValid() first: field writes to an invalid header are
                    // no-ops in the generated code, so a winner whose outer
                    // header was IPv6 or SR would otherwise emit an all-zero
                    // IPv4 header (broken version/ttl/addresses).
                    hdr.ipv4.setValid();
                    hdr.ipv4.version        = 4;
                    hdr.ipv4.ihl            = 5;
                    hdr.ipv4.diffserv       = 0;
                    hdr.ipv4.totalLen       = 44;
                    hdr.ipv4.identification = 0;
                    hdr.ipv4.flags          = 0;
                    hdr.ipv4.fragOffset     = 0;
                    hdr.ipv4.ttl            = 64;
                    hdr.ipv4.protocol       = 17;
                    hdr.ipv4.srcAddr        = hdr.inner_ipv4.srcAddr;
                    hdr.ipv4.dstAddr        = hdr.inner_ipv4.dstAddr;
                hdr.inner_ipv4.setInvalid();
                hdr.polyShim.setInvalid();
                hdr.ipv6.setInvalid();
                hdr.srcRoutes[0].setInvalid();
                hdr.srcRoutes[1].setInvalid();
                hdr.srcRoutes[2].setInvalid();
                hdr.srcRoutes[3].setInvalid();

             if (meta.packet_direction == 0) {
        hdr.ethernet.dstAddr = 0x080000000202;
    }
             else {
        hdr.ethernet.dstAddr = 0x080000000101;
    }
    hdr.ethernet.srcAddr = 0x080000000101;
    standard_metadata.egress_spec = 1;
}
                return;
            }
            // 中间交换机：先查故障表，再走普通转发
            fault_corrupt.apply();
            fault_drop.apply();
            if (meta.fault_dropped == 1) {
                // keep egress_spec at the drop port; ordinary forwarding
                // below would overwrite it and undo the fault drop
                return;
            }
        }

        if (hdr.srcRoutes[0].isValid()){
            if (hdr.srcRoutes[0].bos == 1){
                srcRoute_finish();
            }
            srcRoute_nhop();
            if (hdr.ipv4.isValid()){
                update_ttl();
            }
        }

        else if(hdr.ethernet.etherType == TYPE_IPV4) {
            // M3: schedule experiment traffic before ordinary IPv4 routing.
            if (hdr.udp.isValid()) {
                polymorphic_schedule.apply();
            }
            if (meta.is_polymorphic == 1) {
                // One original packet: one sequence, one source CRC, one saved
                // inner IPv4 and one PolyShim shared by all three replicas.
                sequence_counter.read(meta.sequence_number, (bit<32>)0);
                // First packet of a scenario must get sequence_number 1 so the
                // acceptance tools' fault entries (--fault ...:SEQ with SEQ=1)
                // can locate it.
                meta.sequence_number = meta.sequence_number + 1;
                sequence_counter.write((bit<32>)0, meta.sequence_number);

                hdr.inner_ipv4.setValid();
                hdr.inner_ipv4 = hdr.ipv4;

                // CRC field order is a contract with the destination gateway:
                // inner src/dst, inner protocol, UDP src/dst port, 16B data.
                hash(meta.source_crc32,
                     HashAlgorithm.crc32,
                     (bit<1>)0,
                     { hdr.inner_ipv4.srcAddr,
                       hdr.inner_ipv4.dstAddr,
                       hdr.inner_ipv4.protocol,
                       hdr.udp.srcPort,
                       hdr.udp.dstPort,
                       hdr.protected_data.value },
                     (bit<32>)0xFFFFFFFF);

                hdr.polyShim.setValid();
                hdr.polyShim.magic            = POLY_MAGIC;
                hdr.polyShim.direction        = meta.packet_direction;
                hdr.polyShim.sequence_number  = meta.sequence_number;
                hdr.polyShim.modality_id      = 0; // per-replica value set in Egress
                hdr.polyShim.source_crc32     = meta.source_crc32;
                hdr.polyShim.inner_ether_type = TYPE_IPV4;

                standard_metadata.mcast_grp = POLY_MCAST_GROUP;
            }
            else {
                ipv4_lpm.apply();
            }
        }
        else if(hdr.ethernet.etherType == TYPE_ARP) {
            arp_match.apply();
        }
        else if(hdr.ethernet.etherType == TYPE_IPV6){
	    ipv6_lpm.apply();
	}
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {
        // M4: build one outer encapsulation per replica, selected by the port
        // the PRE assigned. All replicas keep the shared PolyShim fields
        // (sequence_number, source_crc32) written once in Ingress.
        if (meta.is_polymorphic == 1) {
            if (standard_metadata.egress_port == 2) {
                // Outer IPv4, protocol 253; addresses stay the host pair.
                hdr.polyShim.modality_id = MODE_IPV4;
                hdr.ipv4.setValid();
                hdr.ipv4.version  = 4;
                hdr.ipv4.ihl      = 5;
                hdr.ipv4.totalLen = 78;  // 20 IP + 14 PolyShim + 20 inner IP + 8 UDP + 16 data
                hdr.ipv4.ttl      = 64;
                hdr.ipv4.protocol = POLY_IP_PROTOCOL;
            }
            else if (standard_metadata.egress_port == 3) {
                // Outer IPv6, next header 253.
                hdr.polyShim.modality_id = MODE_IPV6;
                hdr.ipv4.setInvalid();
                hdr.ethernet.etherType = TYPE_IPV6;
                hdr.ipv6.setValid();
                hdr.ipv6.version      = 6;
                hdr.ipv6.trafficClass = 0;
                hdr.ipv6.flowLabel    = 0;
                hdr.ipv6.payLoadLen   = 58;  // 14 PolyShim + 20 inner IP + 8 UDP + 16 data
                hdr.ipv6.nextHdr      = POLY_IP_PROTOCOL;
                hdr.ipv6.hopLimit     = 64;
                if (meta.packet_direction == 0) {
                    hdr.ipv6.srcAddr = 0xfe800000000000000000000000001234; // fe80::1234 (h1)
                    hdr.ipv6.dstAddr = 0xfe800000000000000000000000005678; // fe80::5678 (h2)
                } else {
                    hdr.ipv6.srcAddr = 0xfe800000000000000000000000005678; // fe80::5678 (h2)
                    hdr.ipv6.dstAddr = 0xfe800000000000000000000000001234; // fe80::1234 (h1)
                }
            }
            else if (standard_metadata.egress_port == 4) {
                // Source Routing, EtherType 0x1234; stack covers the hops
                // after this gateway's egress port.
                hdr.polyShim.modality_id = MODE_SR;
                hdr.ipv4.setInvalid();
                hdr.ethernet.etherType = TYPE_SRCROUTING;
                if (meta.packet_direction == 0) {
                    // h1 -> h2: s31 out 2, s32 out 2, s2 out 1
                    hdr.srcRoutes[0].setValid(); hdr.srcRoutes[0].bos = 0; hdr.srcRoutes[0].port = 2;
                    hdr.srcRoutes[1].setValid(); hdr.srcRoutes[1].bos = 0; hdr.srcRoutes[1].port = 2;
                    hdr.srcRoutes[2].setValid(); hdr.srcRoutes[2].bos = 1; hdr.srcRoutes[2].port = 1;
                } else {
                    // h2 -> h1: s32 out 1, s31 out 1, s1 out 1
                    hdr.srcRoutes[0].setValid(); hdr.srcRoutes[0].bos = 0; hdr.srcRoutes[0].port = 1;
                    hdr.srcRoutes[1].setValid(); hdr.srcRoutes[1].bos = 0; hdr.srcRoutes[1].port = 1;
                    hdr.srcRoutes[2].setValid(); hdr.srcRoutes[2].bos = 1; hdr.srcRoutes[2].port = 1;
                }
            }
        }
        else if (meta.allow_output == 1) {

            // 失效网络内部头
            hdr.polyShim.setInvalid();
            hdr.ipv6.setInvalid();
            hdr.srcRoutes[0].setInvalid();
            hdr.srcRoutes[1].setInvalid();
            hdr.srcRoutes[2].setInvalid();
            hdr.srcRoutes[3].setInvalid();

            // 目的主机 MAC（与基线拓扑一致：h1=08:00:00:00:01:01，h2=08:00:00:00:02:02）
            if (meta.packet_direction == 0) {
                hdr.ethernet.dstAddr = 0x080000000202;   // h2
            } else {
                hdr.ethernet.dstAddr = 0x080000000101;   // h1
            }

            // 出口端口：从主机侧端口（eth1）发出
            standard_metadata.egress_spec = 1;
        }
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
    apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        // M1/M4: wire order is Ethernet / outer modality header / PolyShim /
        // inner IPv4 / transport / protected data. Header validity decides
        // which modality is serialized.
        packet.emit(hdr.ethernet);
        packet.emit(hdr.srcRoutes);
        packet.emit(hdr.arp);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.ipv6);
        packet.emit(hdr.polyShim);
        packet.emit(hdr.inner_ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
        packet.emit(hdr.protected_data);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
