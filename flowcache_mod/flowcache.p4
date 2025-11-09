// SPDX-License-Identifier: Apache-2.0
/* -*- P4_16 -*- */

#include <core.p4>
#include <v1model.p4>

// typedef bit<9>  egressSpec_t; // Removed, was unused
typedef bit<9>  PortId_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<32> AuthTag_t; // Type for our validation tag

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_AUTH_TAG = 0x1234; // Custom EtherType for tagged packets

typedef bit<16> PortIdToController_t;
const int CPU_PORT_CLONE_SESSION_ID = 57;
const int FL_PACKET_IN = 1;

#define CPU_PORT 510

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

header ethernet_h {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

// New header for the validation tag
header auth_tag_t {
    AuthTag_t tag;
}

header ipv4_h {
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

enum bit<8> ControllerOpcode_t {
    NO_OP                    = 0,
    SEND_TO_PORT_IN_OPERAND0 = 1 // We'll re-purpose this to mean "reprocess"
}

// Added a new reason for punting to the controller
enum bit<8> PuntReason_t {
    NO_PUNT             = 0,
    AUTH_REQUIRED       = 1,
    UNRECOGNIZED_OPCODE = 2
}

@controller_header("packet_out")
header packet_out_header_h {
    ControllerOpcode_t   opcode;
    bit<8>  reserved1;
    bit<32> operand0; // This will be unused by our new P4 logic
}

@controller_header("packet_in")
header packet_in_header_h {
   PortIdToController_t input_port;
   PuntReason_t         punt_reason;
   ControllerOpcode_t   opcode;
}

struct metadata_t {
    @field_list(FL_PACKET_IN)
    PortId_t             ingress_port;
    @field_list(FL_PACKET_IN)
    PuntReason_t         punt_reason;
    @field_list(FL_PACKET_IN)
    ControllerOpcode_t   opcode;
}

struct headers_t {
    packet_in_header_h  packet_in;
    packet_out_header_h packet_out;
    ethernet_h ethernet;
    auth_tag_t auth_tag; // Added tag header
    ipv4_h     ipv4;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                  out headers_t hdr,
                  inout metadata_t meta,
                  inout standard_metadata_t standard_metadata)
{
    state start {
        transition check_for_cpu_port;
    }
    state check_for_cpu_port {
        transition select (standard_metadata.ingress_port) {
            CPU_PORT: parse_controller_packet_out_header;
            default: parse_ethernet;
        }
    }
    state parse_controller_packet_out_header {
        packet.extract(hdr.packet_out);
        // The payload of the PacketOut is the original Ethernet frame
        transition parse_ethernet;
    }
    state parse_ethernet {
        packet.extract(hdr.ethernet);
        // Check for auth tag or plain IPv4
        transition select (hdr.ethernet.etherType) {
            TYPE_IPV4:     parse_ipv4;
            TYPE_AUTH_TAG: parse_auth_tag;
            default:       accept;
        }
    }
    // New state to parse the auth tag
    state parse_auth_tag {
        packet.extract(hdr.auth_tag);
        // We assume the tagged packet encapsulates IPv4
        transition parse_ipv4;
    }
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }
}

/*************************************************************************
************ C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/
control MyVerifyChecksum(inout headers_t hdr, inout metadata_t meta) {
    apply {
        // We only verify the checksum for untagged, valid IPv4 packets.
        // Packets from the CPU (PacketOut) will be re-processed, but we
        // can assume their checksum is valid.
        verify_checksum(!hdr.auth_tag.isValid() && hdr.ipv4.isValid() && hdr.ipv4.ihl == 5 && !hdr.packet_out.isValid(),
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
            hdr.ipv4.hdrChecksum, HashAlgorithm.csum16);
    }
}

/*************************************************************************
************** I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers_t hdr,
                  inout metadata_t meta,
                  inout standard_metadata_t standard_metadata){

    // --- Counters ---
    counter(1024, CounterType.packets_and_bytes) auth_required_counter;
    counter(8192, CounterType.packets_and_bytes) tag_validated_counter;
    counter(8192, CounterType.packets_and_bytes) tag_invalid_counter;

    // --- Actions ---
    action send_to_controller_with_details(
        PuntReason_t       punt_reason,
        ControllerOpcode_t opcode)
    {
        standard_metadata.egress_spec = CPU_PORT;
        meta.ingress_port = standard_metadata.ingress_port;
        meta.punt_reason = punt_reason;
        meta.opcode = opcode;
    }
    
    action send_copy_to_controller(
        PuntReason_t       punt_reason,
        ControllerOpcode_t opcode)
    {
        clone_preserving_field_list(CloneType.I2E, CPU_PORT_CLONE_SESSION_ID, FL_PACKET_IN);
        meta.ingress_port = standard_metadata.ingress_port;
        meta.punt_reason = punt_reason;
        meta.opcode = opcode;
    }
    
    action drop_packet() {
        mark_to_drop(standard_metadata);
    }

    // *** NEW ACTION ***
    // Action for Ingress Switch: Proactively drop unauthorized flows
    action proactive_drop() {
        drop_packet();
    }

    // Action for Ingress Switch: Apply tag and forward
    action apply_tag_and_forward(AuthTag_t tag, PortId_t port,
                                 macAddr_t dst_eth_addr)
    {
        // Add the tag
        hdr.auth_tag.setValid();
        hdr.auth_tag.tag = tag;
        hdr.ethernet.etherType = TYPE_AUTH_TAG;

        // Forwarding logic
        standard_metadata.egress_spec = port;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        hdr.ethernet.dstAddr = dst_eth_addr;
        // The ingress switch's source MAC will be set in Egress
    }

    // Action for Ingress Switch: Punt to controller for auth
    action auth_required () {
        send_copy_to_controller(PuntReason_t.AUTH_REQUIRED,
                                ControllerOpcode_t.NO_OP);
        auth_required_counter.count(1); // Count auth requests
        drop_packet();
    }

    // Action for Transit Switch: Forward tagged packet
    action forward_tagged_flow (PortId_t port, macAddr_t dst_eth_addr)
    {
        standard_metadata.egress_spec = port;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        hdr.ethernet.dstAddr = dst_eth_addr;
        // The switch's source MAC will be set in Egress
        tag_validated_counter.count(1); // Count valid tagged packets
    }

    // Action for Egress Switch: Decapsulate tag and forward to host
    action decapsulate_and_forward (PortId_t port, macAddr_t dst_eth_addr)
    {
        // Remove the tag
        hdr.auth_tag.setInvalid();
        hdr.ethernet.etherType = TYPE_IPV4; // Restore EtherType

        // Forwarding logic
        standard_metadata.egress_spec = port;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        hdr.ethernet.dstAddr = dst_eth_addr;
        tag_validated_counter.count(1);
    }

    action drop_invalid_tag() {
        tag_invalid_counter.count(1); // Count invalid tagged packets
        drop_packet();
    }

    // --- Tables ---

    // Table for Ingress Switch: Check flow authentication
    table flow_auth_table {
        key = {
            hdr.ethernet.srcAddr : exact;
            hdr.ipv4.dstAddr     : exact; // Match on Dst IP as well
        }
        actions = {
            apply_tag_and_forward;
            proactive_drop; // *** ADDED ACTION ***
            auth_required;
        }
        default_action = auth_required();
        size = 8192; // Increased size for more flows
    }

    // Table for Downstream Switches: Validate tag
    table validate_tag_table {
        key = {
            hdr.auth_tag.tag : exact;
        }
        actions = {
            forward_tagged_flow;     // For transit hops
            decapsulate_and_forward; // For final hop
            drop_invalid_tag;
        }
        default_action = drop_invalid_tag();
        size = 8192;
    }

    apply {
        if (hdr.packet_out.isValid()) {
            // Process packet from controller
            switch (hdr.packet_out.opcode) {
                ControllerOpcode_t.SEND_TO_PORT_IN_OPERAND0: {
                    // This action now means "re-process this packet".
                    // We just invalidate the header and let the packet
                    // fall through to the logic below.
                    hdr.packet_out.setInvalid();
                }
                default: {
                    send_to_controller_with_details(
                        PuntReason_t.UNRECOGNIZED_OPCODE,
                        hdr.packet_out.opcode);
                    hdr.packet_out.setInvalid();
                    // Also drop the packet payload
                    drop_packet();
                }
            }
        }
        
        // Note: This is NOT 'else if'.
        // Packets from the controller will fall through to here.
        if (hdr.auth_tag.isValid()) {
            // Packet is tagged -> This is a downstream/egress switch.
            // Validate the tag.
            validate_tag_table.apply();
        } else if (hdr.ipv4.isValid()) {
            // Packet is untagged IPv4 -> This is an ingress switch
            // OR it's a PacketOut payload being reprocessed.
            flow_auth_table.apply();
        } else {
            // Drop other packet types if they are not from controller
            // and not IPv4/tagged.
            // We must check if the packet_in header is valid, because
            // this code block is also executed in egress when forming
            // a packet-in message, but we don't want to drop that.
            if (hdr.packet_in.isValid() == false) {
                 drop_packet();
            }
        }
    }
}

/*************************************************************************
**************** E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers_t hdr,
                 inout metadata_t meta,
                 inout standard_metadata_t standard_metadata){

    // Simple action to rewrite the source MAC on forwarded packets
    action set_egress_smac(macAddr_t smac) {
        hdr.ethernet.srcAddr = smac;
    }
    
    table egress_smac {
        key = {
            standard_metadata.egress_port: exact;
        }
        actions = {
            set_egress_smac;
            NoAction;
        }
        default_action = NoAction;
        size = 256;
    }

    action prepend_packet_in_hdr (
        PuntReason_t punt_reason,
        PortId_t ingress_port)
    {
        hdr.packet_in.setValid();
        hdr.packet_in.input_port = (PortIdToController_t) ingress_port;
        hdr.packet_in.punt_reason = punt_reason;
        hdr.packet_in.opcode = ControllerOpcode_t.NO_OP;
    }
    
    apply {
        if (standard_metadata.egress_port == CPU_PORT) {
            prepend_packet_in_hdr(meta.punt_reason, meta.ingress_port);
        } else {
            // If not sending to CPU, rewrite SMAC based on egress port
            // This table can be populated by the controller to set the
            // correct source MAC for each port.
            egress_smac.apply();
        }
    }
}

/*************************************************************************
************* C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers_t hdr, inout metadata_t meta) {
     apply {
        // Recalculate IPv4 checksum if TTL was decremented
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
*********************** D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers_t hdr) {
    apply {
        packet.emit(hdr.packet_in);
        packet.emit(hdr.ethernet);
        packet.emit(hdr.auth_tag); // Emit the tag if it's valid
        packet.emit(hdr.ipv4);
    }
}

/*************************************************************************
*********************** S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;