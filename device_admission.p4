// SPDX-License-Identifier: Apache-2.0
/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_DEVICE_ADMISSION = 0x9999;  // Custom EtherType for admission

// Service profile types
const bit<8> PROFILE_IOT_SENSOR = 1;
const bit<8> PROFILE_IOT_ACTUATOR = 2;
const bit<8> PROFILE_CRITICAL_DEVICE = 3;
const bit<8> PROFILE_GUEST_DEVICE = 4;

// Admission status codes
const bit<8> STATUS_ADMITTED = 1;
const bit<8> STATUS_DENIED_NO_ENTRY = 2;
const bit<8> STATUS_DENIED_INVALID_TOKEN = 3;
const bit<8> STATUS_DENIED_PROFILE_VIOLATION = 4;
const bit<8> STATUS_DENIED_ANOMALY_DETECTED = 5;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<64> deviceId_t;     // Device identifier (could be MAC-based)
typedef bit<128> token_t;        // Cryptographic token (128-bit for simplicity)

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

// Device Admission Token Header (attached after admission)
header device_token_t {
    deviceId_t device_id;        // Device identifier
    token_t    token;             // Cryptographic token
    bit<8>     service_profile;   // Service profile type
    bit<8>     admission_status;  // Status of admission check
    bit<32>    timestamp;         // Admission timestamp
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

// Metadata for device admission processing
struct device_admission_metadata_t {
    deviceId_t device_id;
    token_t    expected_token;
    bit<8>     service_profile;
    bit<1>     is_admitted;
    bit<1>     anomaly_detected;
    bit<32>    packet_count;
    bit<32>    byte_count;
}

struct metadata {
    device_admission_metadata_t device_admission;
}

struct headers {
    ethernet_t      ethernet;
    device_token_t  device_token;
    ipv4_t          ipv4;
}

/*************************************************************************
*********************** P A R S E R  *************************************
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
            TYPE_DEVICE_ADMISSION: parse_device_token;
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_device_token {
        packet.extract(hdr.device_token);
        transition select(hdr.device_token.admission_status) {
            STATUS_ADMITTED: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
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

    // Counters for anomaly detection per device
    counter(1024, CounterType.packets_and_bytes) device_traffic_counter;
    counter(1024, CounterType.packets) admission_denied_counter;
    counter(1024, CounterType.packets) anomaly_counter;

    // Registers for stateful anomaly detection
    register<bit<32>>(1024) last_packet_time;
    register<bit<32>>(1024) packet_rate;

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    // ========== DEVICE ADMISSION TABLE (DAT) ==========
    // Maps device_id to token and service_profile
    action admit_device(token_t token, bit<8> service_profile) {
        meta.device_admission.expected_token = token;
        meta.device_admission.service_profile = service_profile;
        meta.device_admission.is_admitted = 1;
    }

    action deny_device_no_entry() {
        meta.device_admission.is_admitted = 0;
        admission_denied_counter.count((bit<32>)0);
        mark_to_drop(standard_metadata);
    }

    // Device Admission Table (DAT)
    // Populated by controller at bootstrap
    table device_admission_table {
        key = {
            meta.device_admission.device_id: exact;
        }
        actions = {
            admit_device;
            deny_device_no_entry;
        }
        size = 1024;
        default_action = deny_device_no_entry();
    }

    // ========== SERVICE PROFILE ENFORCEMENT ==========
    // Different profiles have different allowed traffic patterns
    action enforce_iot_sensor_profile() {
        // IoT sensors: low bandwidth, periodic traffic
        // Check if packet rate is within bounds
        bit<32> current_time = standard_metadata.ingress_global_timestamp[31:0];
        bit<32> last_time;
        bit<32> rate;
        bit<32> device_index = (bit<32>)meta.device_admission.device_id[31:0];
        
        last_packet_time.read(last_time, device_index);
        packet_rate.read(rate, device_index);
        
        // Simple rate limiting: if packets arrive too fast, mark anomaly
        if (current_time - last_time < 1000) {  // Less than 1ms apart
            rate = rate + 1;
        } else {
            rate = 0;
        }
        
        if (rate > 100) {  // More than 100 packets in rapid succession
            meta.device_admission.anomaly_detected = 1;
            anomaly_counter.count(device_index);
        }
        
        last_packet_time.write(device_index, current_time);
        packet_rate.write(device_index, rate);
    }

    action enforce_iot_actuator_profile() {
        // IoT actuators: moderate bandwidth, command-response pattern
        // Add specific checks here
    }

    action enforce_critical_device_profile() {
        // Critical devices: high priority, strict monitoring
        // Add specific checks here
    }

    action enforce_guest_device_profile() {
        // Guest devices: restricted access, heavy monitoring
        // Add specific checks here
    }

    table service_profile_enforcement {
        key = {
            meta.device_admission.service_profile: exact;
        }
        actions = {
            enforce_iot_sensor_profile;
            enforce_iot_actuator_profile;
            enforce_critical_device_profile;
            enforce_guest_device_profile;
            NoAction;
        }
        size = 16;
        default_action = NoAction();
    }

    // ========== TOKEN ATTACHMENT ==========
    action attach_admission_token() {
        // Create device token header
        hdr.device_token.setValid();
        hdr.device_token.device_id = meta.device_admission.device_id;
        hdr.device_token.token = meta.device_admission.expected_token;
        hdr.device_token.service_profile = meta.device_admission.service_profile;
        hdr.device_token.timestamp = standard_metadata.ingress_global_timestamp[31:0];
        
        if (meta.device_admission.anomaly_detected == 1) {
            hdr.device_token.admission_status = STATUS_DENIED_ANOMALY_DETECTED;
            mark_to_drop(standard_metadata);
        } else {
            hdr.device_token.admission_status = STATUS_ADMITTED;
        }
        
        // Update EtherType to indicate token present
        hdr.ethernet.etherType = TYPE_DEVICE_ADMISSION;
    }

    // ========== STANDARD IP FORWARDING ==========
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

    // ========== MAIN APPLY BLOCK ==========
    apply {
        // Step 1: Extract device ID from source MAC (or other identifier)
        // In production, you might use 802.1X, RADIUS, or custom protocol
        meta.device_admission.device_id = (bit<64>)hdr.ethernet.srcAddr;
        
        // Step 2: Check if packet already has admission token
        if (hdr.device_token.isValid()) {
            // Already admitted, verify token matches
            if (hdr.device_token.token == meta.device_admission.expected_token) {
                // Token valid, continue processing
                meta.device_admission.is_admitted = 1;
            } else {
                // Invalid token - security violation!
                admission_denied_counter.count((bit<32>)1);
                drop();
                return;
            }
        } else {
            // Step 3: Perform device admission check (DAT lookup)
            device_admission_table.apply();
            
            // Step 4: If not admitted, drop immediately
            if (meta.device_admission.is_admitted == 0) {
                return;  // Already marked for drop
            }
            
            // Step 5: Enforce service profile checks
            service_profile_enforcement.apply();
            
            // Step 6: If anomaly detected, drop
            if (meta.device_admission.anomaly_detected == 1) {
                drop();
                return;
            }
            
            // Step 7: Attach admission token to packet
            attach_admission_token();
        }
        
        // Step 8: Update traffic counters for monitoring
        bit<32> device_index = (bit<32>)meta.device_admission.device_id[31:0];
        device_traffic_counter.count(device_index);
        
        // Step 9: Perform standard IP forwarding
        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
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
        // At egress, you might want to remove the token before sending to host
        // Or keep it for end-to-end verification
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
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
        packet.emit(hdr.ethernet);
        packet.emit(hdr.device_token);  // Emit token if present
        packet.emit(hdr.ipv4);
    }
}

/*************************************************************************
***********************  S W I T C H  ***********************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
