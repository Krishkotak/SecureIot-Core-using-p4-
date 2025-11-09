#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
import argparse
import os
import sys
import asyncio
import traceback
import ipaddress
import pprint
import json
import logging
import socket
from collections import Counter
from scapy.all import *

import grpc

# Import P4Runtime lib from parent utils dir
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 '../../utils/'))
import p4runtime_lib.bmv2
import p4runtime_lib.helper
from p4runtime_lib.switch import ShutdownAllSwitchConnections

# --- Setup standard Python logging ---
log = logging.getLogger('P4Controller')
log.setLevel(logging.INFO)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

RETRY_TIMES = 3
RETRY_SLEEP_SEC = 0.1

global_data = {}
global_data['CPU_PORT'] = 510
global_data['CPU_PORT_CLONE_SESSION_ID'] = 57
global_data['switches'] = {}
global_data['topology'] = {}
global_data['host_info'] = {}
global_data['link_info'] = {}
global_data['path_cache'] = {}

# --- New Global Data for Authentication ---

# 1. Device Authentication List (Device Profile)
# *** MODIFIED as per user request (h1 -> h3 is disallowed) ***
global_data['allowed_devices'] = {
    "08:00:00:00:01:11": ["10.0.2.2", "10.0.4.4"], # h1 (CANNOT ping h3)
    "08:00:00:00:02:22": ["10.0.1.1", "10.0.3.3", "10.0.4.4"], # h2
    "08:00:00:00:03:33": ["10.0.2.2", "10.0.4.4"], # h3
    "08:00:00:00:04:44": ["10.0.1.1", "10.0.2.2", "10.0.3.3"]  # h4
}

# 2. Cache for generated tags
# Format: (src_mac, dst_ip) -> tag
global_data['flow_tags'] = {}
global_data['next_tag_id'] = 1000 # Start tag IDs from 1000

# 3. Cache for installed validation rules to prevent duplicates
# Format: (switch_name, tag) -> True
global_data['tag_validation_rules'] = {}

# 4. Cache for installed device auth rules
# Format: (switch_name, src_mac, dst_ip) -> True
global_data['flow_auth_rules'] = {}

# 5. *** NEW CACHE *** for proactive drop rules
# Format: (switch_name, src_mac, dst_ip) -> True
global_data['flow_drop_rules'] = {}
# --- End New Global Data ---


def load_topology(topo_file_path):
    """Loads and parses the topology.json file."""
    global global_data
    log.info(f"Loading topology from {topo_file_path}...")
    with open(topo_file_path, 'r') as f:
        topo = json.load(f)

    global_data['topology'] = topo

    host_info = {}
    for h_name, h_details in topo['hosts'].items():
        ip = h_details['ip'].split('/')[0]
        host_info[ip] = {'name': h_name, 'mac': h_details['mac']}

    link_info = {}

    def parse_node(node):
        """Helper to parse node strings like 's1-p1'"""
        if '-p' in node:
            parts = node.split('-p')
            return parts[0], int(parts[1])
        return node, None

    for link in topo['links']:
        node1, node2 = link[0], link[1]

        node1_name, node1_port = parse_node(node1)
        node2_name, node2_port = parse_node(node2)

        if node1_name.startswith('h'):
            h_name, sw_name, sw_port = node1_name, node2_name, node2_port
            for ip, info in host_info.items():
                if info['name'] == h_name:
                    info['switch'] = sw_name
                    info['port'] = sw_port
                    break
            link_info.setdefault(sw_name, {})[h_name] = sw_port

        elif node2_name.startswith('h'):
            h_name, sw_name, sw_port = node2_name, node1_name, node1_port
            for ip, info in host_info.items():
                if info['name'] == h_name:
                    info['switch'] = sw_name
                    info['port'] = sw_port
                    break
            link_info.setdefault(sw_name, {})[h_name] = sw_port

        elif node1_name.startswith('s') and node2_name.startswith('s'):
            sw1_name, sw1_port = node1_name, node1_port
            sw2_name, sw2_port = node2_name, node2_port
            link_info.setdefault(sw1_name, {})[sw2_name] = sw1_port
            link_info.setdefault(sw2_name, {})[sw1_name] = sw2_port

    global_data['host_info'] = host_info
    global_data['link_info'] = link_info
    log.info("Topology loaded:")
    log.info(pprint.pformat(global_data['host_info']))
    log.info(pprint.pformat(global_data['link_info']))


def get_path(src_ip, dst_ip):
    """
    Performs a BFS on the topology to find a simple path.
    Caches results in global_data['path_cache'].
    """
    path_key = (src_ip, dst_ip)
    if path_key in global_data['path_cache']:
        return global_data['path_cache'][path_key]

    graph = global_data['link_info']
    host_info = global_data['host_info']

    if src_ip not in host_info or dst_ip not in host_info:
        log.error(f"Error: IP {src_ip} or {dst_ip} not found in host_info")
        return None

    src_switch = host_info[src_ip]['switch']
    dst_switch = host_info[dst_ip]['switch']

    if src_switch == dst_switch:
        path = [src_switch]
        global_data['path_cache'][path_key] = path
        return path

    queue = [(src_switch, [src_switch])]
    visited = {src_switch}

    while queue:
        (current, path) = queue.pop(0)
        if current not in graph:
            continue

        for neighbor in graph[current]:
            if neighbor == dst_switch:
                full_path = path + [dst_switch]
                global_data['path_cache'][path_key] = full_path
                return full_path

            if neighbor.startswith('s') and neighbor not in visited:
                visited.add(neighbor)
                queue.append((neighbor, path + [neighbor]))

    log.error(f"Error: No path found from {src_switch} to {dst_switch}")
    return None

# --- Helper function to generate deterministic MACs for switch ports ---
def get_port_mac(switch_name, port_num):
    """
    Generates a deterministic MAC address for a switch port.
    e.g., s1, port 2 -> "00:AA:BB:01:02:00"
    """
    sw_id = int(switch_name[1:])
    return f"00:AA:BB:{sw_id:02X}:{port_num:02X}:00"

def ipv4ToInt(addr):
    """Converts a dotted-decimal IPv4 string to an integer."""
    return int.from_bytes(socket.inet_aton(addr), byteorder='big')


def intToIpv4(n):
    """Converts a 32-bit integer to a dotted-decimal IPv4 string."""
    return socket.inet_ntoa(n.to_bytes(4, byteorder='big'))


def decodePacketInMetadata(pktin_info, packet):
    pktin_field_to_val = {}
    for md in packet.metadata:
        md_id_int = md.metadata_id
        md_val_int = int.from_bytes(md.value, byteorder='big')
        if md_id_int not in pktin_info:
            log.warning(f"PacketIn: Unknown metadata field ID: {md_id_int}")
            continue
        md_field_info = pktin_info[md_id_int]
        pktin_field_to_val[md_field_info['name']] = md_val_int
    ret = {'metadata': pktin_field_to_val,
           'payload': packet.payload}
    log.debug(f"decodePacketInMetadata: ret={ret}")
    return ret


def serializableEnumDict(p4info_data, name):
    type_info = p4info_data.type_info
    name_to_int = {}
    int_to_name = {}
    if name not in type_info.serializable_enums:
        log.error(f"Serializable enum '{name}' not found in P4Info.")
        return {}, {}
    for member in type_info.serializable_enums[name].members:
        val = int.from_bytes(member.value, byteorder='big')
        name_to_int[member.name] = val
        int_to_name[val] = member.name
    log.debug(f"serializableEnumDict: name='{name}' name_to_int={name_to_int} int_to_name={int_to_name}")
    return name_to_int, int_to_name


def getObj(p4info_obj_map, obj_type, name):
    key = (obj_type, name)
    return p4info_obj_map.get(key, None)


def controllerPacketMetadataDictKeyId(p4info_obj_map, name):
    cpm_info = getObj(p4info_obj_map, "controller_packet_metadata", name)
    assert cpm_info != None, f"Could not find controller_packet_metadata '{name}'"
    ret = {}
    for md in cpm_info.metadata:
        ret[md.id] = {'id': md.id, 'name': md.name, 'bitwidth': md.bitwidth}
    return ret


def makeP4infoObjMap(p4info_data):
    p4info_obj_map = {}
    suffix_count = Counter()
    for obj_type in ["tables", "action_profiles", "actions", "counters",
                     "direct_counters", "controller_packet_metadata"]:
        for obj in getattr(p4info_data, obj_type):
            pre = obj.preamble
            suffix = None
            for s in reversed(pre.name.split(".")):
                suffix = s if suffix is None else s + "." + suffix
                key = (obj_type, suffix)
                p4info_obj_map[key] = obj
                suffix_count[key] += 1
    for key, c in list(suffix_count.items()):
        if c > 1:
            log.warning(f"P4Info short name {key} is ambiguous, removing.")
            del p4info_obj_map[key]
    return p4info_obj_map


def writeCloneSession(sw, clone_session_id, replicas):
    clone_entry = global_data['p4info_helper'].buildCloneSessionEntry(clone_session_id, replicas, 0)
    sw.WritePREEntry(clone_entry)


async def add_flow_auth_rule(sw, src_mac, dst_ip, tag, port, dst_eth_addr):
    """
    Installs a rule in the flow_auth_table.
    """
    rule_key = (sw.name, src_mac, dst_ip)
    if rule_key in global_data['flow_auth_rules']:
        log.debug(f"FlowAuth rule for ({src_mac}, {intToIpv4(dst_ip)}) already on {sw.name}. Skipping.")
        return True # Return True to indicate success/idempotency

    table_entry = global_data['p4info_helper'].buildTableEntry(
        table_name="MyIngress.flow_auth_table",
        match_fields={
            "hdr.ethernet.srcAddr": src_mac,
            "hdr.ipv4.dstAddr": dst_ip
        },
        action_name="MyIngress.apply_tag_and_forward",
        action_params={
            "tag": tag,
            "port": port,
            "dst_eth_addr": dst_eth_addr
        }
    )
    log.info(f"Installing FlowAuth rule on {sw.name}: "
             f"MAC {src_mac}, IP {intToIpv4(dst_ip)} -> attach tag {tag}, fwd port {port}, next_hop {dst_eth_addr}")
    
    if await write_table_entry(sw, table_entry):
        global_data['flow_auth_rules'][rule_key] = True
        return True
    return False

# *** NEW FUNCTION ***
async def add_proactive_drop_rule(sw, src_mac, dst_ip):
    """
    Installs a proactive drop rule in the flow_auth_table.
    """
    rule_key = (sw.name, src_mac, dst_ip)
    if rule_key in global_data['flow_drop_rules']:
        log.debug(f"FlowDrop rule for ({src_mac}, {intToIpv4(dst_ip)}) already on {sw.name}. Skipping.")
        return True
    
    table_entry = global_data['p4info_helper'].buildTableEntry(
        table_name="MyIngress.flow_auth_table",
        match_fields={
            "hdr.ethernet.srcAddr": src_mac,
            "hdr.ipv4.dstAddr": dst_ip
        },
        action_name="MyIngress.proactive_drop",
        action_params={}
    )
    log.info(f"Installing FlowDrop rule on {sw.name}: "
             f"MAC {src_mac}, IP {intToIpv4(dst_ip)} -> DROP")
    
    if await write_table_entry(sw, table_entry):
        global_data['flow_drop_rules'][rule_key] = True
        return True
    return False


async def add_tag_validation_rule(sw, tag, port, dst_eth_addr, is_final_hop):
    """
    Installs a rule in the validate_tag_table.
    Selects the action based on whether this is the final hop.
    """
    rule_key = (sw.name, tag)
    if rule_key in global_data['tag_validation_rules']:
        log.debug(f"Tag validation rule for tag {tag} already on {sw.name}.")
        return True # Return True to indicate success/idempotency

    if is_final_hop:
        action_name = "MyIngress.decapsulate_and_forward"
        log_info_str = "DEC-FWD"
    else:
        action_name = "MyIngress.forward_tagged_flow"
        log_info_str = "FWD-TAG"

    table_entry = global_data['p4info_helper'].buildTableEntry(
        table_name="MyIngress.validate_tag_table",
        match_fields={
            "hdr.auth_tag.tag": tag
        },
        action_name=action_name,
        action_params={
            "port": port,
            "dst_eth_addr": dst_eth_addr
        }
    )
    log.info(f"Installing TagValidate rule on {sw.name}: "
             f"Tag {tag} -> {log_info_str} port {port}, next_hop {dst_eth_addr}")
    
    if await write_table_entry(sw, table_entry):
        global_data['tag_validation_rules'][rule_key] = True
        return True
    return False


async def write_table_entry(sw, table_entry):
    """
    Writes a table entry with retry logic for transient errors.
    """
    for i in range(RETRY_TIMES):
        try:
            sw.WriteTableEntry(table_entry)
            log.debug(f"Successfully wrote entry to {sw.name}")
            return True
        except grpc.RpcError as e:
            if e.code() == grpc.StatusCode.ALREADY_EXISTS:
                log.warning(f"Rule already exists on {sw.name}. Caching it.")
                return True # Treat as success
            if e.code() == grpc.StatusCode.UNKNOWN:
                log.warning(f"gRPC error writing to {sw.name} (Attempt {i + 1}/{RETRY_TIMES}): {e.code().name}. Retrying...")
                await asyncio.sleep(RETRY_SLEEP_SEC)
            else:
                log.error(f"Non-retriable gRPC error writing to {sw.name}:")
                printGrpcError(e)
                return False
        except Exception as e:
            log.error(f"Unexpected error writing to {sw.name}: {e}")
            traceback.print_exc()
            return False
    log.error(f"Failed to write entry to {sw.name} after {RETRY_TIMES} attempts.")
    return False


def packetOutMetadataList(opcode, reserved1, operand0):
    """
    Builds the PacketOut metadata list based on the P4 program's
    packet_out_header_h definition.
    """
    p4info_helper = global_data['p4info_helper']
    pktout_info = getObj(global_data['p4info_obj_map'],
                         "controller_packet_metadata", "packet_out")
    
    meta = {}
    for field in pktout_info.metadata:
        if field.name == "opcode":
            meta[field.id] = (opcode, field.bitwidth)
        elif field.name == "reserved1":
            meta[field.id] = (reserved1, field.bitwidth)
        elif field.name == "operand0":
            meta[field.id] = (operand0, field.bitwidth)

    return [{"value": val, "bitwidth": bw}
            for _id, (val, bw) in sorted(meta.items())]


def sendPacketOut(sw, payload, metadatas):
    """
    Sends a PacketOut message via the switch connection.
    """
    log.debug(f"Sending PacketOut to {sw.name} with {len(payload)} bytes")
    sw.PacketOut(payload, metadatas)


async def processPacket(message):
    """
    Processes a PacketIn message.
    """
    payload = message["packet-in"].payload
    packet = message["packet-in"]
    ingress_sw_name = message["sw"].name
    ingress_sw = message["sw"]
    
    log.info(f"Received PacketIn message of length {len(payload)} "
             f"bytes from switch {ingress_sw_name}")

    if len(payload) == 0:
        return

    pkt = Ether(payload)
    if not pkt.haslayer(IP):
        log.warning("PacketIn is not IP, ignoring.")
        return

    ip_sa_str = pkt[IP].src
    ip_da_str = pkt[IP].dst
    dst_ip_addr = ipv4ToInt(ip_da_str) # Get Dst IP as int for table rule
    src_mac = pkt[Ether].src
    
    pktinfo = decodePacketInMetadata(global_data['cpm_packetin_id2data'], packet)
    punt_reason_int = pktinfo['metadata']['punt_reason']

    if punt_reason_int == global_data['punt_reason_name2int']['AUTH_REQUIRED']:
        log.info(f"Processing AUTH_REQUIRED PacketIn from {ingress_sw_name} "
                 f"for device: {src_mac} (flow: {ip_sa_str} -> {ip_da_str})")

        # 1. Device Authentication & 2. Service Profile Check
        if (src_mac in global_data['allowed_devices'] and
            ip_da_str in global_data['allowed_devices'][src_mac]):

            log.info(f"Device {src_mac} authenticated for destination {ip_da_str}.")

            # 3. Tag Generation (Corrected: per-flow)
            flow_key = (src_mac, ip_da_str)
            if flow_key in global_data['flow_tags']:
                tag = global_data['flow_tags'][flow_key]
                log.debug(f"Flow {flow_key} already has tag: {tag}")
            else:
                tag = global_data['next_tag_id']
                global_data['next_tag_id'] += 1
                global_data['flow_tags'][flow_key] = tag
                log.info(f"Generated new tag {tag} for flow {flow_key}")

            # 4. Path Calculation and Rule Installation
            path = get_path(ip_sa_str, ip_da_str)
            if not path:
                log.error(f"Could not find path for {ip_sa_str} -> {ip_da_str}.")
                return

            final_dest_mac = global_data['host_info'][ip_da_str]['mac']
            install_tasks = []

            # Find the *true* ingress switch (the one connected to the src_ip)
            true_ingress_sw_name = global_data['host_info'][ip_sa_str]['switch']

            for i in range(len(path)):
                current_switch_name = path[i]
                current_switch_obj = global_data['switches'][current_switch_name]

                is_final_hop = (i == len(path) - 1)

                if is_final_hop:
                    # Last hop switch -> destination host
                    dest_node_name = global_data['host_info'][ip_da_str]['name']
                    output_port = global_data['link_info'][current_switch_name][dest_node_name]
                    next_hop_mac = final_dest_mac
                else:
                    # Ingress or transit switch -> next switch
                    dest_node_name = path[i+1] # This is the next switch name
                    output_port = global_data['link_info'][current_switch_name][dest_node_name]
                    # Get the MAC of the input port on the *next* switch
                    next_switch_input_port = global_data['link_info'][dest_node_name][current_switch_name]
                    next_hop_mac = get_port_mac(dest_node_name, next_switch_input_port)

                # Only install the device_auth_rule on the *true* ingress switch
                if current_switch_name == true_ingress_sw_name:
                    task = add_flow_auth_rule(current_switch_obj,
                                                src_mac, dst_ip_addr, tag, output_port,
                                                next_hop_mac)
                    install_tasks.append(task)
                
                # ALL switches on the path need a Tag->Validate rule.
                task = add_tag_validation_rule(current_switch_obj,
                                                 tag, output_port,
                                                 next_hop_mac,
                                                 is_final_hop=is_final_hop)
                install_tasks.append(task)
                
            await asyncio.gather(*install_tasks)
            
            # 5. Send PacketOut to resume the original packet's journey
            # Only send PacketOut from the *true* ingress switch
            if ingress_sw_name == true_ingress_sw_name:
                log.info(f"Sending PacketOut to {ingress_sw_name} to re-process and forward packet")
                metadatas = packetOutMetadataList(
                    global_data['controller_opcode_name2int']['SEND_TO_PORT_IN_OPERAND0'],
                    0, 0) # Port 0 is unused, just re-process
                sendPacketOut(ingress_sw, payload, metadatas)
            else:
                # This was a packet punted from a transit switch.
                # The rules are now installed, so we can drop this packet.
                # The *next* packet from the host will be tagged correctly.
                log.warning(f"Dropping stale punted packet from transit switch {ingress_sw_name}")

        else:
            # *** NEW LOGIC ***
            # Authentication Failed!
            log.warning(f"Device {src_mac} authentication FAILED for dst {ip_da_str}. "
                        f"Installing proactive drop rule.")
            
            # Find the *true* ingress switch to install the drop rule
            true_ingress_sw_name = global_data['host_info'][ip_sa_str]['switch']
            true_ingress_sw_obj = global_data['switches'][true_ingress_sw_name]
            
            # Install the drop rule on the true ingress switch
            await add_proactive_drop_rule(true_ingress_sw_obj, src_mac, dst_ip_addr)
            
            # We don't need to do anything else. The packet that was
            # punted is already dropped by the P4 program.
            # Subsequent packets will be dropped by the new data plane rule.

    else:
        reason = global_data['punt_reason_int2name'].get(punt_reason_int, 'UNKNOWN')
        log.info(f"Ignoring PacketIn from {ingress_sw_name} with "
                 f"reason {reason} for flow: {ip_sa_str} -> {ip_da_str}")

    return


async def processNotif(notif_queue):
    """Main notification processing loop."""
    while True:
        try:
            notif = await notif_queue.get()
            
            if notif["type"] == "packet-in":
                try:
                    await processPacket(notif)
                except Exception as e:
                    log.error(f"Error processing packet: {e}")
                    traceback.print_exc()
            
            notif_queue.task_done()
        except Exception as e:
            log.error(f"Unexpected error in processNotif loop: {e}")
            traceback.print_exc()


async def packetInHandler(notif_queue, sw):
    """Listens for PacketIn messages from a switch."""
    while True:
        try:
            packet_in = await asyncio.to_thread(sw.PacketIn)
            message = {"type": "packet-in", "sw": sw, "packet-in": packet_in}
            await notif_queue.put(message)
        except grpc.RpcError as e:
            if e.code() != grpc.StatusCode.CANCELLED:
                log.warning(f"[gRPC Error in packetInHandler for {sw.name}]")
                printGrpcError(e)
            else:
                log.info(f"PacketIn stream cancelled for {sw.name}.")
                break
            await asyncio.sleep(1) # Wait before retrying
        except Exception as e:
            log.error(f"[Unexpected Error in packetInHandler for {sw.name}]: {e}")
            traceback.print_exc()
            await asyncio.sleep(1)


def printGrpcError(e):
    log.error(f"gRPC Error: {e.details()} (code: {e.code().name})")
    traceback_obj = sys.exc_info()[2]
    if traceback_obj:
        log.error(f"  -> at {traceback_obj.tb_frame.f_code.co_filename}:"
                  f"{traceback_obj.tb_lineno}")


async def main(p4info_file_path, bmv2_file_path, topo_file_path):
    # Instantiate a P4Runtime helper from the p4info file
    global_data['p4info_helper'] = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)
    p4info_helper = global_data['p4info_helper']

    # Load topology
    try:
        load_topology(topo_file_path)
    except Exception as e:
        log.error(f"Error loading topology file: {e}")
        traceback.print_exc()
        sys.exit(1)

    try:
        # --- DYNAMIC SWITCH CONNECTION ---
        global_data['switches'] = {}
        all_switches = []
        grpc_port_base = 50051  # Standard base port

        # Use the topology.json to find switch names
        switch_names = sorted(global_data['topology']['switches'].keys())
        for device_id, sw_name in enumerate(switch_names):
            grpc_port = grpc_port_base + device_id
            sw = p4runtime_lib.bmv2.Bmv2SwitchConnection(
                name=sw_name,
                address=f'127.0.0.1:{grpc_port}',
                device_id=device_id,
                proto_dump_file=f'logs/{sw_name}-p4runtime-requests.txt'
            )
            global_data['switches'][sw_name] = sw
            all_switches.append(sw)
            log.info(f"Connecting to switch {sw_name} on port {grpc_port} (device_id {device_id})")
        
        for sw in all_switches:
            sw.MasterArbitrationUpdate()
            log.info(f"Established mastership for {sw.name}")
            
        for sw in all_switches:
            sw.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                           bmv2_json_file_path=bmv2_file_path)
            log.info(f"Installed P4 Program on {sw.name}")
        # --- END DYNAMIC SWITCH CONNECTION ---

        # Parse P4Info for metadata IDs
        global_data['p4info_obj_map'] = makeP4infoObjMap(p4info_helper.p4info)
        global_data['cpm_packetin_id2data'] = \
            controllerPacketMetadataDictKeyId(global_data['p4info_obj_map'], "packet_in")

        (global_data['punt_reason_name2int'],
         global_data['punt_reason_int2name']) = \
            serializableEnumDict(p4info_helper.p4info, 'PuntReason_t')
        
        (global_data['controller_opcode_name2int'],
         global_data['controller_opcode_int2name']) = \
            serializableEnumDict(p4info_helper.p4info, 'ControllerOpcode_t')

        # Configure clone session for Packet-In
        replicas = [{"egress_port": global_data['CPU_PORT'], "instance": 1}]
        for sw in all_switches:
            writeCloneSession(sw, global_data['CPU_PORT_CLONE_SESSION_ID'], replicas)
        log.info("Configured clone sessions for Packet-In on all switches")
        
        # Add Egress SMAC rules (optional, for correct L2 forwarding)
        for sw_name, links in global_data['link_info'].items():
            if sw_name not in global_data['switches']:
                log.warning(f"Switch {sw_name} from link_info not in connected switches. Skipping SMAC rule.")
                continue
            sw = global_data['switches'][sw_name]
            for node_name, port_num in links.items():
                smac = get_port_mac(sw_name, port_num)
                smac_rule = p4info_helper.buildTableEntry(
                    table_name="MyEgress.egress_smac",
                    match_fields={"standard_metadata.egress_port": port_num},
                    action_name="MyEgress.set_egress_smac",
                    action_params={"smac": smac}
                )
                await write_table_entry(sw, smac_rule)
        log.info("Installed egress source MAC rules on all switches")


        # Start listening for notifications
        notif_queue = asyncio.Queue()
        tasks = [asyncio.create_task(processNotif(notif_queue))]
        for sw in all_switches:
            tasks.append(asyncio.create_task(packetInHandler(notif_queue, sw)))
        
        await asyncio.gather(*tasks)

    except KeyboardInterrupt:
        log.warning(" Shutting down.")
    except grpc.RpcError as e:
        log.error(f"gRPC error occurred in main: {e}")
        printGrpcError(e)
    except Exception as e:
        log.error(f"An unexpected error occurred in main: {e}")
        traceback.print_exc()

    ShutdownAllSwitchConnections()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='P4Runtime Controller')
    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                        type=str, action="store", required=False,
                        default='./build/flowcache.p4.p4info.txtpb')
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
                        type=str, action="store", required=False,
                        default='./build/flowcache.json')
    # Use the new topology file as the default
    parser.add_argument('--topo', help='Topology JSON file',
                        type=str, action="store", required=False,
                        default='topology.json')
    parser.add_argument('--log-level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
                        default='INFO', help='Set the logging level')
    args = parser.parse_args()

    # Set log level
    log.setLevel(getattr(logging, args.log_level))

    topo_file = args.topo
    if not os.path.exists(topo_file):
        log.error(f"Error: Topology file not found: {topo_file}")
        parser.print_help()
        sys.exit(1)

    # Use the P4 program name from the makefile
    p4info_file = args.p4info
    bmv2_file = args.bmv2_json

    if not os.path.exists(p4info_file):
        log.error(f"\nP4Info file not found: {p4info_file}\n"
                  f"Have you run 'make'?")
        parser.exit(1)
    if not os.path.exists(bmv2_file):
        log.error(f"\nBMv2 JSON file not found: {bmv2_file}\n"
                  f"Have you run 'make'?")
        parser.exit(1)

    asyncio.run(main(p4info_file, bmv2_file, topo_file))