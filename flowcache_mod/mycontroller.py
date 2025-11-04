#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
import argparse
import os
import sys
import asyncio
import traceback
import time
import ipaddress
import pprint
import json
import logging
from collections import Counter
from datetime import datetime, timedelta
from scapy.all import *

import grpc

# Import P4Runtime lib from parent utils dir
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 '../../utils/'))
import p4runtime_lib.bmv2
import p4runtime_lib.helper
from p4runtime_lib.switch import ShutdownAllSwitchConnections
import p4runtime_sh.p4runtime as shp4rt

# --- Setup standard Python logging ---
log = logging.getLogger('P4Controller')
log.setLevel(logging.INFO)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

NSEC_PER_SEC = 1000 * 1000 * 1000
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

# ### DISABLED IDLE TIMEOUT ###
# global_data['flow_lock'] = asyncio.Lock()
# global_data['active_flows'] = {}


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
    for link in topo['links']:
        node1, node2 = link[0], link[1]

        def parse_node(node):
            if '-p' in node:
                parts = node.split('-p')
                return parts[0], int(parts[1])
            return node, None

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
            link_info.setdefault(h_name, {})[sw_name] = 0

        elif node2_name.startswith('h'):
            h_name, sw_name, sw_port = node2_name, node1_name, node1_port
            for ip, info in host_info.items():
                if info['name'] == h_name:
                    info['switch'] = sw_name
                    info['port'] = sw_port
                    break
            link_info.setdefault(sw_name, {})[h_name] = sw_port
            link_info.setdefault(h_name, {})[sw_name] = 0

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


def ipv4ToInt(addr):
    """Converts a dotted-decimal IPv4 string to an integer."""
    return int.from_bytes(socket.inet_aton(addr), byteorder='big')


def intToIpv4(n):
    """Converts a 32-bit integer to a dotted-decimal IPv4 string."""
    return socket.inet_ntoa(n.to_bytes(4, byteorder='big'))


def flowCacheEntryToDebugStr(table_entry):
    """
    Generates a P4Info-aware debug string for a flow_cache table entry.
    """
    p4info_helper = global_data['p4info_helper']
    table_name = "MyIngress.flow_cache"
    
    parts = []
    for match_field in table_entry.match:
        field_name = p4info_helper.get_match_field_name(table_name, match_field.field_id)
        
        if field_name == "hdr.ipv4.protocol":
            val = int.from_bytes(match_field.exact.value, byteorder='big')
            parts.append(f"proto={val}")
        elif field_name == "hdr.ipv4.srcAddr":
            val = intToIpv4(int(ipaddress.IPv4Address(match_field.exact.value)))
            parts.append(f"SA={val}")
        elif field_name == "hdr.ipv4.dstAddr":
            val = intToIpv4(int(ipaddress.IPv4Address(match_field.exact.value)))
            parts.append(f"DA={val}")
            
    return f"({', '.join(parts)})"


def get_flow_key_from_table_entry(table_entry):
    """
    Extracts the (src_ip_int, dst_ip_int, proto) tuple from a table entry.
    """
    p4info_helper = global_data['p4info_helper']
    table_name = "MyIngress.flow_cache"
    
    src_ip, dst_ip, proto = None, None, None
    
    for match_field in table_entry.match:
        field_name = p4info_helper.get_match_field_name(table_name, match_field.field_id)
        if field_name == "hdr.ipv4.protocol":
            proto = int.from_bytes(match_field.exact.value, byteorder='big')
        elif field_name == "hdr.ipv4.srcAddr":
            src_ip = int(ipaddress.IPv4Address(match_field.exact.value))
        elif field_name == "hdr.ipv4.dstAddr":
            dst_ip = int(ipaddress.IPv4Address(match_field.exact.value))
    
    if src_ip is None or dst_ip is None or proto is None:
        log.warning(f"Could not parse full flow key from table entry: {table_entry}")
        return None
        
    return (src_ip, dst_ip, proto)


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


async def addFlowRule(ingress_sw, src_ip_addr, dst_ip_addr, protocol, port,
                      new_dscp, decrement_ttl_bool, dst_eth_addr):
    """
    Builds and installs a flow rule in the flow cache table with retry.
    """
    table_entry = global_data['p4info_helper'].buildTableEntry(
        table_name="MyIngress.flow_cache",
        match_fields={
            "hdr.ipv4.protocol": protocol,
            "hdr.ipv4.srcAddr": src_ip_addr,
            "hdr.ipv4.dstAddr": dst_ip_addr
        },
        action_name="MyIngress.cached_action",
        action_params={
            "port":           port,
            "decrement_ttl":  1 if decrement_ttl_bool else 0,
            "new_dscp":       new_dscp,
            "dst_eth_addr":   dst_eth_addr
        }
        # ### DISABLED IDLE TIMEOUT ###
        # idle_timeout_ns=3 * NSEC_PER_SEC
    )
    
    log.info(f"Installing rule on {ingress_sw.name}: "
             f"{flowCacheEntryToDebugStr(table_entry)} -> "
             f"port {port}, mac {dst_eth_addr}")
    
    await write_table_entry(ingress_sw, table_entry)


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
            if e.code() == grpc.StatusCode.UNKNOWN or e.code() == grpc.StatusCode.ALREADY_EXISTS:
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


def createFlowRule(notif):
    """
    Creates a table_entry object from an idle timeout notification.
    This version is P4Info-aware and robust.
    """
    p4info_helper = global_data['p4info_helper']
    table_name = "MyIngress.flow_cache"
    
    match_fields_from_notif = {}
    notif_entry = notif["idle"].table_entry[0]
    
    for match_field in notif_entry.match:
        field_name = p4info_helper.get_match_field_name(table_name, match_field.field_id)
        
        if field_name == "hdr.ipv4.protocol":
            value = int.from_bytes(match_field.exact.value, byteorder='big')
        elif field_name == "hdr.ipv4.srcAddr" or field_name == "hdr.ipv4.dstAddr":
            value = int(ipaddress.IPv4Address(match_field.exact.value))
        else:
            value = p4info_helper.get_match_field_value(match_field)
            
        match_fields_from_notif[field_name] = value

    table_entry = p4info_helper.buildTableEntry(
        table_name=table_name,
        match_fields=match_fields_from_notif
    )
    return table_entry


async def deleteFlowRule(sw, table_entry):
    """
    Deletes a table entry with retry logic.
    """
    log.info(f"Deleting flow_cache entry on {sw.name}: "
             f"{flowCacheEntryToDebugStr(table_entry)}")
    
    for i in range(RETRY_TIMES):
        try:
            sw.DeleteTableEntry(table_entry)
            log.debug(f"Successfully deleted entry from {sw.name}")
            return True
        except grpc.RpcError as e:
            if e.code() == grpc.StatusCode.UNKNOWN or e.code() == grpc.StatusCode.NOT_FOUND:
                log.warning(f"gRPC error deleting from {sw.name} (Attempt {i + 1}/{RETRY_TIMES}): {e.code().name}. Retrying...")
                await asyncio.sleep(RETRY_SLEEP_SEC)
            else:
                log.warning(f"Non-retriable gRPC error deleting from {sw.name} (may be ok):")
                printGrpcError(e)
                return False
        except Exception as e:
            log.error(f"Unexpected error deleting from {sw.name}: {e}")
            traceback.print_exc()
            return False
    log.error(f"Failed to delete entry from {sw.name} after {RETRY_TIMES} attempts.")
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


def readTableRules(p4info_helper, sw):
    """
    Reads and logs all table entries from the switch.
    """
    log.info(f'\n----- Reading tables rules for {sw.name} -----')
    for response in sw.ReadTableEntries():
        for entity in response.entities:
            entry = entity.table_entry
            log.info(entry)
            log.info('-----')


def printCounter(p4info_helper, sw, counter_name, index):
    """
    Reads and logs a specific counter entry.
    """
    try:
        for response in sw.ReadCounters(p4info_helper.get_counters_id(counter_name), index):
            for entity in response.entities:
                counter = entity.counter_entry
                log.info(f"{sw.name} {counter_name} {index}: "
                         f"{counter.data.packet_count} packets "
                         f"({counter.data.byte_count} bytes)")
    except grpc.RpcError as e:
        log.warning(f"[gRPC Error in printCounter for {sw.name}]")
        printGrpcError(e)
    except Exception as e:
        log.error(f"[Unexpected Error in printCounter for {sw.name}]: {e}")
        traceback.print_exc()

def is_device_authenticated(dst_ip, src_mac):
    """
    Checks if a device (IP, MAC) pair is allowed on the network.
    Uses global_data['allowed_devices'] which maps allowed MACs to their IPs and services.
    """
    allowed = global_data.get('allowed_devices', {})

    if src_mac in allowed:
        expected_ip = allowed[src_mac]['ip']
        if expected_ip == dst_ip:
            print(f"[Auth] Device {src_mac}  authenticated for service {allowed[src_mac]['service']} on ip {dst_ip}")
            return True
        else:
            print(f"[Auth] Device {src_mac} has mismatched IP (expected {expected_ip}, got {dst_ip})")
            return False
    else:
        print(f"[Auth] Unknown device {src_mac}, rejecting.")
        return False


async def processPacket(message):
    """
    Processes a PacketIn message.
    Authenticates (src_mac, dst_ip) pairs and installs bidirectional flow rules.
    """
    payload = message["packet-in"].payload
    packet = message["packet-in"]
    ingress_sw_name = message["sw"].name
    log.info(f"Received PacketIn message of length {len(payload)} bytes from switch {ingress_sw_name}")

    if len(payload) == 0:
        return None

    pkt = Ether(payload)
    if not pkt.haslayer(IP):
        log.warning("PacketIn is not IP, ignoring.")
        return None

    ip_proto = pkt[IP].proto
    ip_sa_str = pkt[IP].src
    ip_da_str = pkt[IP].dst
    src_ip_addr = ipv4ToInt(ip_sa_str)
    dst_ip_addr = ipv4ToInt(ip_da_str)
    counter_index = int(pkt[IP].dst.split('.')[3])
    flow_key = (src_ip_addr, dst_ip_addr, ip_proto)

    pktinfo = decodePacketInMetadata(global_data['cpm_packetin_id2data'], packet)

    # Ignore PacketIns that aren't flow-miss
    if pktinfo['metadata']['punt_reason'] != global_data['punt_reason_name2int']['FLOW_UNKNOWN']:
        reason = global_data['punt_reason_int2name'].get(pktinfo['metadata']['punt_reason'], 'UNKNOWN')
        log.info(f"Ignoring PacketIn from {ingress_sw_name} with reason {reason} for flow: {ip_sa_str} -> {ip_da_str}")
        return counter_index

    log.info(f"Processing FLOW_UNKNOWN PacketIn from {ingress_sw_name} for flow: {ip_sa_str} -> {ip_da_str}")

    # --- AUTHENTICATION CHECK ---
    src_mac = pkt.src
    if not is_device_authenticated(ip_da_str, src_mac):
        log.warning(f"[SECURITY] Unauthorized device {src_mac} attempting to send packet from {ip_sa_str}. Dropping.")
        return
    # --- END AUTHENTICATION CHECK ---

    # --- PATH COMPUTATION ---
    path = get_path(ip_sa_str, ip_da_str)
    if not path:
        log.error(f"Could not find path for {ip_sa_str} -> {ip_da_str}. Packet will be dropped.")
        return counter_index

    final_dest_mac = global_data['host_info'][ip_da_str]['mac']
    packet_out_port = None

    # --- FORWARD FLOW INSTALLATION (src -> dst) ---
    forward_tasks = []
    for i in range(len(path)):
        current_switch_name = path[i]
        current_switch_obj = global_data['switches'][current_switch_name]

        if i == len(path) - 1:
            dest_host_name = global_data['host_info'][ip_da_str]['name']
            output_port = global_data['link_info'][current_switch_name][dest_host_name]
            dest_mac = final_dest_mac
        else:
            next_switch_name = path[i + 1]
            output_port = global_data['link_info'][current_switch_name][next_switch_name]
            dest_mac = final_dest_mac

        if i == 0:
            packet_out_port = output_port

        forward_tasks.append(addFlowRule(
            current_switch_obj, src_ip_addr, dst_ip_addr, ip_proto,
            output_port, new_dscp=5, decrement_ttl_bool=True, dst_eth_addr=dest_mac))

    # --- REVERSE FLOW INSTALLATION (dst -> src) ---
    reverse_tasks = []
    reverse_src_ip_addr = dst_ip_addr
    reverse_dst_ip_addr = src_ip_addr
    reverse_src_mac = final_dest_mac
    reverse_dst_mac = pkt.src

    reverse_path = list(reversed(path))
    for i in range(len(reverse_path)):
        current_switch_name = reverse_path[i]
        current_switch_obj = global_data['switches'][current_switch_name]

        if i == len(reverse_path) - 1:
            dest_host_name = global_data['host_info'][ip_sa_str]['name']
            output_port = global_data['link_info'][current_switch_name][dest_host_name]
            dest_mac = reverse_dst_mac
        else:
            next_switch_name = reverse_path[i + 1]
            output_port = global_data['link_info'][current_switch_name][next_switch_name]
            dest_mac = reverse_dst_mac

        reverse_tasks.append(addFlowRule(
            current_switch_obj, reverse_src_ip_addr, reverse_dst_ip_addr, ip_proto,
            output_port, new_dscp=5, decrement_ttl_bool=True, dst_eth_addr=dest_mac))

    # Install both directions concurrently
    await asyncio.gather(*(forward_tasks + reverse_tasks))

    # Send the original packet out from ingress switch
    if packet_out_port is not None:
        log.info(f"Sending PacketOut to {ingress_sw_name} (port {packet_out_port}) to continue flow")
        metadatas = packetOutMetadataList(
            global_data['controller_opcode_name2int']['SEND_TO_PORT_IN_OPERAND0'],
            0, packet_out_port)
        sendPacketOut(message["sw"], payload, metadatas)
    else:
        log.error("Could not determine PacketOut port. Packet not sent.")

    return counter_index


async def processNotif(notif_queue):
    """Main notification processing loop."""
    while True:
        try:
            notif = await notif_queue.get()
            
            if notif["type"] == "packet-in":
                counter_index = None  # Default
                try:
                    counter_index = await processPacket(notif)
                except Exception as e:
                    log.error(f"Error processing packet: {e}")
                    traceback.print_exc()

                if counter_index is not None:
                    read_index = counter_index % 4
                    log.info(f"--- Reading counters for index {read_index} on "
                             f"{notif['sw'].name} ---")
                    printCounter(global_data['p4info_helper'], notif["sw"],
                                 'MyIngress.ingressPktOutCounter', read_index)
                    printCounter(global_data['p4info_helper'], notif["sw"],
                                 'MyEgress.egressPktInCounter', read_index)
            
            # ### DISABLED IDLE TIMEOUT ###
            # elif notif["type"] == "idle-notif":
            #     log.info("Idle timeout notification received, but functionality is disabled.")
            
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

# ### DISABLED IDLE TIMEOUT ###
# async def idleTimeHandler(notif_queue, sw):
#     """Listens for IdleTimeout notifications from a switch."""
#     while True:
#         try:
#             idle_notif = await asyncio.to_thread(sw.IdleTimeoutNotification)
#             message = {"type": "idle-notif", "sw": sw, "idle": idle_notif}
#             await notif_queue.put(message)
#         except grpc.RpcError as e:
#             if e.code() != grpc.StatusCode.CANCELLED:
#                 log.warning(f"[gRPC Error in idleTimeHandler for {sw.name}]")
#                 printGrpcError(e)
#             else:
#                 log.info(f"IdleTimeout stream cancelled for {sw.name}.")
#                 break
#             await asyncio.sleep(1)
#         except Exception as e:
#             log.error(f"[Unexpected Error in idleTimeHandler for {sw.name}]: {e}")
#             traceback.print_exc()
#             await asyncio.sleep(1)


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

    # ### FIXED: Added the try...except block back
    try:
        # --- DYNAMIC SWITCH CONNECTION ---
        global_data['switches'] = {}
        global_data['allowed_devices'] = {
    "08:00:00:00:01:11": {"ip": "10.0.2.2", "service": "sensing"},
    "08:00:00:00:02:22": {"ip": "10.0.3.3", "service": "actuating"},
    "08:00:00:00:03:33": {"ip": "10.0.1.1", "service": "analytics"}
}

        switch_names = sorted(global_data['topology']['switches'].keys())
        all_switches = []
        device_id_counter = 0
        grpc_port_base = 50051  # Standard base port

        for sw_name in switch_names:
            device_id = device_id_counter
            grpc_port = grpc_port_base + device_id
            
            sw = p4runtime_lib.bmv2.Bmv2SwitchConnection(
                name=sw_name,
                address=f'127.0.0.1:{grpc_port}',
                device_id=device_id,
                proto_dump_file=f'logs/{sw_name}-p4runtime-requests.txt'
            )
            global_data['switches'][sw_name] = sw
            all_switches.append(sw)
            device_id_counter += 1
        
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

        # Start listening for notifications
        notif_queue = asyncio.Queue()
        tasks = [asyncio.create_task(processNotif(notif_queue))]
        for sw in all_switches:
            tasks.append(asyncio.create_task(packetInHandler(notif_queue, sw)))
            # ### DISABLED IDLE TIMEOUT ###
            # tasks.append(asyncio.create_task(idleTimeHandler(notif_queue, sw)))
        
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
    parser.add_argument('--topo', help='Topology JSON file', # ### FIXED: 'add_gument' typo
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

    for f in [args.p4info, args.bmv2_json]:
        if not os.path.exists(f):
            log.error(f"\nFile not found: {f}\nHave you run 'make'?")
            parser.print_help()
            sys.exit(1)

    asyncio.run(main(args.p4info, args.bmv2_json, topo_file))