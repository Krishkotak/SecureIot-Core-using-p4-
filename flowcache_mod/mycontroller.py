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

NSEC_PER_SEC = 1000 * 1000 * 1000

global_data = {}

global_data['CPU_PORT'] = 510
global_data['CPU_PORT_CLONE_SESSION_ID'] = 57
global_data['NUM_PORTS'] = 3
# 'index' is deprecated, will be determined per-packet
# global_data['index'] = 0 
global_data["10.0.1.1"] = "08:00:00:00:01:11"
global_data["10.0.2.2"] = "08:00:00:00:02:22"
global_data["10.0.3.3"] = "08:00:00:00:03:33"

# NEW: Topology data structures
global_data['switches'] = {} # s1, s2, s3, s4, s5 objects
global_data['topology'] = {} # Loaded topology.json
global_data['host_info'] = {} # IP -> {name, mac, switch, port}
global_data['link_info'] = {} # s1 -> {s2: port, h1: port}


## The notification database keeps track of the received idle notifications
notif_db = {}


def load_topology(topo_file_path):
    """Loads and parses the topology.json file."""
    global global_data
    print(f"Loading topology from {topo_file_path}...")
    with open(topo_file_path, 'r') as f:
        topo = json.load(f)
    
    global_data['topology'] = topo
    
    host_info = {}
    # Load host info (IP -> name, mac)
    for h_name, h_details in topo['hosts'].items():
        ip = h_details['ip'].split('/')[0] # Get IP without prefix
        host_info[ip] = {'name': h_name, 'mac': h_details['mac']}
    
    link_info = {}
    # Parse links to find host locations and switch-switch ports
    for link in topo['links']:
        node1, node2 = link[0], link[1]
        
        # Determine if port is specified, e.g., "s1-p1"
        def parse_node(node):
            if '-p' in node:
                parts = node.split('-p')
                return parts[0], int(parts[1])
            return node, None # Host or switch name without port

        node1_name, node1_port = parse_node(node1)
        node2_name, node2_port = parse_node(node2)

        if node1_name.startswith('h'):
            h_name = node1_name
            sw_name = node2_name
            sw_port = node2_port
            # Find the IP for this host
            for ip, info in host_info.items():
                if info['name'] == h_name:
                    info['switch'] = sw_name
                    info['port'] = sw_port
                    break
            link_info.setdefault(sw_name, {})[h_name] = sw_port
            link_info.setdefault(h_name, {})[sw_name] = 0 # Host port doesn't matter
            
        elif node2_name.startswith('h'):
            h_name = node2_name
            sw_name = node1_name
            sw_port = node1_port
            # Find the IP for this host
            for ip, info in host_info.items():
                if info['name'] == h_name:
                    info['switch'] = sw_name
                    info['port'] = sw_port
                    break
            link_info.setdefault(sw_name, {})[h_name] = sw_port
            link_info.setdefault(h_name, {})[sw_name] = 0
            
        elif node1_name.startswith('s') and node2_name.startswith('s'):
            # Switch-to-switch link
            sw1_name, sw1_port = node1_name, node1_port
            sw2_name, sw2_port = node2_name, node2_port
            
            link_info.setdefault(sw1_name, {})[sw2_name] = sw1_port
            link_info.setdefault(sw2_name, {})[sw1_name] = sw2_port

    global_data['host_info'] = host_info
    global_data['link_info'] = link_info
    print("Topology loaded:")
    pprint.pprint(global_data['host_info'])
    pprint.pprint(global_data['link_info'])


def get_path(src_ip, dst_ip):
    """
    Performs a BFS on the topology to find a simple path.
    Returns: A list of switch names (e.g., ['s1', 's4', 's2']) or None
    """
    graph = global_data['link_info']
    host_info = global_data['host_info']

    if src_ip not in host_info or dst_ip not in host_info:
        print(f"Error: IP {src_ip} or {dst_ip} not found in host_info")
        return None

    src_switch = host_info[src_ip]['switch']
    dst_switch = host_info[dst_ip]['switch']

    if src_switch == dst_switch:
        return [src_switch] # Path is just the one switch

    queue = [(src_switch, [src_switch])]  # (current_node, path_list)
    visited = {src_switch}

    while queue:
        (current, path) = queue.pop(0)
        if current not in graph:
            continue 
        
        for neighbor in graph[current]:
            if neighbor == dst_switch:
                return path + [dst_switch]
            
            if neighbor.startswith('s') and neighbor not in visited:
                visited.add(neighbor)
                queue.append((neighbor, path + [neighbor]))
    
    print(f"Error: No path found from {src_switch} to {dst_switch}")
    return None # No path found

def ipv4ToInt(addr):
    """Converts a dotted-decimal IPv4 string to an integer."""
    bytes_ = [int(b, 10) for b in addr.split('.')]
    return int.from_bytes(bytes(bytes_), byteorder='big')

def intToIpv4(n):
    """Converts a 32-bit integer to a dotted-decimal IPv4 string."""
    return "%d.%d.%d.%d" % ((n >> 24) & 0xff,
                            (n >> 16) & 0xff,
                            (n >> 8) & 0xff,
                            n & 0xff)

def flowCacheEntryToDebugStr(table_entry, include_action=False):
    # This function is now safer as it iterates fields
    src_ip, dst_ip, proto = "","",""
    p4info_helper = global_data['p4info_helper']
    table_name = "MyIngress.flow_cache"
    
    for match_field in table_entry.match:
        field_name = p4info_helper.get_match_field_name(table_name, match_field.field_id)
        if field_name == "hdr.ipv4.protocol":
            proto = int.from_bytes(match_field.exact.value, byteorder='big')
        elif field_name == "hdr.ipv4.srcAddr":
            src_ip = intToIpv4(int(ipaddress.IPv4Address(match_field.exact.value)))
        elif field_name == "hdr.ipv4.dstAddr":
            dst_ip = intToIpv4(int(ipaddress.IPv4Address(match_field.exact.value)))
            
    return (f"(SA={src_ip}, DA={dst_ip}, proto={proto})")

def decodePacketInMetadata(pktin_info, packet):
    pktin_field_to_val = {}
    for md in packet.metadata:
        md_id_int = md.metadata_id
        md_val_int = int.from_bytes(md.value, byteorder='big')
        assert md_id_int in pktin_info
        md_field_info = pktin_info[md_id_int]
        pktin_field_to_val[md_field_info['name']] = md_val_int
    ret = {'metadata': pktin_field_to_val,
           'payload': packet.payload}
    print(f"decodePacketInMetadata: ret={ret}")
    return ret

def serializableEnumDict(p4info_data, name):
    type_info = p4info_data.type_info
    name_to_int = {}
    int_to_name = {}
    for member in type_info.serializable_enums[name].members:
        name = member.name
        int_val = int.from_bytes(member.value, byteorder='big')
        name_to_int[name] = int_val
        int_to_name[int_val] = name
    print(f"serializableEnumDict: name='{name}' name_to_int={name_to_int} int_to_name={int_to_name}")
    return name_to_int, int_to_name

def getObj(p4info_obj_map, obj_type, name):
    key = (obj_type, name)
    return p4info_obj_map.get(key, None)

def controllerPacketMetadataDictKeyId(p4info_obj_map, name):
    cpm_info = getObj(p4info_obj_map, "controller_packet_metadata", name)
    assert cpm_info != None
    ret = {}
    for md in cpm_info.metadata:
        id = md.id
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
            del p4info_obj_map[key]
    return p4info_obj_map

def writeCloneSession(sw, clone_session_id, replicas):
    clone_entry = global_data['p4info_helper'].buildCloneSessionEntry(clone_session_id, replicas, 0)
    sw.WritePREEntry(clone_entry)

def addFlowRule(ingress_sw, src_ip_addr, dst_ip_addr, protocol, port, new_dscp, decrement_ttl_bool, dst_eth_addr):
    """Install flow rule in flow cache table with idle timeout."""
    if decrement_ttl_bool:
        x = 1
    else:
        x = 0

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
            "decrement_ttl":  x,
            "new_dscp":       new_dscp,
            "dst_eth_addr":   dst_eth_addr
        },
        idle_timeout_ns = 3 * NSEC_PER_SEC  # 3 second idle timeout
    )
    ingress_sw.WriteTableEntry(table_entry)

def createFlowRule(notif):
    """
    Creates a table_entry object from an idle timeout notification.
    This version is more robust and uses P4Info.
    """
    p4info_helper = global_data['p4info_helper']
    table_name = "MyIngress.flow_cache"
    
    match_fields_from_notif = {}
    for match_field in notif["idle"].table_entry[0].match:
        field_name = p4info_helper.get_match_field_name(table_name, match_field.field_id)
        
        # Re-build the Python value from the protobuf bytes
        if field_name == "hdr.ipv4.protocol":
            value = int.from_bytes(match_field.exact.value, byteorder='big')
        elif field_name == "hdr.ipv4.srcAddr" or field_name == "hdr.ipv4.dstAddr":
            value = int(ipaddress.IPv4Address(match_field.exact.value))
        else:
            # Fallback for other match types, though not used here
            value = p4info_helper.get_match_field_value(match_field)
            
        match_fields_from_notif[field_name] = value

    table_entry = p4info_helper.buildTableEntry(
        table_name=table_name,
        match_fields=match_fields_from_notif
    )
    return table_entry

def deleteFlowRule(sw, table_entry):
    sw.DeleteTableEntry(table_entry)
    print(f"Deleted flow_cache entry on {sw.name}. {flowCacheEntryToDebugStr(table_entry)}")

# --- Idle Timeout DB Functions ---
def addNotification(sw_name, flow_rule):
    notification = {"timestamp": datetime.now(), "flow_rule": flow_rule}
    notif_db[sw_name].append(notification)

def checkFlowRule(sw_name, flow_rule):
    """
    Checks if a flow rule with the same match fields is already in the notification DB.
    FIX: Compares the .match field directly instead of the whole object.
    """
    if sw_name not in notif_db:
        return False

    for notif in notif_db[sw_name]:
        # Compare the match fields directly
        if notif["flow_rule"].match == flow_rule.match:
            return True
        
    return False

def isExpired(timestamp, timeout):
    return datetime.now() - timestamp > timedelta(seconds=timeout)

def cleanExpiredNotifiction(sw_name, timeout=5):
    if sw_name not in notif_db:
        return False
    notif_db[sw_name] = [
        notif for notif in notif_db[sw_name]
        if not isExpired(notif["timestamp"], timeout)
    ]
    return True
# --- End Idle Timeout DB Functions ---

def packetOutMetadataList(opcode, reserved1, operand0):
    return [{"value": opcode, "bitwidth": 8},
            {"value": reserved1, "bitwidth": 8},
            {"value": operand0, "bitwidth": 32}]

def sendPacketOut(sw, payload, metadatas):
    sw.PacketOut(payload, metadatas)

def readTableRules(p4info_helper, sw):
    print(f'\n----- Reading tables rules for {sw.name} -----')
    for response in sw.ReadTableEntries():
        for entity in response.entities:
            entry = entity.table_entry
            print(entry)
            print('-----')

def printCounter(p4info_helper, sw, counter_name, index):
    try:
        for response in sw.ReadCounters(p4info_helper.get_counters_id(counter_name), index):
            for entity in response.entities:
                counter = entity.counter_entry
                print(f"{sw.name} {counter_name} {index}: {counter.data.packet_count} packets ({counter.data.byte_count} bytes)")
    except grpc.RpcError as e:
           print(f"[gRPC Error in printCounter for {sw.name}]")
           printGrpcError(e)
           if e.code() == grpc.StatusCode.UNKNOWN:
            print(f"Unknown gRPC error from {sw.name}. Retrying...")
            time.sleep(2)
    except Exception as e:
           print(f"[Unexpected Error in printCounter for {sw.name}]: {e}")
           traceback.print_exc()
           time.sleep(2)

def processPacket(message):
        """Processes a PacketIn message."""
        payload = message["packet-in"].payload
        packet = message["packet-in"]
        ingress_sw_name = message["sw"].name
        print(f"Received PacketIn message of length {len(payload)} bytes from switch {ingress_sw_name}")
        
        if len(payload) == 0:
            return None # Return None if no payload

        pkt = Ether(payload)
        if not pkt.haslayer(IP):
            return None # Return None if not IP

        ip_proto = pkt[IP].proto
        ip_sa_str = pkt[IP].src
        src_ip_addr = ipv4ToInt(ip_sa_str)
        ip_da_str = pkt[IP].dst
        dst_ip_addr = ipv4ToInt(ip_da_str)
        
        # Calculate the counter index based on the P4 logic
        counter_index = int(pkt[IP].dst.split('.')[3])
        
        pktinfo = decodePacketInMetadata(global_data['cpm_packetin_id2data'], packet)

        if pktinfo['metadata']['punt_reason'] != global_data['punt_reason_name2int']['FLOW_UNKNOWN']:
            print(f"Ignoring PacketIn from {ingress_sw_name} with reason {pktinfo['metadata']['punt_reason']}")
            return counter_index # Return the index for logging

        print(f"Processing FLOW_UNKNOWN PacketIn from {ingress_sw_name} for flow: {ip_sa_str} -> {ip_da_str}")

        # 1. Calculate the full path of switches
        path = get_path(ip_sa_str, ip_da_str)
        if not path:
            print(f"Could not find path for {ip_sa_str} -> {ip_da_str}. Dropping.")
            return counter_index # Return the index for logging

        # 2. Find where in the path this PacketIn came from
        try:
            ingress_sw_index = path.index(ingress_sw_name)
        except ValueError:
            print(f"Error: Switch {ingress_sw_name} not on path {path} for flow. Dropping.")
            return counter_index # Return the index for logging

        # 3. Get final destination MAC (for L2 rewrite on the last hop)
        final_dest_mac = global_data['host_info'][ip_da_str]['mac']
        
        packet_out_port = None

        # 4. Install flow rules on all switches *from this point forward* in the path
        for i in range(ingress_sw_index, len(path)):
            current_switch_name = path[i]
            current_switch_obj = global_data['switches'][current_switch_name]
            
            if i == len(path) - 1:
                # This is the last switch. Forward to the destination host.
                dest_host_name = global_data['host_info'][ip_da_str]['name']
                output_port = global_data['link_info'][current_switch_name][dest_host_name]
                dest_mac = final_dest_mac
                print(f"Installing Egress rule on {current_switch_name}: flow -> port {output_port} (to host {dest_host_name})")
            else:
                # This is a transit switch. Forward to the next switch.
                next_switch_name = path[i+1]
                output_port = global_data['link_info'][current_switch_name][next_switch_name]
                dest_mac = final_dest_mac 
                print(f"Installing Transit rule on {current_switch_name}: flow -> port {output_port} (to switch {next_switch_name})")

            if i == ingress_sw_index:
                packet_out_port = output_port

            addFlowRule(current_switch_obj,
                        src_ip_addr,
                        dst_ip_addr,
                        ip_proto,
                        output_port,
                        new_dscp=5,
                        decrement_ttl_bool=True,
                        dst_eth_addr=dest_mac)

        # 5. Send PacketOut to the switch that sent the PacketIn
        if packet_out_port is not None:
            print(f"Sending PacketOut to {ingress_sw_name} to forward packet to port {packet_out_port}")
            metadatas = packetOutMetadataList(
                global_data['controller_opcode_name2int']['SEND_TO_PORT_IN_OPERAND0'],
                0, packet_out_port)
            sendPacketOut(message["sw"], payload, metadatas)
        else:
            print("Error: Could not determine PacketOut port.")

        return counter_index

async def processNotif(notif_queue):
        """Main notification processing loop."""
        while True:
            notif = await notif_queue.get()
            
            if notif["type"] == "packet-in":
                counter_index = None # Default
                try:
                    counter_index = processPacket(notif)
                except Exception as e:
                    print(f"Error processing packet: {e}")
                    traceback.print_exc()
                
                if counter_index is not None:
                    # Apply the P4 logic: index is mod 4
                    read_index = counter_index % 4
                    print(f"--- Reading counters for index {read_index} on {notif['sw'].name} ---")
                    printCounter(global_data['p4info_helper'], notif["sw"], 'MyIngress.ingressPktOutCounter', read_index)
                    printCounter(global_data['p4info_helper'], notif["sw"], 'MyEgress.egressPktInCounter', read_index)
                
            elif notif["type"] == "idle-notif":
                sw_name = notif["sw"].name
                if sw_name not in notif_db:
                    notif_db[sw_name] = []
                else:
                    cleanExpiredNotifiction(sw_name, 10) # Clean old notifications

                table_entry = createFlowRule(notif)

                if not checkFlowRule(sw_name, table_entry):
                    addNotification(sw_name, table_entry)
                    print(f"Received IdleTimeout for flow on {sw_name}. Deleting rule.")
                    
                    # --- FIX: Add try/except block around the gRPC call ---
                    try:
                        deleteFlowRule(notif["sw"], table_entry)
                    except grpc.RpcError as e:
                        print(f"Error deleting rule on {sw_name}:")
                        printGrpcError(e)
                    # --- END FIX ---
                        
                else:
                    print(f"Received duplicate idle timeout notification for switch={sw_name}, ignoring.")
            
            notif_queue.task_done()

async def packetInHandler(notif_queue, sw):
    """Listens for PacketIn messages from a switch."""
    while True:
        try:
            packet_in = await asyncio.to_thread(sw.PacketIn)
            message = {"type": "packet-in", "sw": sw, "packet-in": packet_in}
            await notif_queue.put(message)
        except grpc.RpcError as e:
            print(f"[gRPC Error in packetInHandler for {sw.name}]")
            printGrpcError(e)
            if e.code() == grpc.StatusCode.UNKNOWN:
                print(f"Unknown gRPC error from {sw.name}. Retrying...")
            await asyncio.sleep(2)
        except Exception as e:
            print(f"[Unexpected Error in packetInHandler for {sw.name}]: {e}")
            traceback.print_exc()
            await asyncio.sleep(2)

async def idleTimeHandler(notif_queue, sw):
    """Listens for IdleTimeout notifications from a switch."""
    while True:
        try:
            idle_notif = await asyncio.to_thread(sw.IdleTimeoutNotification)
            message = {"type": "idle-notif", "sw": sw, "idle": idle_notif}
            await notif_queue.put(message)
        except grpc.RpcError as e:
            print(f"[gRPC Error in idleTimeHandler for {sw.name}]")
            printGrpcError(e)
            if e.code() == grpc.StatusCode.UNKNOWN:
                print(f"Unknown gRPC error from {sw.name}. Retrying...")
            await asyncio.sleep(2)
        except Exception as e:
            print(f"[Unexpected Error in idleTimeHandler for {sw.name}]: {e}")
            traceback.print_exc()
            await asyncio.sleep(2)


def printGrpcError(e):
    print("gRPC Error:", e.details(), end=' ')
    status_code = e.code()
    print(f"({status_code.name})", end=' ')
    traceback_obj = sys.exc_info()[2]
    if traceback_obj:
        print(f"[{traceback_obj.tb_frame.f_code.co_filename}:{traceback_obj.tb_lineno}]")
    else:
        print("[No traceback info]")

async def main(p4info_file_path, bmv2_file_path, topo_file_path):
    # Instantiate a P4Runtime helper from the p4info file
    global_data['p4info_helper'] = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)
    p4info_helper = global_data['p4info_helper']

    # Load topology
    try:
        load_topology(topo_file_path)
    except Exception as e:
        print(f"Error loading topology file: {e}")
        traceback.print_exc()
        sys.exit(1)

    try:
        # --- DYNAMIC SWITCH CONNECTION ---
        global_data['switches'] = {}
        switch_names = sorted(global_data['topology']['switches'].keys())
        
        all_switches = []
        device_id_counter = 0
        grpc_port_base = 50051 # Standard base port

        for sw_name in switch_names:
            device_id = device_id_counter
            grpc_port = grpc_port_base + device_id_counter
            
            sw = p4runtime_lib.bmv2.Bmv2SwitchConnection(
                name=sw_name,
                address=f'127.0.0.1:{grpc_port}',
                device_id=device_id,
                proto_dump_file=f'logs/{sw_name}-p4runtime-requests.txt'
            )
            global_data['switches'][sw_name] = sw
            all_switches.append(sw)
            device_id_counter += 1
        
        # Master arbitration and pipeline config for all switches
        for sw in all_switches:
            sw.MasterArbitrationUpdate()
            print(f"Established mastership for {sw.name}")
            
        for sw in all_switches:
            sw.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                           bmv2_json_file_path=bmv2_file_path)
            print(f"Installed P4 Program on {sw.name}")
        # --- END DYNAMIC SWITCH CONNECTION ---

        # Parse P4Info for metadata IDs
        global_data['p4info_obj_map'] = makeP4infoObjMap(p4info_helper.p4info)
        global_data['cpm_packetin_id2data'] = \
            controllerPacketMetadataDictKeyId(global_data['p4info_obj_map'], "packet_in")

        global_data['punt_reason_name2int'], _ = \
            serializableEnumDict(p4info_helper.p4info, 'PuntReason_t')
        global_data['controller_opcode_name2int'], _ = \
            serializableEnumDict(p4info_helper.p4info, 'ControllerOpcode_t')

        # Configure clone session for Packet-In
        replicas = [{ "egress_port": global_data['CPU_PORT'], "instance": 1 }]
        for sw in all_switches:
            writeCloneSession(sw, global_data['CPU_PORT_CLONE_SESSION_ID'], replicas)
        print("Configured clone sessions for Packet-In")

        # Start listening for notifications
        notif_queue = asyncio.Queue()
        tasks = [asyncio.create_task(processNotif(notif_queue))]
        for sw in all_switches:
            tasks.append(asyncio.create_task(packetInHandler(notif_queue, sw)))
            tasks.append(asyncio.create_task(idleTimeHandler(notif_queue, sw)))
        
        await asyncio.gather(*tasks)

    except KeyboardInterrupt:
        print(" Shutting down.")
    except grpc.RpcError as e:
        print(f"gRPC error occurred: {e}")
        print(f"Status code: {e.code()}")
        print(f"Details: {e.details()}")
        printGrpcError(e)
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
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
    # FIX: Changed this from a positional argument to an optional one.
    parser.add_argument('--topo', help='Topology JSON file',
                        type=str, action="store", required=False,
                        default='topology.json')
    args = parser.parse_args()

    # Use the provided topology.json file
    topo_file = args.topo
    if not os.path.exists(topo_file):
        print(f"Error: Topology file not found: {topo_file}")
        parser.print_help()
        sys.exit(1)

    for f in [args.p4info, args.bmv2_json]:
        if not os.path.exists(f):
            parser.print_help()
            print(f"\nFile not found: {f}\nHave you run 'make'?")
            sys.exit(1)

    asyncio.run(main(args.p4info, args.bmv2_json, topo_file))

