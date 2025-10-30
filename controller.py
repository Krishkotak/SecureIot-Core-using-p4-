#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
import argparse
import asyncio
import os
import sys
from time import sleep
import json
import grpc
import traceback
import secrets

# Import P4Runtime lib from parent utils dir
# Probably there's a better way of doing this.
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 '../../utils/'))
import p4runtime_lib.bmv2
import p4runtime_lib.helper
from p4runtime_lib.switch import ShutdownAllSwitchConnections


SWITCH_TO_HOST_PORT = 1
SWITCH_TO_SWITCH1_PORT = 2
SWITCH_TO_SWITCH2_PORT = 3






from scapy.all import Ether, IP

def load_topology(filename):
    with open(filename, 'r') as f:
        topology = json.load(f)
    return topology

def parse_packetin(packet_in):
    """
    Extracts source MAC and destination IP from a PacketIn payload.
    
    Args:
        packet_in: P4Runtime PacketIn object containing payload and metadata.
    
    Returns:
        (src_mac, dst_ip)
    """
    try:
        pkt = Ether(packet_in.payload)  # Decode raw bytes
        
        src_mac = pkt.src
        dst_ip = pkt[IP].dst if IP in pkt else None
        
        return src_mac, dst_ip

    except Exception as e:
        print(f"[Error] Failed to parse PacketIn: {e}")
        return None, None


# Load topology (if present) so handler helpers can use it.
# Topology file is expected next to this controller script.
_topo_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'topology.json')
try:
    topo = load_topology(_topo_path)
    allowed_devices = {info.get('mac','').lower(): name for name, info in topo.get('hosts', {}).items() if info.get('mac')}
except Exception:
    topo = {}
    allowed_devices = {}

# def onPacketIn(switch, packet):
#     mac, dst_ip = parse_packetin(packet)
#     print(f"Received new packet from {mac} → {dst_ip}")

#    if authenticate_device(mac, dst_ip):
#        token = generate_token(mac, dst_ip)
#        src_sw = switch.name
#        dst_sw = find_service_switch(dst_ip)
#        path = compute_path(topo, src_sw, dst_sw)
#        install_token_rules(path, token)
#        send_packetout(switch, packet, token)
#    else:
#        print(f"Unauthorized device {mac}, dropping.")

# def authenticate_device(mac,dst_ip):
#     if mac in allowed_devices :
#         if



# def on_packetin(switch, packet):
#     mac, dst_ip = parse_packetin(packet)
#     print(f"Received new packet from {mac} → {dst_ip}")
    
#     if authenticate_device(mac, dst_ip):
#         token = generate_token(mac, dst_ip)
#         src_sw = switch.name
#         dst_sw = find_service_switch(dst_ip)
#         path = compute_path(topo, src_sw, dst_sw)
#         install_token_rules(path, token)
#         send_packetout(switch, packet, token)
#     else:
#         print(f"Unauthorized device {mac}, dropping.")



# async def packetInHandler(notif_queue,sw):
#     while True:
#         try:
#             packet_in = await asyncio.to_thread(sw.PacketIn)
#             #print(f"Received packet: {packet_in}")
#             message = {"type": "packet-in", "sw": sw, "packet-in": packet_in}
#             await notif_queue.put(message)

#         except grpc.RpcError as e:
#             print(f"[gRPC Error in packetInHandler for {sw.name}]")
#             printGrpcError(e)

#             if e.code() == grpc.StatusCode.UNKNOWN:
#                 print(f"Unknown gRPC error from {sw.name}. Retrying...")
#             await asyncio.sleep(2)

#         except Exception as e:
#             print(f"[Unexpected Error in packetInHandler for {sw.name}]: {e}")
#             traceback.print_exc()
#             await asyncio.sleep(2)



def printGrpcError(e):
    print("gRPC Error:", e.details(), end=' ')
    status_code = e.code()
    print("(%s)" % status_code.name, end=' ')
    traceback = sys.exc_info()[2]
    print("[%s:%d]" % (traceback.tb_frame.f_code.co_filename, traceback.tb_lineno))
 
 # --- Controller helper functions and improved packetInHandler ---


def generate_token(mac, dst_ip):
    return secrets.token_hex(16)


def find_service_switch(dst_ip):
    hosts = topo.get('hosts', {})
    for host_name, info in hosts.items():
        ip = info.get('ip', '')
        ip_addr = ip.split('/')[0]
        if ip_addr == dst_ip:
            for a, b in topo.get('links', []):
                endpoint = None
                if a == host_name:
                    endpoint = b
                elif b == host_name:
                    endpoint = a
                if endpoint and endpoint.startswith('s'):
                    return endpoint.split('-')[0]
    return None


def compute_path(topo, src_sw, dst_sw):
    if not src_sw or not dst_sw:
        return []
    if src_sw == dst_sw:
        return [src_sw]
    adj = {}
    for a, b in topo.get('links', []):
        def sw_of(ep):
            return ep.split('-')[0] if ep.startswith('s') else None
        sa = sw_of(a)
        sb = sw_of(b)
        if sa and sb and sa != sb:
            adj.setdefault(sa, set()).add(sb)
            adj.setdefault(sb, set()).add(sa)
    from collections import deque
    q = deque([src_sw])
    prev = {src_sw: None}
    while q:
        u = q.popleft()
        for v in adj.get(u, ()): 
            if v not in prev:
                prev[v] = u
                q.append(v)
                if v == dst_sw:
                    path = [v]
                    while prev[path[-1]] is not None:
                        path.append(prev[path[-1]])
                    return list(reversed(path))
    return []


def install_token_rules(path, token):
    if not path:
        print("[install_token_rules] empty path, skipping")
        return
    print(f"[install_token_rules] would install token on path={path} token={token}")


def send_packetout(sw, packet_in, token):
    try:
        payload = packet_in.payload
        if hasattr(sw, 'PacketOut'):
            try:
                sw.PacketOut(payload)
                print(f"[send_packetout] PacketOut sent on {getattr(sw,'name',str(sw))} token={token}")
            except Exception:
                print(f"[send_packetout] PacketOut call failed for {getattr(sw,'name',str(sw))}")
        else:
            print(f"[send_packetout] switch object has no PacketOut; token={token}")
    except Exception as e:
        print(f"[send_packetout] error: {e}")


async def packetInHandler(notif_queue, sw):
    while True:
        try:
            packet_in = await asyncio.to_thread(sw.PacketIn)
            mac, dst_ip = parse_packetin(packet_in)
            print(f"[{getattr(sw,'name',str(sw))}] PacketIn from {mac} -> {dst_ip}")

            if authenticate_device(mac, dst_ip):
                token = generate_token(mac, dst_ip)
                src_sw = getattr(sw, 'name', None)
                dst_sw = find_service_switch(dst_ip)
                path = compute_path(topo, src_sw, dst_sw) if src_sw and dst_sw else []
                install_token_rules(path, token)
                send_packetout(sw, packet_in, token)
            else:
                print(f"Unauthorized device {mac}, dropping (controller decision).")

        except grpc.RpcError as e:
            print(f"[gRPC Error in packetInHandler for {getattr(sw,'name',str(sw))}]")
            printGrpcError(e)
            await asyncio.sleep(2)

        except Exception as e:
            print(f"[Unexpected Error in packetInHandler for {getattr(sw,'name',str(sw))}]: {e}")
            traceback.print_exc()
            await asyncio.sleep(2)
 
def main(p4info_file_path, bmv2_file_path):
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)

    try:
        # Create a switch connection object for switch s1
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
        s3 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s3',
            address='127.0.0.1:50053',
            device_id=2,
            proto_dump_file='logs/s3-p4runtime-requests.txt')
        s1.MasterArbitrationUpdate()
        s2.MasterArbitrationUpdate()
        s3.MasterArbitrationUpdate()
        # Install the P4 program on the switches    
        s1.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                      bmv2_json_file_path=bmv2_file_path)
        print("Installed P4 Program using SetForwardingPipelineConfig on s1")
        s2.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                      bmv2_json_file_path=bmv2_file_path)
        print("Installed P4 Program using SetForwardingPipelineConfig on s2")
        s3.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                      bmv2_json_file_path=bmv2_file_path)
        print("Installed P4 Program using SetForwardingPipelineConfig on s3")

        
    except KeyboardInterrupt:
        print(" Shutting down.")
    except grpc.RpcError as e:
        printGrpcError(e)

    ShutdownAllSwitchConnections()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='P4Runtime Controller')
    parser.add_argument('--p4info', help='p4info file', type=str,
                        action="store", required=False,default='build/data_plane.p4.p4info.txt')
    parser.add_argument('--bmv2-json', help='BMv2 JSON file', type=str,
                        action="store", required=False,default='build/data_plane.json')
    args = parser.parse_args()

    p4info_helper = p4runtime_lib.helper.P4InfoHelper(args.p4info)

    if not os.path.exists(args.p4info):
        parser.print_help()
        print("\np4info file not found: %s\nHave you run 'make'?" % args.p4info)
        parser.exit(1)
    if not os.path.exists(args.bmv2_json):
        parser.print_help()
        print("\nBMv2 JSON file not found: %s\nHave you run 'make'?" % args.bmv2_json)
        parser.exit(1)
    
    main(args.p4info, args.bmv2_json)