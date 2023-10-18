from tools import get_traffic_type,is_netflow_9,is_valid_port,clean_up_ip_ranges
import traffic
import netflow
import socket
from netaddr import IPAddress
import web
import ipaddress
import configparser
import os
import sys

dirname = os.path.dirname(__file__)
config = configparser.RawConfigParser()
config_path = os.path.join(dirname,"./config.ini")
config.read(config_path)

local_ip_ranges = clean_up_ip_ranges(config.get("Network","ranges").split(","))
netflow_port = int(config.get("Netflow","port"))
is_netflow_port_valid = is_valid_port(netflow_port)
web_port = int(config.get("Web","port"))
is_web_port_valid = is_valid_port(web_port)
templates = {"netflow": {}}
sequence = None
uptime = None
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("0.0.0.0", netflow_port))




try:
    if is_web_port_valid and is_netflow_port_valid:
        web.start_web_service()
        while True:
            payload, client = sock.recvfrom(4096)
            try:
                parsed_payload = netflow.parse_packet(payload, templates)
                is_netflow_9(parsed_payload.header.version)
                if(sequence == None):
                    sequence = parsed_payload.header.sequence

                if(uptime == None):
                    uptime = parsed_payload.header.uptime

                if(parsed_payload.header.sequence < sequence):
                    if(parsed_payload.header.uptime < uptime):
                        uptime = parsed_payload.header.uptime
                        sequence = parsed_payload.header.sequence
                    elif(sequence - parsed_payload.header.sequence > 10):
                        sequence = parsed_payload.header.sequence

                if(parsed_payload.header.sequence >= sequence):
                    if(parsed_payload.header.sequence > sequence):
                        sequence = parsed_payload.header.sequence
                    
                    for flow in parsed_payload.flows:
                        ipSrc = str(IPAddress(flow.IPV4_SRC_ADDR))
                        ipDst = str(IPAddress(flow.IPV4_DST_ADDR))
                        
                        try:
                            ipSrcPostNat = str(ipaddress.ip_address(flow.NF_F_XLATE_SRC_ADDR_IPV4))
                            ipDstPostNat = str(ipaddress.ip_address(flow.NF_F_XLATE_DST_ADDR_IPV4))
                        except ValueError:
                            print("IP address could not be parsed: {}".format(repr(flow.NF_F_XLATE_DST_ADDR_IPV4)))
                            try:
                                ipSrcPostNat = str(IPAddress(flow.NF_F_XLATE_SRC_ADDR_IPV4))
                                ipDstPostNat = str(IPAddress(flow.NF_F_XLATE_DST_ADDR_IPV4))
                            except:
                                ipSrcPostNat = str(flow.NF_F_XLATE_SRC_ADDR_IPV4)
                                ipDstPostNat = str(flow.NF_F_XLATE_DST_ADDR_IPV4)
                                print("IP address could not be parsed: {}".format(repr(flow.NF_F_XLATE_DST_ADDR_IPV4)))
                        
                        traffic_type = get_traffic_type(ipSrc,ipDstPostNat,local_ip_ranges)
                        print(traffic_type)
                        nbytes = flow.IN_BYTES
                        npackets = flow.IN_PKTS
                        k = ipSrc \
                            + ipDstPostNat \
                            + str(flow.L4_SRC_PORT) \
                            + str(flow.L4_DST_PORT) \
                            + str(flow.PROTOCOL)
                        if(k in traffic.data):
                            nbytes += traffic.data[k]['bytes']
                            npackets += traffic.data[k]['packets']
                        traffic.data[k] = {
                            'traffic_type': traffic_type,
                            'src_ip': ipSrc,
                            'dst_ip': ipDstPostNat,
                            'bytes': nbytes,
                            'packets': npackets,
                            'src_port': flow.L4_SRC_PORT,
                            'dst_port': flow.L4_DST_PORT,
                            'timestamp': parsed_payload.header.timestamp,
                            'protocol': flow.PROTOCOL
                        }
                    sequence += 1

            except Exception as e:
                pass
    else:
        print("Invalid Port Configuration.")
except:
    sys.exit(0)

