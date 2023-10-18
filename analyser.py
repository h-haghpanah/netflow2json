# from tools import get_traffic_type, is_netflow_9, is_valid_port, clean_up_ip_ranges
from tools import Validator,CleanUp,TrafficType
import traffic
import netflow
import socket
from netaddr import IPAddress
import web
import ipaddress
import configparser
import os
import sys

class NetflowProcessor:
    def __init__(self):
        # Initialize the configuration
        dirname = os.path.dirname(__file__)
        config = configparser.RawConfigParser()
        config_path = os.path.join(dirname, "./config.ini")
        config.read(config_path)

        # Extract configuration values
        self.local_ip_ranges = CleanUp.ip_ranges(config.get("Network", "ranges").split(","))
        self.netflow_port = int(config.get("Netflow", "port"))
        self.is_netflow_port_valid = Validator.is_valid_port(self.netflow_port)
        self.web_port = config.get("Web", "port")
        self.is_web_port_valid = Validator.is_valid_port(self.web_port)
        self.templates = {"netflow": {}}
        self.sequence = None
        self.uptime = None
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("0.0.0.0", self.netflow_port))

    def process_netflow(self):
        try:
            if self.is_web_port_valid and self.is_netflow_port_valid:
                web.start_web_service()
                while True:
                    payload, client = self.sock.recvfrom(4096)
                    try:
                        parsed_payload = netflow.parse_packet(payload, self.templates)
                        Validator.is_netflow_9(parsed_payload.header.version)
                        if self.sequence is None:
                            self.sequence = parsed_payload.header.sequence

                        if self.uptime is None:
                            self.uptime = parsed_payload.header.uptime

                        if parsed_payload.header.sequence < self.sequence:
                            if parsed_payload.header.uptime < self.uptime:
                                self.uptime = parsed_payload.header.uptime
                                self.sequence = parsed_payload.header.sequence
                            elif self.sequence - parsed_payload.header.sequence > 10:
                                self.sequence = parsed_payload.header.sequence

                        if parsed_payload.header.sequence >= self.sequence:
                            if parsed_payload.header.sequence > self.sequence:
                                self.sequence = parsed_payload.header.sequence

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

                                traffic_type = TrafficType.get(ipSrc, ipDstPostNat, self.local_ip_ranges)
                                nbytes = flow.IN_BYTES
                                npackets = flow.IN_PKTS
                                k = ipSrc + ipDstPostNat + str(flow.L4_SRC_PORT) + str(flow.L4_DST_PORT) + str(flow.PROTOCOL)
                                if k in traffic.data:
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
                            self.sequence += 1

                    except Exception as e:
                        pass
            else:
                print("Invalid Port Configuration.")
        except:
            sys.exit(0)

if __name__ == "__main__":
    processor = NetflowProcessor()
    processor.process_netflow()
