import re
import ipaddress
import sys

def is_valid_ip(ip):
    ip_pattern = r"^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.\
                 (25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.\
                 (25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.\
                 (25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"

    if re.match(ip_pattern, str(ip)):
        return True
    else:
        return False

def is_valid_port(port):
    try:
        port = int(port)
        if 1 <= port <= 65535:
            return True
        else:
            return False
    except ValueError:
        return False
    
def is_local_ip(local_ip_ranges,ip_to_check):

    ip = ipaddress.IPv4Address(ip_to_check)
    for ip_range in local_ip_ranges:
        if ip in ipaddress.IPv4Network(ip_range):
            return True
    return False      

def clean_up_ip_ranges(local_ip_ranges):
    for i in range(0,len(local_ip_ranges)):
        local_ip_ranges[i] = local_ip_ranges[i].replace(" ","")
    return local_ip_ranges

def get_traffic_type(src,dst,local_ip_ranges):
    if is_local_ip(local_ip_ranges,src):
        if is_local_ip(local_ip_ranges,dst):
            return "Local"
        else:
            return "Upload"
    else:
        if is_local_ip(local_ip_ranges,dst):
            return "Download"
        else:
            return "Local"
        
def is_netflow_9(version):
    if(version != 9):
        sys.exit()