#! /usr/bin/env python

import sys,argparse,enum
from scapy.all import sr1,IP,ICMP,UDP,TCP

# What is implemented:
#   - Allows user to scan by host and port 
#   - Shows simple response to user
#   - Implements TCP and UDP
#   - Allows range of IP addresses (IP-IP)
#   - Allows range of Ports (Port-Port)

# Scanning Results 
class Status(enum.Enum):
    OPEN = 1
    CLOSED = 2
    FILTERED = 3
    OPEN_OR_FILTERED = 4
    
def scan_tcp(ip, port, t_out=10):
    # SYN Scan
    ip_crafted = IP(dst=ip)
    tcp_crafted = TCP(dport=int(port), flags="S")
    packet = sr1(ip_crafted/tcp_crafted, verbose=0, timeout=t_out)
    if packet:
        flags = packet['TCP'].flags
        if flags == "SA": # SA stands for SYN-ACK
            return Status.OPEN
        else:
            return Status.CLOSED
    else:
        return Status.CLOSED

def scan_udp(ip, port, t_out=10, attempts=5):
    # Send UDP and wait
    ip_crafted = IP(dst=ip)
    udp_crafted = UDP(dport=port)
    packet = sr1(ip_crafted/udp_crafted, verbose=0, timeout=t_out)
    if packet:
        if packet.haslayer(UDP):  # If the target returns a udp packet, it's open
            return Status.OPEN
        elif packet.haslayer(ICMP):
            ICMP_layer = packet.getlayer(ICMP) # Pull ICMP 
            if int(ICMP_layer.type) == 3: # ICMP Type 3 = ICMP Error
                if int(ICMP_layer.code) == 3: # Code 3 = Closed
                    return Status.CLOSED
                elif int(ICMP_layer.code) in [1, 2, 9, 10, 13]: # Code 1, 2, 9, 10 or 13 = Filtered
                    return Status.FILTERED
    else: # if nothing is returned, it's unknown try again
        if attempts > 0:
            scan_udp(ip, port, t_out, attempts-1)
        return Status.OPEN_OR_FILTERED # it's either OPEN or CLOSED

def start_scan(prot_name):
    print "Scanning " + prot_name + ":"
    print "%-20s%-12s%-12s" % ("TARGET", "PORT", "STATUS")

def get_ips(ips):
    ips_arr = []
    if '-' in ips:
        range1,range2 = ips.split("-")
        prefix = range1.split(".")[:-1] # all but last element
        prefix_str = ".".join(prefix)
        start = int(range1.split(".")[-1])
        end = int(range2.split(".")[-1])
        for i in range(start, end+1):
            ip = prefix_str + "." + str(i)
            ips_arr.append(ip)
    else:
        ips_arr.append(ips)
    return ips_arr

def get_ports(ports):
    ports_arr = []
    if '-' in ports:
        start,end = ports.split("-")
        for i in range(int(start), int(end)+1):
            ports_arr.append(i)
    else:
        ports_arr.append(int(ports))
    return ports_arr

def scan_multiples(ips, ports, t_out, scan_func, tcp=True, udp=False):
    if tcp:
        start_scan("TCP")
    else:
        start_scan("UDP")

    ips_array = get_ips(ips)
    ports_array = get_ports(ports)
    for ip in ips_array:
        for port in ports_array:
            result = scan_func(str(ip), int(port), t_out)
            print "%-20s%-12i%-12s" % (str(ip), int(port), result.name)


# Commandline parser
parser = argparse.ArgumentParser(description="Scan target using host and port.")
parser.add_argument("ip", type=str, help="enter the IP address or range (ip-ip) to target")
parser.add_argument("port", type=str, help="enter the Port or range (port-port) to target")
parser.add_argument("-tcp", help="scan using tcp", action="store_true")
parser.add_argument("-udp", help="scan using udp", action="store_true")
args = parser.parse_args()

timeout = 4 # Default timeout is 10 seconds

if not args.tcp and not args.udp:
    scan_multiples(str(args.ip), str(args.port), timeout, scan_tcp)
if args.tcp:
    scan_multiples(str(args.ip), str(args.port), timeout, scan_tcp)
if args.udp:
    scan_multiples(str(args.ip), str(args.port), timeout, scan_tcp, False, True)
