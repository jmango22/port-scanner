#! /usr/bin/env python

import sys, argparse
from scapy.all import sr1,IP,ICMP,UDP,TCP

# Scanning functions

def tcp_scan(ip, port):
  # SYN Scan
  print("Scanning TCP")
  result = sr1(IP(dst=str(ip))/TCP(dport=int(port),flags="S"))
  if result:
    result.show()

  
def udp_scan(dst_ip,dst_port,dst_timeout):
  udp_scan_resp = sr1(IP(dst=dst_ip)/UDP(dport=dst_port),timeout=dst_timeout)
  if (str(type(udp_scan_resp))=="<type 'NoneType'>"):
    retrans = []
    for count in range(0,3):
      retrans.append(sr1(IP(dst=dst_ip)/UDP(dport=dst_port),timeout=dst_timeout))
    for item in retrans:
      if (str(type(item))!="<type 'NoneType'>"):
        udp_scan(dst_ip,dst_port,dst_timeout)
        return "Open|Filtered"
      elif (udp_scan_resp.haslayer(UDP)):
        return "Open"
      elif(udp_scan_resp.haslayer(ICMP)):
        if(int(udp_scan_resp.getlayer(ICMP).type)==3 and int(udp_scan_resp.getlayer(ICMP).code)==3):
          return "Closed"
        elif(int(udp_scan_resp.getlayer(ICMP).type)==3 and int(udp_scan_resp.getlayer(ICMP).code) in [1,2,9,10,13]):
          return "Filtered"

# Commandline parser
parser = argparse.ArgumentParser(description="Scan target using host and port.")
parser.add_argument("host", type=str, help="enter the IP address to target")
parser.add_argument("port", type=int, help="enter the Port on the Host to target")
parser.add_argument("-tcp", help="scan using tcp", action="store_true")
parser.add_argument("-udp", help="scan using udp", action="store_true")
args = parser.parse_args()

if args.tcp:
  tcp_scan(args.host, args.port)
if args.udp:
  print("UDP turned on!")