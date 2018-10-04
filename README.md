# port-scanner
Port Scanner Program for IT 567

This tool scans for open ports using either TCP and UDP
By default the tool just performs a TCP scan

Usage: 
  - python scanner.py [host] [port] [-tcp] [-udp]
  - [host] - Either a single host (ip address or URL) or range of IP addresses (IP-IP)
  - [port] - Either a single port (e.g. 80) or range of Ports (Port-Port)
  - [-tcp] - Force TCP scan
  - [-udp] - Force UDP scan
