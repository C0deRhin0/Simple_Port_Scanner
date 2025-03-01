#!/usr/bin/env python3
"""
SimplePortScanner: A basic multi-threaded network port scanner.
This tool is intended for educational purposes and authorized testing only.
"""

import socket
import ipaddress
import logging
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed

def scan_port(ip, port, timeout=1):
    """Check if a specific port is open on the given IP."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        try:
            #connect_ex returns 0 on success
            return sock.connect_ex((str(ip), port)) == 0
        except Exception:
            return False

def scan_ports_on_host(ip, ports, timeout=1, max_threads=100):
    """Scan a list of ports on a given host using multi-threading."""
    open_ports = []
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        future_to_port = {executor.submit(scan_port, ip, port, timeout): port for port in ports}
        for future in as_completed(future_to_port):
            port = future_to_port[future]
            try:
                if future.result():
                    open_ports.append(port)
            except Exception as error:
                logging.error(f"Error scanning {ip}:{port} - {error}")
    return open_ports

def parse_ip_range(ip_range_str):
    """
    Parse an IP range from a string.
    Accepted formats:
      - Single IP (e.g., "192.168.1.1")
      - Dash-separated range (e.g., "192.168.1.1-192.168.1.10")
      - CIDR notation (e.g., "192.168.1.0/24")
    """
    ip_range_str = ip_range_str.strip()
    if '/' in ip_range_str:
        network = ipaddress.ip_network(ip_range_str, strict=False)
        return list(network.hosts())
    elif '-' in ip_range_str:
        start_str, end_str = ip_range_str.split('-')
        start_ip = ipaddress.ip_address(start_str.strip())
        end_ip = ipaddress.ip_address(end_str.strip())
        if int(end_ip) < int(start_ip):
            raise ValueError("End IP must be greater than or equal to the start IP.")
        return [ipaddress.ip_address(ip) for ip in range(int(start_ip), int(end_ip) + 1)]
    else:
        return [ipaddress.ip_address(ip_range_str)]

def parse_port_range(port_range_str):
    """
    Parse a port or range of ports from a string.
    Accepted formats:
      - Single port (e.g., "80")
      - Dash-separated range (e.g., "20-80")
      - Common service names (e.g., "http", "ftp")
    """
    services = {
        'http': 80,
        'https': 443,
        'ftp': 21,
        'ssh': 22,
        'telnet': 23,
        'smtp': 25,
        'pop3': 110,
        'imap': 143
    }
    port_range_str = port_range_str.lower().strip()
    if port_range_str in services:
        return [services[port_range_str]]
    elif '-' in port_range_str:
        start, end = port_range_str.split('-')
        start_port = int(start.strip())
        end_port = int(end.strip())
        if end_port < start_port:
            raise ValueError("End port must be greater than or equal to the start port.")
        return list(range(start_port, end_port + 1))
    else:
        return [int(port_range_str)]

def main():
    parser = argparse.ArgumentParser(
        description="SimplePortScanner: A basic multi-threaded network port scanner.\n"
                    "For educational and authorized testing purposes only."
    )
    parser.add_argument("-ip", "--ip_range", required=True,
                        help="IP range to scan (e.g., 192.168.1.1, 192.168.1.1-192.168.1.10, or 192.168.1.0/24)")
    parser.add_argument("-p", "--port_range", required=True,
                        help="Port or port range to scan (e.g., 80, 20-80, or a service name like http)")
    parser.add_argument("-t", "--timeout", type=float, default=1,
                        help="Timeout in seconds for each port scan (default: 1)")
    parser.add_argument("-T", "--threads", type=int, default=100,
                        help="Number of threads to use for scanning (default: 100)")
    args = parser.parse_args()

    logging.basicConfig(filename='port_scanner.log', level=logging.INFO,
                        format='%(asctime)s - %(levelname)s - %(message)s')
    logging.info("Starting network scan.")

    try:
        ip_list = parse_ip_range(args.ip_range)
    except Exception as err:
        print(f"Error parsing IP range: {err}")
        logging.error(f"Error parsing IP range: {err}")
        return

    try:
        ports = parse_port_range(args.port_range)
    except Exception as err:
        print(f"Error parsing port range: {err}")
        logging.error(f"Error parsing port range: {err}")
        return

    logging.info(f"Scanning IPs: {[str(ip) for ip in ip_list]} on ports: {ports}")

    for ip in ip_list:
        print(f"\nScanning {ip}...")
        open_ports = scan_ports_on_host(ip, ports, timeout=args.timeout, max_threads=args.threads)
        if open_ports:
            ports_str = ", ".join(map(str, open_ports))
            print(f"Open ports on {ip}: {ports_str}")
            logging.info(f"Open ports on {ip}: {open_ports}")
        else:
            print(f"No open ports found on {ip}.")
            logging.info(f"No open ports found on {ip}.")

if __name__ == "__main__":
    main()
