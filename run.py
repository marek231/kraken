import argparse
from argparse import RawDescriptionHelpFormatter
from app.host_scanner import HostScanner
from app.data.ports import TCP_COMMON_PORTS, UDP_COMMON_PORTS, HTTP_S_PORTS, SMB_PORTS, SNMP_PORTS
import threading
from app.validator.host_validator import is_host_valid
import sys
import time
import os
import socket

PORTS = {
    "TCP": TCP_COMMON_PORTS.keys(),
    "UDP": UDP_COMMON_PORTS.keys()
}


def fetch_open_ports(host_scanner, ports):
    open_ports = []
    thread_pool = []

    for port_type, subset in ports.items():
        if port_type == 'TCP':
            worker = host_scanner.tcp_scan
        else:
            worker = host_scanner.udp_scan

        thread = threading.Thread(target=lambda _open_ports, _subset: _open_ports.extend(worker(_subset)),
                                  args=(open_ports, subset))
        thread_pool.append(thread)
        thread.start()

    for thread in thread_pool:
        thread.join()

    return open_ports


def run_external_scans(external_scanners):
    thread_pool = []

    for external_scanner in external_scanners:
        thread = threading.Thread(target=external_scanner.call)
        thread_pool.append(thread)
        thread.start()

    for thread in thread_pool:
        thread.join()


def build_external_scanners_list(host, open_ports, target_directory):
    external_scanners = []

    http_s_open_ports = HTTP_S_PORTS.intersection(open_ports)
    smb_open_ports = SMB_PORTS.intersection(open_ports)
    snmp_open_ports = SNMP_PORTS.intersection(open_ports)

    if http_s_open_ports:
        from app.external.nikto_scanner import NiktoScanner
        external_scanners.append(NiktoScanner(host, http_s_open_ports, 'http(s)', target_directory))

    if smb_open_ports:
        from app.external.enum4linux_scanner import Enum4linuxScanner
        port = smb_open_ports.pop()
        external_scanners.append(Enum4linuxScanner(host, port, UDP_COMMON_PORTS[port], target_directory))

    if snmp_open_ports:
        from app.external.snmpcheck_scanner import SnmpcheckScanner
        port = snmp_open_ports.pop()
        external_scanners.append(SnmpcheckScanner(host, port, UDP_COMMON_PORTS[port], target_directory))

    return external_scanners


def main(arguments, ports=None):
    if ports is None:
        ports = PORTS

    host = arguments.host

    if not is_host_valid(host):
        sys.exit('Hostname is invalid...')

    try:
        ip_address = socket.gethostbyname(host)
    except socket.gaierror as e:
        sys.exit(str(e))

    tcp_scan_type = arguments.tcpscan

    host_scanner = HostScanner(ip_address, tcp_scan_type)
    open_ports = fetch_open_ports(host_scanner, ports)

    if not open_ports:
        sys.exit('Could not find any open ports for the given target...')

    target_directory = f'{host}_{int(time.time())}'
    os.mkdir(target_directory)

    run_external_scans(build_external_scanners_list(host, open_ports, target_directory))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='''
    Welcome to Kraken.
    
    This tool is intended to enumerate the available services of a host and perform a deeper analysis on the results
    using other specific tools.
    ''', formatter_class=RawDescriptionHelpFormatter)

    parser.add_argument('host', type=str, help='Target you wish to scan, e.g. google.com or 216.58.214.238')
    parser.add_argument('--tcpscan', type=str, metavar='TYPE', help='Type of TCP scan to perform', choices=['connect', 'stealth'])
    args = parser.parse_args()
    main(args)
