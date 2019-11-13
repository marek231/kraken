import socket
import logging
import time
from scapy.all import IP, TCP, UDP, sr1, sr, ICMP
from .data.icmp_control_messages import SS_UNREACHABLE_ERROR, UDPS_UNREACHABLE_ERROR, OTHER_UDPS_UNREACHABLE_ERROR


class HostScanner:
    DEFAULT_TIMEOUT = 0.5
    SUCCESS_INDICATOR = 0
    MAX_UDP_RETRANSMISSIONS = 10

    SYN_ACK = 0x12
    RST_ACK = 0x14

    def __init__(self, host, tcp_scan_type, timeout=DEFAULT_TIMEOUT):
        self.host = host
        self.timeout = timeout

        if tcp_scan_type is None or tcp_scan_type == 'connect':
            self.internal_tcp_scan = self.__tcp_connect_scan
        elif tcp_scan_type == 'stealth':
            self.internal_tcp_scan = self.__tcp_stealth_scan

        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.setLevel(logging.INFO)
        file_handler = logging.FileHandler(f'{host}_{int(time.time())}.log')
        file_handler.setLevel(logging.INFO)
        file_handler.setFormatter(logging.Formatter('[%(asctime)s] - %(levelname)s - %(message)s'))
        self.logger.addHandler(file_handler)

    def tcp_scan(self, ports):
        open_ports = []
        for port in ports:
            if self.internal_tcp_scan(port) == 'Open':
                open_ports.append(port)
                self.logger.info(f'[+] TCP Port {port} is Open...')

        return open_ports

    def udp_scan(self, ports):
        open_ports = []
        for port in ports:
            port_status = self.__udp_scan(port)

            if port_status == 'Open|Filtered':
                self.logger.info(f'[+] UDP Port {port} reported as {port_status}. Retransmitting...')
                retransmission_results = [self.__udp_scan(port) for _ in range(HostScanner.MAX_UDP_RETRANSMISSIONS)]
                filtered_results = list(filter(lambda status: status == 'Open', retransmission_results))
                if len(filtered_results) != 0:
                    open_ports.append(port)
                    self.logger.info(f'[+] UDP Port {port} is Open...')

            elif port_status == 'Open':
                open_ports.append(port)
                self.logger.info(f'[+] UDP Port {port} is Open...')

        return open_ports

    def __tcp_connect_scan(self, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(self.timeout)

        connected = sock.connect_ex((self.host, port))

        sock.close()
        return 'Open' if connected == HostScanner.SUCCESS_INDICATOR else 'Closed'

    def __tcp_stealth_scan(self, port):
        tcp_packet = IP(dst=self.host) / TCP(dport=port, flags='S')
        response = sr1(tcp_packet, timeout=self.timeout, verbose=0)

        if response is None:
            return 'Filtered'

        if response.haslayer(TCP):
            if response.getlayer(TCP).flags == HostScanner.SYN_ACK:
                rst_packet = IP(dst=self.host) / TCP(dport=port, flags='R')
                sr(rst_packet, timeout=self.timeout, verbose=0)
                return 'Open'

            if response.getlayer(TCP).flags == HostScanner.RST_ACK:
                return 'Closed'

        if response.haslayer(ICMP):
            icmp_error_type = int(response.getlayer(ICMP).type)
            icmp_error_code = int(response.getlayer(ICMP).code)

            if icmp_error_type == SS_UNREACHABLE_ERROR["type"] and icmp_error_code in SS_UNREACHABLE_ERROR["codes"]:
                return 'Filtered'

    def __udp_scan(self, port):
        udp_packet = IP(dst=self.host) / UDP(dport=port)
        response = sr1(udp_packet, timeout=self.timeout, verbose=0)

        if response is None:
            return 'Open|Filtered'

        if response.haslayer(UDP):
            return 'Open'

        if response.haslayer(ICMP):
            icmp_error_type = int(response.getlayer(ICMP).type)
            icmp_error_code = int(response.getlayer(ICMP).code)

            if icmp_error_type == UDPS_UNREACHABLE_ERROR["type"] and icmp_error_code == UDPS_UNREACHABLE_ERROR["code"]:
                return 'Closed'

            if icmp_error_type == OTHER_UDPS_UNREACHABLE_ERROR["type"] and icmp_error_code in OTHER_UDPS_UNREACHABLE_ERROR["codes"]:
                return 'Filtered'
