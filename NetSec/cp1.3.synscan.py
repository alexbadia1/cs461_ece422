import multiprocessing
import random
from socket import *
import sys

from scapy.all import *


SYN  = 0b000010
RST  = 0b000100
ACK  = 0b010000

SYN_ACK = SYN | ACK


def scan_port(ip, port):
    sport = random.randint(0, 65535)
    resp = sr1(IP(dst=ip) / TCP(sport=sport, dport=port, flags=SYN), timeout=.250)
    if resp is not None:
        if resp.haslayer(TCP):
            if resp[TCP].flags.value == SYN_ACK:
                send(IP(dst=ip) / TCP(sport=sport, dport=port, flags=RST))
                return True
    return False


def worker(start_port, end_port, target_ip):
    # Scan each port from 1 to 1024
    for port in range(start_port, end_port + 1):
        if scan_port(target_ip, port):
            print(f'{target_ip},{port}')


def main():
    """ sudo python3 shared-with-host/abadia2/NetSec/cp1.3.synscan.py eth0 10.4.22.9 """

    conf.verb = 0

    # Get the interface and target IP from the command line arguments
    conf.iface = sys.argv[1]
    target_ip = sys.argv[2]

    p1 = multiprocessing.Process(target=worker, args=(0, 256, target_ip))
    p2 = multiprocessing.Process(target=worker, args=(257, 512, target_ip))
    p3 = multiprocessing.Process(target=worker, args=(513, 768, target_ip))
    p4 = multiprocessing.Process(target=worker, args=(769, 1024, target_ip))
    
    p1.start()
    p2.start()
    p3.start()
    p4.start()

    p1.join()
    p2.join()
    p3.join()
    p4.join()


if __name__ == '__main__':
    main()
