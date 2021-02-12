# -*- coding: utf-8 -*-
#!/usr/bin/env python3

# Authors:
# Germano Sobroza
# Yuri Oliveira Alves

"""
    RUN THIS CODE WITH ROOT PRIVILEGES
"""
import dns.resolver as resolver
import netifaces as ni
from time import sleep
from scapy.all import IP, UDP, TCP, DNS, DNSQR, DNSRR, DNS, send, sniff

"""
    DNSpoof is a DNSFirewall service
    resolve DNS and block spoof domains

    Dependence modules: 
        dns, netifaces, scapy
"""

""" 
    Class responsible to change the console 
    print colors
"""
class bcolors:
    HEADER = '\033[95m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'

""" 

"""
def handle_packet_fn(iface, spoof_ip, spoof_domains):
    def handle_packet(packet):
        ip = packet.getlayer(IP)
        udp = packet.getlayer(UDP)
        
        try: 
            # Ignore packets containing data we aren't interested in.
            if hasattr(packet, 'qd') and packet.qd is not None:
                queried_host = packet.qd.qname[:-1].decode("utf-8")
                
                # If the queried_host is one of the domains we want
                # to spoof, return a modified copy of package.
                if queried_host in spoof_domains:

                    resolved_ip = '172.217.29.228'

                    # payload = bytes(packet[UDP].payload)
                    # pkt = IP(payload)
                    
                    response_packet = \
                        IP(src=ip.dst, dst=ip.src)/\
                        UDP(dport=udp.sport, sport=udp.dport)/\
                        DNS(id=packet[DNS].id, qr=1, aa=1, qd=packet.qd,
                            an=DNSRR(rrname='google.com', ttl=60, type="A", rclass="IN",
                            rdata=resolved_ip)) 
                    
                    #DNS(id=packet[DNS].id, qr=1, aa=1, qd=DNSQR(qname='google.com'),
                    # del response_packet[IP].len
                    # del response_packet[IP].chksum
                    # del response_packet[UDP].len
                    # del response_packet[UDP].chksum

                    packet.payload = response_packet.payload

                    print(f"{bcolors.FAIL}xx Spoofing DNS request for {queried_host}"\
                        f" changed to {resolved_ip} for {ip.src}{bcolors.ENDC}")
                    
                    #sleep(1)

                # Else use dns.resolver to make a real DNS "A record"
                # request, and return the result of that.
                else:
                    a_records = resolver.resolve(queried_host, 'A')                
                    resolved_ip = a_records[0].address

                    # Build the DNS response by constructing the IP
                    # packet, the UDP "datagram" that goes inside the
                    # packet, and finally the DNS response that goes
                    # inside the datagram.
                    response_packet = \
                        IP(src=ip.dst, dst=ip.src)/\
                        UDP(sport=udp.dport, dport=udp.sport)/\
                        DNS(id=packet[DNS].id, qr=1, aa=1, qd=packet.qd,
                            an=DNSRR(rrname=queried_host + ".", ttl=60, type="A", rclass="IN", 
                            rdata=resolved_ip))      
                
                    print(f"{bcolors.OKGREEN}>> Resolved DNS request for {queried_host} to "\
                        f"{resolved_ip} for {ip.src}{bcolors.ENDC}")

                send(response_packet,iface=iface, verbose=False)

            else:
                print(f"Ignoring unrecognized packet from {ip.src}")

        except resolver.NXDOMAIN:
            print(f"{bcolors.WARNING}!! This domain does not exist{bcolors.ENDC}")
        except resolver.NoAnswer:
            print(f"{bcolors.WARNING}!! No answer from this op{bcolors.ENDC}")
        except resolver.Timeout:
            print(f"{bcolors.WARNING}!!Connection as timeout{bcolors.ENDC}")
        except resolver.NoNameservers:
            print(f"{bcolors.WARNING}!!No namedserver to query typed{bcolors.ENDC}")
        
    return handle_packet

"""

"""
def run(iface, local_ip, sniff_filter, spoof_domains):
    print(f"#" * 40)
    print(f"-#-#-#-#-#-RUNNING DNS SPOOFER-#-#-#-#-#")
    print(f"#" * 40)
    print(f"Interface:\t\t{iface}\n" \
          f"Resolving to IP:\t{local_ip}\n" \
          f"Spoof domains:\t\t{', '.join(spoof_domains)}\n"  \
          f"BPF sniff filter:\t{sniff_filter}\n"  \
          f"Waiting for DNS requests...\n"\
          f"[Make sure the device you are targeting, is set to use"\
          f" ({local_ip}) as its DNS server]")

    sniff(iface =iface,
          filter=sniff_filter,
          prn   =handle_packet_fn(iface,
                                  local_ip,
                                  spoof_domains))

"""
    Class responsible to return the IP
    from network interface
"""
def _get_local_ip(iface):
    return ni.ifaddresses(iface)[ni.AF_INET][0]['addr']

def spoof():  
    IFACE= 'wlp2s0'
    #IFACE = str(input("Type the network interface to be used:\n"))
    
    local_ip = _get_local_ip(IFACE)
    client_ip = '192.168.0.150'

    SPOOF_DOMAINS = ['www.uol.com.br', 'uol.com.br']
    SNIFF_FILTER = (f"udp port 53 && dst {local_ip} && src {client_ip}")
    
    run(IFACE, local_ip, SNIFF_FILTER, SPOOF_DOMAINS)

if __name__ == "__main__":
    spoof()
