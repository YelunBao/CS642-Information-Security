import sys
from scapy.all import *

# rdpcap comes from scapy and loads in our pcap file
packets = rdpcap(sys.argv[1])


#myfilter = 'tcp and tcp.flags.syn==1 and tcp.flags.ack==0'
#pkts = sniff(packets, filter=myfilter)
# Let's iterate through every packet

def detect_Spoofing(packets):
    mac_count_dict = {}
    for idx, packet in enumerate(packets):
        if packet.haslayer(ARP):
            if packet.psrc in mac_count_dict:
                if packet.src != mac_count_dict[packet.psrc]:
                    print("ARP spoofing!")
                    print("MAC: " + packet.src)
                    print("Packet number: " + str(idx+1))
            else:
                mac_count_dict[packet.psrc] = packet.src


def detect_Scan(packets):
    port_dict = {}
    for idx, packet in enumerate(packets):
        if packet.haslayer(TCP) or packet.haslayer(UDP):
            if packet.haslayer(IP):
                if not packet[IP].dst in port_dict:
                    port_dict[packet[IP].dst] = [[packet.dport],1,[idx+1]]            
                else:
                    if not packet.dport in port_dict[packet[IP].dst][0]:
                        port_dict[packet[IP].dst][0].append(packet.dport)
                        port_dict[packet[IP].dst][1] += 1
                        port_dict[packet[IP].dst][2].append(idx+1)
                    else:
                        port_dict[packet[IP].dst][2].append(idx+1)
                    
    for key in port_dict:
        if port_dict[key][1] >= 100:
            print("Port scan!")
            print("IP: " + key)
            print("Packet number: " + str(port_dict[key][2]))
    
    
def detect_Floods(packets):
    ip_count_dict = {}
    already_print = []
    for idx, packet in enumerate(packets):
        # We're only interested packets with a TCP layer
        if packet.haslayer(TCP):
            if packet[TCP].flags == "S":
                key = packet[IP].dst + " " + str(int(packet.time))
                if key in ip_count_dict:
                    ip_count_dict[key] += 1
                else:
                    ip_count_dict[key] = 1
                if ip_count_dict[key] == 101:
                    if not packet[IP].dst in already_print:
                        print("SYN floods!")
                        print("IP: " + packet[IP].dst)
                        print("Packet number: " + str(idx+1))
                        already_print.append(packet[IP].dst)


'''
                    
for key in ip_count_dict:
    if ip_count_dict[key] > 100
        # If the an(swer) is a DNSRR, print the name it replied with.



def detect_Floods(pkg):
    if pkg.haslayer(TCP):
        packet_src=pkg[IP].src
        packet_dst=pkg[IP].dst
        stream = packet_src + ':' + packet_dst
    if stream in ip_count_dict:
        ip_count_dict[stream] += 1
    else:
        ip_count_dict[stream] = 1
    for stream in type(self).__ip_cnt_TCP:
        pckts_sent = type(self).__ip_cnt_TCP[stream]
        if pckts_sent > type(self).__THRESH:
            src = stream.split(':')[0]
            dst = stream.split(':')[1]
            print("Possible Flooding Attack from %s --> %s"%(src,dst))

'''
detect_Spoofing(packets)
detect_Scan(packets)
detect_Floods(packets)