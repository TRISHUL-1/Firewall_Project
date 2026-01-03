from scapy.all import *

def get_info(packet):

    # Check if it's an IP packet
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
    else:
        src_ip = None
        dst_ip = None

    protocol = None
    src_port = None
    dst_port = None

    # Extract ports/protocol safely
    if TCP in packet:
        protocol = "TCP"
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
    elif UDP in packet:
        protocol = "UDP"
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
    elif ICMP in packet:
        protocol = "ICMP"

    else:
        protocol = packet.lastlayer().name  # fallback layer name

    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol
    }
