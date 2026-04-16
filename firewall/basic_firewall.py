import subprocess
import time
import sys
import os
from collections import defaultdict
from scapy.all import sniff, IP, TCP
from firewall.send_mail import gmail_authenticate, send_email, get_information
from firewall.log_event import log_event
from firewall.packet_info import get_info
from firewall.block_manager import block_ip

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
whitelist_path = os.path.join(BASE_DIR, "whitelist.txt")
blacklist_path = os.path.join(BASE_DIR, "blacklist.txt")

THRESHOLD = 40


def read_ip_file(filename):
    """Reads a file containing a list of IPs and returns a set."""
    with open(filename, "r") as file:
        return set(line.strip() for line in file if line.strip())


def drop_ip(ip: str):
    """Drops an IP via iptables safely — no shell, no injection risk."""
    subprocess.run(
        ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
        check=False
    )


def is_nimda_worm(packet):
    """Checks if the packet contains traces of the Nimda worm."""
    if packet.haslayer(TCP) and packet[TCP].dport == 80:
        payload = packet[TCP].payload
        return "GET /scripts/root.exe" in str(payload)
    return False


def make_packet_callback(whitelist_ips, blacklist_ips, packet_count,
                         start_time, user_alert_info, gmail_service, alerted_ips):
    """
    Returns a packet callback closed over all shared state.
    alerted_ips: set of IPs already emailed this session — prevents alert spam.
    """
    def packet_callback(packet):
        packet_info = get_info(packet)
        src_ip = packet_info["src_ip"]

        if src_ip is None:
            return

        # Whitelisted — log and allow
        if src_ip in whitelist_ips:
            log_event(packet_info=packet_info, action="NONE",
                      message=f"Allowed ip: {src_ip}")
            return

        # Already blacklisted — enforce iptables rule and log
        if src_ip in blacklist_ips:
            drop_ip(src_ip)
            log_event(packet_info=packet_info, action="BLOCK",
                      message=f"Blocking blacklisted ip: {src_ip}")
            return

        # Nimda worm detection
        if is_nimda_worm(packet):
            print(f"Blocking Nimda worm from: {src_ip}")
            drop_ip(src_ip)
            log_event(packet_info=packet_info, action="BLOCK",
                      message=f"Blocking Nimda source ip: {src_ip}")
            block_ip(ip=src_ip, reason="Nimda Worm Detected")
            blacklist_ips.add(src_ip)

            if src_ip not in alerted_ips:
                send_email(gmail_service,
                           user_alert_info["to"],
                           user_alert_info["subject"],
                           user_alert_info["message_text"])
                alerted_ips.add(src_ip)
            return

        # Rate-limit tracking
        packet_count[src_ip] += 1
        current_time = time.time()
        time_interval = current_time - start_time[0]

        if time_interval >= 1:
            for ip, count in packet_count.items():
                packet_rate = count / time_interval
                if packet_rate > THRESHOLD and ip not in blacklist_ips:
                    print(f"Blocking ip: {ip}, packet_rate: {packet_rate:.1f}")
                    drop_ip(ip)
                    log_event(packet_info=packet_info, action="BLOCK",
                              message=f"Blocking source ip: {ip}, packet_rate: {packet_rate:.2f}")
                    block_ip(ip=ip, reason="High Packet Rate Detected")
                    blacklist_ips.add(ip)

                    if ip not in alerted_ips:
                        send_email(gmail_service,
                                   user_alert_info["to"],
                                   user_alert_info["subject"],
                                   user_alert_info["message_text"])
                        alerted_ips.add(ip)

            packet_count.clear()
            start_time[0] = current_time

    return packet_callback


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("This script requires root privileges.")
        sys.exit(1)

    print(f"Threshold: {THRESHOLD} packets/sec")

    whitelist_ips = read_ip_file(whitelist_path)
    blacklist_ips = read_ip_file(blacklist_path)

    packet_count = defaultdict(int)
    start_time = [time.time()]
    alerted_ips = set()

    # Gmail auth only runs here at startup — not at import time
    gmail_service = gmail_authenticate()
    user_alert_info = get_information()

    callback = make_packet_callback(
        whitelist_ips, blacklist_ips, packet_count,
        start_time, user_alert_info, gmail_service, alerted_ips
    )

    print("Monitoring Network Traffic...")
    sniff(filter="ip", prn=callback)