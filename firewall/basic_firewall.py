import os
import time
import sys
from collections import defaultdict
from scapy.all import sniff,IP,TCP
from firewall.send_mail import *
from firewall.log_event import *
from firewall.packet_info import *
from firewall.blocked_ip import block_ip

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
whitelist_path = os.path.join(BASE_DIR, "whitelist.txt")
blacklist_path = os.path.join(BASE_DIR, "blacklist.txt")


THRESHOLD = 40
GMAIL_SERVICE = gmail_authenticate()
print(f"Threshold: {THRESHOLD}")

def read_ip_file(filename):
	""" It reads a file containing list of ips and returns a set of ips """
	with open(filename, "r") as file:
		ips = [line.strip() for line in file]
		return set(ips)

def is_nimda_worm(packet):
	""" checks if the packet contains traces of the nimda worm """
	if packet.haslayer(TCP) and packet[TCP].dport == 80:
		payload = packet[TCP].payload
		return "GET /scripts/root.exe" in str(payload)
	return False

def packet_callback(packet):
	""" It breakesdown and analyzes the packet send to detect threats and blacklist ips """
	
	packet_info = get_info(packet)

	if packet_info["src_ip"] in whitelist_ips:
		log_event(packet_info=packet_info, action="NONE" ,message=f"Allowed ip: {packet_info["src_ip"]}")
		return

	if packet_info["src_ip"] in blacklist_ips:
		os.system(f"iptables -A INPUT -s {packet_info["src_ip"]} -j DROP")
		log_event(packet_info=packet_info, action="BLOCK" ,message=f"Blocking Blacklisted ip: {packet_info["src_ip"]}")
		return

	if is_nimda_worm(packet):
		print(f"Blocking nimda worm: {packet_info["src_ip"]}")
		os.system(f"iptables -A INPUT -s {packet_info["src_ip"]} -j DROP")
		log_event(packet_info=packet_info, action="BLOCK" ,message=f"Blocking Nimda source ip: {packet_info["src_ip"]}")
		block_ip(ip=packet_info["src_ip"], reason="Nimda Worm Detected")

		send_email(GMAIL_SERVICE, 
			user_alert_info["to"],
			user_alert_info["subject"], 
			user_alert_info["message_text"])

		return

	packet_count[packet_info["src_ip"]] += 1
	current_time = time.time()
	time_interval = current_time - start_time[0]

	if time_interval >= 1:
		for ip, count in packet_count.items():
			packet_rate = count / time_interval
			if packet_rate > THRESHOLD and ip not in blacklist_ips:
				
				send_email(GMAIL_SERVICE, 
							user_alert_info["to"],
							user_alert_info["subject"], 
							user_alert_info["message_text"])
				
				print(f"Blocking ip: {packet_info["src_ip"]}, packet_rate: {packet_rate}")
				os.system(f"iptables -A INPUT -s {packet_info["src_ip"]} -j DROP")
				log_event(packet_info=packet_info, action="BLOCK", message=f"Blocking source ip: {packet_info["src_ip"]}, packet_rate: {packet_rate}")
				block_ip(ip=packet_info["src_ip"], reason="High Packet Rate Detected")
				blacklist_ips.add(ip)
		packet_count.clear()
		start_time[0] = current_time

if __name__ == "__main__":
	if os.geteuid() != 0:
		print("This script requires root privileges")
		sys.exit(1)

	#collects the whitelisted and blacklisted ip sets
	whitelist_ips = read_ip_file(whitelist_path)
	blacklist_ips = read_ip_file(blacklist_path)

	packet_count = defaultdict(int)
	user_alert_info = get_information()
	start_time = [time.time()]

	print("Monitoring Network Traffic...")
	sniff(filter="ip", prn=packet_callback)
