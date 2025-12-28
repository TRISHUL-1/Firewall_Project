import os
import time
import sys
from collections import defaultdict
from scapy.all import sniff,IP,TCP
from send_mail import *  #gmail_authenticate, send_email, get_information,

THRESHOLD = 40
GMAIL_SERVICE = gmail_authenticate()
print(f"Threshold: {THRESHOLD}")

def read_ip_file(filename):
	""" It reads a file containing list of ips and returns a set of ips """
	with open(filename, "r") as file:
		ips = [line.strip() for line in file]
		return set(ips)

def log_event(message):
	""" It takes a message as an argument and then creates an log file inside the log folder """
	log_folder = "logs"
	os.mkdirs(log_folder, exist_ok=True)
	time_stamp = time.strftime("%Y-%m-%D_%H-%M-%S",time.localtime())
	log_file = os.path.join(log_folder, f"log_{time_stamp}.txt")

	with open(log_file, "a") as file:
		file.write(f"{message}\n")

def is_nimda_worm(packet):
	""" checks if the packet contains traces of the nimda worm """
	if packet.haslayer(TCP) and packet[TCP].dport == 80:
		payload = packet[TCP].payload
		return "GET /scripts/root.exe" in str(payload)
	return False

def packet_callback(packet):
	""" It breakesdown and analyzes the packet send to detect threats and blacklist ips """
	src_ip = packet[IP].src

	if src_ip in whitelist_ips:
		return

	if src_ip in blacklist_ips:
		os.system(f"iptables -A INPUT -s {src_ip} -j DROP")
		log_event(f"Blocking Blacklisted ip: {src_ip}")
		return

	if is_nimda_worm(packet):
		print(f"Blocking nimda worm: {src_ip}")
		os.system(f"iptables -A INPUT -s {src_ip} -j DROP")
		log_event(f"Blocking Nimda source ip: {src_ip}")

		send_email(GMAIL_SERVICE, 
			user_alert_info["to"],
			user_alert_info["subject"], 
			user_alert_info["message_text"])

		return

	packet_count[src_ip] += 1
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
				
				print(f"Blocking ip: {src_ip}, packet_rate: {packet_rate}")
				os.system(f"iptables -A INPUT -s {src_ip} -j DROP")
				log_event(f"Blocking source ip: {src_ip}, packet_rate: {packet_rate}")
				blacklist_ips.add()
		packet_count.clear()
		start_time[0] = current_time

if __name__ == "__main__":
	if os.geteuid() != 0:
		print("This script requires root privileges")
		sys.exit(1)

	#collects the whitelisted and blacklisted ip sets
	whitelist_ips = read_ip_file("whitelist.txt")
	blacklist_ips = read_ip_file("blacklist.txt")

	packet_count = defaultdict(int)
	user_alert_info = get_information()
	start_time = [time.time()]

	print("Monitoring Network Traffic...")
	sniff(filter="ip", prn=packet_callback)
