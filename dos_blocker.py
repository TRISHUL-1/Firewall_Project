import os
import sys
import time
from collections import defaultdict
from scapy.all import sniff,IP

THRESHOLD = 40
print(f"Threshold: {THRESHOLD}")

def packet_callback(packet):
	src_ip = packet[IP].src
	packet_count[src_ip] += 1

	current_time = time.time()
	time_interval = current_time - start_time[0]

	if time_interval >= 1:
		for ip, count in packet_count.items():
			packet_rate = count / time_interval
			if packet_rate > THRESHOLD and ip not in blocked_ips:
				print(f"Blocking ip: {ip}, packet_rate={packet_rate}")
				os.system(f"iptables -A INPUT -s {ip} -j DROP")

		packet_count.clear()
		start_time[0] = current_time

if __name__ == "__main__" :
	if os.geteuid() != 0:
		print("This system requires root privileges")
		sys.exit(1)
	packet_count = defaultdict(int)
	start_time = [time.time()]
	blocked_ips = set()

	print("Monitoring network traffic...")
	sniff(filter="ip", prn=packet_callback)
