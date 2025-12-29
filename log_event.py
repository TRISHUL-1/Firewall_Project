import os
import time
import json

def log_event(packet_info, action, message):
    """Logs packet information into a rotating daily JSON log file"""

    log_folder = "logs"
    os.makedirs(log_folder, exist_ok=True)

    # Use date only for filename to accumulate logs per day
    date_stamp = time.strftime("%Y-%m-%d", time.localtime())
    log_file = os.path.join(log_folder, f"log_{date_stamp}.log")

    # Full timestamp inside log event
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

    log_dict = {
        "timestamp": timestamp,
        "src_ip": packet_info.get("src_ip"),
        "dst_ip": packet_info.get("dst_ip"),
        "src_port": packet_info.get("src_port"),
        "dst_port": packet_info.get("dst_port"),
        "protocol": packet_info.get("protocol"),
        "action": action,
        "reason": message
    }

    with open(log_file, "a") as file:
        file.write(json.dumps(log_dict) + "\n")


# def log_event(message):
# 	""" It takes a message as an argument and then creates an log file inside the log folder """
# 	log_folder = "logs"
# 	os.mkdirs(log_folder, exist_ok=True)
# 	time_stamp = time.strftime("%Y-%m-%D_%H-%M-%S",time.localtime())
# 	log_file = os.path.join(log_folder, f"log_{time_stamp}.txt")

# 	with open(log_file, "a") as file:
# 		file.write(f"{message}\n")