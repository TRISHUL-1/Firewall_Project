import os
import time
import json

BACKEND_URL = "http://127.0.0.1:8000/logs"

def log_event(packet_info, action, message):
    """
    Logs a packet event to:
      1. A rotating daily JSON file (always, as a durable backup)
      2. The PostgreSQL database (for the live dashboard feed)

    The DB write is best-effort — if it fails (e.g. DB is down), the
    file log is unaffected and the firewall keeps running normally.
    """
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

    log_dict = {
        "timestamp":  timestamp,
        "src_ip":     packet_info.get("src_ip"),
        "dst_ip":     packet_info.get("dst_ip"),
        "src_port":   packet_info.get("src_port"),
        "dst_port":   packet_info.get("dst_port"),
        "protocol":   packet_info.get("protocol"),
        "action":     action,
        "reason":     message
    }

    # --- 1. Write to JSON file (primary, always runs) ---
    log_folder = "logs"
    os.makedirs(log_folder, exist_ok=True)
    date_stamp = time.strftime("%Y-%m-%d", time.localtime())
    log_file = os.path.join(log_folder, f"log_{date_stamp}.log")

    with open(log_file, "a") as f:
        f.write(json.dumps(log_dict) + "\n")

    # --- 2. Write to DB (best-effort, for dashboard live feed) ---
    try:
        from api.database import sessionLocal
        from api.models import Firewall_log

        db = sessionLocal()
        entry = Firewall_log(
            timestamp = log_dict["timestamp"],
            src_ip    = log_dict["src_ip"],
            dst_ip    = log_dict["dst_ip"],
            src_port  = log_dict["src_port"],
            dst_port  = log_dict["dst_port"],
            protocol  = log_dict["protocol"],
            action    = log_dict["action"],
            reason    = log_dict["reason"]
        )
        db.add(entry)
        db.commit()
        db.close()
    except Exception as e:
        # DB being down must never crash the firewall
        print(f"[log_event] DB write failed (file log still saved): {e}")
