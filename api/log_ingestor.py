import json
from database import sessionLocal
from models import Firewall_log

LOG_FILE = "logs/log_2025-01-03.log"

def ingest_log():

    db = sessionLocal()

    with open(LOG_FILE, "r") as file:
        for line in file:
            data = json.loads(line)

            log = Firewall_log(
                timestamp = data["timestamp"],
                src_ip = data["src_ip"],
                dst_ip = data["dst_ip"],
                src_port = data["src_port"],
                dst_port = data["dst_port"],
                protocol = data["protocol"],
                action = data["action"],
                reason = data["reason"]
            )

            db.add(log)
    
    db.commit()
    db.close()

ingest_log()