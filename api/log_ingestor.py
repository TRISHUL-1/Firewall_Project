import json
from api.database import sessionLocal
from api.models import Firewall_log

LOG_FILE = "logs/log_2025-01-03.log"


def ingest_log(log_file: str = LOG_FILE):
    """Ingests a JSON log file into the database. Run manually when needed."""
    db = sessionLocal()

    inserted = 0
    with open(log_file, "r") as file:
        for line in file:
            line = line.strip()
            if not line:
                continue
            data = json.loads(line)

            log = Firewall_log(
                timestamp=data["timestamp"],
                src_ip=data["src_ip"],
                dst_ip=data["dst_ip"],
                src_port=data["src_port"],
                dst_port=data["dst_port"],
                protocol=data["protocol"],
                action=data["action"],
                reason=data["reason"]
            )
            db.add(log)
            inserted += 1

    db.commit()
    db.close()
    print(f"Ingested {inserted} log entries from {log_file}")


if __name__ == "__main__":
    import sys
    file = sys.argv[1] if len(sys.argv) > 1 else LOG_FILE
    ingest_log(file)