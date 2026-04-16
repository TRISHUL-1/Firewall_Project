import subprocess
from api.database import sessionLocal
from api.models import BlockedIP


def block_ip(ip: str, reason: str = "Manual Block"):
    """Adds an iptables DROP rule and records the IP in the database."""
    db = sessionLocal()

    subprocess.run(
        ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
        check=False
    )

    exists = db.query(BlockedIP).filter(BlockedIP.ip == ip).first()
    if not exists:
        blocked = BlockedIP(ip=ip, reason=reason)
        db.add(blocked)
        db.commit()

    db.close()


def unblock_ip(ip: str):
    """Removes the iptables DROP rule and deletes the IP from the database."""
    db = sessionLocal()

    subprocess.run(
        ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
        check=False
    )

    db.query(BlockedIP).filter(BlockedIP.ip == ip).delete()
    db.commit()
    db.close()