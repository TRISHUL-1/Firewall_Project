from api.database import sessionLocal
from api.models import BlockedIP

def block_ip(ip, reason):
    db = sessionLocal()

    exists = db.query(BlockedIP).filter(BlockedIP.ip == ip).first()
    if not exists:
        blocked = BlockedIP(ip=ip, reason=reason)
        db.add(blocked)

        db.commit()

    db.close()