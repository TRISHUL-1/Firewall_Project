from fastapi import FastAPI
from api.database import sessionLocal, engine
from api import models
from api.models import Firewall_log, BlockedIP
from sqlalchemy import func
from firewall.block_manager import block_ip, unblock_ip

app = FastAPI(title="Firewall Dashboard API")

models.Base.metadata.create_all(bind=engine)

@app.get("/logs")
def get_logs(limit: int = 100):
    db = sessionLocal()
    logs = (db.query(Firewall_log).order_by(Firewall_log.id.desc()).limit(limit).all())
    db.close()
    return logs


@app.get("/stats")
def get_stats():
    db = sessionLocal()

    total_logs = db.query(func.count(Firewall_log.id)).scalar()

    total_blocked = db.query(func.count(Firewall_log.id))\
        .filter(Firewall_log.action == "BLOCK").scalar()
    
    total_allowed = db.query(func.count(Firewall_log.id))\
        .filter(Firewall_log.action == "ALLOW").scalar()
    
    unique_source_ips = db.query(\
        func.count(func.distinct(Firewall_log.src_ip))).scalar()

    top_ports = (
        db.query(Firewall_log.dst_port, func.count(Firewall_log.dst_port).label("count"))\
        .group_by(Firewall_log.dst_port)\
        .order_by(func.count(Firewall_log.dst_port).desc())\
        .limit(5)\
        .all()
    )

    db.close()

    return {
        "total_logs": total_logs,
        "total_blocked": total_blocked,
        "total_allowed": total_allowed,
        "unique_source_ips": unique_source_ips,
        "top_targeted_ports": [
            {"port": port, "count": count} for port, count in top_ports
        ]
    }


@app.get("/blocked_ips")
def get_blocked_ips():
    db = sessionLocal()

    blocked = db.query(BlockedIP).order_by(BlockedIP.blocked_at.desc()).all()
    db.close()

    return blocked

@app.post("/block/{ip}")
def api_block_ip(ip: str, reason: str = "Blocked by Admin"):
    block_ip(ip= ip, reason= reason)

    return {
        "status" : "success",
        "ip" : ip,
        "action" : "blocked",
        "reason" : reason
    }

@app.delete("unblock/{ip}")
def api_unblock_ip(ip: str):
    unblock_ip(ip= ip)

    return {
        "status" : "success",
        "ip" : ip,
        "action" : "unblocked",
    }