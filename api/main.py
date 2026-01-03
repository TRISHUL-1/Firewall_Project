from fastapi import FastAPI
from api.database import sessionLocal, engine
from api import models
from api.models import Firewall_log

app = FastAPI(title="Firewall Dashboard API")

models.Base.metadata.create_all(bind=engine)

@app.get("/logs")
def get_logs(limit: int = 100):
    db = sessionLocal()
    logs = (db.query(Firewall_log).order_by(Firewall_log.id.desc()).limit(limit).all())
    db.close()
    return logs
