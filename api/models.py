from sqlalchemy import Column, Integer, String, Text, TIMESTAMP
from sqlalchemy.dialects.postgresql import INET
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.sql import func

Base = declarative_base()

class Firewall_log(Base):

    __tablename__ = "firewall_logs"

    id = Column(Integer, primary_key=True)
    timestamp = Column(TIMESTAMP)
    src_ip = Column(INET, index=True)
    dst_ip = Column(INET, index=True)
    src_port = Column(Integer)
    dst_port = Column(Integer)
    protocol = Column(String)
    action = Column(String, index=True)
    reason = Column(Text)

class BlockedIP(Base):
    __tablename__ = "blocked_ips"

    id = Column(Integer, primary_key=True)
    ip = Column(INET, unique=True, nullable=False)
    blocked_at = Column(TIMESTAMP, server_default=func.now())
    reason = Column(Text)