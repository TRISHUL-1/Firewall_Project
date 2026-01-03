from sqlalchemy import Column, Integer, String, Text, TIMESTAMP
from sqlalchemy.dialects.postgresql import INET
from sqlalchemy.ext.declarative import declarative_base

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