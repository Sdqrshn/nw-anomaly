from sqlalchemy import create_engine, Column, Integer, DateTime
from sqlalchemy.orm import declarative_base

DATABASE_URL = "sqlite:///./network.db"

engine = create_engine(DATABASE_URL)

Base = declarative_base()


class TrafficRecord(Base):
    __tablename__ = "traffic_records"

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime)
    packet_count = Column(Integer)
    total_bytes = Column(Integer)
    tcp_count = Column(Integer)
    udp_count = Column(Integer)
    unique_destinations = Column(Integer)
    unique_ports = Column(Integer)


Base.metadata.create_all(engine)
