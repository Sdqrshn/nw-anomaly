import pandas as pd

from app.database import TrafficRecord, engine
from sqlalchemy.orm import sessionmaker

Session = sessionmaker(bind=engine)
session = Session()

records = session.query(TrafficRecord).all()

data = [
    {
        "packet_count": r.packet_count,
        "total_bytes": r.total_bytes,
        "tcp_count": r.tcp_count,
        "udp_count": r.udp_count,
        "unique_destinations": r.unique_destinations,
        "unique_ports": r.unique_ports
    }
    for r in records
]

df = pd.DataFrame(data)

print(df.describe())

session.close()