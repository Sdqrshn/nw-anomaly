from app.database import TrafficRecord, engine
from sqlalchemy.orm import sessionmaker

Session = sessionmaker(bind=engine)
session = Session()

records = session.query(TrafficRecord).all()

print("Total records:", len(records))

session.close()