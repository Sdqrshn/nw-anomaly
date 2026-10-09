import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest

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

features = [
    "packet_count",
    "total_bytes",
    "tcp_count",
    "udp_count",
    "unique_destinations",
    "unique_ports"
]

X = df[features]

model = IsolationForest(
    contamination=0.05,
    random_state=42
)

model.fit(X)

predictions = model.predict(X)
scores=model.decision_function(X)
print("Lowest anomaly score:", scores.min())
print("Highest anomaly score:", scores.max())
print("Average anomaly score:", scores.mean())
print("Normal:", (predictions == 1).sum())
print("Anomalies:", (predictions == -1).sum())

joblib.dump(model, "model.pkl")
print("Model saved.")

df["anomaly"] = model.predict(X)

df["score"] = model.decision_function(X)

anomalies = df[df["anomaly"] == -1]

print("\nPotential anomalies:")
print(anomalies[features + ["score"]])

test_data = [[
    100000,     # packets
    100000000,  # bytes
    50000,      # TCP
    50000,      # UDP
    500,        # destinations
    1000        # ports
]]

test_X = pd.DataFrame(test_data, columns=features)

prediction = model.predict(test_X)[0]
score = model.decision_function(test_X)[0]

print("\nSynthetic test:")
print("Anomaly score:", score)
print("Prediction:", prediction)

session.close()