import joblib
from scapy.all import sniff, IP, IPv6, TCP, UDP
from collections import Counter
import pandas as pd
from app.database import TrafficRecord, engine
from sqlalchemy.orm import sessionmaker
from datetime import datetime
import csv
import os

model = joblib.load("model.pkl")
Session = sessionmaker(bind=engine)
session = Session()

packet_count = 0
total_bytes = 0
tcp_count = 0
udp_count = 0
destinations = Counter()
ports = Counter()


def process_packet(packet):
    global packet_count, total_bytes, tcp_count, udp_count

    packet_count += 1
    total_bytes += len(packet)

    if packet.haslayer(TCP):
        tcp_count += 1
        ports[packet["TCP"].dport] += 1

    elif packet.haslayer(UDP):
        udp_count += 1
        ports[packet["UDP"].dport] += 1

    if packet.haslayer(IP):
        destinations[packet[IP].dst] += 1

    elif packet.haslayer(IPv6):
        destinations[packet[IPv6].dst] += 1

features = [
    "packet_count",
    "total_bytes",
    "tcp_count",
    "udp_count",
    "unique_destinations",
    "unique_ports"
]

for i in range(10):
    print("\nCollecting traffic for 10 seconds...")
    timestamp = datetime.now()

    sniff(
        timeout=10,
        prn=process_packet,
        store=False
    )

    data = [[
        packet_count,
        total_bytes,
        tcp_count,
        udp_count,
        len(destinations),
        len(ports)
    ]]

    X = pd.DataFrame(data, columns=features)

    prediction = model.predict(X)[0]
    print("Prediction:", prediction)
    score = model.decision_function(X)[0]
    record = TrafficRecord(
        timestamp=datetime.now(),
        packet_count=packet_count,
        total_bytes=total_bytes,
        tcp_count=tcp_count,
        udp_count=udp_count,
        unique_destinations=len(destinations),
        unique_ports=len(ports)
    )

    session.add(record)
    session.commit()

    print(f"\n[{timestamp}]Traffic analyzed.")
    print("Packets:", packet_count)
    print("Bytes:", total_bytes)
    print("TCP:", tcp_count)
    print("UDP:", udp_count)
    print("Unique destinations:", len(destinations))
    print("Unique ports:", len(ports))
    print("Anomaly score:", score)

    if prediction == -1:
        if score < -0.05:
            severity = "High"
        else:
            severity = "Low"
        file_exists = os.path.isfile("anomalies.csv")

        with open("anomalies.csv", "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)

            if not file_exists:
                writer.writerow([
                    "timestamp", "packet_count", "total_bytes",
                    "tcp_count", "udp_count", "unique_destinations",
                    "unique_ports", "anomaly_score","severity"
                ])

            writer.writerow([
                timestamp, packet_count, total_bytes, tcp_count,
                udp_count, len(destinations), len(ports), score, severity
            ])

        print("⚠ Potential anomaly detected")
    else:
        print("Traffic appears normal")

    packet_count = 0
    total_bytes = 0
    tcp_count = 0
    udp_count = 0
    destinations.clear()
    ports.clear()

session.close()