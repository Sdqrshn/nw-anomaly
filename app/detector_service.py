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

detector_status = "ready"
latest_result = None

features = [
    "packet_count",
    "total_bytes",
    "tcp_count",
    "udp_count",
    "unique_destinations",
    "unique_ports"
]

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

def run_detection():
    global packet_count, total_bytes, tcp_count, udp_count, detector_status, latest_result
    detector_status = "running"

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
    score = model.decision_function(X)[0]

    explanations = []
    if prediction == -1:
        if packet_count > 30000:
            explanations.append("High packet count")

        if total_bytes > 50000000:
            explanations.append("High traffic volume")

        if len(destinations) > 30:
            explanations.append("Many unique destinations")

        if len(ports) > 50:
            explanations.append("Many unique ports")

        if tcp_count > packet_count * 0.8:
            explanations.append("Unusually high TCP traffic")

        if udp_count > packet_count * 0.8:
            explanations.append("Unusually high UDP traffic")

    record = TrafficRecord(
        timestamp=timestamp,
        packet_count=packet_count,
        total_bytes=total_bytes,
        tcp_count=tcp_count,
        udp_count=udp_count,
        unique_destinations=len(destinations),
        unique_ports=len(ports)
    )

    session = Session()
    session.add(record)
    session.commit()
    session.close()

    if prediction == -1:
        severity = "High" if score < -0.05 else "Low"

        file_exists = os.path.isfile("anomalies.csv")

        with open("anomalies.csv", "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)

            if not file_exists:
                writer.writerow([
                    "timestamp", "packet_count", "total_bytes",
                    "tcp_count", "udp_count",
                    "unique_destinations", "unique_ports",
                    "anomaly_score", "severity", "explanations"
                ])

            writer.writerow([
                timestamp, packet_count, total_bytes,
                tcp_count, udp_count,
                len(destinations), len(ports),
                score, severity, ";".join(explanations)
            ])

    result = {
        "timestamp": timestamp,
        "prediction": int(prediction),
        "score": float(score),
        "severity": (
                    "High" if prediction == -1 and score < -0.05
                    else "Low" if prediction == -1
                    else "Normal"
                ),
        "explanations": explanations,
        "packet_count": packet_count,
        "total_bytes": total_bytes,
        "tcp_count": tcp_count,
        "udp_count": udp_count,
        "unique_destinations": len(destinations),
        "unique_ports": len(ports)
        
    }

    packet_count = 0
    total_bytes = 0
    tcp_count = 0
    udp_count = 0
    destinations.clear()
    ports.clear()

    detector_status = "ready"
    latest_result = None

    latest_result = result

    return result

