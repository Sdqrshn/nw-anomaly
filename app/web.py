from flask import Flask, render_template, redirect
from app.database import TrafficRecord, engine
from sqlalchemy.orm import sessionmaker
from datetime import datetime
from app import detector_service
import csv
import threading
import os

app = Flask(__name__)

Session = sessionmaker(bind=engine)


@app.route("/")
def home():
    session = Session()
    records = session.query(TrafficRecord).all()
    session.close()

    status = detector_service.detector_status
    latest_result = detector_service.latest_result

    if os.path.isfile("anomalies.csv"):
        with open("anomalies.csv", newline="", encoding="utf-8") as f:
            anomalies = list(csv.DictReader(f))
    else:
        anomalies = []

    high_anomalies = sum(1 for a in anomalies if a["severity"] == "High")
    low_anomalies = sum(1 for a in anomalies if a["severity"] == "Low")

    last_updated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    return render_template(
        "index.html",
        records=records[-10:],
        anomalies=anomalies,
        total_records=len(records),
        total_anomalies=len(anomalies),
        high_anomalies=high_anomalies,
        low_anomalies=low_anomalies,
        last_updated=last_updated,
        status=status,
        latest_result=latest_result
    )

@app.route("/anomalies")
def anomaly_page():
    if os.path.isfile("anomalies.csv"):
        with open("anomalies.csv", newline="", encoding="utf-8") as f:
            anomalies = list(csv.DictReader(f))
    else:
        anomalies = []

    for anomaly in anomalies:
        if anomaly.get("explanations"):
            anomaly["explanations"] = anomaly["explanations"].split("; ")
        else:
            anomaly["explanations"] = []

    return render_template("anomalies.html", anomalies=anomalies)

@app.route("/detect")
def detect():
    thread = threading.Thread(target=detector_service.run_detection)
    thread.start()

    return redirect("/")

@app.route("/status")
def status():
    return {
        "status": detector_service.detector_status
    }

@app.route("/latest")
def latest():
    return detector_service.latest_result or {
        "status": "No detection has been run yet"
    }

if __name__ == "__main__":
    app.run(debug=True)