import json
import os
from flask import Flask, render_template, jsonify

app = Flask(__name__)

PROJECT_ROOT = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

LOG_FILE = os.path.join(
    PROJECT_ROOT,
    "logs",
    "incidents.json"
)


def load_incidents():
    if not os.path.exists(LOG_FILE):
        return []

    try:
        with open(LOG_FILE, "r", encoding="utf-8") as file:
            return json.load(file)

    except (json.JSONDecodeError, OSError):
        return []


@app.route("/")
def dashboard():
    incidents = load_incidents()

    total_incidents = len(incidents)

    high_severity = sum(
        1 for incident in incidents
        if incident.get("severity") == "HIGH"
    )

    contained = sum(
        1 for incident in incidents
        if incident.get("system_status") == "HEALTHY"
    )

    system_status = (
        incidents[-1].get("system_status", "HEALTHY")
        if incidents
        else "HEALTHY"
    )

    return render_template(
        "index.html",
        incidents=list(reversed(incidents)),
        total_incidents=total_incidents,
        high_severity=high_severity,
        contained=contained,
        system_status=system_status
    )


@app.route("/api/incidents")
def api_incidents():
    return jsonify(load_incidents())


if __name__ == "__main__":
    print("=" * 60)
    print(" Security Dashboard")
    print(" http://127.0.0.1:5000")
    print("=" * 60)

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )