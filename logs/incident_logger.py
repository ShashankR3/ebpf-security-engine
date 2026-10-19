import json
import os
from datetime import datetime


class IncidentLogger:

    def __init__(self):
        project_root = os.path.dirname(
            os.path.dirname(os.path.abspath(__file__))
        )

        self.log_file = os.path.join(
            project_root,
            "logs",
            "incidents.json"
        )

    def log_incident(
        self,
        threat,
        response,
        system_status
    ):

        incident = {
            "timestamp": datetime.now().isoformat(
                timespec="seconds"
            ),
            "event": "THREAT_DETECTED",
            "process": threat["process"],
            "pid": threat["pid"],
            "severity": threat["severity"],
            "reason": threat["reason"],
            "response": response,
            "system_status": system_status
        }

        incidents = []

        if os.path.exists(self.log_file):

            try:
                with open(
                    self.log_file,
                    "r",
                    encoding="utf-8"
                ) as file:

                    incidents = json.load(file)

            except (json.JSONDecodeError, OSError):
                incidents = []

        incidents.append(incident)

        with open(
            self.log_file,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                incidents,
                file,
                indent=4
            )

        print(
            f"[LOGGING] Incident recorded: "
            f"{self.log_file}"
        )