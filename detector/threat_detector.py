class ThreatDetector:

    def __init__(self):
        self.suspicious_processes = {
            "demo_attack",
            "suspicious_process",
            "k8s_demo_attack",
            "attack_simulator"
        }

    def analyze_process(self, process_name, pid):

        process_name = process_name.lower().strip()

        if process_name in self.suspicious_processes:
            return {
                "threat": True,
                "severity": "HIGH",
                "process": process_name,
                "pid": pid,
                "reason": "Suspicious process detected"
            }

        return {
            "threat": False,
            "severity": "SAFE",
            "process": process_name,
            "pid": pid,
            "reason": "Normal process activity"
        }


if __name__ == "__main__":

    detector = ThreatDetector()

    print("Testing Threat Detection Engine\n")

    normal = detector.analyze_process("python3", 1001)
    print(normal)

    suspicious = detector.analyze_process("demo_attack", 1002)
    print(suspicious)