import os
import signal
from datetime import datetime


class SelfHealingEngine:

    def remediate(self, threat):

        pid = threat["pid"]
        process = threat["process"]

        print("\n[AUTONOMOUS RESPONSE]")
        print(f"[+] Threat process : {process}")
        print(f"[+] Target PID     : {pid}")

        # Safety: this prototype only terminates our designated test processes
        allowed_test_processes = {
            "demo_attack",
            "suspicious_process",
            "attack_simulator"
        }

        if process not in allowed_test_processes:
            print("[-] Automatic termination blocked by safety policy.")
            return False

        try:
            os.kill(pid, signal.SIGTERM)

            print("[+] Threat process terminated")
            print("[+] System remediation completed")
            print("[+] System status: HEALTHY")

            return True

        except ProcessLookupError:
            print("[-] Process already exited.")
            return True

        except PermissionError:
            print("[-] Permission denied while terminating process.")
            return False

        except Exception as error:
            print(f"[-] Remediation error: {error}")
            return False


if __name__ == "__main__":

    engine = SelfHealingEngine()

    test_threat = {
        "process": "demo_attack",
        "pid": 999999,
        "severity": "HIGH"
    }

    print("Self-Healing Engine Test")
    engine.remediate(test_threat)