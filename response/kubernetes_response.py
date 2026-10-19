import subprocess
import time


class KubernetesResponseEngine:

    def __init__(self, namespace="default"):
        self.namespace = namespace

    def get_security_test_pod(self):
        """
        Find only the explicitly labelled security-demo pod.
        """
        try:
            result = subprocess.run(
                [
                    "kubectl",
                    "get",
                    "pods",
                    "-n",
                    self.namespace,
                    "-l",
                    "security-demo=true",
                    "-o",
                    "jsonpath={.items[0].metadata.name}"
                ],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode != 0:
                return None

            pod_name = result.stdout.strip()

            return pod_name if pod_name else None

        except (subprocess.SubprocessError, OSError):
            return None

    def remediate_test_pod(self):
        """
        Delete ONLY the pod explicitly labelled security-demo=true.
        Kubernetes Deployment will recreate it.
        """

        pod_name = self.get_security_test_pod()

        if not pod_name:
            print("[KUBERNETES] No authorized security-test pod found.")
            return False

        print("\n[KUBERNETES RESPONSE]")
        print(f"[+] Target Pod : {pod_name}")
        print(f"[+] Namespace  : {self.namespace}")
        print("[+] Action     : Delete compromised test Pod")

        try:
            result = subprocess.run(
                [
                    "kubectl",
                    "delete",
                    "pod",
                    pod_name,
                    "-n",
                    self.namespace,
                    "--wait=false"
                ],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode != 0:
                print(
                    "[!] Kubernetes remediation failed:",
                    result.stderr.strip()
                )
                return False

            print("[+] Compromised test Pod removed.")
            print("[+] Waiting for Kubernetes self-healing...")

            return self.wait_for_recovery(pod_name)

        except (subprocess.SubprocessError, OSError) as error:
            print(f"[!] Kubernetes error: {error}")
            return False

    def wait_for_recovery(self, old_pod_name):
        """
        Verify that Kubernetes created a NEW Ready pod.
        """

        for _ in range(30):

            time.sleep(1)

            new_pod = self.get_security_test_pod()

            if new_pod and new_pod != old_pod_name:

                try:
                    result = subprocess.run(
                        [
                            "kubectl",
                            "get",
                            "pod",
                            new_pod,
                            "-n",
                            self.namespace,
                            "-o",
                            "jsonpath={.status.containerStatuses[0].ready}"
                        ],
                        capture_output=True,
                        text=True,
                        timeout=10
                    )

                    if (
                        result.returncode == 0
                        and result.stdout.strip().lower() == "true"
                    ):
                        print(f"[+] Replacement Pod : {new_pod}")
                        print("[+] Replacement Pod is READY.")
                        print("[+] Kubernetes self-healing completed.")
                        return True

                except (subprocess.SubprocessError, OSError):
                    pass

        print("[!] Replacement Pod did not become ready in time.")
        return False


if __name__ == "__main__":

    engine = KubernetesResponseEngine()

    print("Kubernetes Response Engine Test")
    print("=" * 50)

    success = engine.remediate_test_pod()

    if success:
        print("\n[+] CLOUD-NATIVE SELF-HEALING SUCCESSFUL")
    else:
        print("\n[-] CLOUD-NATIVE SELF-HEALING FAILED")