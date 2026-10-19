import os
import sys
from datetime import datetime
from bcc import BPF

# ---------------------------------------------------------
# Project imports
# ---------------------------------------------------------

PROJECT_ROOT = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from detector.threat_detector import ThreatDetector
from response.self_healing import SelfHealingEngine
from logs.incident_logger import IncidentLogger
from response.kubernetes_response import KubernetesResponseEngine

detector = ThreatDetector()
healer = SelfHealingEngine()
logger = IncidentLogger()
k8s_healer = KubernetesResponseEngine()
# ---------------------------------------------------------
# eBPF program
# ---------------------------------------------------------

program = r"""
#include <uapi/linux/ptrace.h>

struct data_t {
    u32 pid;
    u32 tid;
    char comm[16];
    char filename[256];
};

BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(syscalls, sys_enter_execve)
{
    struct data_t data = {};

    u64 id = bpf_get_current_pid_tgid();

    /*
     * Upper 32 bits = TGID (userspace process PID)
     * Lower 32 bits = thread ID
     */
    data.pid = id >> 32;
    data.tid = (u32)id;

    bpf_get_current_comm(
        &data.comm,
        sizeof(data.comm)
    );

    bpf_probe_read_user_str(
        &data.filename,
        sizeof(data.filename),
        args->filename
    );

    events.perf_submit(
        args,
        &data,
        sizeof(data)
    );

    return 0;
}
"""


# ---------------------------------------------------------
# Start monitor
# ---------------------------------------------------------

print("=" * 65)
print(" Autonomous Cloud-Native Threat Detection & Security Engine")
print(" eBPF Real-Time Process Monitor")
print("=" * 65)

bpf = BPF(text=program)

print("[+] eBPF monitor started successfully")
print("[+] Threat Detection Engine loaded successfully")
print("[+] Self-Healing Engine loaded successfully")
print("[+] Monitoring process execution...")
print("[+] Press Ctrl+C to stop\n")


# ---------------------------------------------------------
# Process verification
# ---------------------------------------------------------

def process_is_alive(pid):
    return os.path.exists(f"/proc/{pid}")


def get_live_process_name(pid):
    """
    Read the current executable name from /proc when possible.
    """

    try:
        executable = os.readlink(f"/proc/{pid}/exe")
        return os.path.basename(executable)

    except (FileNotFoundError, PermissionError, ProcessLookupError):
        return None


# ---------------------------------------------------------
# Handle eBPF event
# ---------------------------------------------------------

def handle_event(cpu, data, size):

    event = bpf["events"].event(data)

    pid = int(event.pid)

    filename = event.filename.decode(
        "utf-8",
        errors="replace"
    ).rstrip("\x00")

    process = os.path.basename(filename)

    current_time = datetime.now().strftime("%H:%M:%S")

    result = detector.analyze_process(
        process,
        pid
    )

    # -----------------------------------------------------
    # Threat detected
    # -----------------------------------------------------

    if result["threat"]:

        print("\n" + "!" * 60)
        print("THREAT DETECTED")
        print(f"Time     : {current_time}")
        print(f"Process  : {result['process']}")
        print(f"PID      : {result['pid']}")
        print(f"Severity : {result['severity']}")
        print(f"Reason   : {result['reason']}")
        print("!" * 60)

        # --------------------------------------------------
        # Cloud-native Kubernetes remediation
        # --------------------------------------------------
        if process == "k8s_demo_attack":

            print("\n[CLOUD-NATIVE] Kubernetes threat trigger detected.")

            remediation_success = k8s_healer.remediate_test_pod()

            if remediation_success:
                print(
                    "[CLOUD-NATIVE SELF-HEALING] "
                    "Kubernetes workload successfully restored."
                )

                logger.log_incident(
                    result,
                    "KUBERNETES_POD_REMEDIATED",
                    "HEALTHY"
                )

            else:
                print(
                    "[CLOUD-NATIVE SELF-HEALING] "
                    "Kubernetes remediation failed."
                )

                logger.log_incident(
                    result,
                    "KUBERNETES_REMEDIATION_FAILED",
                    "DEGRADED"
                )

            return

        # Check whether the PID still exists before remediation
        if not process_is_alive(pid):

            print("\n[AUTONOMOUS RESPONSE]")
            print(f"[+] Threat process : {process}")
            print(f"[+] Target PID     : {pid}")
            print("[+] Process exited before remediation.")
            print("[+] Threat no longer active.")
            print("[+] System status: HEALTHY")
            print("[SELF-HEALING] Threat contained.\n")
            logger.log_incident(
                result,
                "CONTAINED_PROCESS_EXITED",
                "HEALTHY"
            )


            return

        # Verify what currently owns this PID
        live_process = get_live_process_name(pid)

        if live_process is not None and live_process != process:

            print("\n[AUTONOMOUS RESPONSE]")
            print(f"[+] Original threat : {process}")
            print(f"[+] PID             : {pid}")
            print(f"[!] PID now belongs to: {live_process}")
            print("[!] Termination blocked to avoid killing the wrong process.\n")

            return

        # Perform remediation
        remediation_success = healer.remediate(result)

        if remediation_success:
            print(
                "[SELF-HEALING] "
                "Threat automatically remediated."
            )

            logger.log_incident(
                result,
                "AUTOMATIC_REMEDIATION",
                "HEALTHY"
            )

        else:
            print(
                "[SELF-HEALING] "
                "Remediation failed."
            )

            logger.log_incident(
                result,
                "REMEDIATION_FAILED",
                "ATTENTION_REQUIRED"
            )

    # -----------------------------------------------------
    # Safe process
    # -----------------------------------------------------

    else:

        print(
            f"[{current_time}] "
            f"SAFE | "
            f"PID: {pid} | "
            f"Process: {process}"
        )


# ---------------------------------------------------------
# Open perf buffer
# ---------------------------------------------------------

bpf["events"].open_perf_buffer(
    handle_event
)


# ---------------------------------------------------------
# Event loop
# ---------------------------------------------------------

try:

    while True:
        bpf.perf_buffer_poll()

except KeyboardInterrupt:

    print("\n[-] Security monitor stopped.")