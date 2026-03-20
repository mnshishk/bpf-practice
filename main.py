from datetime import datetime
import time
from report4.flow_capture import loadBPF, attachKProbe, getFlows
from report5.SVM import predict as svm_predict
from report5.RF import predict as rf_predict

ALERT_LOG = f"report5/alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
NORMAL_LOG = f"report5/normal_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
SLEEP = 2

def log_alert(message):
    print(message)
    with open(ALERT_LOG, "a") as f:
        f.write(message+"\n")

def log_normal(message):
    print(message)
    with open(NORMAL_LOG, "a") as f:
        f.write(message+"\n")

def runIDS(bpf):
    print(f"IDS is up. Logging to: {ALERT_LOG}\n")
    normal_sample_count = 0
    try:
        while True:
            time.sleep(SLEEP)
            flows = getFlows(bpf)

            for flow in flows:
                svm_result = svm_predict(flow)
                rf_result = rf_predict(flow)

                if svm_result == 1 or rf_result == 1:
                    alert_msg = (
                        f"[{datetime.now().strftime('%H:%M:%S')}] Suspicious Traffic | "
                        f"src={flow['src_ip']}:{flow['src_port']} "
                        f"dst={flow['dst_ip']}:{flow['dst_port']} | "
                        f"SVM={svm_result} RF={rf_result} | "
                        f"bytes={flow['total_bytes']}"
                    )
                    log_alert(alert_msg)
                else:
                    if normal_sample_count % 10 == 0:
                        normal_msg = (
                            f"[{datetime.now().strftime('%H:%M:%S')}] NORMAL | " 
                            f"src={flow['src_ip']}:{flow['src_port']} dst={flow['dst_ip']}:{flow['dst_port']} bytes={flow['total_bytes']}"
                        )
                        log_normal(normal_msg)
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] OK | "
                            f"src={flow['src_ip']} dst_port={flow['dst_port']}")
    except KeyboardInterrupt:
        print("\nIDS stopped.")
        print(f"Alerts saved to: {ALERT_LOG}")

def main() -> None:
    bpf = loadBPF()
    attachKProbe(bpf)
    runIDS(bpf)


if __name__ == "__main__":
    main()