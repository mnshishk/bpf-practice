from datetime import datetime
import time
from report4.flow_capture_XDP import attachXDP
from report4.flow_capture import loadBPF, getFlows
from report5.SVM import predict as svm_predict
from report5.RF import predict as rf_predict
from report6.ensemble import evaluate_threat_level
from report6.analytics import log_attack_pattern, print_summary, export_summary_to_csv
from report6.IP_blocking import IP_blocking

# ALERT_LOG = f"report6/alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
NORMAL_LOG = f"report6/normal_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
SLEEP = 2

defender = IP_blocking(threshold=5,)

def log_normal(message):
    print(message)
    with open(NORMAL_LOG, "a") as f:
        f.write(message+"\n")

def runIDS(bpf):
    print(f"IDS is up.\n")
    normal_sample_count = 0
    
    try:
        while True:
            time.sleep(SLEEP)
            defender.cleanup_expired_blocks()
            start = time.perf_counter()
            flows = getFlows(bpf)

            for flow in flows:
                svm_result = svm_predict(flow)
                rf_result = rf_predict(flow)

                threat_level = evaluate_threat_level(svm_result, rf_result)

                if threat_level != "NORMAL":
                    defender.process_incident(flow['src_ip'])
                    log_attack_pattern(flow, threat_level)
                else:
                    if normal_sample_count % 10 == 0:
                        normal_msg = (
                            f"[{datetime.now().strftime('%H:%M:%S')}] NORMAL | " 
                            f"src={flow['src_ip']}:{flow['src_port']} | "
                            f"dst={flow['dst_ip']}:{flow['dst_port']} | "
                            # f"SVM={svm_result} RF={rf_result} | "
                            f"bytes={flow['total_bytes']}"
                        )
                        log_normal(normal_msg)
                        print(f"[{datetime.now().strftime('%H:%M:%S')}] OK | "
                                f"src={flow['src_ip']} dst_port={flow['dst_port']}")

            end = time.perf_counter()
            print(f"Processed {len(flows)} flows in {(end-start)*1000:.2f}ms")
    except KeyboardInterrupt:
        print("\nIDS stopped.")
        print_summary()
        export_summary_to_csv()

def main() -> None:
    bpf = loadBPF()
    attachXDP(bpf)
    runIDS(bpf)

if __name__ == "__main__":
    main()