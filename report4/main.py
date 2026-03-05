import time
import csv
from datetime import datetime
from report4.flow_capture import loadBPF, attachKProbe, getFlows

#generate the traffic into CSV only

FREQUENCY = 2

CSV_HEADER = [
    "timestamp", "src_ip", "dst_ip", "src_port",
    "dst_port", "packet_count", "total_bytes",
    "duration_ms", "label", "protocol"
]

def open_csv_writers(timestamp):
    file_normal = open(f"normal_traffic_{timestamp}.csv", "w", newline="")
    file_attack = open(f"attack_traffic_{timestamp}.csv", "w", newline="")
    write_normal, write_attack = csv.writer(file_normal), csv.writer(file_attack)
    write_normal.writerow(CSV_HEADER)
    write_attack.writerow(CSV_HEADER)
    return write_normal, write_attack, file_normal, file_attack

def writeFlows(flows, write_normal, write_attack, timestamp):
    normal_count = 0
    attack_count = 0
    for flow in flows:
        row = [timestamp] + [flow[col] for col in CSV_HEADER[1:]]
        if flow["label"] == 0:
            write_normal.writerow(row)
            normal_count += 1
        else:
            write_attack.writerow(row)
            attack_count += 1
    return normal_count, attack_count

def main():
    bpf = loadBPF()
    attachKProbe(bpf)

    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    write_normal, write_attack, file_normal, file_attack = open_csv_writers(timestamp)

    print("Flow Tracking...")
    print(f"Normal traffic logging to:  normal_traffic_{timestamp}.csv")
    print(f"Attack traffic logging to:  attack_traffic_{timestamp}.csv")
    print("Generate TCP traffic. Press Ctrl+C to stop.\n")

    try:
        while True:
            time.sleep(FREQUENCY)
            flows = getFlows(bpf)
            cur_timestamp = time.time()
            normal_count, attack_count = writeFlows(flows, write_normal, write_attack, cur_timestamp)
            file_normal.flush()
            file_attack.flush()
            print(f"[{datetime.now().strftime('%H:%M:%S')}] Normal flows: {normal_count} | Suspicious flows: {attack_count}")

    except KeyboardInterrupt:
        print("\nStopping...")
    finally:
        file_normal.close()
        file_attack.close()
        print(f"Saved: normal_traffic_{timestamp}.csv")
        print(f"Saved: attack_traffic_{timestamp}.csv")


if __name__ == "__main__":
    main()