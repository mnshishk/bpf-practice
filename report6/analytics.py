from collections import Counter
from datetime import datetime
import csv
import os

# Global tracking structure
attack_stats = {
    "top_attackers": Counter(),
    "targeted_ports": Counter(),
    "attack_times": []
}

# Timestamped output files
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
ALERT_LOG_FILE = f"alerts_{timestamp}.txt"
SUMMARY_CSV_FILE = f"attack_summary_{timestamp}.csv"


def log_attack_pattern(flow: dict, threat_level: str):

    src_ip = flow.get("src_ip", "unknown")
    dst_port = flow.get("dst_port", 0)
    current_time = datetime.now()

    attack_stats["top_attackers"][src_ip] += 1
    attack_stats["targeted_ports"][dst_port] += 1
    attack_stats["attack_times"].append(current_time)

    with open(ALERT_LOG_FILE, "a") as f:
        f.write(
            f"[{current_time}] {threat_level} ALERT | "
            f"src_ip={src_ip} | dst_port={dst_port}\n"
        )
    print(f"[{current_time}] {threat_level} ALERT | "
          f"src_ip={src_ip} | dst_port={dst_port}\n")


def generate_summary():

    summary = {
        "total_alerts": len(attack_stats["attack_times"]),
        "top_5_attackers": attack_stats["top_attackers"].most_common(5),
        "top_5_targeted_ports": attack_stats["targeted_ports"].most_common(5)
    }

    return summary


def print_summary():

    summary = generate_summary()

    print("\n=== Attack Summary ===")
    print(f"Total Alerts: {summary['total_alerts']}")

    print("\nTop 5 Attackers:")
    for ip, count in summary["top_5_attackers"]:
        print(f"{ip}: {count} attempts")

    print("\nTop 5 Targeted Ports:")
    for port, count in summary["top_5_targeted_ports"]:
        print(f"Port {port}: {count} hits")


def export_summary_to_csv():

    summary = generate_summary()

    with open(SUMMARY_CSV_FILE, "w", newline="") as f:
        writer = csv.writer(f)

        writer.writerow(["Metric", "Value"])

        writer.writerow(["Total Alerts", summary["total_alerts"]])

        writer.writerow([])
        writer.writerow(["Top 5 Attackers", "Count"])
        for ip, count in summary["top_5_attackers"]:
            writer.writerow([ip, count])

        writer.writerow([])
        writer.writerow(["Top 5 Targeted Ports", "Count"])
        for port, count in summary["top_5_targeted_ports"]:
            writer.writerow([port, count])

    print(f"\nSummary exported to: {SUMMARY_CSV_FILE}")
