from bcc import BPF
import time
import socket
import struct
import csv
from datetime import datetime

BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <bcc/helpers.h>

#define AF_INET 2

struct sock_common {
    u32 skc_daddr;
    u32 skc_rcv_saddr;
    u32 skc_hash;
    u16 skc_dport;
    u16 skc_num;
    u16 skc_family;
};

struct sock {
    struct sock_common __sk_common;
};

struct flow_key_t {
    u32 saddr;
    u32 daddr;
    u16 lport;
    u16 dport;
};

struct flow_stats_t {
    u64 packet_count;
    u64 total_bytes;
    u64 start_ns;
    u64 last_ns;
};

BPF_HASH(flow_table, struct flow_key_t, struct flow_stats_t);

int trace_tcp_send(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    size_t size = (size_t)PT_REGS_PARM3(ctx);

    u16 family = sk->__sk_common.skc_family;
    if (family != AF_INET) return 0;

    struct flow_key_t key = {};
    key.saddr = sk->__sk_common.skc_rcv_saddr;
    key.daddr = sk->__sk_common.skc_daddr;
    key.lport = sk->__sk_common.skc_num;
    key.dport = sk->__sk_common.skc_dport;

    u64 now = bpf_ktime_get_ns();
    struct flow_stats_t *stats, vars = {};
    stats = flow_table.lookup(&key);

    if (stats) {
        stats->packet_count++;
        stats->total_bytes += size;
        stats->last_ns = now;
    } else {
        vars.packet_count = 1;
        vars.total_bytes = size;
        vars.start_ns = now;
        vars.last_ns = now;
        flow_table.update(&key, &vars);
    }
    return 0;
}
"""

def ip_from_u32(addr: int) -> str:
    return socket.inet_ntoa(struct.pack("<L", addr))

def attach_send_kprobe(bpf: BPF):
    for sym in ("tcp_sendmsg", "__tcp_sendmsg"):
        try:
            bpf.attach_kprobe(event=sym, fn_name="trace_tcp_send")
            print(f"Attached kprobe to: {sym}")
            return
        except Exception:
            continue
    raise RuntimeError("Could not attach to tcp_sendmsg or __tcp_sendmsg. Check your kernel symbols.")

def main():
    print("Flow Tracking — writing ML-ready CSV")

    b = BPF(text=BPF_PROGRAM)
    attach_send_kprobe(b)

    out_file = f"flow_data_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    f = open(out_file, "w", newline="")
    w = csv.writer(f)
    w.writerow([
        "timestamp",
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port",
        "packet_count",
        "total_bytes",
        "duration_ms"
    ])
    f.flush()
    print(f"Logging to: {out_file}")
    print("Generate some TCP traffic. Press Ctrl+C to stop.\n")

    try:
        while True:
            time.sleep(2)
            flows = b.get_table("flow_table")
            now_ts = time.time()

            for key, val in flows.items():
                duration_ms = (val.last_ns - val.start_ns) / 1_000_000
                w.writerow([
                    now_ts,
                    ip_from_u32(key.saddr),
                    ip_from_u32(key.daddr),
                    int(key.lport),
                    int(socket.ntohs(key.dport)),
                    int(val.packet_count),
                    int(val.total_bytes),
                    round(duration_ms, 2)
                ])
            f.flush()

    except KeyboardInterrupt:
        print("\nStopping...")
    finally:
        f.close()
        print(f"Saved dataset: {out_file}")

if __name__ == "__main__":
    main()