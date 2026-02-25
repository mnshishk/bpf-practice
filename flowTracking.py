from bcc import BPF
import time
import socket
import struct

BPF_PROGRAM = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

struct flow_key_t {
    u32 saddr;
    u32 daddr;
    u16 lport;
    u16 dport;
};

struct flow_stats_t {
    u64 packet_count;
    u64 total_bytes;
    u64 start_ns;    // Timestamp when flow started
    u64 last_ns;     // Timestamp of last activity
};

BPF_HASH(flow_table, struct flow_key_t, struct flow_stats_t);

int trace_tcp_send(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t size) {
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

def format_ip(addr):
    return socket.inet_ntoa(struct.pack("<L", addr))

def main():
    print("Person 2: Finalizing Connection & Flow Tracking...")
    b = BPF(text=BPF_PROGRAM)
    b.attach_kprobe(event="tcp_sendmsg", fn_name="trace_tcp_send")
    
    # Column headers for Person 2's Report
    header = f"{'Source IP':<15} {'Dest IP':<15} {'DPort':<6} {'Pkts':<6} {'Bytes':<10} {'Duration (ms)':<15}"
    print(header)
    print("-" * len(header))

    try:
        while True:
            time.sleep(2)
            flows = b.get_table("flow_table")
            for key, val in flows.items():
                # Calculate duration in milliseconds for ML feature engineering
                duration_ms = (val.last_ns - val.start_ns) / 1000000
                
                print(f"{format_ip(key.saddr):<15} "
                      f"{format_ip(key.daddr):<15} "
                      f"{socket.ntohs(key.dport):<6} "
                      f"{val.packet_count:<6} "
                      f"{val.total_bytes:<10} "
                      f"{duration_ms:<15.2f}")
    except KeyboardInterrupt:
        print("\nStopping...")

if __name__ == "__main__":
    main()