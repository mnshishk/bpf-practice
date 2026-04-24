from bcc import BPF
import time
import socket
import struct

BPF_PROGRAM = """
#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

struct flow_key_t {
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
};

struct flow_stats_t {
    u64 packet_count;
    u64 total_bytes;
};

BPF_HASH(flow_table, struct flow_key_t, struct flow_stats_t);

int xdp_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    
    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;
    
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;
    
    struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;
    
    struct flow_key_t key = {};
    key.saddr = ip->saddr;
    key.daddr = ip->daddr;
    key.sport = ntohs(tcp->source);
    key.dport = ntohs(tcp->dest);
    
    struct flow_stats_t *stats, new_stats = {};
    stats = flow_table.lookup(&key);
    
    if (stats) {
        stats->packet_count++;
        stats->total_bytes += (data_end - data);
    } else {
        new_stats.packet_count = 1;
        new_stats.total_bytes = (data_end - data);
        flow_table.update(&key, &new_stats);
    }
    
    return XDP_PASS;
}
"""

def format_ip(addr):
    return socket.inet_ntoa(struct.pack("<L", addr))

def main():
    print("Person 2: Finalizing Connection & Flow Tracking...")
    b = BPF(text=BPF_PROGRAM)
    b.attach_kprobe(event="tcp_sendmsg", fn_name="trace_tcp_send")
    
    header = f"{'Source IP':<15} {'Dest IP':<15} {'DPort':<6} {'Pkts':<6} {'Bytes':<10} {'Duration (ms)':<15}"
    print(header)
    print("-" * len(header))

    try:
        while True:
            time.sleep(1)
            flows = b.get_table("flow_table")
            for key, val in flows.items():
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