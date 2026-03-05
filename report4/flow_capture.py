import socket
from bcc import BPF
from report3.flowTracking import BPF_PROGRAM, format_ip

PORTS = {
    22, 25, 53, 80, 443, 8080,
    8443, 3306, 5432, 6379
}

def loadBPF():
    return BPF(text=BPF_PROGRAM)

def classifyFlow(dst_port):
    # 0 = normal traffic; 1 = sus traffic
    return 0 if dst_port in PORTS else 1

def attachKProbe(bpf):
    # attach to tcp_sendmsg
    for sym in ("tcp_sendmsg", "__tcp_sendmsg"):
        try:
            bpf.attach_kprobe(event=sym, fn_name="trace_tcp_send")
            print(f"Attached kprobe to: {sym}")
            return
        except Exception:
            continue
    raise RuntimeError("Could not attach to tcp_sendmsg or __tcp_sendmsg.")

def getFlows(bpf):
    flows = []
    for key, val in bpf.get_table("flow_table").items():
        dst_port = int(socket.ntohs(key.dport))
        flows.append({
            "src_ip": format_ip(key.saddr),
            "dst_ip": format_ip(key.daddr),
            "src_port": int(key.lport),
            "dst_port": dst_port,
            "packet_count": int(val.packet_count),
            "total_bytes": int(val.total_bytes),
            "duration_ms": round((val.last_ns - val.start_ns) / 1_000_000, 2),
            "label": classifyFlow(dst_port),
            "protocol": "TCP"
        })
    return flows
