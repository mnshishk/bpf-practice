from bcc import BPF
from report3.flowTracking import BPF_PROGRAM, format_ip

ATTACK_PORTS = {21, 23, 1337, 31337, 4444, 5555, 6666, 8888, 9999}

def loadBPF():
    return BPF(text=BPF_PROGRAM)

def attachXDP(bpf, interfaces=["enp0s3", "lo"]):
    fn = bpf.load_func("xdp_filter", BPF.XDP)
    for iface in interfaces:
        try:
            bpf.attach_xdp(iface, fn, flags=2)
            print(f"Attached XDP to {iface}")
        except:
            print(f"Could not attach to {iface}")

def classifyFlow(dst_port, src_port):    
    if dst_port in ATTACK_PORTS or src_port in ATTACK_PORTS:
        return 1
    return 0

def getFlows(bpf):
    flows = []
    for key, val in bpf.get_table("flow_table").items():
        flows.append({
            "src_ip": format_ip(key.saddr),
            "dst_ip": format_ip(key.daddr),
            "src_port": int(key.sport),
            "dst_port": int(key.dport),
            "packet_count": int(val.packet_count),
            "total_bytes": int(val.total_bytes),
            "duration_ms": 0,
            "label": classifyFlow(int(key.dport), int(key.sport)),
            "protocol": "TCP"
        })
    return flows