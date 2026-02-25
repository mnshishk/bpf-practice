from bcc import BPF
import time

INTERFACE = "enp0s3"
INTERVAL = 1

BPF_PROGRAM = """
BPF_ARRAY(packet_count, u64, 1);

int count_packets(struct xdp_md *context) {
    int key = 0;
    u64 *count = packet_count.lookup(&key);
    if (count)
        (*count)++;
    return XDP_PASS;
}
""" # BPF map with counter value

def loadBPF(interface):
    b = BPF(text=BPF_PROGRAM)
    b.attach_xdp(interface, b.load_func("count_packets", BPF.XDP)) # attach the XDP to the network
    return b

def packetCount(bpf, interface):
    packet_count = bpf["packet_count"]

    print("Counting packets on {interface}; press Ctrl+C to stop")
    try:
        while True:
            count = packet_count[0].value           # retreieve the map value
            print(f"Packets seen: {count}")
            time.sleep(INTERVAL)                    # polling interval
    except KeyboardInterrupt:
        print("\nInterrupt received, stopping...")
    finally:
        bpf.remove_xdp(interface)  # clean up
        print("Done.")

def main():
    # use ping in the terminal to start sending packets; ping goosgle.com
    bpf = loadBPF(INTERFACE)
    packetCount(bpf, INTERFACE)

if __name__ == "__main__":
    main()