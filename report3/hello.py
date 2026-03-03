from bcc import BPF

# quick test

program = """
int hello(void *context) {
    bpf_trace_printk("Hello, World!\\n");
    return 0;
}
"""

b = BPF(text=program)
b.attach_kprobe(event=b.get_syscall_fnname("clone"), fn_name="hello")
b.trace_print()