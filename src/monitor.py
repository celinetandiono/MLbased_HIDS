from bcc import BPF
import os
from datetime import datetime
import json

# Global variables
requests = 0
monitor_pid = os.getpid()

def get_path(name):
    relative_path = os.path.join(os.path.dirname(__file__), name)
    absolute_path = os.path.abspath(relative_path)  
    return absolute_path

def get_ebpf_program(syscalls_mapping):
    # Define eBPF program
    prog = f"""
    #define MONITOR_PID {monitor_pid}
    #include <linux/sched.h>
    #include <linux/ptrace.h>

    struct data_t {{
        u32 pid;
        u32 syscall;
        char comm[TASK_COMM_LEN];
    }};

    BPF_PERF_OUTPUT(syscall_events);

    static int submit_syscall_event(struct pt_regs *ctx, u32 syscall_id) {{
        struct data_t data = {{}};

        data.pid = bpf_get_current_pid_tgid() >> 32;
        if (data.pid == MONITOR_PID){{
            return 0;
        }}

        data.syscall = syscall_id;

        bpf_get_current_comm(&data.comm, sizeof(data.comm));
        syscall_events.perf_submit(ctx, &data, sizeof(data));
        return 0;
    }}
    """

    for i in syscalls_mapping.keys():
        prog += f"int get_info_{i}(struct pt_regs *ctx) {{\n\
        return submit_syscall_event(ctx, {syscalls_mapping.get(i)});\n\
        }}\n\n"
    
    return prog

if __name__ == "__main__":
    with open(get_path("../data/train_syscalls_map.json"), 'r') as file:
        syscalls_mapping = json.load(file)

    prog = get_ebpf_program(syscalls_mapping)

    #Initialize BPF
    b = BPF(text=prog)

    def print_event(cpu, data, size):
        """ Prints details of events triggered """
        global requests
        event = b["syscall_events"].event(data)
        if (event.comm.decode() != "sshd"):
            requests += 1
            print(f"PID {event.pid}: | System Call: {event.syscall} | Command:{event.comm.decode()}")

    # Attach the BPF program to the sys_exit tracepoint (for a specific syscall)
    count = 0
    array = []
    for syscall_name in syscalls_mapping.keys():
        try:
            b.attach_kprobe(event=b.get_syscall_fnname(syscall_name), fn_name=f"get_info_{syscall_name}")
        except:
            count += 1
            print(f"Unable to attach kprobe {count}: {syscall_name}")
            array.append(syscall_name)
            continue
        
    file_path = get_path("unable.txt")
    with open(file_path, 'w') as file:
        file.write('\n'.join(map(str, array)))

    # Open the perf buffer
    b["syscall_events"].open_perf_buffer(print_event)

    start_time = datetime.now()
    # Poll for events
    while True:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            duration = (datetime.now() - start_time).total_seconds()
            rate = requests/ duration
            print(f"{requests} system calls triggered in {duration} seconds")
            print(f"rate: {rate}")
            print(f"my PID: {monitor_pid}")
            break
