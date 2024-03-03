#!/usr/bin/python3

from bcc import BPF
import os
from datetime import datetime
import json
import time
from kafka import KafkaProducer

# Global variables
monitor_pid = os.getpid()
terminal_pid = os.getppid()
msg_buffer = []
buffer_timestamp = None
time_window = 15

def get_path(name):
    relative_path = os.path.join(os.path.dirname(__file__), name)
    absolute_path = os.path.abspath(relative_path)  
    return absolute_path

def get_ebpf_program(syscalls, syscalls_mapping):
    # Define eBPF program
    prog = f"""
    #define MONITOR_PID {monitor_pid}
    #define TERMINAL_PID {terminal_pid}
    #include <linux/sched.h>
    #include <linux/ptrace.h>

    struct data_t {{
        u32 pid;
        u32 syscall;
        char comm[TASK_COMM_LEN];
        u32 ppid;
    }};
    
    BPF_PERF_OUTPUT(syscall_events);

    static int submit_syscall_event(struct pt_regs *ctx, u32 syscall_id) {{
        struct data_t data = {{}};

        data.pid = bpf_get_current_pid_tgid() >> 32;
        
        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	data.ppid = task->real_parent->tgid;
        
        if (data.pid == MONITOR_PID || data.pid == TERMINAL_PID || data.ppid ==
        3279 || data.ppid == 1241){{
            return 0;
        }}

        data.syscall = syscall_id;

        bpf_get_current_comm(&data.comm, sizeof(data.comm));
        syscall_events.perf_submit(ctx, &data, sizeof(data));
        return 0;
    }}
    """

    for syscall in syscalls:
        try:
            syscall_no = syscalls_mapping.get(syscall)
            prog += f"""
            int get_info_{syscall}(struct pt_regs *ctx) {{
                return submit_syscall_event(ctx, {syscall_no});
            }}"""
        except:
            print(f"{syscall}: not found")
    
    return prog
    
def send_msg_to_kafka():
    global msg_buffer
    print(f"{len(msg_buffer)} messages in buffer")
    if msg_buffer:
        for msg in msg_buffer:
            producer.send('syscalls', value=msg)
        producer.flush()  # Ensure all buffered messages are sent
        print("messages sent")
        message_buffer = []  # Clear the buffer after sending

if __name__ == "__main__":
    with open(get_path("../data/train_syscalls_map.json"), 'r') as file:
        syscalls_mapping = json.load(file)
    
    with open(get_path("syscalls.txt")) as file:
        syscalls = file.read().split()
    
    producer = KafkaProducer(
	bootstrap_servers=['localhost:9092'],

	value_serializer=lambda v: json.dumps(v).encode('utf-8'),
	acks='all',  # Ensures maximum durability
	retries=5 # Retry a few times in case of send failure
    )

    prog = get_ebpf_program(syscalls, syscalls_mapping)
   
    #Initialize BPF
    b = BPF(text=prog)
  
    def print_event(cpu, data, size):
        """ Prints details of events triggered """
        global msg_buffer
        event = b["syscall_events"].event(data)
        msg = {"PID":event.pid, "syscall": event.syscall}
        msg_buffer.append(msg)
        
    # Attach the BPF program to the sys_exit tracepoint (for a specific syscall)
    count = 0
    failed = []
    for syscall_name in syscalls:
        try:
            b.attach_tracepoint(tp=f"syscalls:sys_exit_{syscall_name}", fn_name=f"get_info_{syscall_name}")
        except:
            count += 1
            print(f"Unable to attach kprobe {count}: {syscall_name}")
            failed.append(syscall_name)
            continue

    if failed:    
        file_path = get_path("unable.txt")
        with open(file_path, 'w') as file:
            file.write('\n'.join(map(str, array)))

    # Open the perf buffer
    b["syscall_events"].open_perf_buffer(print_event)

    start_time = datetime.now()
    # Poll for events
    while True:
        try:
            current_time = time.time()
            b.perf_buffer_poll()
            
            if buffer_timestamp is None:
                buffer_timestamp = current_time
            
            if current_time - buffer_timestamp >= time_window:
                send_msg_to_kafka() 
                buffer_timestamp = None
            
        except KeyboardInterrupt:
            for syscall_name in syscalls:
                b.detach_tracepoint(tp=f"syscalls:sys_exit_{syscall_name}")
            duration = (datetime.now() - start_time).total_seconds()
            print(f"rate: {int(buffer/duration)}")
            print(f"duration: {duration}")
            print(f"my PID: {monitor_pid}")
            break
