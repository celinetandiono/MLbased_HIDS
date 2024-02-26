from bcc import BPF
import os
from datetime import datetime
import json
from confluent_kafka import Producer

# Global variables
monitor_pid = os.getpid()
batch_size = 50000
buffer = 0

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
        prog += f"""
        int get_info_{i}(struct pt_regs *ctx) {{
            return submit_syscall_event(ctx, {syscalls_mapping.get(i)});
        }}"""
    
    return prog

if __name__ == "__main__":
    #Setup Kafka Producer
    kafka_config = {'bootstrap.servers': 'localhost:9092'}
    producer = Producer(kafka_config)
    topic = 'systemcalls'

    def partitioner(pid):
        return hash(pid) % 5

    with open(get_path("../data/train_syscalls_map.json"), 'r') as file:
        syscalls_mapping = json.load(file)
    
    prog = get_ebpf_program(syscalls_mapping)
   
    #Initialize BPF
    b = BPF(text=prog)
  
    def send_to_kafka(cpu, data, size):
        """ Prints details of events triggered """
        global buffer
        buffer += 1
        event = b["syscall_events"].event(data)

        msg = {}
        msg["PID"] = event.pid
        msg["syscall"] = event.syscall
        msg = json.dumps(msg).encode('utf-8')

        partition = partitioner(event.pid)
        key = str(event.pid).encode('utf-8')
        
        producer.produce(topic_name, value=msg, key=key, partition=partition)

        if buffer == 50000:
            producer.flush()
            buffer = 0
        

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
    b["syscall_events"].open_perf_buffer(send_to_kafka)

    start_time = datetime.now()
    # Poll for events
    while True:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            duration = (datetime.now() - start_time).total_seconds()
            print(f"duration: {duration}")
            print(f"my PID: {monitor_pid}")
            break
