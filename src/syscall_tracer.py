#/usr/bin/python3

import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from utils.utils import get_path, initialize_parser, get_syscalls_mapping
from utils.elastic_setup import ElasticsearchLogger

import argparse
from bcc import BPF
from datetime import datetime
from kafka import KafkaProducer
import json
import logging
import time

# Global variables
monitor_pid = os.getpid()
terminal_pid = os.getppid()

msg_buffer = []
buffer_timestamp = None
time_window = 15
rate = 0
filters = []

# Initialize Elasticsearch logger
elasticsearch_logger = ElasticsearchLogger(filename=os.path.basename(__file__))
logger = elasticsearch_logger.get_logger()
logger.info("Elasticsearch logger initialised")

# Initialize Kafka Consumser
def initialize_kafka_producer():
    logger.info("Initializing Kafka Producer")
    try:
        producer = KafkaProducer(
            bootstrap_servers=['localhost:9092'],
            value_serializer=lambda v: json.dumps(v).encode('utf-8'),
            acks='all',  # Ensures maximum durability
            retries=5   # Retry a few times in case of send failure
        )
        logger.info("Kafka Producer set up")
        return producer
    except Exception as e:
        logger.error(f"Unable to initialize producer: {e}")
        logger.info("Exiting program")
        sys.exit(1)

def get_ebpf_program(syscalls, syscalls_mapping, filters):
    logger.info("Defining ebpf program text")
    filter_msg = ""
    
    for filter in filters:
        if filter_msg:
            filter_msg += " || "
        filter_msg += f"data.pid == {filter}"

    if filters:
        filter_msg = "|| " + filter_msg

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
}};

BPF_PERF_OUTPUT(syscall_events);

static int submit_syscall_event(struct pt_regs *ctx, u32 syscall_id) {{
    struct data_t data = {{}};

    data.pid = bpf_get_current_pid_tgid() >> 32;
    
    if (data.pid == MONITOR_PID || data.pid == TERMINAL_PID {filter_msg}) {{
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
            logging.warning(f"{syscall} not found in mapping")
    
    return prog
    
def send_msg_to_kafka():
    global msg_buffer
    if msg_buffer:
        try:
            logger.debug(f"Sending {len(msg_buffer)} messages in buffer to kafka")
            for msg in msg_buffer:
                producer.send('syscalls', value=msg)
            producer.flush()
            logger.debug("Messages sent")
            msg_buffer.clear()
        except Exception as e:
            logger.error(f"Unable to send messages to kafka - {e}")
            sys.exit(1)
        
if __name__ == "__main__":
    # Initialize argument parser
    parser = initialize_parser()
    parser.add_argument("-f", "--filters", type=str, help="List of PIDs to filter/ not include. Format: <PID>,<PID>,<PID> (comma-seperated with no spaces)")
    parser.add_argument("-s", "--syscalls", type=str, default="../src/syscalls.txt", help="Path to .txt files containing the list of syscalls to attach tracepoints to. Default: syscalls.txt")
    args = parser.parse_args()
    
    if args.filters:
        filters = args.filters.split(",")
        filters = [int(filter) for filter in filters]
    if args.loglevel:
        elasticsearch_logger.set_log_level(args.loglevel)

    syscalls_mapping = get_syscalls_mapping()
    
    with open(get_path(args.syscalls)) as file:
        syscalls = file.read().split()
    
    producer = initialize_kafka_producer()

    #Initialize BPF
    prog = get_ebpf_program(syscalls, syscalls_mapping, filters)
    b = BPF(text=prog)
  
    def process_event(cpu, data, size):
        global msg_buffer
        time_now = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        event = b["syscall_events"].event(data)
        msg = {"PID":event.pid, "syscall": event.syscall,"timestamp":time_now}
        print(msg)
        msg_buffer.append(msg)
        
    # Attach the BPF program to the sys_exit tracepoint (for a specific syscall)
    for syscall_name in syscalls:
        try:
            logger.info(f"Attaching tracepoint to sys_exit_{syscall_name}")
            b.attach_tracepoint(tp=f"syscalls:sys_exit_{syscall_name}", fn_name=f"get_info_{syscall_name}")
        except:
            logger.warning(f"Unable to attach tracepoint {syscall_name}")

    # Open the perf buffer
    b["syscall_events"].open_perf_buffer(process_event)

    start_time = datetime.now()
    # Poll for events
    logger.info("Polling events - details can be found in grafana/influxdb")
    while True:
        try:
            current_time = time.time()
            b.perf_buffer_poll()
            
            if buffer_timestamp is None:
                buffer_timestamp = current_time
            
            elapsed_time = current_time - buffer_timestamp
            if elapsed_time >= time_window:
                send_msg_to_kafka() 
                avg = int(len(msg_buffer)/elapsed_time)
                rate = int((rate + avg)/2) if rate else rate
                buffer_timestamp = None
            
        except Exception as e:
            logger.error(f"Error occured - {e}")
            duration = (current_time - start_time).total_seconds()
            if not rate:
                rate = int(len(msg_buffer)/duration)
            logger.info(f"rate: {rate} system calls triggered per second")
            logger.info("Exiting")
            break

