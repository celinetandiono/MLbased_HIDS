from kafka import KafkaConsumer
from influxdb import InfluxDBClient
import json
import os
import time
from datetime import datetime

# global variables
msg_buffer = []
buffer_timestamp = None
time_window = 10

print(os.getpid())

# InfluxDB config
host = os.getenv("INFLUXDB_HOST")
port = os.getenv("INFLUXDB_PORT")
uname = os.getenv("INFLUXDB_UNAME")
pwd = os.getenv("INFLUXDB_PWD")
database = os.getenv("INFLUXDB_DB")

# Initialize influxdb client
client = InfluxDBClient(host=host, port=port, username=uname, password=pwd, database=database)

# Initialize Kafka consumer
consumer = KafkaConsumer(
    'syscalls',  
    bootstrap_servers='localhost:9092', 
    auto_offset_reset='earliest',  # Start reading from the earliest message if no offset is stored
    group_id='aglclt',
    enable_auto_commit=False,  # Enable automatic offset commit
    value_deserializer=lambda x: json.loads(x.decode('utf-8'))  # Deserializer for JSON-encoded messages
)


# Consume messages
for message in consumer:
    try:
        current_time = time.time()
        if buffer_timestamp is None: 
            buffer_timestamp = current_time

        data = message.value
        print(data)
        timestamp = datetime.strptime(data["timestamp"], "%d/%m/%Y %H:%M:%S")
        
        data_point = {
            "measurement": "syscalls",
            "tags": {"PID": str(data["PID"])},
            "time": timestamp,
            "fields": {"syscall": data["syscall"]}
        }
        msg_buffer.append(data_point)

        elapsed_time = current_time - buffer_timestamp
        if len(msg_buffer) >= 5000 or elapsed_time >= time_window:
            print("limit reached - flushing")
            client.write_points(msg_buffer)
            msg_buffer.clear()
            buffer_timestamp = None
            
        consumer.commit()
    
    except Exception as e:
        print(f"An error occurred: {e}")
        consumer.close()
        client.close()



