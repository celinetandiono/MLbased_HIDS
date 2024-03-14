#/usr/bin/python3

import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from utils.elastic_setup import ElasticsearchLogger
from utils.utils import get_path, initialize_parser, get_syscalls_mapping
from kafka import KafkaConsumer
import json
import time
from datetime import datetime
import argparse
import mysql.connector

# global variables
msg_buffer = []
buffer_timestamp = None
time_window = 10

# Initialize Elasticsearch logger
elasticsearch_logger = ElasticsearchLogger(filename=os.path.basename(__file__))
logger = elasticsearch_logger.get_logger()
logger.info("Elasticsearch logger initialised")

# Initialize Kafka Consumer
def initialize_kafka_consumer():
    logger.info("Initializing Kafka Producer")
    try:
        consumer = KafkaConsumer(
            'syscalls',  
            bootstrap_servers='localhost:9092', 
            auto_offset_reset='earliest',  # Start reading from the earliest message if no offset is stored
            group_id='aglclt',
            enable_auto_commit=False,  # Enable automatic offset commit
            value_deserializer=lambda x: json.loads(x.decode('utf-8'))  # Deserializer for JSON-encoded messages
        )
        logger.info("Kafka consumer set up")
        return consumer
    except Exception as e:
        logger.error(f"Unable to initialize consumer: {e}")
        logger.info("Exiting program")
        sys.exit(1)

if __name__ == "__main__":
    # Initialize argument parser
    parser = initialize_parser()
    args = parser.parse_args()
    if args.loglevel:
        elasticsearch_logger.set_log_level(args.loglevel)
    
    # MySQL Config
    mysql_host = os.getenv("MYSQL_HOST")
    mysql_user = os.getenv("MYSQL_USER")
    mysql_password = os.getenv("MYSQL_PWD")
    mysql_database = os.getenv("MYSQL_DB")

    # Initialize MySQL Connection
    logger.info("Initializing MySQL Connection")
    try:
        mysql_connection = mysql.connector.connect(
            host=mysql_host,
            user=mysql_user,
            password=mysql_password,
            database=mysql_database
        )
        mysql_cursor = mysql_connection.cursor()
        logger.info("MySQL connection established")
    except Exception as e:
        logger.error(f"Unable to connect to MySQL database: {e}")
        logger.info("Exiting program")
        sys.exit(1)

    # Initialize Kafka consumer
    consumer = initialize_kafka_consumer()
    
    mapping = get_syscalls_mapping()
    reverse_mapping = {value:key for key,value in mapping.items()}
    
    # Consume messages
    for message in consumer:
        try:
            current_time = time.time()
            if buffer_timestamp is None: 
                buffer_timestamp = current_time

            data = message.value
            timestamp = datetime.strptime(data["timestamp"], "%d/%m/%Y %H:%M:%S")
            syscall = data["syscall"]
            
            # Prepare SQL statement
            sql = "INSERT INTO syscalls (timestamp, syscall_no, syscall, pid) VALUES (%s, %s, %s, %s)"
            values = (timestamp, syscall, reverse_mapping.get(syscall),data["PID"])
            msg_buffer.append(values)

            elapsed_time = current_time - buffer_timestamp
            if len(msg_buffer) >= 5000 or elapsed_time >= time_window:
                # Execute SQL batch insert
                mysql_cursor.executemany(sql, msg_buffer)
                mysql_connection.commit()
                logger.debug(f"{len(msg_buffer)} data points written to InfluxDB")
                msg_buffer.clear()
                buffer_timestamp = None
            
            consumer.commit()
    
        except Exception as e:
            logger.error(f"An error occurred: {e}")
            consumer.close()
            client.close()
            sys.exit(1)



