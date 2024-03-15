#/usr/bin/python3

import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from utils.utils import get_path, initialize_parser, get_syscalls_mapping
from utils.elastic_setup import ElasticsearchLogger
import pandas as pd
import os
import tensorflow as tf
import numpy as np
import json
import time
import mysql.connector
from sklearn.metrics import log_loss
from alerting import generate_alert
from datetime import datetime

# Global variables
window_size = 100
last_timestamp = None
theta = os.getenv("HIDS_THRESHOLD")

# Initialize Elasticsearch logger
elasticsearch_logger = ElasticsearchLogger(filename=os.path.basename(__file__))
logger = elasticsearch_logger.get_logger()
logger.info("Elasticsearch logger initialised")

mapping = get_syscalls_mapping()
reverse_mapping = {value:key for key,value in mapping.items()}

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
    print(f"failed mysql - {e}")
    logger.error(f"Unable to connect to MySQL database: {e}")
    logger.info("Exiting program")
    sys.exit(1)
    

def send_to_db(timestamp, pid):
    sql = "INSERT INTO anomalies (timestamp, pid) VALUES (%s, %s)"
    values = (timestamp, pid)
    mysql_cursor.execute(sql,values)
    mysql_connection.commit()
    logger.info("Sent anomaly details to DB")


def get_trace_anomaly_score(model, trace):

    syscalls = np.array(trace, dtype=np.float32)
    # Prepare the input sequences and target system calls
    X = tf.keras.preprocessing.sequence.pad_sequences([syscalls[:-1]], dtype='float32')
    y = tf.keras.preprocessing.sequence.pad_sequences([syscalls[1:]], dtype='float32')

    # Get the model's predictions for the input sequences
    y_pred = model.predict(X)

    # Get the predicted system calls for the entire sequence
    predicted_syscalls = np.argmax(y_pred, axis=-1)

    # Calculate the log loss
    log_likelihood = -log_loss(y, y_pred.squeeze())

    return -log_likelihood

def get_application_anomaly_score(model, app_syscalls):
    
    trace_scores = [get_trace_anomaly_score(model, trace) for trace in app_syscalls]
    
    app_score = np.median(trace_scores)
    
    return app_score 
    
def analyze_sequence(model, pid, traces):
    # Split into window size
    app_syscalls = []
    sequence = []
    
    for idx, trace in enumerate(traces):
        sequence.append(trace)
        print(f"{idx}:{trace}")
        if len(sequence) == window_size or idx == len(traces) - 1:
            app_syscalls.append(sequence)
            sequence = []
    
    app_score = get_application_anomaly_score(model, app_syscalls)
    if app_score > theta:
        timestamp = datetime.now()
        subject = "ANOMALY DETECTED: Process ID {pid}}"
        body = f"anomaly detected at {timestamp} from process ID {pid}\nSystem call sequences triggered: {[reverse_mapping.get(trace) for trace in traces]}"
        logger.info(body) 
        send_to_db(timestamp, pid)

if __name__ == "__main__":
    # Load LSTM model
    model_path = get_path("../model/model_lstm_2.ckpt")
    model = tf.keras.models.load_model(model_path)

    # Construct Flux query to retrieve unique PIDs
    while True:
        try:
            filter = f"'{last_timestamp}'" if last_timestamp else "DATE_SUB(NOW(), INTERVAL 1 DAY)"

            query = f'''SELECT s1.pid, s1.syscall_no, s1.timestamp
                FROM syscalls s1
                JOIN (SELECT DISTINCT pid FROM syscalls) s2
                ON s1.pid = s2.pid
                WHERE s1.timestamp > {filter}
                ORDER BY s1.pid, s1.timestamp desc;
            '''

            # Execute query
            mysql_cursor.execute(query)
            result = mysql_cursor.fetchall()
            
            if result:
                sequence = []
                group_pid = result[0][0]
                
                for idx, (pid, syscall, timestamp) in enumerate(result):
                    if group_pid != pid or idx == len(result)-1 : 
                        analyze_sequence(model, group_pid, sequence)
                        
                        if not last_timestamp or timestamp > last_timestamp:
                            last_timestamp = timestamp
                        sequence.clear()
                        group_pid = pid
                
                    sequence.append(syscall)
        except Exception as e:
            error_msg = f"An exception occurred - {e}. \n Please investigate"
            logger.error(error_msg)
            subject = "NODE UNAVAILABLE - [Anomaly detection engine down]"
            generate_alert(subject, error_msg)
            
            mysql_cursor.close()
            mysql_connection.close()
            sys.exit(1)
