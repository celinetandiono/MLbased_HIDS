from influxdb import InfluxDBClient
import pandas as pd
import os
import tensorflow as tf
from sklearn.ensemble import IsolationForest
import numpy as np
import json
import time

window_size = 100
last_timestamp = None

def get_path(name):
    relative_path = os.path.join(os.path.dirname(__file__), name)
    absolute_path = os.path.abspath(relative_path)  
    return absolute_path

# Get syscalls mapping and flip
with open(get_path("../data/train_syscalls_map.json")) as file:
    mapping = json.load(file)
reverse_mapping = {value:key for key,value in mapping.items()}

host = os.getenv("INFLUXDB_HOST")
port = os.getenv("INFLUXDB_PORT")
uname = os.getenv("INFLUXDB_UNAME")
pwd = os.getenv("INFLUXDB_PWD")
database = os.getenv("INFLUXDB_DB")

# Create InfluxDB client
client = InfluxDBClient(host=host, port=port, username=uname, password=pwd, database=database)

# Load LSTM model
model_path = get_path("../model/model_<keras.src.engine.functional.Functional object at 0x2a6eeea30>_2.ckpt")
model = tf.keras.models.load_model(model_path)
anomaly_detector = IsolationForest(contamination=0.1)

# Construct Flux query to retrieve unique PIDs
while True:
    if last_timestamp is None:
        query = '''
            SELECT *
    	    FROM "syscalls"
    	    WHERE time > now() - 1d
    	    GROUP BY "PID"
        '''
    else:
        query = f'''
            SELECT *
    	    FROM "syscalls"

    	    WHERE time > '{last_timestamp}'
    	    GROUP BY "PID"
        '''

    # Execute query
    result = client.query(query, database=database)
    
    for group_key, group_data in result.items():
        print(f"Analyzing PID: {group_key[1]['PID']}")
        sequences = []
        for point in group_data:
            sequences.append(point['syscall'])
            if last_timestamp is None or pd.to_datetime(point['time']) > pd.to_datetime(last_timestamp):
                last_timestamp = point['time']
        
        sequences = np.array(sequences, dtype=np.float32)
        print(sequences)   
        
        if len(sequences) < window_size:
            padded_syscalls = np.pad(sequences, (0, window_size - len(sequences)), mode='constant')
            sequences = padded_syscalls.reshape(1, window_size)
        else:
            num_windows = len(sequences) //  window_size
            sequences = sequences[:num_windows * window_size].reshape(-1, window_size)

        # Use LSTM autoencoder model for prediction
        predictions = model.predict(sequences)

        # Calculate reconstruction error for each sequence
        reconstruction_errors = tf.keras.losses.sparse_categorical_crossentropy(sequences, predictions).numpy().mean(axis=1)
        
        anomalies = anomaly_detector.fit_predict(reconstruction_errors.reshape(-1, 1)) == -1

        # Process anomalies
        for idx, is_anomaly in enumerate(anomalies):
            if is_anomaly:
                sequence = sequences[idx]
                print(f"Anomaly detected in sequence of PID {pid}: {sequence}")
                decoded = [reverse_mapping.get(int(syscall)) for syscall in sequence]
                print(f"Decoded sequence: {decoded}")

