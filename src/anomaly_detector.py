from influxdb import InfluxDBClient
import pandas as pd
import os
import tensorflow as tf
from sklearn.ensemble import IsolationForest
import numpy as np
import json

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

# InfluxDB config
host = os.getenv("INFLUXDB_HOST")
port = os.getenv("INFLUXDB_PORT")
username = os.getenv("INFLUXDB_USERNAME")
password = os.getenv("INFLUXDB_PASSWORD")
database = os.getenv("INFLUXDB_DATABASE")

# Create InfluxDB client
client = InfluxDBClient(host=host, port=port, username=username, password=password, database=database)

# Load LSTM model
model_path = get_path("../model/model_<keras.src.engine.functional.Functional object at 0x2a6eeea30>_2.ckpt")
model = tf.keras.models.load_model(model_path)
anomaly_detector = IsolationForest(contamination=0.1)

# Construct Flux query to retrieve unique PIDs
while True:
    try:
        if last_timestamp is None:
            query = '''
                SELECT "PID", "syscall"
                FROM "syscalls"
                WHERE time > now() - 1d
            '''
        else:
            query = f'''
                SELECT "PID", "syscall"
                FROM "syscalls"
                WHERE time > '{last_timestamp}'
            '''

        # Execute query
        print(query)
        result = client.query(query)
    
        if not result.empty:
            last_timestamp = pd.to_datetime(result.index[-1]).isoformat()
            grouped = result.groupby("PID")

            for pid, group in grouped:
                print(f"Analyzing {pid}")
                sequences = group['syscall'].astype(np.float32).values
                
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
            
    except Exception as e:
        print(f"Exception occurred: {e}")
        client.close()
