"""
File: preprocess.py
Author: Celine Tandiono (based on code by John Ring)
Date: 28 February 2024
Description: Contains the preprocessing the ADFA-LD and PLAID dataset for ML training

References:
John H. Ring IV, Colin M. Van Oort, Samson Durst, Vanessa White, Joseph P. Near, and Christian Skalka. 2021. Methods for Host-based Intrusion Detection with Deep Learning. Digit. Threat. Res. Pract. 2, 4, Article 26 (October 2021), 29 pages. https://doi.org/10.1145/3461462

This code is based on the concepts and methodologies described in the above paper by John Ring et al., with modifications and enhancements made by Celine Tandiono.
"""
#/usr/bin/python3

import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from utils.utils import get_path, get_syscalls_mapping
import os
import numpy as np
import tensorflow as tf
from pathlib import Path

syscall_mapping = get_syscalls_mapping()
def encode(syscall):
    return syscall_mapping[syscall]

def get_sequence(files):
    sequences = []
    for file in files:
        with open(file) as file:
            sequence = file.read().strip().split(" ")
            if 8 <= len(sequence) <= 4495:
                sequences.append(sequence)
    return sequences
    
def get_training_data(dataset):
    """Loads requested system call data set from disk
    """

    if dataset == "adfa":
        attack_path = "../data/ADFA_decoded/Attack_Data_Master"
        normal_path = "../data/ADFA_decoded/normal"
    elif dataset == "plaid":
        attack_path = "../data/ADFA_decoded/Attack_Data_Master"
        normal_path = "../data/ADFA_decoded/Training_Data_Master"
    else:
        attack_path = "../data/merged_data/attack"
        normal_path = "../data/merged_data/normal"

    attack_files = list(Path(get_path(attack_path)).rglob("*.txt"))
    normal_files = list(Path(get_path(normal_path)).rglob("*.txt")) 

    print("Obtaining attack sequences...")
    attack_sequences = get_sequence(attack_files)
    print("Obtaining normal sequences...")
    normal_sequences = get_sequence(normal_files)

    return attack_sequences, normal_sequences

def load_data_splits(attack_sequences, normal_sequences):
    # create test with 1:1 ratio attack and val
    normal_idxs = np.arange(len(normal_sequences)) 
    np.random.shuffle(normal_idxs)
    test_val_files = []

    split = len(attack_sequences)
    for idx in normal_idxs[: split]:
        test_val_files.append(normal_sequences[idx])

    normal_idxs = normal_idxs[split :]
    val_split = 0.2 # 0.2 for validation, 0.8 for training
    val_split = int(np.round(len(normal_idxs) * val_split))
    val_files = []
    for idx in normal_idxs[:val_split]:
        val_files.append(normal_sequences[idx])

    train_files = []
    for idx in normal_idxs[val_split:]:
        train_files.append(normal_sequences[idx])

    vec_encode = np.vectorize(encode)
    train = [vec_encode(row).astype(np.float32) for row in train_files]
    val = [vec_encode(row).astype(np.float32) for row in val_files]
    atk = [vec_encode(row).astype(np.float32) for row in attack_sequences]
    test_val = [vec_encode(row).astype(np.float32) for row in test_val_files]

    train = tf.data.Dataset.from_tensor_slices(tf.ragged.constant(train))
    val = tf.data.Dataset.from_tensor_slices(tf.ragged.constant(val))
    return train, val, test_val, atk

def get_data(dataset="adfa", batch_size=64):
    attack_sequences, normal_sequences = get_training_data(dataset)
    train, val, test_val, atk = load_data_splits(attack_sequences, normal_sequences) 

    def add_train_labels(x):
        result = x[:-1], x[1:]
        return result

    train = (
        train.map(add_train_labels)
        .shuffle(buffer_size=1024)
        .padded_batch(batch_size, padded_shapes=([None], [None]))
    )
    val = (
        val.map(add_train_labels)
        .padded_batch(batch_size, padded_shapes=([None],[None],))
    )
    test = (
        tf.data.Dataset.from_tensor_slices(tf.ragged.constant(test_val + atk))
        .map(lambda x: x)
        .padded_batch(batch_size, padded_shapes=(None,))
    )
    test_labels = np.zeros(len(test_val) + len(atk))
    test_labels[len(test_val) :] = 1
    return (
        train,
        val,
        (test, test_labels),
    )

if __name__ == "__main__":
    train, cal, tests = get_data()