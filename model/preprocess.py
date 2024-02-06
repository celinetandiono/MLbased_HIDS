import os
import torch
from torch.nn.utils.rnn import pack_sequence, PackedSequence, pad_sequence
from torch.utils.data import DataLoader, Dataset

def get_path(folder_name):
    relative_path = os.path.join(os.path.dirname(__file__), f"../ADFA-LD/{folder_name}")
    absolute_path = os.path.abspath(relative_path)  
    return absolute_path

def custom_collate_fn(batch):
    batch.sort(key=lambda x: len(x), reverse=True)

    # Pack the padded sequences
    packed_batch = pack_sequence(batch, enforce_sorted=True)

    return packed_batch

def load_data(batch_size):
    folders = ["Training_Data_Master", "Validation_Data_Master"]
    sequences = []
    
    for folder in folders:
        folder_path = get_path(folder)
       
        for file in os.listdir(folder_path):
            file_path = os.path.join(folder_path, file)
            with open(file_path, 'r') as file:
                traces = [int(value) for value in file.read().split()]
                sequences.append(torch.tensor(traces, dtype=torch.float32))

    return DataLoader(sequences, batch_size = batch_size, shuffle = False, collate_fn=custom_collate_fn)


def preprocess_data(batch_size):
    return load_data(batch_size)

class twoDListDataset(Dataset):
    def __init__(self, list_of_lists):
        self.list_of_lists = list_of_lists

    def __len__(self):
        return len(self.list_of_lists)

    def __getitem__(self, idx):
        return self.list_of_lists[idx]
