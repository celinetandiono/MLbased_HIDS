import os
import torch
from torch.nn.utils.rnn import pack_sequence

def get_path(folder_name):
    relative_path = os.path.join(os.path.dirname(__file__), f"../ADFA-LD/{folder_name}")
    absolute_path = os.path.abspath(relative_path)  

    return absolute_path

def convert_to_tensor(filepath):
    with open(filepath, 'r') as file:
        data = [int(value) for value in file.read().split()]
        print(data)
        
        # convert data to tensor
        tensor_data = torch.tensor(data, dtype=torch.int32)
        return tensor_data

def preprocess():
    folders = ["Training_Data_Master", "Validation_Data_Master"]
    data = []
    
    for folder in folders:
        print(folder)
        path = get_path(folder)

        for file in os.listdir(path):
            data.append(convert_to_tensor(os.path.join(path,file)))
            break
            
    return pack_sequence(data, enforce_sorted=True)

preprocess()