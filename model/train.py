import torch.nn as nn
from torch.nn.utils.rnn import pack_sequence
from torch.optim import Adam
from lstm import seq2seq # Adjust this import based on your file structure
from preprocess import load_data

import torch
import random
import numpy as np
import time

# Set a fixed random seed for reproducibility
seed = 42
torch.manual_seed(seed)
random.seed(seed)
np.random.seed(seed)

# Set device (CPU or GPU)
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
torch.set_printoptions(threshold=5_000)

def train():
    # Hyperparameters
    learning_rate = 0.001
    num_epochs = 10
    batch_size = 64

    # Load the ADFA-LD dataset
    data = load_data(batch = False, batch_size = batch_size)

    # Initialize model components
    model = seq2seq()

    #Define the loss function (MSE) and optimizer
    criterion = nn.MSELoss()
    optimizer = Adam(model.parameters(), lr=learning_rate)

    # Assuming `dataset` is a list or a tensor containing your data.
    batch_size = 64
    
    # Process your batch
    for epoch in range(num_epochs):
        start_time = time.time() 
        random.shuffle(data)

        print(f'Epoch [{epoch + 1}/{num_epochs}]')
        total_loss = 0
        
        for i in range(0, len(data), batch_size):
            batch = data[i:i+batch_size] 
            batch.sort(key=lambda x: len(x), reverse=True)

            packed_batch = pack_sequence(batch, enforce_sorted=True)

            optimizer.zero_grad()
            
            # Forward pass
            output_sequence = model(packed_batch)
            
            # Compute the loss between the output and input sequence
            unpacked_batch, _ = nn.utils.rnn.pad_packed_sequence(packed_batch, batch_first=True)
            loss = criterion(output_sequence, unpacked_batch)
            
            # Backpropagation and optimization
            loss.backward()
            optimizer.step()
            
            total_loss += loss.item()
            
        
        # Print the average loss for this epoch
        average_loss = total_loss / len(data)
        print(f'  Loss: {average_loss:.4f}')
        end_time = time.time()  # Timer stops after the loop iteration
        print(f'  Time taken: {end_time - start_time} seconds')

if __name__ == "__main__":
    train()
