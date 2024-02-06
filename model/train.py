import torch.nn as nn
from torch.utils.data import DataLoader
from torch.nn.utils.rnn import pack_sequence
from torch.optim import Adam
from lstm import seq2seq, encoder, decoder  # Adjust this import based on your file structure
from preprocess import preprocess_data

import torch
import random
import numpy as np

# Set a fixed random seed for reproducibility
seed = 42
torch.manual_seed(seed)
random.seed(seed)
np.random.seed(seed)

# Set device (CPU or GPU)
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

def train():
    # Hyperparameters
    learning_rate = 0.001
    num_epochs = 10
    batch_size = 64

    # Create data loader
    dataloader = preprocess_data(batch_size)
    # data_loader = create_data_loader(data_list, batch_size)

    # Initialize model components
    
    model = seq2seq()


    #Define the loss function (MSE) and optimizer
    criterion = nn.MSELoss()
    optimizer = Adam(model.parameters(), lr=learning_rate)

    # Train the model
    # model.train_model(data_list, num_epochs, learning_rate)
    for epoch in range(num_epochs):
        total_loss = 0
        
        for packed_sequence in dataloader:
            optimizer.zero_grad()
            
            # Forward pass
            output_sequence = model(packed_sequence)
            
            # Compute the loss between the output and input sequence
            loss = criterion(output_sequence.data, packed_sequence.data)
            
            # Backpropagation and optimization
            loss.backward()
            optimizer.step()
            
            total_loss += loss.item()
        
        # Print the average loss for this epoch
        average_loss = total_loss / len(dataloader)
        print(f'Epoch [{epoch + 1}/{num_epochs}], Loss: {average_loss:.4f}')


if __name__ == "__main__":
    train()
