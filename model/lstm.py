import torch.nn as nn
from torch.optim import Adam


class encoder(nn.Module):

    def __init__(self, input_size = 1, hidden_size = 1, num_layers = 3, batch_first = True):
        
        super().__init__()
        self.input_size = input_size
        self.hidden_size = hidden_size
        self.num_layers = num_layers

        # define LSTM layer
        self.lstm = nn.LSTM(input_size=input_size, hidden_size=hidden_size, 
                            num_layers=num_layers, batch_first=batch_first)

    def forward(self, packed_input):
        input_data, batch_sizes = nn.utils.rnn.pad_packed_sequence(packed_input, batch_first=True)

        packed_output, (hidden, cell) = self.lstm(input_data.unsqueeze(-1))
        # packed_output will be a PackedSequence containing all hidden states
        # hidden is the last hidden state for each layer in the LSTM, and cell is the last cell state
        return packed_output, (hidden, cell)

class decoder(nn.Module):
    def __init__(self, input_size = 1, hidden_size = 1, num_layers = 3):
        
        super().__init__()
        self.input_size = input_size
        self.hidden_size = hidden_size
        self.num_layers = num_layers

        self.lstm = nn.LSTM(input_size, hidden_size, num_layers)
        self.linear = nn.Linear(hidden_size, input_size)           

    def forward(self, encoder_output, hidden):
        # packed_input is the packed sequence from the encoder
        # hidden is the last hidden state and cell state from the encoder

        lstm_out, self.hidden = self.lstm(encoder_output, hidden)

        reconstructed_sequence = self.linear(lstm_out)

        return reconstructed_sequence, self.hidden

class seq2seq(nn.Module):
    
    def __init__(self):
        super().__init__()

        self.encoder = encoder(input_size=1, hidden_size=1, num_layers=3)
        self.decoder = decoder(input_size=1, hidden_size=1, num_layers=3)

    def forward(self, input_sequence):
        # Encode the input sequence
        encoded, (hidden, cell) = self.encoder(input_sequence)

        # Decode using the encoder's hidden and cell states
        reconstructed_sequence, _ = self.decoder(encoded, (hidden, cell))
        
        return reconstructed_sequence
    
