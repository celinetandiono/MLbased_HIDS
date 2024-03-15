"""
File: models.py
Author: Celine Tandiono (based on code by John Ring)
Date: 28 February 2024
Description: Contains the model definition and training for HIDS development

References:
John H. Ring IV, Colin M. Van Oort, Samson Durst, Vanessa White, Joseph P. Near, and Christian Skalka. 2021. Methods for Host-based Intrusion Detection with Deep Learning. Digit. Threat. Res. Pract. 2, 4, Article 26 (October 2021), 29 pages. https://doi.org/10.1145/3461462

This code is based on the concepts and methodologies described in the above paper by John Ring et al., with modifications made by Celine Tandiono.
"""
#/usr/bin/python3

import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from utils.utils import get_path
import os
from pathlib import Path
from tensorflow.keras import layers, models, optimizers
from functools import partial
from preprocess import get_data
import numpy as np

def create_lstm_model(hp=None, vocab_size=176, depth=2, cells=200, dropout=0.5):
    """Replication of LSTM model used for IDS development on ADFA-LD.

    paper: LSTM-Based System-Call Language Modeling and Robust Ensemble Method for Designing Host-Based Intrusion
     Detection Systems https://arxiv.org/abs/1611.01726

    Parameters
    ----------
    hp : Keras Tuner Hyper-Parameters
        Contains and sets the following: depth, filters, dropout, and emb_n. Used in place of setting parameters
        individually. See below for a description of each parameter.
    vocab_size : int
        Number of input and output features.
    depth : int
         Number of consecutive LSTM layers used in model construction. Only takes affect if hp is None.
    cells : int
        Number of units in each LSTM and embedding layers. Only takes affect if hp is None.
    dropout : float
        Dropout rate to use, no dropout is applied if value is None. Value must be in range [0, 1). Only takes affect if
        hp is None.

    Returns
    -------
    Compiled tf.keras model.

    """
    if hp is not None:
        depth = hp.Int("depth", 1, 4)
        cells = hp.Choice("cells", [128, 200, 256, 400, 512])
        dropout = hp.Float("drop_rate", min_value=0.0, max_value=0.9, step=0.01)

    input_layer = layers.Input(shape=[None])
    embedding_layer = layers.Embedding(vocab_size, cells, input_length=None)(
        input_layer
    )
    lstm = layers.LSTM(cells, return_sequences=True)(embedding_layer)
    for _ in range(depth - 1):
        lstm = layers.LSTM(cells, return_sequences=True)(lstm)
    lstm = layers.Dropout(dropout)(lstm)
    out_layer = layers.Dense(vocab_size, activation="softmax")(lstm)

    # Model compilation
    final_model = models.Model(inputs=[input_layer], outputs=out_layer)
    adam = optimizers.legacy.Adam(learning_rate=1e-4, clipnorm=5)
    final_model.compile(
        loss="sparse_categorical_crossentropy",
        optimizer=adam,
        metrics=["sparse_categorical_accuracy"],
    )
    final_model.summary()
    return final_model

def create_lstm_autoencoder(hp=None, vocab_size=176, depth=2, cells=200, dropout=0.5, embedding_dim=200):
    """Modify to create an LSTM autoencoder for sequence data.
    
    Parameters are kept similar to the original model where applicable.
    """
    if hp is not None:
        depth = hp.Int("depth", 1, 4)
        cells = hp.Choice("cells", [128, 200, 256, 400, 512])
        dropout = hp.Float("drop_rate", min_value=0.0, max_value=0.9, step=0.01)
        embedding_dim = hp.Choice("embedding_dim", [128, 200, 256, 400, 512])

    # Encoder
    input_layer = layers.Input(shape=[None])
    embedding_layer = layers.Embedding(vocab_size, embedding_dim, input_length=None)(input_layer)
    
    # Adding LSTM layers for encoding, with dropout if specified
    encoder = embedding_layer
    for i in range(depth):
        return_sequences = i < depth - 1  # Only return sequences for layers before the last one
        encoder = layers.LSTM(cells, return_sequences=return_sequences)(encoder)
        if dropout is not None and dropout > 0:
            encoder = layers.Dropout(dropout)(encoder)

    # Decoder
    repeated_context = layers.RepeatVector(4495)(encoder)
    decoder = repeated_context
    for _ in range(depth):
        decoder = layers.LSTM(cells, return_sequences=True)(decoder)
        if dropout is not None and dropout > 0:
            decoder = layers.Dropout(dropout)(decoder)

    # Output layer
    out_layer = layers.TimeDistributed(layers.Dense(vocab_size, activation="softmax"))(decoder)
    
    # Model compilation
    final_model = models.Model(inputs=[input_layer], outputs=out_layer)
    adam = optimizers.Adam(learning_rate=1e-4, clipnorm=5)
    final_model.compile(
        loss="sparse_categorical_crossentropy",
        optimizer=adam,
        metrics=["sparse_categorical_accuracy"],
    )
    final_model.summary()
    return final_model

def train(dataset, batch_size=16, model_type="lstm", epochs=10):
    vocab_size = 235

    if model_type == "lstm":
        models = [
                partial(create_lstm_model, depth=1, cells=200, vocab_size=vocab_size),
                # partial(create_lstm_model, depth=1, cells=400, vocab_size=vocab_size),
                # partial(create_lstm_model, depth=2, cells=400, vocab_size=vocab_size),
            ]
    else:
        models = [
                partial(create_lstm_autoencoder, depth=1, cells=200, vocab_size=vocab_size),
                partial(create_lstm_autoencoder, depth=1, cells=400, vocab_size=vocab_size),
                partial(create_lstm_autoencoder, depth=2, cells=400, vocab_size=vocab_size),
            ]

    train_gen, val_gen, test = get_data(dataset, batch_size=batch_size)

    for idx, build_model in enumerate(models):

        model = build_model()

        model.fit(
            x=train_gen,
            validation_data=val_gen,
            epochs=epochs,
            verbose=2,
            shuffle=True
        )

        model_path = Path(get_path(f"model_{model_type}_{idx}.ckpt"))
        model.save(model_path)

        # Evaluate the model on the test data
        test_data, test_labels = test
        test_preds = model.predict(test_data)

        # Convert the predictions to class labels (0 for normal, 1 for attack)
        test_preds_labels = np.argmax(test_preds, axis=-1)
        test_preds_labels = np.where(test_preds_labels == 0, 0, 1)

        # Calculate the accuracy
        accuracy = np.mean(test_preds_labels == test_labels)
        print(f"Test Accuracy: {accuracy}")

if __name__ == "__main__":
    train("adfa")
