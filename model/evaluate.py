#/usr/bin/python3

import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from utils.utils import get_path
import numpy as np
from sklearn.metrics import precision_score, recall_score, f1_score
from preprocess import get_data

def get_mode(arr):
    """
    Calculate the mode (most frequent value) across all time steps for each sample.
    """
    unique_vals, counts = np.unique(arr, return_counts=True)
    return unique_vals[np.argmax(counts)]

# def evaluate(model_path, batch_size=64):
#     # Load the saved model
#     model = tf.keras.models.load_model(model_path)

#     # Get the test data
#     _, _, test = get_data(batch_size=batch_size)
#     test_data, test_labels = test

#     # Evaluate the model on the test data
#     test_preds = model.predict(test_data)

#     # Get the predicted class labels for each time step
#     test_preds_labels = np.argmax(test_preds, axis=-1)

#     # Take the mode (most frequent value) across all time steps for each sample
#     # Calculate the mode (most frequent value) across all time steps for each sample
#     test_preds_labels = np.apply_along_axis(get_mode, axis=-1, arr=test_preds_labels)

#     # Ensure test_preds_labels has the same shape as test_labels
#     if test_preds_labels.ndim == 0:
#         test_preds_labels = np.array([test_preds_labels])
#     elif test_preds_labels.ndim == 2:
#         test_preds_labels = test_preds_labels.flatten()

#     # Calculate the accuracy
#     accuracy = np.mean(test_preds_labels == test_labels)
#     # Calculate the accuracy
#     accuracy = np.mean(test_preds_labels == test_labels)
#     print(f"Test Accuracy: {accuracy}")

#     print("test_labels shape:", test_labels.shape)
#     print("test_preds_labels shape:", test_preds_labels.shape)
#     print("test_labels:", test_labels)
#     print("test_preds_labels:", test_preds_labels)

#     test_labels = test_labels.ravel()
#     test_preds_labels = test_preds_labels.ravel()

#     if len(np.unique(test_labels)) == 1 or len(np.unique(test_preds_labels)) == 1:
#         print("Warning: Only one class label present. Precision, recall, and F1 score may not be meaningful.")
#     else:
#         # Calculate precision, recall, and F1 score
#         precision = precision_score(test_labels, test_preds_labels)
#         recall = recall_score(test_labels, test_preds_labels)
#         f1 = f1_score(test_labels, test_preds_labels)

#         print(f"Precision: {precision}")
#         print(f"Recall: {recall}")
#         print(f"F1 Score: {f1}")


def analyse_existing():
    # Load the .npz file
    data = np.load(get_path('../data/adfa.npz'), allow_pickle=True)
    print(data)

    # Check the names of the arrays in the file
    print("Array names:", data.files)
    file = data['arr_0']
    for content in file:
        print(content)
        break


    
    # baseline = data[data.files[1]]
    # time_taken = data[data.files[2]]
    # Close the file
    data.close()

    # Print the loaded data
    # print("Scores:", scores)
    # print("Baseline:", baseline)
    # print("Time taken:", time_taken)

if __name__ == "__main__":
    model_path = get_path("../model/model_<keras.src.engine.functional.Functional object at 0x2a6eeea30>_2.ckpt")
    analyse_existing()
