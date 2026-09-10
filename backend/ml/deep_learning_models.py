import os
import json
import numpy as np

# Vocabulary for character-level URL sequence encoding
CHAR_VOCAB = "abcdefghijklmnopqrstuvwxyz0123456789-._~:/?#[]@!$&'()*+,;=%"
CHAR_TO_IDX = {ch: idx + 1 for idx, ch in enumerate(CHAR_VOCAB)}  # 0 is reserved for padding
MAX_URL_LEN = 150

def encode_url_sequence(url: str, max_len: int = MAX_URL_LEN) -> np.ndarray:
    """
    Converts a raw URL string into a fixed-length numerical character sequence vector.
    """
    url_clean = (url or "").strip().lower()
    seq = [CHAR_TO_IDX.get(ch, 0) for ch in url_clean[:max_len]]
    if len(seq) < max_len:
        seq += [0] * (max_len - len(seq))
    return np.array(seq, dtype=np.int32)

def build_char_cnn_model(max_len: int = MAX_URL_LEN, vocab_size: int = len(CHAR_VOCAB) + 1):
    """
    Builds a Character-Level 1D-CNN architecture for URL sequence classification.
    """
    import tensorflow as tf
    from tensorflow.keras import layers, models

    inputs = layers.Input(shape=(max_len,), name="char_input")
    x = layers.Embedding(input_dim=vocab_size, output_dim=32, input_length=max_len)(inputs)
    
    # 1D Convolutional blocks with varying kernel sizes (captures 3-gram and 5-gram patterns)
    conv1 = layers.Conv1D(filters=64, kernel_size=3, activation="relu", padding="same")(x)
    pool1 = layers.MaxPooling1D(pool_size=2)(conv1)
    
    conv2 = layers.Conv1D(filters=64, kernel_size=5, activation="relu", padding="same")(pool1)
    pool2 = layers.MaxPooling1D(pool_size=2)(conv2)
    
    gap = layers.GlobalAveragePooling1D()(pool2)
    dropout1 = layers.Dropout(0.3)(gap)
    
    dense1 = layers.Dense(64, activation="relu")(dropout1)
    dropout2 = layers.Dropout(0.2)(dense1)
    outputs = layers.Dense(1, activation="sigmoid", name="phishing_prob")(dropout2)
    
    model = models.Model(inputs=inputs, outputs=outputs, name="Char_1D_CNN")
    model.compile(optimizer="adam", loss="binary_crossentropy", metrics=["accuracy"])
    return model

def build_deep_mlp_model(input_dim: int = 24):
    """
    Builds a Deep Multilayer Perceptron (ANN) with Dropout and Batch Normalization.
    """
    import tensorflow as tf
    from tensorflow.keras import layers, models

    inputs = layers.Input(shape=(input_dim,), name="feature_input")
    x = layers.Dense(128, activation="relu")(inputs)
    x = layers.BatchNormalization()(x)
    x = layers.Dropout(0.3)(x)
    
    x = layers.Dense(64, activation="relu")(x)
    x = layers.Dropout(0.2)(x)
    
    x = layers.Dense(32, activation="relu")(x)
    outputs = layers.Dense(1, activation="sigmoid", name="phishing_prob")(x)
    
    model = models.Model(inputs=inputs, outputs=outputs, name="Deep_MLP_ANN")
    model.compile(optimizer="adam", loss="binary_crossentropy", metrics=["accuracy"])
    return model
