# -*- coding: utf-8 -*-
"""
FS-Net: A Flow Sequence Network For Encrypted Traffic Classification
This script provides a complete, runnable implementation to reproduce the
FS-Net model as described in the paper. It includes data loading, preprocessing,
model definition, and a 5-fold cross-validation training and evaluation loop.

(Version 3: Fixed KerasTensor error by using Keras layers for TF operations)
"""

import numpy as np
import pandas as pd
import tensorflow as tf
from tensorflow.keras.models import Model
from tensorflow.keras.layers import Input, Embedding, Bidirectional, GRU, Dense, Lambda, Multiply, Subtract, concatenate
from tensorflow.keras.preprocessing.sequence import pad_sequences
from sklearn.model_selection import StratifiedKFold
from sklearn.preprocessing import LabelEncoder
import gc
import os

# -----------------------------------------------------------------------------
# 1. DATA LOADING AND PREPROCESSING
# -----------------------------------------------------------------------------

def load_and_preprocess_data(filepath, max_len=100):
    """
    Loads the dataset from the specified CSV file and preprocesses it for
    the FS-Net model.
    """
    print("Step 1: Loading and preprocessing data...")
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Dataset file not found at: {filepath}")

    sequences = []
    labels = []
    max_packet_val = 0

    with open(filepath, 'r') as f:
        for i, line in enumerate(f):
            try:
                parts = line.strip().split(',')
                if len(parts) < 2:
                    continue
                label = parts[-1]
                seq = []
                for p in parts[:-1]:
                    try:
                        seq.append(int(p))
                    except ValueError:
                        pass
                if not seq:
                    continue
                sequences.append(seq)
                labels.append(label)
                current_max = max(seq)
                if current_max > max_packet_val:
                    max_packet_val = current_max
            except (ValueError, IndexError) as e:
                print(f"Warning: Skipping malformed line {i+1} in {filepath}. Error: {e}")
                continue

    if not sequences:
        raise ValueError(
            "Failed to load any valid sequences from the dataset. Please check the format of 'dataset.csv'."
        )

    print(f"Successfully loaded {len(sequences)} sequences.")

    label_encoder = LabelEncoder()
    encoded_labels = label_encoder.fit_transform(labels)
    num_classes = len(label_encoder.classes_)
    print(f"Found {num_classes} unique classes.")

    padded_sequences = pad_sequences(sequences, maxlen=max_len, padding='post', truncating='post', value=0)
    print(f"Padded/truncated sequences to max length: {max_len}")

    vocab_size = max_packet_val + 1
    print(f"Determined vocabulary size: {vocab_size}")

    return padded_sequences, encoded_labels, num_classes, vocab_size, label_encoder

# -----------------------------------------------------------------------------
# 2. MODEL DEFINITION (FS-Net)
# -----------------------------------------------------------------------------

def build_fs_net(max_len, vocab_size, embedding_dim, gru_units, num_classes):
    """
    Builds the FS-Net Keras model based on the paper's architecture.
    """
    print("Step 2: Building FS-Net model architecture...")
    
    # A. Embedding Layer (Removed deprecated 'input_length')
    input_layer = Input(shape=(max_len,), name='input_layer')
    embedding_layer = Embedding(input_dim=vocab_size, output_dim=embedding_dim, name='embedding_layer')(input_layer)

    # B. Encoder Layer (2-layer stacked Bi-GRU)
    encoder_l1_out = Bidirectional(GRU(gru_units, return_sequences=True, return_state=True), name='encoder_l1')(embedding_layer)
    encoder_l1_seq, encoder_l1_fwd_h, encoder_l1_bwd_h = encoder_l1_out
    encoder_l2_out = Bidirectional(GRU(gru_units, return_sequences=True, return_state=True), name='encoder_l2')(encoder_l1_seq)
    _, encoder_l2_fwd_h, encoder_l2_bwd_h = encoder_l2_out

    encoder_features = concatenate(
        [encoder_l1_fwd_h, encoder_l1_bwd_h, encoder_l2_fwd_h, encoder_l2_bwd_h],
        name='encoder_features'
    )

    # C. Decoder Layer (2-layer stacked Bi-GRU)
    decoder_input = tf.keras.layers.RepeatVector(max_len)(encoder_features)
    decoder_l1_out = Bidirectional(GRU(gru_units, return_sequences=True, return_state=True), name='decoder_l1')(decoder_input)
    decoder_l1_seq, decoder_l1_fwd_h, decoder_l1_bwd_h = decoder_l1_out
    decoder_l2_out = Bidirectional(GRU(gru_units, return_sequences=True, return_state=True), name='decoder_l2')(decoder_l1_seq)
    decoder_l2_seq, decoder_l2_fwd_h, decoder_l2_bwd_h = decoder_l2_out

    decoder_features = concatenate(
        [decoder_l1_fwd_h, decoder_l1_bwd_h, decoder_l2_fwd_h, decoder_l2_bwd_h],
        name='decoder_features'
    )

    # D. Reconstruction Layer
    reconstruction_output = Dense(vocab_size, activation='softmax', name='reconstruction_output')(decoder_l2_seq)

    # --- FIX: Use Keras layers for tensor operations ---
    # E & F. Dense and Classification Layers
    # Feature combination (Eq. 16)
    element_wise_product = Multiply(name='element_wise_product')([encoder_features, decoder_features])
    element_wise_diff = Subtract(name='element_wise_subtract')([encoder_features, decoder_features])
    abs_diff = Lambda(tf.abs, name='absolute_difference')(element_wise_diff)

    combined_features = concatenate(
        [encoder_features, decoder_features,
         element_wise_product,
         abs_diff],
        name='combined_features'
    )
    # --- END OF FIX ---

    # Feature compression with two-layer perceptron (Eq. 17)
    dense_layer_1 = Dense(512, activation='selu', name='dense_1')(combined_features)
    compressed_features = Dense(256, activation='selu', name='dense_2')(dense_layer_1)

    # Final classification layer
    classification_output = Dense(num_classes, activation='softmax', name='classification_output')(compressed_features)

    # G. Build and Compile Model
    model = Model(
        inputs=input_layer,
        outputs=[classification_output, reconstruction_output],
        name='FS-Net'
    )

    losses = {
        'classification_output': 'sparse_categorical_crossentropy',
        'reconstruction_output': 'sparse_categorical_crossentropy'
    }
    loss_weights = {
        'classification_output': 1.0,
        'reconstruction_output': 1.0
    }

    optimizer = tf.keras.optimizers.Adam(learning_rate=0.0005)
    model.compile(
        optimizer=optimizer,
        loss=losses,
        loss_weights=loss_weights,
        metrics={'classification_output': 'accuracy'}
    )
    return model

# -----------------------------------------------------------------------------
# 3. TRAINING AND EVALUATION
# -----------------------------------------------------------------------------

def train_and_evaluate(dataset_path):
    """
    The main function to orchestrate the FS-Net training and evaluation experiment.
    """
    MAX_LEN = 100
    EMBEDDING_DIM = 128
    GRU_UNITS = 128
    N_SPLITS = 5
    EPOCHS = 20
    BATCH_SIZE = 64

    X, y, num_classes, vocab_size, _ = load_and_preprocess_data(dataset_path, max_len=MAX_LEN)

    print(f"\nStep 3: Starting {N_SPLITS}-Fold Cross-Validation...")
    skf = StratifiedKFold(n_splits=N_SPLITS, shuffle=True, random_state=42)

    fold_no = 1
    scores = []
    histories = []

    for train_index, val_index in skf.split(X, y):
        print(f"\n{'='*20} FOLD {fold_no}/{N_SPLITS} {'='*20}")

        X_train, X_val = X[train_index], X[val_index]
        y_train, y_val = y[train_index], y[val_index]

        y_train_recon = np.expand_dims(X_train, -1)
        y_val_recon = np.expand_dims(X_val, -1)

        model = build_fs_net(
            max_len=MAX_LEN,
            vocab_size=vocab_size,
            embedding_dim=EMBEDDING_DIM,
            gru_units=GRU_UNITS,
            num_classes=num_classes
        )

        if fold_no == 1:
            model.summary()

        print(f"Training on {len(X_train)} samples, validating on {len(X_val)} samples...")
        history = model.fit(
            X_train,
            {'classification_output': y_train, 'reconstruction_output': y_train_recon},
            validation_data=(X_val, {'classification_output': y_val, 'reconstruction_output': y_val_recon}),
            epochs=EPOCHS,
            batch_size=BATCH_SIZE,
            verbose=1
        )
        histories.append(history)

        score = model.evaluate(X_val, {'classification_output': y_val, 'reconstruction_output': y_val_recon}, verbose=0)
        scores.append(score)
        print(f"\nFold {fold_no} Validation Score -> Total Loss: {score[0]:.4f} | Classification Accuracy: {score[3]:.4f}")

        del model
        gc.collect()
        tf.keras.backend.clear_session()

        fold_no += 1

    print(f"\n{'='*20} Cross-Validation Training Complete {'='*20}")
    avg_loss = np.mean([s[0] for s in scores])
    avg_accuracy = np.mean([s[3] for s in scores])
    print(f"Average Total Loss across {N_SPLITS} folds: {avg_loss:.4f}")
    print(f"Average Classification Accuracy across {N_SPLITS} folds: {avg_accuracy:.4f}")
    print("\nExperiment finished.")


# -----------------------------------------------------------------------------
# 4. SCRIPT EXECUTION
# -----------------------------------------------------------------------------

if __name__ == '__main__':
    DATASET_PATH = 'dataset.csv'
    train_and_evaluate(DATASET_PATH)

