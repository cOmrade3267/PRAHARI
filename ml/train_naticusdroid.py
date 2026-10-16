#!/usr/bin/env python3
"""
Train a small permission-based malware classifier on the NATICUSdroid dataset and export a
quantized model.tflite + features.json for on-device inference in the Prahari auditor.

Pipeline (one-time, on your machine — needs network only to fetch the dataset):
    raw 0/1 permission vectors  ->  tiny Keras MLP  ->  dynamic-range int8 TFLite

The resulting model.tflite runs FULLY OFFLINE on the phone. It is a *second opinion* only:
the rule engine remains the source of risk explanations (see ../PLAN.md). Inputs stay raw 0/1
(no scaler) so the Android side just sets 1.0 for each permission the app has, in features.json
order.

Dataset: NATICUSdroid (UCI ML Repository id 722, CC BY 4.0) — ~29k apps, 86 permission features,
binary target (benign / malware).

Usage:
    python -I train_naticusdroid.py                 # auto-download via ucimlrepo
    python -I train_naticusdroid.py --csv NATICUSdroid.csv   # use a local CSV instead
    python -I train_naticusdroid.py --int8          # full-int8 quantization (smaller, int IO)
    python -I train_naticusdroid.py --out out        # output directory (default: ./out)

Outputs (in --out):
    model.tflite    the quantized model
    features.json   input feature order + I/O contract for the Android side
    metrics.json    honest held-out test metrics from THIS run
    model.keras     the full Keras model (for later retraining)
"""
import argparse
import datetime
import json
import os
import sys

SEED = 42
TARGET_CANDIDATES = ("Result", "result", "class", "Class", "label", "Label", "malware", "Malware")


def load_data(csv_path):
    """Return (X float32 [n,f], y int [n], feature_names list). y: 0=benign, 1=malware."""
    import numpy as np
    import pandas as pd

    if csv_path:
        if not os.path.exists(csv_path):
            sys.exit(f"CSV not found: {csv_path}")
        df = pd.read_csv(csv_path)
        target = next((c for c in TARGET_CANDIDATES if c in df.columns), df.columns[-1])
        print(f"[data] CSV loaded: {df.shape[0]} rows, target column = '{target}'")
        y_raw = df[target]
        X_df = df.drop(columns=[target])
    else:
        try:
            from ucimlrepo import fetch_ucirepo
        except ImportError:
            sys.exit("ucimlrepo not installed. Run: pip install ucimlrepo  (or use --csv PATH)")
        print("[data] Fetching NATICUSdroid (UCI id 722) via ucimlrepo …")
        ds = fetch_ucirepo(id=722)
        X_df = ds.data.features
        y_raw = ds.data.targets.iloc[:, 0]
        print(f"[data] Downloaded: {X_df.shape[0]} rows, {X_df.shape[1]} features")

    feature_names = [str(c) for c in X_df.columns]

    # Coerce target to 0/1 (1 = malware).
    y = pd.to_numeric(y_raw, errors="coerce")
    uniq = set(pd.unique(y.dropna()))
    if not uniq.issubset({0, 1}):
        sys.exit(f"Target values are not 0/1 ({sorted(uniq)[:6]}…). Inspect the dataset / --csv and "
                 f"map benign->0, malware->1 before training.")
    if y.isna().any():
        sys.exit("Target column has non-numeric / missing values. Clean it and retry.")

    X = X_df.apply(pd.to_numeric, errors="coerce").fillna(0).clip(0, 1).astype("float32").values
    return X, y.astype("int64").values, feature_names


def build_model(n_features):
    import tensorflow as tf
    tf.random.set_seed(SEED)
    model = tf.keras.Sequential([
        tf.keras.layers.Input(shape=(n_features,), name="permissions"),
        tf.keras.layers.Dense(64, activation="relu"),
        tf.keras.layers.Dropout(0.3),
        tf.keras.layers.Dense(32, activation="relu"),
        tf.keras.layers.Dense(1, activation="sigmoid", name="p_malware"),
    ])
    model.compile(
        optimizer=tf.keras.optimizers.Adam(1e-3),
        loss="binary_crossentropy",
        metrics=["accuracy", tf.keras.metrics.AUC(name="auc")],
    )
    return model


def main():
    ap = argparse.ArgumentParser(description="Train NATICUSdroid permission classifier -> TFLite.")
    ap.add_argument("--csv", default=None, help="Local NATICUSdroid CSV (else auto-download).")
    ap.add_argument("--out", default="out", help="Output directory (default: ./out).")
    ap.add_argument("--epochs", type=int, default=60)
    ap.add_argument("--batch", type=int, default=128)
    ap.add_argument("--int8", action="store_true", help="Full int8 quantization (smaller, int I/O).")
    args = ap.parse_args()

    import numpy as np
    import tensorflow as tf
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import (accuracy_score, precision_score, recall_score, f1_score,
                                  roc_auc_score, confusion_matrix, precision_recall_curve)

    np.random.seed(SEED)
    os.makedirs(args.out, exist_ok=True)

    X, y, feature_names = load_data(args.csv)
    n_features = X.shape[1]
    pos = int(y.sum())
    print(f"[data] {len(y)} samples, {n_features} features, malware={pos} ({pos/len(y):.1%})")

    X_tr, X_tmp, y_tr, y_tmp = train_test_split(X, y, test_size=0.30, random_state=SEED, stratify=y)
    X_val, X_te, y_val, y_te = train_test_split(X_tmp, y_tmp, test_size=0.50, random_state=SEED, stratify=y_tmp)

    # Class weights for any imbalance.
    n0, n1 = int((y_tr == 0).sum()), int((y_tr == 1).sum())
    cw = {0: len(y_tr) / (2.0 * max(n0, 1)), 1: len(y_tr) / (2.0 * max(n1, 1))}

    model = build_model(n_features)
    model.fit(
        X_tr, y_tr,
        validation_data=(X_val, y_val),
        epochs=args.epochs, batch_size=args.batch, class_weight=cw, verbose=2,
        callbacks=[tf.keras.callbacks.EarlyStopping(monitor="val_auc", mode="max",
                                                    patience=8, restore_best_weights=True)],
    )

    # --- honest held-out evaluation ---
    proba = model.predict(X_te, verbose=0).ravel()
    pred = (proba >= 0.5).astype(int)
    prec, rec, thr = precision_recall_curve(y_te, proba)
    f1s = (2 * prec * rec) / np.clip(prec + rec, 1e-9, None)
    best_f1_thr = float(thr[int(np.nanargmax(f1s[:-1]))]) if len(thr) else 0.5
    metrics = {
        "accuracy": round(float(accuracy_score(y_te, pred)), 4),
        "precision": round(float(precision_score(y_te, pred, zero_division=0)), 4),
        "recall": round(float(recall_score(y_te, pred, zero_division=0)), 4),
        "f1": round(float(f1_score(y_te, pred, zero_division=0)), 4),
        "roc_auc": round(float(roc_auc_score(y_te, proba)), 4),
        "confusion_matrix_tn_fp_fn_tp": [int(v) for v in confusion_matrix(y_te, pred).ravel()],
        "best_f1_threshold": round(best_f1_thr, 4),
        "test_samples": int(len(y_te)),
    }
    print("[eval] test metrics:", json.dumps(metrics, indent=2))

    model.save(os.path.join(args.out, "model.keras"))

    # --- TFLite conversion ---
    converter = tf.lite.TFLiteConverter.from_keras_model(model)
    converter.optimizations = [tf.lite.Optimize.DEFAULT]  # dynamic-range int8 weights, float I/O
    io_dtype = "float32"
    if args.int8:
        def rep():
            for i in range(min(300, len(X_tr))):
                yield [X_tr[i:i + 1].astype(np.float32)]
        converter.representative_dataset = rep
        converter.target_spec.supported_ops = [tf.lite.OpsSet.TFLITE_BUILTINS_INT8]
        converter.inference_input_type = tf.int8
        converter.inference_output_type = tf.int8
        io_dtype = "int8"
    tflite_model = converter.convert()
    tflite_path = os.path.join(args.out, "model.tflite")
    with open(tflite_path, "wb") as f:
        f.write(tflite_model)
    print(f"[tflite] wrote {tflite_path} ({len(tflite_model)/1024:.1f} KiB, I/O dtype={io_dtype})")

    # --- features.json: the on-device input contract ---
    features = {
        "model": "naticusdroid-permission-mlp",
        "schemaVersion": 1,
        "created": datetime.date.today().isoformat(),
        "input": {
            "order": feature_names,
            "length": n_features,
            "dtype": io_dtype,
            "encoding": "binary presence: set 1.0 if the app declares/was granted this permission, else 0.0",
        },
        "output": {
            "dtype": io_dtype,
            "meaning": "P(malware)",
            "threshold": 0.5,
            "best_f1_threshold": metrics["best_f1_threshold"],
            "classes": {"0": "benign", "1": "malware"},
        },
        "training": {
            "dataset": "NATICUSdroid (UCI id 722, CC BY 4.0)",
            "samples": int(len(y)),
            "seed": SEED,
        },
        "notes": "Second opinion only; the rule score remains the source of explanations. "
                 "Permission-only models age — retrain on fresh data periodically.",
    }
    feat_path = os.path.join(args.out, "features.json")
    with open(feat_path, "w", encoding="utf-8") as f:
        json.dump(features, f, indent=2)
    with open(os.path.join(args.out, "metrics.json"), "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)
    print(f"[done] -> {feat_path}  (copy model.tflite + features.json into app/src/main/assets/ml/)")


if __name__ == "__main__":
    main()
