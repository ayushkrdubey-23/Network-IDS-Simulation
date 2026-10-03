
"""
Network Intrusion Detection System (IDS) Simulation

Machine Learning Model Training and Evaluation

Author: Ayush Kumar Dubey

Models:
1. Logistic Regression
2. Random Forest
3. Isolation Forest

Only synthetic network-flow CSV data is used.
"""

import argparse
import json
import warnings
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler


# --------------------------------------------------
# CONFIGURATION
# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent.parent

INPUT_FILE = BASE_DIR / "data" / "processed_network_traffic.csv"

MODEL_DIR = BASE_DIR / "models"

REPORT_DIR = BASE_DIR / "reports"

RANDOM_STATE = 42

TARGET_COLUMN = "label"

FEATURE_COLUMNS = [
    "source_port",
    "destination_port",
    "packet_count",
    "byte_count",
    "duration_seconds",
    "connection_count",
    "failed_connection_count",
    "syn_count",
    "rst_count",
    "average_packet_size",
    "bytes_per_second",
    "packets_per_second",
    "failed_connection_rate",
    "syn_ratio",
    "rst_ratio",
]


# --------------------------------------------------
# DATA LOADING
# --------------------------------------------------

def load_data(input_path):

    input_path = Path(input_path)

    if not input_path.exists():
        raise FileNotFoundError(
            f"Dataset not found: {input_path}"
        )

    dataframe = pd.read_csv(input_path)

    required_columns = FEATURE_COLUMNS + [TARGET_COLUMN]

    missing_columns = [
        column
        for column in required_columns
        if column not in dataframe.columns
    ]

    if missing_columns:
        raise ValueError(
            "Dataset is missing columns: "
            + ", ".join(missing_columns)
        )

    if dataframe.empty:
        raise ValueError("Dataset is empty.")

    dataframe = dataframe.copy()

    dataframe[TARGET_COLUMN] = (
        dataframe[TARGET_COLUMN]
        .astype(str)
        .str.upper()
    )

    if not set(dataframe[TARGET_COLUMN]).issubset(
        {"NORMAL", "SUSPICIOUS"}
    ):
        raise ValueError(
            "Target labels must be NORMAL or SUSPICIOUS."
        )

    dataframe[FEATURE_COLUMNS] = dataframe[
        FEATURE_COLUMNS
    ].apply(
        pd.to_numeric,
        errors="coerce"
    )

    dataframe[FEATURE_COLUMNS] = dataframe[
        FEATURE_COLUMNS
    ].replace(
        [np.inf, -np.inf],
        np.nan
    )

    # Drop rows without usable numeric features.
    dataframe = dataframe.dropna(
        subset=FEATURE_COLUMNS + [TARGET_COLUMN]
    )

    if dataframe.empty:
        raise ValueError(
            "No usable records remain after data cleaning."
        )

    if dataframe[TARGET_COLUMN].nunique() != 2:
        raise ValueError(
            "Training requires both NORMAL and SUSPICIOUS labels."
        )

    return dataframe


# --------------------------------------------------
# DATA SPLITTING
# --------------------------------------------------

def split_data(dataframe):

    X = dataframe[FEATURE_COLUMNS]

    y = dataframe[TARGET_COLUMN].map({
        "NORMAL": 0,
        "SUSPICIOUS": 1,
    })

    if y.value_counts().min() < 2:
        raise ValueError(
            "Each class needs at least two records."
        )

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=RANDOM_STATE,
        stratify=y
    )

    return X_train, X_test, y_train, y_test


# --------------------------------------------------
# MODEL EVALUATION
# --------------------------------------------------

def evaluate_classifier(model, X_test, y_test):

    predictions = model.predict(X_test)

    metrics = {
        "accuracy": float(
            accuracy_score(y_test, predictions)
        ),
        "precision": float(
            precision_score(
                y_test,
                predictions,
                zero_division=0
            )
        ),
        "recall": float(
            recall_score(
                y_test,
                predictions,
                zero_division=0
            )
        ),
        "f1_score": float(
            f1_score(
                y_test,
                predictions,
                zero_division=0
            )
        ),
        "confusion_matrix": confusion_matrix(
            y_test,
            predictions,
            labels=[0, 1]
        ).tolist(),
        "classification_report": classification_report(
            y_test,
            predictions,
            labels=[0, 1],
            target_names=["NORMAL", "SUSPICIOUS"],
            zero_division=0,
            output_dict=True
        ),
    }

    return metrics


# --------------------------------------------------
# SUPERVISED MODEL TRAINING
# --------------------------------------------------

def train_supervised_models(
    X_train,
    X_test,
    y_train,
    y_test
):

    models = {
        "logistic_regression": Pipeline([
            ("imputer", SimpleImputer(strategy="median")),
            ("scaler", StandardScaler()),
            ("classifier", LogisticRegression(
                max_iter=1000,
                class_weight="balanced",
                random_state=RANDOM_STATE
            ))
        ]),

        "random_forest": Pipeline([
            ("imputer", SimpleImputer(strategy="median")),
            ("classifier", RandomForestClassifier(
                n_estimators=150,
                max_depth=12,
                class_weight="balanced",
                random_state=RANDOM_STATE,
                n_jobs=-1
            ))
        ]),
    }

    results = {}

    for model_name, model in models.items():

        print(f"\nTraining {model_name}...")

        model.fit(X_train, y_train)

        metrics = evaluate_classifier(
            model,
            X_test,
            y_test
        )

        results[model_name] = metrics

        model_path = MODEL_DIR / f"{model_name}.joblib"

        joblib.dump(
            model,
            model_path
        )

        print(
            f"Accuracy: {metrics['accuracy']:.4f}"
        )

        print(
            f"Precision: {metrics['precision']:.4f}"
        )

        print(
            f"Recall: {metrics['recall']:.4f}"
        )

        print(
            f"F1-score: {metrics['f1_score']:.4f}"
        )

        print(
            f"Saved model: {model_path}"
        )

    return results


# --------------------------------------------------
# UNSUPERVISED MODEL TRAINING
# --------------------------------------------------

def train_isolation_forest(
    X_train,
    X_test,
    y_test
):

    # Fit anomaly detector using training features.
    model = Pipeline([
        ("imputer", SimpleImputer(strategy="median")),
        ("scaler", StandardScaler()),
        ("detector", IsolationForest(
            n_estimators=150,
            contamination="auto",
            random_state=RANDOM_STATE,
            n_jobs=-1
        ))
    ])

    print("\nTraining isolation_forest...")

    model.fit(X_train)

    raw_predictions = model.predict(X_test)

    # Isolation Forest:
    # 1 means inlier, -1 means outlier.
    # Convert to our binary convention:
    # 0 means NORMAL, 1 means SUSPICIOUS.
    predictions = np.where(
        raw_predictions == -1,
        1,
        0
    )

    metrics = {
        "accuracy": float(
            accuracy_score(y_test, predictions)
        ),
        "precision": float(
            precision_score(
                y_test,
                predictions,
                zero_division=0
            )
        ),
        "recall": float(
            recall_score(
                y_test,
                predictions,
                zero_division=0
            )
        ),
        "f1_score": float(
            f1_score(
                y_test,
                predictions,
                zero_division=0
            )
        ),
        "confusion_matrix": confusion_matrix(
            y_test,
            predictions,
            labels=[0, 1]
        ).tolist(),
        "classification_report": classification_report(
            y_test,
            predictions,
            labels=[0, 1],
            target_names=["NORMAL", "SUSPICIOUS"],
            zero_division=0,
            output_dict=True
        ),
    }

    model_path = MODEL_DIR / "isolation_forest.joblib"

    joblib.dump(
        model,
        model_path
    )

    print(
        f"Accuracy: {metrics['accuracy']:.4f}"
    )

    print(
        f"Precision: {metrics['precision']:.4f}"
    )

    print(
        f"Recall: {metrics['recall']:.4f}"
    )

    print(
        f"F1-score: {metrics['f1_score']:.4f}"
    )

    print(
        f"Saved model: {model_path}"
    )

    return metrics


# --------------------------------------------------
# SAVE EVALUATION REPORT
# --------------------------------------------------

def save_report(results, report_path):

    report_path = Path(report_path)

    report_path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with report_path.open(
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            results,
            file,
            indent=4
        )

    print(
        f"\nEvaluation report saved: {report_path}"
    )


# --------------------------------------------------
# COMPLETE TRAINING PIPELINE
# --------------------------------------------------

def run_training(input_path=INPUT_FILE):

    MODEL_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    REPORT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    print("\nLoading dataset...")

    dataframe = load_data(input_path)

    print(
        f"Usable records: {len(dataframe)}"
    )

    print("\nClass distribution:")

    print(
        dataframe[TARGET_COLUMN].value_counts()
    )

    X_train, X_test, y_train, y_test = split_data(
        dataframe
    )

    print("\nDataset split:")

    print(f"Training records: {len(X_train)}")

    print(f"Testing records: {len(X_test)}")

    results = train_supervised_models(
        X_train,
        X_test,
        y_train,
        y_test
    )

    results["isolation_forest"] = train_isolation_forest(
        X_train,
        X_test,
        y_test
    )

    report_path = REPORT_DIR / "ml_evaluation.json"

    save_report(
        results,
        report_path
    )

    print("\n" + "=" * 55)
    print("MACHINE LEARNING TRAINING COMPLETED")
    print("=" * 55)

    print("\nModel comparison:")

    for name, metrics in results.items():

        print(
            f"{name}: "
            f"Accuracy={metrics['accuracy']:.4f}, "
            f"Precision={metrics['precision']:.4f}, "
            f"Recall={metrics['recall']:.4f}, "
            f"F1={metrics['f1_score']:.4f}"
        )

    print("=" * 55)

    return results


# --------------------------------------------------
# COMMAND LINE INTERFACE
# --------------------------------------------------

def main():

    parser = argparse.ArgumentParser(
        description=(
            "Train and evaluate ML models "
            "for synthetic network intrusion detection."
        )
    )

    parser.add_argument(
        "--input",
        default=str(INPUT_FILE),
        help="Processed network-flow CSV."
    )

    args = parser.parse_args()

    try:

        run_training(
            input_path=args.input
        )

    except (OSError, ValueError) as error:

        parser.exit(
            status=1,
            message=f"\nML training failed: {error}\n"
        )


if __name__ == "__main__":
    main()
    