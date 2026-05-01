import os
import pandas as pd
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    roc_auc_score,
    average_precision_score
)


def log_test_metrics(report, cm, auc_roc, auc_pr, dataset_name, options, window_size, step_size):

    row = {
        "dataset": dataset_name,
        "train_samples": options["train_samples"],
        "top_k": options["top_k"],

        "normal_precision": report["0"]["precision"],
        "normal_recall": report["0"]["recall"],
        "normal_f1": report["0"]["f1-score"],
        "normal_support": report["0"]["support"],

        "anomaly_precision": report["1"]["precision"],
        "anomaly_recall": report["1"]["recall"],
        "anomaly_f1": report["1"]["f1-score"],
        "anomaly_support": report["1"]["support"],

        "accuracy": report["accuracy"],

        "macro_precision": report["macro avg"]["precision"],
        "macro_recall": report["macro avg"]["recall"],
        "macro_f1": report["macro avg"]["f1-score"],

        "weighted_precision": report["weighted avg"]["precision"],
        "weighted_recall": report["weighted avg"]["recall"],
        "weighted_f1": report["weighted avg"]["f1-score"],

        "TN": cm[0][0],
        "FP": cm[0][1],
        "FN": cm[1][0],
        "TP": cm[1][1],

        "AUC_ROC": auc_roc,
        "AUC_PR": auc_pr
    }

    os.makedirs("outputs", exist_ok=True)

    filename = f"outputs/{dataset_name}.W{window_size}.S{step_size}_test_runs.csv"

    df = pd.DataFrame([row])
    df.to_csv(
        filename,
        mode="a",
        header=not os.path.exists(filename),
        index=False
    )

    print(f"Appended results to {filename}")