import argparse
import csv
import os
from typing import Dict, List, Optional

import matplotlib.pyplot as plt

UNIQUE_LOG_KEYS = 101
RATIO_TARGETS = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9]
TOPK_VALUES = list(range(1, 22, 2))


def read_rows(csv_path: str) -> List[Dict[str, str]]:
    with open(csv_path, "r", newline="") as f:
        return list(csv.DictReader(f))


def as_float(row: Dict[str, str], key: str) -> Optional[float]:
    value = row.get(key, "")
    if value is None or value == "":
        return None
    try:
        return float(value)
    except ValueError:
        return None


def as_int(row: Dict[str, str], key: str) -> Optional[int]:
    value = row.get(key, "")
    if value is None or value == "":
        return None
    try:
        return int(float(value))
    except ValueError:
        return None


def best_row_for_topk(rows: List[Dict[str, str]], top_k: int) -> Optional[Dict[str, str]]:
    candidates = [r for r in rows if as_int(r, "top_k") == top_k]
    if not candidates:
        return None
    return max(candidates, key=lambda r: as_float(r, "accuracy") or -1.0)


def ratio_rows(rows: List[Dict[str, str]]) -> List[Dict[str, float]]:
    output = []
    used_topk = set()
    for target_ratio in RATIO_TARGETS:
        target_topk = round(target_ratio * UNIQUE_LOG_KEYS)
        row = best_row_for_topk(rows, target_topk)
        if row is None:
            candidates = []
            for r in rows:
                k = as_int(r, "top_k")
                if k is None or k in used_topk:
                    continue
                ratio = round(k / UNIQUE_LOG_KEYS, 1)
                if ratio == target_ratio:
                    candidates.append(r)
            if candidates:
                row = max(candidates, key=lambda r: as_float(r, "accuracy") or -1.0)
        if row is None:
            continue
        k = as_int(row, "top_k")
        used_topk.add(k)
        output.append({
            "x": target_ratio,
            "precision": as_float(row, "anomaly_precision"),
            "recall": as_float(row, "anomaly_recall"),
            "f1": as_float(row, "anomaly_f1"),
        })
    return output


def topk_rows(rows: List[Dict[str, str]]) -> List[Dict[str, float]]:
    output = []
    for top_k in TOPK_VALUES:
        row = best_row_for_topk(rows, top_k)
        if row is None:
            continue
        output.append({
            "x": top_k,
            "precision": as_float(row, "anomaly_precision"),
            "recall": as_float(row, "anomaly_recall"),
            "f1": as_float(row, "anomaly_f1"),
        })
    return output


def plot_metric_lines(data: List[Dict[str, float]], output_path: str, title: str, x_label: str, x_ticks: List[float]) -> None:
    if not data:
        raise ValueError(f"No matching rows found for {title}")

    x = [d["x"] for d in data]
    precision = [d["precision"] for d in data]
    recall = [d["recall"] for d in data]
    f1 = [d["f1"] for d in data]

    plt.figure(figsize=(8, 5))
    plt.plot(x, precision, marker="o", label="Precision")
    plt.plot(x, recall, marker="o", label="Recall")
    plt.plot(x, f1, marker="o", label="F1-score")
    plt.title(title)
    plt.xlabel(x_label)
    plt.ylabel("Score")
    plt.ylim(0, 1.05)
    plt.xticks(x_ticks)
    plt.grid(True, linestyle="--", linewidth=0.5, alpha=0.6)
    plt.legend()
    plt.tight_layout()
    plt.savefig(output_path, dpi=300)
    plt.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate Linux LogGPT precision/recall/F1 graphs from test-run CSV results.")
    parser.add_argument("--csv", default="datasets/Linux.W60.S30_test_runs.csv", help="Path to test-run CSV file.")
    parser.add_argument("--outdir", default="graphs", help="Directory where graph PNG files will be saved.")
    args = parser.parse_args()

    rows = read_rows(args.csv)
    os.makedirs(args.outdir, exist_ok=True)

    ratio_data = ratio_rows(rows)
    topk_data = topk_rows(rows)

    ratio_output = os.path.join(args.outdir, "linux_topk_ratio_precision_recall_f1.png")
    topk_output = os.path.join(args.outdir, "linux_topk_value_precision_recall_f1.png")

    plot_metric_lines(
        ratio_data,
        ratio_output,
        "Linux LogGPT: Top-k Ratio vs Anomaly Metrics",
        "Top-k Ratio",
        RATIO_TARGETS,
    )

    plot_metric_lines(
        topk_data,
        topk_output,
        "Linux LogGPT: Top-k Value vs Anomaly Metrics",
        "Top-k Value",
        TOPK_VALUES,
    )

    print(f"Saved: {ratio_output}")
    print(f"Saved: {topk_output}")


if __name__ == "__main__":
    main()
