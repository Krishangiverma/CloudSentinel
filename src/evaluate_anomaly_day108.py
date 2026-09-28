"""Day 108: Synthetic threshold-sensitivity evaluation.

This benchmark extends the Day 105 dataset with benign repeated-IP events.
It measures behavior on labeled synthetic data only, not real-world accuracy.
"""

from copy import deepcopy

from src.analyzers.anomaly_detector import detect_anomalies
from src.evaluate_anomaly_day105 import build_dataset, calculate_metrics


THRESHOLDS = (30, 40, 60)


def build_extended_dataset():
    """Extend the existing labeled dataset with benign repeated-IP events."""
    dataset = deepcopy(build_dataset())

    for index in range(1, 5):
        dataset.append({
            "id": f"benign_repeated_ip_{index}",
            "label": False,
            "event": {
                "event_type": "HEARTBEAT",
                "severity": "LOW",
                "message": "Routine system heartbeat",
                "ip": "192.0.2.77",
                "ip_address": "192.0.2.77",
            },
        })

    return dataset


def run_threshold_evaluation():
    """Evaluate identical events at multiple detection thresholds."""
    dataset = build_extended_dataset()
    labels = [row["label"] for row in dataset]
    events = [deepcopy(row["event"]) for row in dataset]

    reports = {}

    for threshold in THRESHOLDS:
        results = detect_anomalies(events, threshold=threshold)
        predictions = [result.is_anomaly for result in results]

        reports[threshold] = {
            "metrics": calculate_metrics(labels, predictions),
            "scores": [result.anomaly_score for result in results],
            "predictions": predictions,
        }

    return {
        "dataset_size": len(dataset),
        "positive_labels": sum(labels),
        "negative_labels": len(labels) - sum(labels),
        "dataset": dataset,
        "reports": reports,
    }


def print_report(report):
    print("DAY 108 SYNTHETIC THRESHOLD EVALUATION")
    print(f"Events: {report['dataset_size']}")
    print(f"Suspicious labels: {report['positive_labels']}")
    print(f"Benign labels: {report['negative_labels']}")
    print("Results apply only to this synthetic dataset.")

    for threshold, result in report["reports"].items():
        metrics = result["metrics"]
        print(f"\nThreshold: {threshold}")
        print(
            f"TP={metrics['TP']} FP={metrics['FP']} "
            f"TN={metrics['TN']} FN={metrics['FN']}"
        )
        for name in ("precision", "recall", "false_positive_rate"):
            value = metrics[name]
            display = "N/A" if value is None else f"{value:.3f}"
            print(f"{name}: {display}")

    print("\nPer-event scores at threshold-independent scoring:")
    for index, row in enumerate(report["dataset"]):
        scores = {
            threshold: result["scores"][index]
            for threshold, result in report["reports"].items()
        }
        print(
            f"{row['id']}: label={int(row['label'])}, "
            f"score={scores[THRESHOLDS[0]]}"
        )


if __name__ == "__main__":
    print_report(run_threshold_evaluation())
