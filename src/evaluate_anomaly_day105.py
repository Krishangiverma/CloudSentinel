"""Day 105: Synthetic benchmark for rules vs anomaly detection."""

from copy import deepcopy

from src.analyzers.anomaly_detector import detect_anomalies
from src.rules.default_rules import DEFAULT_RULES
from src.rules.rule_engine import RuleEngine


def build_dataset():
    """Build a deterministic synthetic dataset with ground-truth labels."""
    normal_events = [
        ("normal_heartbeat", "HEARTBEAT", "Routine system heartbeat", "192.0.2.1"),
        ("normal_login", "LOGIN_SUCCESS", "Accepted password for alice", "192.0.2.2"),
        ("normal_cron", "SYSTEM_ACTIVITY", "cron: completed scheduled backup", "N/A"),
        ("normal_sudo", "SYSTEM_ACTIVITY", "sudo: authorized maintenance command", "N/A"),
    ]

    dataset = []
    for event_id, event_type, message, ip in normal_events:
        dataset.append({
            "id": event_id,
            "label": False,
            "event": {
                "event_type": event_type,
                "severity": "LOW",
                "message": message,
                "ip": ip,
                "ip_address": ip,
            },
        })

    dataset.append({
        "id": "isolated_failed_login",
        "label": True,
        "event": {
            "event_type": "FAILED_LOGIN",
            "severity": "HIGH",
            "message": "Failed password for user alice",
            "ip": "192.0.2.10",
            "ip_address": "192.0.2.10",
        },
    })

    for index in range(1, 4):
        dataset.append({
            "id": f"brute_force_{index}",
            "label": True,
            "event": {
                "event_type": "BRUTE_FORCE",
                "severity": "HIGH",
                "message": "Brute force: failed password attempt",
                "ip": "192.0.2.50",
                "ip_address": "192.0.2.50",
            },
        })

    return dataset


def calculate_metrics(labels, predictions):
    """Calculate binary classification metrics."""
    if len(labels) != len(predictions):
        raise ValueError("labels and predictions must have equal lengths")

    tp = sum(y and p for y, p in zip(labels, predictions))
    tn = sum(not y and not p for y, p in zip(labels, predictions))
    fp = sum(not y and p for y, p in zip(labels, predictions))
    fn = sum(y and not p for y, p in zip(labels, predictions))

    def ratio(numerator, denominator):
        return numerator / denominator if denominator else None

    return {
        "TP": tp,
        "FP": fp,
        "TN": tn,
        "FN": fn,
        "precision": ratio(tp, tp + fp),
        "recall": ratio(tp, tp + fn),
        "false_positive_rate": ratio(fp, fp + tn),
        "total": len(labels),
    }


def run_evaluation():
    """Compare predefined rules with the Day 104 prototype."""
    dataset = build_dataset()
    labels = [row["label"] for row in dataset]
    events = [deepcopy(row["event"]) for row in dataset]

    # This is DEFAULT_RULES, not the YAML-configured production detector.
    rule_engine = RuleEngine(deepcopy(DEFAULT_RULES))
    rule_predictions = [
        bool(rule_engine.evaluate(event))
        for event in events
    ]

    # Batch evaluation allows the prototype to inspect repeated source IPs.
    anomaly_results = detect_anomalies(events)
    anomaly_predictions = [result.is_anomaly for result in anomaly_results]

    return {
        "dataset_size": len(dataset),
        "labels": labels,
        "rule_predictions": rule_predictions,
        "anomaly_predictions": anomaly_predictions,
        "anomaly_scores": [result.anomaly_score for result in anomaly_results],
        "rule_baseline": calculate_metrics(labels, rule_predictions),
        "day104_anomaly": calculate_metrics(labels, anomaly_predictions),
        "events": dataset,
    }


def print_report(report):
    print("DAY 105 SYNTHETIC BENCHMARK")
    print("Ground truth: explicit synthetic labels")
    print(f"Events: {report['dataset_size']}")
    print("Not evidence of real-world accuracy.")

    for name in ("rule_baseline", "day104_anomaly"):
        metrics = report[name]
        print(f"\n{name}")
        print(
            f"TP={metrics['TP']} FP={metrics['FP']} "
            f"TN={metrics['TN']} FN={metrics['FN']}"
        )
        for key in ("precision", "recall", "false_positive_rate"):
            value = metrics[key]
            print(f"{key}: {'N/A' if value is None else f'{value:.3f}'}")

    print("\nPer-event results:")
    for index, row in enumerate(report["events"]):
        print(
            f"{row['id']}: label={int(row['label'])}, "
            f"rule={int(report['rule_predictions'][index])}, "
            f"anomaly_score={report['anomaly_scores'][index]}, "
            f"anomaly={int(report['anomaly_predictions'][index])}"
        )


if __name__ == "__main__":
    print_report(run_evaluation())
