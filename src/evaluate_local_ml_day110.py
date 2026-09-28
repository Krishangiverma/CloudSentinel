"""Day 110: Isolated evaluation of the local statistical anomaly prototype."""

from copy import deepcopy

from src.analyzers.local_ml_anomaly import LocalStatisticalAnomalyModel


def event(message, event_type="HEARTBEAT", severity="LOW",
          source="system", user=None, ip_address="N/A"):
    return {
        "message": message,
        "event_type": event_type,
        "severity": severity,
        "source": source,
        "user": user,
        "ip_address": ip_address,
    }


def build_scenarios():
    # Training contains benign examples only.
    training = [
        event("Routine service heartbeat"),
        event("Routine periodic heartbeat"),
        event("Normal system heartbeat"),
        event("Scheduled service check"),
        event("Routine background task"),
        event("Normal health check"),
        event("Scheduled backup completed",
              event_type="SYSTEM_ACTIVITY"),
        event("Routine maintenance task completed",
              event_type="SYSTEM_ACTIVITY", severity="MEDIUM"),
        event("User authentication succeeded",
              event_type="LOGIN_SUCCESS", source="auth",
              user="operator", ip_address="192.0.2.11"),
        event("Periodic network health check",
              event_type="NETWORK_CHECK", source="network",
              ip_address="192.0.2.12"),
        event("Routine authentication service status",
              event_type="SERVICE_STATUS", source="auth"),
        event("Normal scheduled system maintenance completed",
              event_type="SYSTEM_ACTIVITY", source="system"),
    ]

    # Labels are scenario-level ground truth for this synthetic test set.
    test_cases = [
        ("benign_heartbeat", event("Routine service heartbeat"), False),
        ("benign_scheduled_task",
         event("Scheduled backup completed successfully",
               event_type="SYSTEM_ACTIVITY"), False),
        ("benign_authorized_login",
         event("User login succeeded", event_type="LOGIN_SUCCESS",
               user="operator", ip_address="192.0.2.10"), False),
        ("suspicious_long_message",
         event("Suspicious activity details: " + "X" * 300,
               event_type="INTRUSION", severity="HIGH",
               source="auth", ip_address="192.0.2.50"), True),
        ("suspicious_port_scan",
         event("Port scan detected from source host",
               event_type="PORT_SCAN", severity="HIGH",
               source="network", ip_address="192.0.2.60"), True),
        ("failed_login",
         event("Failed password for user alice",
               event_type="FAILED_LOGIN", severity="HIGH",
               source="auth", user="alice", ip_address="192.0.2.70"), True),
    ]
    return training, test_cases


def metrics(labels, predictions):
    if len(labels) != len(predictions):
        raise ValueError("labels and predictions must have equal lengths")

    tp = sum(y and p for y, p in zip(labels, predictions))
    fp = sum((not y) and p for y, p in zip(labels, predictions))
    tn = sum((not y) and (not p) for y, p in zip(labels, predictions))
    fn = sum(y and (not p) for y, p in zip(labels, predictions))

    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    fpr = fp / (fp + tn) if fp + tn else None

    # F1 is undefined when there are no true, false-positive,
    # or false-negative positive predictions/labels.
    f1_denominator = (2 * tp) + fp + fn
    f1 = (2 * tp / f1_denominator) if f1_denominator else None

    return {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": precision, "recall": recall,
        "f1_score": f1,
        "false_positive_rate": fpr,
    }


def run_evaluation(threshold=3.0):
    training, test_cases = build_scenarios()
    model = LocalStatisticalAnomalyModel(threshold=threshold)
    model.fit(deepcopy(training))

    labels = [label for _, _, label in test_cases]
    results = []

    for name, sample, label in test_cases:
        prediction = model.predict_one(sample)
        results.append({
            "scenario": name,
            "expected_anomaly": label,
            "predicted_anomaly": prediction.is_anomaly,
            "score": round(prediction.anomaly_score, 3),
            "deviations": dict(prediction.feature_deviations),
        })

    report = metrics(
        labels,
        [item["predicted_anomaly"] for item in results],
    )
    return {
        "training_count": model.training_count,
        "threshold": threshold,
        "metrics": report,
        "results": results,
        "warning": (
            "Synthetic demonstration only; these results do not establish "
            "real-world security detection efficacy."
        ),
    }


if __name__ == "__main__":
    import json
    print(json.dumps(run_evaluation(), indent=2))
