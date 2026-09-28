"""Day 109: Scenario-isolated synthetic anomaly evaluation.

Each scenario is scored independently to avoid cross-scenario IP-frequency
contamination. Results are synthetic and are not real-world accuracy claims.
"""

from copy import deepcopy

from src.analyzers.anomaly_detector import detect_anomalies
from src.evaluate_anomaly_day105 import calculate_metrics


THRESHOLDS = (30, 40, 60)


def build_scenarios():
    """Return labeled scenarios with isolated event batches."""
    return [
        {
            "id": "benign_heartbeat",
            "label": False,
            "events": [{
                "event_type": "HEARTBEAT",
                "severity": "LOW",
                "message": "Routine heartbeat",
                "ip": "192.0.2.1",
            }],
        },
        {
            "id": "benign_repeated_ip",
            "label": False,
            "events": [
                {
                    "event_type": "HEARTBEAT",
                    "severity": "LOW",
                    "message": "Routine heartbeat",
                    "ip": "192.0.2.20",
                }
                for _ in range(4)
            ],
        },
        {
            "id": "isolated_failed_login",
            "label": True,
            "events": [{
                "event_type": "FAILED_LOGIN",
                "severity": "HIGH",
                "message": "Failed password for user alice",
                "ip": "192.0.2.30",
            }],
        },
        {
            "id": "repeated_failed_logins",
            "label": True,
            "events": [
                {
                    "event_type": "FAILED_LOGIN",
                    "severity": "HIGH",
                    "message": "Failed password for user alice",
                    "ip": "192.0.2.40",
                }
                for _ in range(3)
            ],
        },
        {
            "id": "high_signal_port_scan",
            "label": True,
            "events": [{
                "event_type": "PORT_SCAN",
                "severity": "HIGH",
                "message": "Suspicious port scan detected",
                "ip": "192.0.2.50",
            }],
        },
        {
            "id": "suspicious_event_without_ip",
            "label": True,
            "events": [{
                "event_type": "INTRUSION",
                "severity": "HIGH",
                "message": "Suspicious intrusion indicator",
                "ip": "N/A",
            }],
        },
        {
            "id": "benign_authorized_maintenance",
            "label": False,
            "events": [{
                "event_type": "SYSTEM_ACTIVITY",
                "severity": "MEDIUM",
                "message": "Authorized maintenance activity",
                "ip": "192.0.2.60",
            }],
        },
    ]


def run_scenario_evaluation():
    scenarios = build_scenarios()
    reports = {}

    for threshold in THRESHOLDS:
        labels = []
        predictions = []
        details = []

        for scenario in scenarios:
            events = deepcopy(scenario["events"])
            results = detect_anomalies(events, threshold=threshold)

            # Scenario is flagged if any event in its batch is flagged.
            flagged = any(result.is_anomaly for result in results)
            labels.append(scenario["label"])
            predictions.append(flagged)

            details.append({
                "id": scenario["id"],
                "label": scenario["label"],
                "scores": [result.anomaly_score for result in results],
                "event_predictions": [
                    result.is_anomaly for result in results
                ],
                "scenario_flagged": flagged,
            })

        reports[threshold] = {
            "metrics": calculate_metrics(labels, predictions),
            "details": details,
        }

    return {
        "scenario_count": len(scenarios),
        "positive_scenarios": sum(s["label"] for s in scenarios),
        "negative_scenarios": sum(not s["label"] for s in scenarios),
        "reports": reports,
    }


def print_report(report):
    print("DAY 109 SCENARIO-ISOLATED SYNTHETIC EVALUATION")
    print(f"Scenarios: {report['scenario_count']}")
    print(f"Suspicious scenarios: {report['positive_scenarios']}")
    print(f"Benign scenarios: {report['negative_scenarios']}")
    print("Each scenario is scored independently.")
    print("Results are not evidence of real-world accuracy.")

    for threshold, result in report["reports"].items():
        metrics = result["metrics"]
        print(f"\nThreshold: {threshold}")
        print(
            f"TP={metrics['TP']} FP={metrics['FP']} "
            f"TN={metrics['TN']} FN={metrics['FN']}"
        )
        for key in ("precision", "recall", "false_positive_rate"):
            value = metrics[key]
            print(f"{key}: {'N/A' if value is None else f'{value:.3f}'}")

        for detail in result["details"]:
            scores = ",".join(map(str, detail["scores"]))
            print(
                f"  {detail['id']}: label={int(detail['label'])} "
                f"scores=[{scores}] "
                f"flagged={int(detail['scenario_flagged'])}"
            )


if __name__ == "__main__":
    print_report(run_scenario_evaluation())
