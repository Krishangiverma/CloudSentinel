"""
Default CloudSentinel detection rules.

Day 36 rule-engine abstraction.

Day 37 will externalize these definitions into
YAML/JSON configuration.
"""

from src.rules.rule_engine import DetectionRule


def _message_contains(text):
    """
    Build a reusable case-insensitive message matcher.
    """

    keyword = text.lower()

    def condition(event):
        message = str(
            event.get("message", "")
        ).lower()

        return keyword in message

    return condition


DEFAULT_RULES = [

    DetectionRule(
        name="ssh_failed_password",
        condition=_message_contains(
            "failed password"
        ),
        event_type="SUSPICIOUS_ACTIVITY",
        severity="MEDIUM",
        description=(
            "Detect failed SSH password authentication."
        ),
    ),

    DetectionRule(
        name="ssh_invalid_user",
        condition=_message_contains(
            "invalid user"
        ),
        event_type="SUSPICIOUS_ACTIVITY",
        severity="MEDIUM",
        description=(
            "Detect authentication attempts against invalid users."
        ),
    ),

    DetectionRule(
        name="authentication_failure",
        condition=_message_contains(
            "authentication failure"
        ),
        event_type="SUSPICIOUS_ACTIVITY",
        severity="MEDIUM",
        description=(
            "Detect authentication failure messages."
        ),
    ),

    DetectionRule(
        name="brute_force_keyword",
        condition=_message_contains(
            "brute force"
        ),
        event_type="BRUTE_FORCE",
        severity="HIGH",
        description=(
            "Detect explicit brute-force indicators."
        ),
    ),

    DetectionRule(
        name="sudo_activity",
        condition=lambda event: (
            "sudo:" in str(
                event.get("message", "")
            ).lower()
            or
            "sudo " in str(
                event.get("message", "")
            ).lower()
        ),
        event_type="SUDO_ACTIVITY",
        severity="MEDIUM",
        description=(
            "Detect sudo-related security activity."
        ),
    ),

    DetectionRule(
        name="session_opened",
        condition=_message_contains(
            "session opened"
        ),
        event_type="SECURITY_LOG",
        severity="LOW",
        description=(
            "Detect session-open events."
        ),
    ),

    DetectionRule(
        name="session_closed",
        condition=_message_contains(
            "session closed"
        ),
        event_type="SECURITY_LOG",
        severity="LOW",
        description=(
            "Detect session-close events."
        ),
    ),

    DetectionRule(
        name="cron_activity",
        condition=_message_contains(
            "cron"
        ),
        event_type="SECURITY_LOG",
        severity="LOW",
        description=(
            "Detect cron-related security log activity."
        ),
    ),
]
