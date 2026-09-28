from datetime import datetime

from src.models.event import SecurityEvent
from src.data.database import (
    initialize_database,
    save_event,
    get_all_events,
)


def main():
    """Run the database smoke test only when explicitly executed."""
    initialize_database()

    event = SecurityEvent(
        timestamp=datetime.now(),
        event_type="BRUTE_FORCE",
        severity="HIGH",
        message="Multiple failed login attempts detected.",
        source="CloudSentinel",
    )

    save_event(event)
    events = get_all_events()

    print("\n=== DATABASE TEST ===")
    for item in events:
        print(item)


if __name__ == "__main__":
    main()
