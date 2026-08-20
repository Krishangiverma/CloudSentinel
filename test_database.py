from datetime import datetime

from src.models.event import SecurityEvent
from src.data.database import initialize_database, save_event, get_all_events


# Initialize database
initialize_database()


# Create test security event
event = SecurityEvent(
    timestamp=datetime.now(),
    event_type="BRUTE_FORCE",
    severity="HIGH",
    message="Multiple failed login attempts detected.",
    source="CloudSentinel"
)


# Save event
save_event(event)


# Retrieve events
events = get_all_events()


print("\n=== DATABASE TEST ===")

for item in events:
    print(item)
