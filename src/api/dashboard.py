import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from src.data.database import get_all_events


def show_events(events):
    if not events:
        print("\nNo matching security events found.")
        return

    print()
    print("-" * 75)

    for event in events:
        print(
            f"ID={event[0]} | "
            f"{event[1]} | "
            f"{event[3]:<6} | "
            f"{event[2]:<15}"
        )
        print(f"Message : {event[4]}")
        print(f"Source  : {event[5]}")
        print("-" * 75)


def show_dashboard():

    events = get_all_events()

    print()
    print("=" * 75)
    print("                 CLOUDSENTINEL")
    print("              SECURITY DASHBOARD")
    print("=" * 75)

    while True:

        print()
        print("1. Show all events")
        print("2. Show HIGH severity events")
        print("3. Show MEDIUM severity events")
        print("4. Show LOW severity events")
        print("5. Show BRUTE FORCE events")
        print("6. Exit")

        choice = input("\nEnter your choice: ").strip()

        if choice == "1":

            print("\n--- ALL SECURITY EVENTS ---")
            show_events(events)

        elif choice == "2":

            print("\n--- HIGH SEVERITY EVENTS ---")

            filtered = [
                event for event in events
                if event[3] == "HIGH"
            ]

            show_events(filtered)

        elif choice == "3":

            print("\n--- MEDIUM SEVERITY EVENTS ---")

            filtered = [
                event for event in events
                if event[3] == "MEDIUM"
            ]

            show_events(filtered)

        elif choice == "4":

            print("\n--- LOW SEVERITY EVENTS ---")

            filtered = [
                event for event in events
                if event[3] == "LOW"
            ]

            show_events(filtered)

        elif choice == "5":

            print("\n--- BRUTE FORCE EVENTS ---")

            filtered = [
                event for event in events
                if event[2] == "BRUTE_FORCE"
            ]

            show_events(filtered)

        elif choice == "6":

            print("\nExiting CloudSentinel Dashboard...")
            break

        else:

            print("\nInvalid choice. Please select 1-6.")


if __name__ == "__main__":
    show_dashboard()
