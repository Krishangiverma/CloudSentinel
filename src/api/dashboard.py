import sys
from pathlib import Path


# ============================================================
# PROJECT PATH SETUP
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[2]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


# ============================================================
# DATABASE IMPORT
# ============================================================

from src.data.database import get_all_events


# ============================================================
# TERMINAL COLORS
# ============================================================

RESET = "\033[0m"

RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
CYAN = "\033[96m"
WHITE = "\033[97m"

BOLD = "\033[1m"


# ============================================================
# DASHBOARD WIDTH
# ============================================================

WIDTH = 75


# ============================================================
# CLEAR SCREEN
# ============================================================

def clear_screen():
    """
    Clears the terminal screen.
    """

    print("\033[2J\033[H", end="")


# ============================================================
# PRINT LINE
# ============================================================

def print_line(character="-"):
    """
    Prints a horizontal line.
    """

    print(character * WIDTH)


# ============================================================
# HEADER
# ============================================================

def print_header():
    """
    Prints CloudSentinel dashboard header.
    """

    print_line("=")

    print("CLOUDSENTINEL".center(WIDTH))
    print("SECURITY DASHBOARD".center(WIDTH))

    print_line("=")


# ============================================================
# GET SEVERITY COLOR
# ============================================================

def get_severity_color(severity):
    """
    Returns terminal color according to severity.
    """

    if severity == "HIGH":
        return RED + BOLD

    elif severity == "MEDIUM":
        return YELLOW + BOLD

    elif severity == "LOW":
        return GREEN

    return WHITE


# ============================================================
# DISPLAY ONE EVENT
# ============================================================

def display_event(event):
    """
    Displays a single security event.
    """

    event_id = event[0]
    timestamp = event[1]
    event_type = event[2]
    severity = event[3]
    message = event[4]
    source = event[5]

    severity_color = get_severity_color(severity)

    # Highlight BRUTE_FORCE separately
    if event_type == "BRUTE_FORCE":

        event_type_display = (
            RED
            + BOLD
            + event_type
            + RESET
        )

    else:

        event_type_display = event_type

    print(
        f"ID={event_id} | "
        f"{timestamp} | "
        f"{severity_color}{severity:<6}{RESET} | "
        f"{event_type_display}"
    )

    print(f"Message : {message}")

    print(f"Source  : {source}")

    print_line()


# ============================================================
# DISPLAY EVENTS
# ============================================================

def show_events(events):
    """
    Displays multiple security events.
    """

    if not events:

        print()

        print(
            YELLOW
            + "No matching security events found."
            + RESET
        )

        print()

        return

    print()

    for event in events:

        display_event(event)


# ============================================================
# CALCULATE STATISTICS
# ============================================================

def calculate_statistics(events):
    """
    Calculates security statistics.
    """

    total_events = len(events)

    high_events = 0
    medium_events = 0
    low_events = 0
    brute_force_events = 0

    for event in events:

        severity = event[3]
        event_type = event[2]

        if severity == "HIGH":

            high_events += 1

        elif severity == "MEDIUM":

            medium_events += 1

        elif severity == "LOW":

            low_events += 1

        if event_type == "BRUTE_FORCE":

            brute_force_events += 1

    return (
        total_events,
        high_events,
        medium_events,
        low_events,
        brute_force_events
    )


# ============================================================
# SECURITY SUMMARY
# ============================================================

def show_security_summary(events):
    """
    Displays security statistics.
    """

    (
        total_events,
        high_events,
        medium_events,
        low_events,
        brute_force_events
    ) = calculate_statistics(events)

    print()

    print("SECURITY SUMMARY")

    print_line()

    print(
        f"Total Events       : "
        f"{total_events}"
    )

    print(
        f"HIGH Severity      : "
        f"{RED}{BOLD}{high_events}{RESET}"
    )

    print(
        f"MEDIUM Severity    : "
        f"{YELLOW}{BOLD}{medium_events}{RESET}"
    )

    print(
        f"LOW Severity       : "
        f"{GREEN}{low_events}{RESET}"
    )

    print(
        f"BRUTE FORCE Events : "
        f"{RED}{BOLD}{brute_force_events}{RESET}"
    )

    print_line()


# ============================================================
# ALL EVENTS
# ============================================================

def show_all_events(events):
    """
    Displays all security events.
    """

    print()

    print(
        CYAN
        + BOLD
        + "--- ALL SECURITY EVENTS ---"
        + RESET
    )

    show_events(events)


# ============================================================
# HIGH EVENTS
# ============================================================

def show_high_events(events):
    """
    Displays HIGH severity events.
    """

    print()

    print(
        RED
        + BOLD
        + "--- HIGH SEVERITY EVENTS ---"
        + RESET
    )

    filtered_events = [
        event
        for event in events
        if event[3] == "HIGH"
    ]

    show_events(filtered_events)


# ============================================================
# MEDIUM EVENTS
# ============================================================

def show_medium_events(events):
    """
    Displays MEDIUM severity events.
    """

    print()

    print(
        YELLOW
        + BOLD
        + "--- MEDIUM SEVERITY EVENTS ---"
        + RESET
    )

    filtered_events = [
        event
        for event in events
        if event[3] == "MEDIUM"
    ]

    show_events(filtered_events)


# ============================================================
# LOW EVENTS
# ============================================================

def show_low_events(events):
    """
    Displays LOW severity events.
    """

    print()

    print(
        GREEN
        + BOLD
        + "--- LOW SEVERITY EVENTS ---"
        + RESET
    )

    filtered_events = [
        event
        for event in events
        if event[3] == "LOW"
    ]

    show_events(filtered_events)


# ============================================================
# BRUTE FORCE EVENTS
# ============================================================

def show_brute_force_events(events):
    """
    Displays BRUTE_FORCE events.
    """

    print()

    print(
        RED
        + BOLD
        + "--- BRUTE FORCE EVENTS ---"
        + RESET
    )

    filtered_events = [
        event
        for event in events
        if event[2] == "BRUTE_FORCE"
    ]

    show_events(filtered_events)


# ============================================================
# RECENT EVENTS
# ============================================================

def show_recent_events(events):
    """
    Displays the 10 most recent events.

    Events are sorted using their timestamp.
    Newest events appear first.
    """

    print()

    print(
        CYAN
        + BOLD
        + "--- RECENT SECURITY EVENTS ---"
        + RESET
    )

    if not events:

        print()

        print(
            YELLOW
            + "No security events found."
            + RESET
        )

        print()

        return

    # --------------------------------------------------------
    # Sort events by timestamp
    #
    # event[1] contains the timestamp.
    #
    # reverse=True means newest timestamp first.
    # --------------------------------------------------------

    sorted_events = sorted(
        events,
        key=lambda event: str(event[1]),
        reverse=True
    )

    # --------------------------------------------------------
    # Take only the latest 10 events
    # --------------------------------------------------------

    recent_events = sorted_events[:10]

    print()

    print(
        CYAN
        + f"Showing latest {len(recent_events)} events"
        + RESET
    )

    print()

    show_events(recent_events)


# ============================================================
# MENU
# ============================================================

def show_menu():
    """
    Displays dashboard menu.
    """

    print()

    print("1. Show all events")

    print("2. Show HIGH severity events")

    print("3. Show MEDIUM severity events")

    print("4. Show LOW severity events")

    print("5. Show BRUTE FORCE events")

    print("6. Show recent events")

    print("7. Exit")

    print()


# ============================================================
# MAIN DASHBOARD
# ============================================================

def show_dashboard():
    """
    Main CloudSentinel dashboard loop.
    """

    while True:

        # ----------------------------------------------------
        # Get latest database events
        # ----------------------------------------------------

        events = get_all_events()

        # ----------------------------------------------------
        # Clear screen
        # ----------------------------------------------------

        clear_screen()

        # ----------------------------------------------------
        # Display header
        # ----------------------------------------------------

        print_header()

        # ----------------------------------------------------
        # Display summary
        # ----------------------------------------------------

        show_security_summary(events)

        # ----------------------------------------------------
        # Display menu
        # ----------------------------------------------------

        show_menu()

        # ----------------------------------------------------
        # Get user choice
        # ----------------------------------------------------

        try:

            choice = input(
                "Enter your choice: "
            ).strip()

        except KeyboardInterrupt:

            print()

            print(
                "\nExiting CloudSentinel dashboard..."
            )

            break

        except EOFError:

            print()

            print(
                "\nExiting CloudSentinel dashboard..."
            )

            break

        # ====================================================
        # OPTION 1
        # ====================================================

        if choice == "1":

            clear_screen()

            print_header()

            show_all_events(events)

            input(
                "\nPress Enter to return to dashboard..."
            )

        # ====================================================
        # OPTION 2
        # ====================================================

        elif choice == "2":

            clear_screen()

            print_header()

            show_high_events(events)

            input(
                "\nPress Enter to return to dashboard..."
            )

        # ====================================================
        # OPTION 3
        # ====================================================

        elif choice == "3":

            clear_screen()

            print_header()

            show_medium_events(events)

            input(
                "\nPress Enter to return to dashboard..."
            )

        # ====================================================
        # OPTION 4
        # ====================================================

        elif choice == "4":

            clear_screen()

            print_header()

            show_low_events(events)

            input(
                "\nPress Enter to return to dashboard..."
            )

        # ====================================================
        # OPTION 5
        # ====================================================

        elif choice == "5":

            clear_screen()

            print_header()

            show_brute_force_events(events)

            input(
                "\nPress Enter to return to dashboard..."
            )

        # ====================================================
        # OPTION 6
        # ====================================================

        elif choice == "6":

            clear_screen()

            print_header()

            show_recent_events(events)

            input(
                "\nPress Enter to return to dashboard..."
            )

        # ====================================================
        # OPTION 7
        # ====================================================

        elif choice == "7":

            clear_screen()

            print_header()

            print()

            print(
                CYAN
                + BOLD
                + "Exiting CloudSentinel dashboard..."
                + RESET
            )

            print()

            break

        # ====================================================
        # INVALID CHOICE
        # ====================================================

        else:

            print()

            print(
                RED
                + "Invalid choice. Please select 1-7."
                + RESET
            )

            input(
                "\nPress Enter to continue..."
            )


# ============================================================
# PROGRAM ENTRY POINT
# ============================================================

if __name__ == "__main__":

    show_dashboard()
