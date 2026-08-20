"""
CloudSentinel Central Configuration
"""

# Brute-force detection threshold
BRUTE_FORCE_THRESHOLD = 3

# Number of recent events shown in reports/dashboard
RECENT_EVENTS_LIMIT = 10

# Log file used by CloudSentinel
AUTH_LOG_PATH = "/var/log/auth.log"

# Database location
DATABASE_PATH = "data/cloudsentinel.db"

# Security severity levels
SEVERITY_LOW = "LOW"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_HIGH = "HIGH"

# CloudSentinel application name
APP_NAME = "CloudSentinel"
