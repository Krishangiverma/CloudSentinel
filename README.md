# CloudSentinel

CloudSentinel is a Linux-based security monitoring project designed to detect suspicious activities, analyze security events, generate security alerts, send notifications, and provide a web dashboard for monitoring.

## Overview

CloudSentinel collects security-related information from Linux system logs and processes the collected data through detection and analysis components.

Detected security events are stored in an SQLite database. The alert management system processes important events and can generate security notifications.

A Flask-based REST API exposes the security data, while the web dashboard provides a visual interface for monitoring events and their severity.

## Features

- Linux security log monitoring
- Security event collection
- Security event analysis
- Brute-force attack detection
- Suspicious activity detection
- IP-related detection
- Event severity classification
- SQLite database integration
- Security alert management
- Security alert notifications
- Notification cooldown mechanism
- Notification logging
- REST API
- Web-based security dashboard
- Automatic dashboard data refresh
- Security reports

## System Architecture

```text
Linux Security Logs
        |
        v
   Log Collector
        |
        v
 Event Analyzer / Detectors
        |
        v
  Security Events
        |
        v
 SQLite Database
        |
        +------------------+
        |                  |
        v                  v
 Alert Manager       REST API
        |                  |
        v                  v
 Notifications       Web Dashboard
Project Structure
CloudSentinel/
│
├── config/
│   ├── __init__.py
│   └── settings.py
│
├── data/
│   ├── __init__.py
│   └── cloudsentinel.db
│
├── logs/
│   └── notifications.log
│
├── reports/
│   ├── security_alerts.txt
│   └── security_report.txt
│
├── src/
│   ├── alerts/
│   │   ├── __init__.py
│   │   └── alert_engine.py
│   │
│   ├── analyzers/
│   │   ├── __init__.py
│   │   └── event_analyzer.py
│   │
│   ├── api/
│   │   ├── app.py
│   │   └── dashboard.py
│   │
│   ├── collectors/
│   │   └── security_log.py
│   │
│   ├── data/
│   │   └── database.py
│   │
│   ├── models/
│   │   ├── __init__.py
│   │   └── event.py
│   │
│   ├── reports/
│   │   ├── __init__.py
│   │   └── security_report.py
│   │
│   ├── agent.py
│   ├── alert.py
│   ├── alert_manager.py
│   ├── brute_force.py
│   ├── detector.py
│   ├── event.py
│   ├── ip_detector.py
│   ├── log_collector.py
│   ├── main.py
│   ├── notification_manager.py
│   ├── realtime_monitor.py
│   ├── report_generator.py
│   └── system_monitor.py
│
├── templates/
│   └── dashboard.html
│
├── tests/
│   └── data/
│       └── sample_auth.log
│
├── .gitignore
├── README.md
└── test_database.py
Security Detection
CloudSentinel analyzes Linux security events and identifies potentially suspicious behavior.
The project includes detection logic for:
Brute-force login attempts
Suspicious activity
Security log activity
Sudo activity
IP-related security events
Events are assigned severity levels:
HIGH
MEDIUM
LOW
Event Management
Security events are stored in the SQLite database.
Each event can contain:
Event ID
Timestamp
Event type
Severity
Message
Source
IP address
The API can retrieve stored events and also supports creating new security events.
Alert Management
The alert management system processes detected security events and generates security alerts based on event information and severity.
Alerts are stored and can be used by the notification system.
Notification System
CloudSentinel includes a notification system for security alerts.
The notification system provides:
Security alert notifications
Notification cooldown
Notification logging
Prevention of excessive repeated notifications
Notification activity is recorded in:
logs/notifications.log
Database
CloudSentinel uses SQLite for persistent local storage.
The database contains security-related information such as events and alerts.
Database location:
data/cloudsentinel.db
REST API
The project includes a Flask REST API.
API Endpoints
Method	Endpoint	Description
GET	/	Returns CloudSentinel API information
GET	/api	Returns available API information
GET	/api/health	Checks API health
GET	/api/events	Returns stored security events
POST	/api/events	Creates a new security event
GET	/api/stats	Returns event statistics
GET	/dashboard	Opens the security dashboard
Web Dashboard
CloudSentinel includes a browser-based security monitoring dashboard.
The dashboard displays:
Total security events
HIGH severity events
MEDIUM severity events
LOW severity events
Security event table
The event table displays:
ID
Event type
Severity
Message
Source
IP address
Timestamp
The dashboard retrieves event information from the Flask API.
Dashboard data automatically refreshes every 10 seconds.
Running the Project
1. Activate the virtual environment
source venv/bin/activate
2. Start the Flask API
From the project root:
python -m src.api.app
The Flask server runs on port 5000.
Dashboard Access
From the Ubuntu VM:
http://127.0.0.1:5000/dashboard
From the Mac host:
http://192.168.64.3:5000/dashboard
API Testing
Health Check
curl http://127.0.0.1:5000/api/health
Get Security Events
curl http://127.0.0.1:5000/api/events
Get Statistics
curl http://127.0.0.1:5000/api/stats
Testing
The project contains tests for multiple CloudSentinel components, including:
Database functionality
Alert Manager
Brute-force detection
General event detection
IP detection
Example:
python -m unittest src.test_alert_manager
Reports
CloudSentinel can generate security-related reports.
Reports are stored under:
reports/
Current report files include:
security_alerts.txt
security_report.txt
Development Environment
The project has been developed and tested in a Linux environment using Ubuntu running inside a virtual machine.
The Flask API is configured to listen on:
0.0.0.0:5000
This allows the dashboard to be accessed from the host machine when VM networking is configured correctly.
Current Project Status
The following major components are implemented:
Security log collection
Security event detection
Event analysis
SQLite database integration
Brute-force detection
Suspicious activity detection
Alert management
Security alert notifications
Notification cooldown
Notification logging
Flask REST API
Web security dashboard
Dashboard automatic refresh
Security reports
Ubuntu VM deployment and testing
Future Improvements
Possible future improvements include:
Dashboard authentication
Role-based access control
Advanced security visualizations
Real-time event streaming
Improved alert filtering
Email or external notification integrations
Production WSGI deployment
Containerized deployment
Cloud deployment
More advanced threat detection
Disclaimer
CloudSentinel is an educational cybersecurity monitoring project intended for learning, experimentation, and defensive security monitoring.
