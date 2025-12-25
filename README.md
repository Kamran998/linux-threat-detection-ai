# Linux Threat Detection Agent (AI-Assisted)

A lightweight, host-based threat detection agent for Linux systems built with Python.

This project monitors system behavior and authentication activity on a Linux host, establishes a baseline of normal behavior, and detects suspicious or anomalous activity using unsupervised machine learning and rule-based security analysis. The agent is designed to run continuously as a background service and generate structured alerts for investigation.

---

## Overview

The Linux Threat Detection Agent combines host telemetry analysis with authentication log monitoring to provide basic host-level visibility into potentially malicious or abnormal behavior. Rather than relying on signatures alone, the system uses an Isolation Forest model to identify deviations from normal system activity while also detecting high-risk security events from system logs.

The goal of this project is to explore practical, AI-assisted threat detection techniques in a Linux environment and demonstrate core security engineering concepts such as log analysis, anomaly detection, and automated monitoring.

---

## Key Features

### Host Telemetry Monitoring
- Collects live system metrics including CPU usage, memory usage, and process count
- Establishes a baseline of normal behavior
- Flags anomalous system activity using an Isolation Forest model

### Authentication & Privilege Monitoring
- Monitors SSH authentication events via `journald`
- Detects suspected SSH brute-force attempts based on configurable thresholds
- Tracks sudo usage and privileged session activity
- Detects user and account management actions (useradd, userdel, group changes)

### Alerting & Logging
- Generates structured JSON alerts for all detected events
- Includes contextual details such as timestamps, host, severity, and event metadata
- Designed for easy ingestion into SIEM or log analysis tools

### Continuous Operation
- Runs as a background service using a systemd user unit
- Maintains state between runs using journal cursors
- Supports both one-time execution and continuous monitoring loops

---

## Architecture

The system is composed of two primary detection components:

- **Telemetry Anomaly Detector**
  - Uses an unsupervised machine learning model (Isolation Forest)
  - Scores live system metrics against a trained baseline

- **Authentication Event Detector**
  - Analyzes Linux authentication and security logs via `journalctl`
  - Applies rule-based logic to detect suspicious behavior

A unified runner coordinates both detectors and handles alert emission and health reporting.

---

## Technologies Used

- Python
- systemd
- journald / journalctl
- scikit-learn (Isolation Forest)
- Linux system metrics
- JSON-based logging

---

## Use Case

This project is intended as:
- A learning and experimentation platform for host-based intrusion detection
- A demonstration of AI-assisted anomaly detection in cybersecurity
- A portfolio project showcasing Linux administration, security monitoring, and Python development

It is **not intended for production use** without further hardening, tuning, and validation.

---

## Project Status

This project is currently complete as a functional prototype. Future enhancements could include:
- Improved model training and feature engineering
- Alert correlation and severity scoring
- Integration with external SIEM platforms
- Additional detection modules


