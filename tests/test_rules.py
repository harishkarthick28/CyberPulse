"""
Comprehensive test suite for CyberPulse detection rules and correlation engine.
Run with: pytest
"""

import pytest
import json
import os
from rules.detector import DetectionEngine, Alert, SEVERITY_POINTS
from rules.correlator import CorrelationEngine, IncidentCluster
from utils.explainer import generate_plain_language_narrative, get_guided_remediation_actions


@pytest.fixture
def detector():
    return DetectionEngine()


@pytest.fixture
def correlator():
    return CorrelationEngine()


@pytest.fixture
def synthetic_data():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    json_path = os.path.join(base_dir, "data", "synthetic_logs.json")
    with open(json_path, "r", encoding="utf-8") as f:
        return json.load(f)


def test_rule_01_password_spray(detector):
    event = {
        "event_id": "T-01",
        "timestamp": "2026-10-25T10:00:00Z",
        "event_type": "password_spray_burst",
        "user": "test.user@company.com",
        "ip_address": "198.51.100.1",
        "details": {"failed_attempts": 12}
    }
    alerts = detector.evaluate_event(event)
    assert len(alerts) == 1
    assert alerts[0].rule_id == "RULE-01"
    assert alerts[0].severity == "Medium"
    assert alerts[0].points == 15


def test_rule_02_impossible_travel(detector):
    event = {
        "event_id": "T-02",
        "timestamp": "2026-10-25T10:00:00Z",
        "event_type": "impossible_travel_login",
        "user": "test.user@company.com",
        "ip_address": "203.0.113.5",
        "geo_location": "Moscow, Russia",
        "details": {"speed_kmh": 4000, "previous_location": "Chicago, IL, USA"}
    }
    alerts = detector.evaluate_event(event)
    assert len(alerts) == 1
    assert alerts[0].rule_id == "RULE-02"
    assert alerts[0].severity == "High"
    assert alerts[0].points == 25


def test_rule_03_unrecognized_device(detector):
    event = {
        "event_id": "T-03",
        "timestamp": "2026-10-25T10:00:00Z",
        "event_type": "new_device_enrolled",
        "user": "test.user@company.com",
        "device_id": "DEV-ROGUE-99",
        "details": {"compliance_status": "Non-Compliant"}
    }
    alerts = detector.evaluate_event(event)
    assert len(alerts) == 1
    assert alerts[0].rule_id == "RULE-03"


def test_rule_04_mfa_fatigue(detector):
    event = {
        "event_id": "T-04",
        "timestamp": "2026-10-25T10:00:00Z",
        "event_type": "mfa_push_flood_bypass",
        "user": "test.user@company.com",
        "details": {"push_count_last_10m": 10}
    }
    alerts = detector.evaluate_event(event)
    assert len(alerts) == 1
    assert alerts[0].rule_id == "RULE-04"
    assert alerts[0].mitre_tactic == "Credential Access"


def test_rule_05_inbox_forwarding(detector):
    event = {
        "event_id": "T-05",
        "timestamp": "2026-10-25T10:00:00Z",
        "event_type": "inbox_forwarding_rule_created",
        "user": "test.user@company.com",
        "details": {"forward_to": "hacker@evil.org"}
    }
    alerts = detector.evaluate_event(event)
    assert len(alerts) == 1
    assert alerts[0].rule_id == "RULE-05"


def test_rule_06_privilege_escalation(detector):
    event = {
        "event_id": "T-06",
        "timestamp": "2026-10-25T10:00:00Z",
        "event_type": "privilege_escalation_admin",
        "user": "test.user@company.com",
        "details": {"role_granted": "Global Administrator"}
    }
    alerts = detector.evaluate_event(event)
    assert len(alerts) == 1
    assert alerts[0].rule_id == "RULE-06"
    assert alerts[0].severity == "Critical"
    assert alerts[0].points == 40


def test_rule_07_encoded_powershell(detector):
    event = {
        "event_id": "T-07",
        "timestamp": "2026-10-25T10:00:00Z",
        "event_type": "encoded_powershell_executed",
        "user": "test.user@company.com",
        "details": {"command_line": "powershell.exe -enc SQBFAFgA"}
    }
    alerts = detector.evaluate_event(event)
    assert len(alerts) == 1
    assert alerts[0].rule_id == "RULE-07"


def test_rule_08_shadow_copy_deletion(detector):
    event = {
        "event_id": "T-08",
        "timestamp": "2026-10-25T10:00:00Z",
        "event_type": "shadow_copy_deleted",
        "user": "test.user@company.com",
        "details": {"utility": "vssadmin.exe", "arguments": "delete shadows /all /quiet"}
    }
    alerts = detector.evaluate_event(event)
    assert len(alerts) == 1
    assert alerts[0].rule_id == "RULE-08"
    assert alerts[0].severity == "Critical"


def test_rule_09_abnormal_offhours(detector):
    event = {
        "event_id": "T-09",
        "timestamp": "2026-10-25T10:00:00Z",
        "event_type": "abnormal_offhours_access",
        "user": "test.user@company.com",
        "details": {"local_time_at_user_tz": "03:40 AM (Sunday)"}
    }
    alerts = detector.evaluate_event(event)
    assert len(alerts) == 1
    assert alerts[0].rule_id == "RULE-09"


def test_rule_10_mass_data_exfiltration(detector):
    event = {
        "event_id": "T-10",
        "timestamp": "2026-10-25T10:00:00Z",
        "event_type": "mass_file_download",
        "user": "test.user@company.com",
        "details": {"files_downloaded_count": 850}
    }
    alerts = detector.evaluate_event(event)
    assert len(alerts) == 1
    assert alerts[0].rule_id == "RULE-10"
    assert alerts[0].severity == "Critical"


def test_correlator_ransomware_scenario(detector, correlator, synthetic_data):
    raw_events = synthetic_data["scenarios"]["ransomware_chain"]["events"]
    alerts = detector.evaluate_logs(raw_events)
    assert len(alerts) >= 7

    clusters = correlator.correlate(alerts)
    assert len(clusters) == 1
    primary_cluster = clusters[0]

    # Verify score reaches Red Critical band (>= 75)
    assert primary_cluster.score >= 75
    assert primary_cluster.severity_band == "Red"
    assert "sarah.connors@smb-retail.com" in primary_cluster.correlated_users
    assert "185.220.101.45" in primary_cluster.correlated_ips

    # Verify lead time is computed
    lead_time = primary_cluster.lead_time_display
    assert "hr" in lead_time or "min" in lead_time

    # Verify Plain-Language generation
    narrative = generate_plain_language_narrative(primary_cluster)
    assert "Ransomware" in narrative["headline"]
    assert len(narrative["why_linked"]) > 20

    # Verify remediation actions
    actions = get_guided_remediation_actions(primary_cluster)
    assert len(actions) >= 4
    action_ids = [a["id"] for a in actions]
    assert "lock_account" in action_ids
    assert "block_ip" in action_ids


def test_correlator_normal_scenario(detector, correlator, synthetic_data):
    raw_events = synthetic_data["scenarios"]["normal_day"]["events"]
    alerts = detector.evaluate_logs(raw_events)
    # Routine logs should trigger 0 alerts
    assert len(alerts) == 0

    clusters = correlator.correlate(alerts)
    assert len(clusters) == 0

    narrative = generate_plain_language_narrative(None)
    assert "Zero Active Threats" in narrative["headline"]
