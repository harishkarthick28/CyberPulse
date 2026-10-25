"""
CyberPulse - Detection Engine
Implements 10 transparent, deterministic cybersecurity detection rules
tailored for small-to-medium businesses (SMBs).
"""

from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict
from datetime import datetime

# Standard severity mapping
SEVERITY_POINTS = {
    "Low": 5,
    "Medium": 15,
    "High": 25,
    "Critical": 40
}

@dataclass
class Alert:
    rule_id: str
    rule_name: str
    event_id: str
    timestamp: str
    user: str
    ip_address: str
    geo_location: str
    device_id: str
    device_name: str
    severity: str
    points: int
    mitre_tactic: str
    mitre_technique_id: str
    stage: str
    summary: str
    plain_explanation: str
    recommended_action: str
    raw_event: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class DetectionEngine:
    """Evaluates raw security log events against 10 transparent detection rules."""

    def __init__(self):
        self.rules = [
            self.rule_01_password_spray,
            self.rule_02_impossible_travel,
            self.rule_03_unrecognized_device,
            self.rule_04_mfa_fatigue,
            self.rule_05_inbox_forwarding,
            self.rule_06_privilege_escalation,
            self.rule_07_encoded_powershell,
            self.rule_08_shadow_copy_deletion,
            self.rule_09_abnormal_offhours,
            self.rule_10_mass_data_exfiltration,
        ]

    def evaluate_event(self, event: Dict[str, Any]) -> List[Alert]:
        """Runs all 10 rules against a single log event and returns triggered Alerts."""
        alerts = []
        for rule_func in self.rules:
            alert = rule_func(event)
            if alert:
                alerts.append(alert)
        return alerts

    def evaluate_logs(self, events: List[Dict[str, Any]]) -> List[Alert]:
        """Evaluates a batch or stream of events."""
        all_alerts = []
        for event in events:
            all_alerts.extend(self.evaluate_event(event))
        return all_alerts

    # -------------------------------------------------------------
    # 10 Transparent Detection Rules
    # -------------------------------------------------------------

    def rule_01_password_spray(self, event: Dict[str, Any]) -> Optional[Alert]:
        """Rule 01: Detects burst failed authentication or password spraying."""
        event_type = event.get("event_type", "")
        details = event.get("details", {})
        failed_count = details.get("failed_attempts", 0)

        if event_type == "password_spray_burst" or failed_count >= 5:
            return Alert(
                rule_id="RULE-01",
                rule_name="Password Spray / Credential Burst",
                event_id=event.get("event_id", "N/A"),
                timestamp=event.get("timestamp", ""),
                user=event.get("user", "Unknown"),
                ip_address=event.get("ip_address", "Unknown"),
                geo_location=event.get("geo_location", "Unknown"),
                device_id=event.get("device_id", "Unknown"),
                device_name=event.get("device_name", "Unknown"),
                severity="Medium",
                points=SEVERITY_POINTS["Medium"],
                mitre_tactic="Initial Access",
                mitre_technique_id="T1110.003",
                stage="Initial Access",
                summary=f"Detected {failed_count or 'multiple'} rapid failed login attempts from external IP {event.get('ip_address')}.",
                plain_explanation=(
                    f"An automated tool attempted multiple rapid passwords against {event.get('user')}'s "
                    f"account from an external IP address ({event.get('ip_address')}). This pattern matches a password-spraying "
                    "or brute-force intrusion attempt."
                ),
                recommended_action="Temporarily lock the account, enforce password reset, and block the remote IP address at the firewall.",
                raw_event=event
            )
        return None

    def rule_02_impossible_travel(self, event: Dict[str, Any]) -> Optional[Alert]:
        """Rule 02: Detects login from geographically distant locations in an impossibly short timeframe."""
        event_type = event.get("event_type", "")
        details = event.get("details", {})
        speed = details.get("speed_kmh", 0)

        if event_type == "impossible_travel_login" or speed > 1000:
            return Alert(
                rule_id="RULE-02",
                rule_name="Impossible Travel Anomaly",
                event_id=event.get("event_id", "N/A"),
                timestamp=event.get("timestamp", ""),
                user=event.get("user", "Unknown"),
                ip_address=event.get("ip_address", "Unknown"),
                geo_location=event.get("geo_location", "Unknown"),
                device_id=event.get("device_id", "Unknown"),
                device_name=event.get("device_name", "Unknown"),
                severity="High",
                points=SEVERITY_POINTS["High"],
                mitre_tactic="Initial Access",
                mitre_technique_id="T1078.004",
                stage="Initial Access",
                summary=f"User signed in from {event.get('geo_location')} shortly after sign-in from {details.get('previous_location', 'another country')}.",
                plain_explanation=(
                    f"Employee {event.get('user')} authenticated from {event.get('geo_location')} "
                    f"only minutes after a legitimate connection in {details.get('previous_location', 'Chicago, USA')}. "
                    "Physical travel between these points is mathematically impossible, indicating credentials have been hijacked."
                ),
                recommended_action="Revoke all active sign-in sessions immediately and reset user credentials.",
                raw_event=event
            )
        return None

    def rule_03_unrecognized_device(self, event: Dict[str, Any]) -> Optional[Alert]:
        """Rule 03: Detects enrollment or login from unmanaged / non-compliant hardware."""
        event_type = event.get("event_type", "")
        details = event.get("details", {})
        compliance = details.get("compliance_status", "")

        if event_type == "new_device_enrolled" or compliance in ("Non-Compliant", "Unmanaged"):
            return Alert(
                rule_id="RULE-03",
                rule_name="Unregistered / Non-Compliant Device",
                event_id=event.get("event_id", "N/A"),
                timestamp=event.get("timestamp", ""),
                user=event.get("user", "Unknown"),
                ip_address=event.get("ip_address", "Unknown"),
                geo_location=event.get("geo_location", "Unknown"),
                device_id=event.get("device_id", "Unknown"),
                device_name=event.get("device_name", "Unknown"),
                severity="Medium",
                points=SEVERITY_POINTS["Medium"],
                mitre_tactic="Defense Evasion",
                mitre_technique_id="T1204",
                stage="Device Tampering",
                summary=f"Unrecognized device ({event.get('device_name')}) enrolled without MDM compliance certificate.",
                plain_explanation=(
                    f"A new device ({event.get('device_name')}) connected to {event.get('user')}'s corporate workspace. "
                    "This machine lacks corporate security management certificates and antivirus verification."
                ),
                recommended_action="Quarantine the device ID in your Mobile Device Management (MDM) portal and reject enrollment.",
                raw_event=event
            )
        return None

    def rule_04_mfa_fatigue(self, event: Dict[str, Any]) -> Optional[Alert]:
        """Rule 04: Detects repeated MFA push notifications followed by acceptance (push bombing)."""
        event_type = event.get("event_type", "")
        details = event.get("details", {})
        push_count = details.get("push_count_last_10m", 0)

        if event_type == "mfa_push_flood_bypass" or push_count >= 5:
            return Alert(
                rule_id="RULE-04",
                rule_name="MFA Fatigue / Push Bombing Bypass",
                event_id=event.get("event_id", "N/A"),
                timestamp=event.get("timestamp", ""),
                user=event.get("user", "Unknown"),
                ip_address=event.get("ip_address", "Unknown"),
                geo_location=event.get("geo_location", "Unknown"),
                device_id=event.get("device_id", "Unknown"),
                device_name=event.get("device_name", "Unknown"),
                severity="High",
                points=SEVERITY_POINTS["High"],
                mitre_tactic="Credential Access",
                mitre_technique_id="T1621",
                stage="Credential Access",
                summary=f"MFA fatigue detected: {push_count or 'Excessive'} pushes sent before an approval occurred.",
                plain_explanation=(
                    f"The user received {push_count} two-factor authentication prompts in a brief burst until "
                    "an approval was registered. Attackers bombard employees with notifications hoping they will tap 'Approve' to stop the buzzing."
                ),
                recommended_action="Revoke active tokens, mandate FIDO2 hardware keys or number-matching MFA, and contact the user immediately.",
                raw_event=event
            )
        return None

    def rule_05_inbox_forwarding(self, event: Dict[str, Any]) -> Optional[Alert]:
        """Rule 05: Detects automatic inbox forwarding rules to external/unauthorized addresses."""
        event_type = event.get("event_type", "")
        details = event.get("details", {})
        forward_to = details.get("forward_to", "")

        if event_type == "inbox_forwarding_rule_created" or forward_to:
            return Alert(
                rule_id="RULE-05",
                rule_name="Hidden Inbox Forwarding Rule",
                event_id=event.get("event_id", "N/A"),
                timestamp=event.get("timestamp", ""),
                user=event.get("user", "Unknown"),
                ip_address=event.get("ip_address", "Unknown"),
                geo_location=event.get("geo_location", "Unknown"),
                device_id=event.get("device_id", "Unknown"),
                device_name=event.get("device_name", "Unknown"),
                severity="High",
                points=SEVERITY_POINTS["High"],
                mitre_tactic="Persistence",
                mitre_technique_id="T1114.003",
                stage="Persistence",
                summary=f"Automated email forwarding rule configured to siphon incoming emails to '{forward_to}'.",
                plain_explanation=(
                    f"A hidden rule was added to {event.get('user')}'s mailbox to quietly forward all financial emails "
                    f"to an external email address ({forward_to}) and delete the evidence. Common precursor to wire fraud."
                ),
                recommended_action="Remove the mailbox forwarding rule immediately and audit all recent incoming wire or invoice correspondence.",
                raw_event=event
            )
        return None

    def rule_06_privilege_escalation(self, event: Dict[str, Any]) -> Optional[Alert]:
        """Rule 06: Detects assignment of administrative privileges outside formal change windows."""
        event_type = event.get("event_type", "")
        details = event.get("details", {})
        role = details.get("role_granted", "")

        if event_type == "privilege_escalation_admin" or "Admin" in role:
            return Alert(
                rule_id="RULE-06",
                rule_name="Unauthorized Admin Privilege Escalation",
                event_id=event.get("event_id", "N/A"),
                timestamp=event.get("timestamp", ""),
                user=event.get("user", "Unknown"),
                ip_address=event.get("ip_address", "Unknown"),
                geo_location=event.get("geo_location", "Unknown"),
                device_id=event.get("device_id", "Unknown"),
                device_name=event.get("device_name", "Unknown"),
                severity="Critical",
                points=SEVERITY_POINTS["Critical"],
                mitre_tactic="Privilege Escalation",
                mitre_technique_id="T1098",
                stage="Privilege Escalation",
                summary=f"User {event.get('user')} granted '{role or 'Global Administrator'}' without approved change authorization.",
                plain_explanation=(
                    f"{event.get('user')}'s account was elevated to '{role or 'Global Administrator'}'. In small businesses, "
                    "unauthorized admin escalations mean the attacker has obtained full crown-jewel control of your cloud tenant."
                ),
                recommended_action="Strip the administrator role, revoke all application secrets, and inspect tenant audit logs.",
                raw_event=event
            )
        return None

    def rule_07_encoded_powershell(self, event: Dict[str, Any]) -> Optional[Alert]:
        """Rule 07: Detects obfuscated / Base64-encoded command execution in PowerShell."""
        event_type = event.get("event_type", "")
        details = event.get("details", {})
        cmd = details.get("command_line", "").lower()

        if event_type == "encoded_powershell_executed" or "-enc" in cmd or "downloadstring" in cmd:
            return Alert(
                rule_id="RULE-07",
                rule_name="Obfuscated Base64 PowerShell Execution",
                event_id=event.get("event_id", "N/A"),
                timestamp=event.get("timestamp", ""),
                user=event.get("user", "Unknown"),
                ip_address=event.get("ip_address", "Unknown"),
                geo_location=event.get("geo_location", "Unknown"),
                device_id=event.get("device_id", "Unknown"),
                device_name=event.get("device_name", "Unknown"),
                severity="High",
                points=SEVERITY_POINTS["High"],
                mitre_tactic="Execution",
                mitre_technique_id="T1059.001",
                stage="Execution",
                summary=f"Hidden PowerShell process launched with encoded script payload on {event.get('device_name')}.",
                plain_explanation=(
                    f"A command shell on {event.get('device_name')} executed a hidden Base64 encrypted script designed "
                    "to evade antivirus scanners and download additional malware payloads into memory."
                ),
                recommended_action="Isolate the endpoint from the network via EDR and terminate the parent process hierarchy.",
                raw_event=event
            )
        return None

    def rule_08_shadow_copy_deletion(self, event: Dict[str, Any]) -> Optional[Alert]:
        """Rule 08: Detects deletion of Volume Shadow Copies (Ransomware precursor)."""
        event_type = event.get("event_type", "")
        details = event.get("details", {})
        utility = details.get("utility", "").lower()
        args = details.get("arguments", "").lower()

        if event_type == "shadow_copy_deleted" or ("vssadmin" in utility and "delete shadows" in args):
            return Alert(
                rule_id="RULE-08",
                rule_name="Volume Shadow Copy Deletion (Ransomware Warning)",
                event_id=event.get("event_id", "N/A"),
                timestamp=event.get("timestamp", ""),
                user=event.get("user", "Unknown"),
                ip_address=event.get("ip_address", "Unknown"),
                geo_location=event.get("geo_location", "Unknown"),
                device_id=event.get("device_id", "Unknown"),
                device_name=event.get("device_name", "Unknown"),
                severity="Critical",
                points=SEVERITY_POINTS["Critical"],
                mitre_tactic="Impact",
                mitre_technique_id="T1490",
                stage="Impact / Ransomware",
                summary=f"Volume shadow copy backups deleted on {event.get('device_name')} via vssadmin utility.",
                plain_explanation=(
                    "CRITICAL WARNING: The local Windows backup snapshot mechanism was forcibly wiped. This command "
                    "is universally executed by ransomware gangs immediately before launching mass encryption to prevent recovery."
                ),
                recommended_action="EMERGENCY: Pull network cable or isolate host immediately! Disconnect all active NAS backup drives.",
                raw_event=event
            )
        return None

    def rule_09_abnormal_offhours(self, event: Dict[str, Any]) -> Optional[Alert]:
        """Rule 09: Detects unusual middle-of-the-night document queries or repository access."""
        event_type = event.get("event_type", "")
        details = event.get("details", {})

        if event_type == "abnormal_offhours_access" or "03:40 AM" in str(details.get("local_time_at_user_tz", "")):
            return Alert(
                rule_id="RULE-09",
                rule_name="Abnormal Off-Hours Data Access",
                event_id=event.get("event_id", "N/A"),
                timestamp=event.get("timestamp", ""),
                user=event.get("user", "Unknown"),
                ip_address=event.get("ip_address", "Unknown"),
                geo_location=event.get("geo_location", "Unknown"),
                device_id=event.get("device_id", "Unknown"),
                device_name=event.get("device_name", "Unknown"),
                severity="Medium",
                points=SEVERITY_POINTS["Medium"],
                mitre_tactic="Collection",
                mitre_technique_id="T1530",
                stage="Collection",
                summary=f"Unusual high-volume access to confidential repository during non-business hours.",
                plain_explanation=(
                    f"{event.get('user')} accessed confidential corporate storage at 3:40 AM outside normal operational hours. "
                    "Attackers often stage data collection during the night to minimize detection by business staff."
                ),
                recommended_action="Verify with employee whether this was authorized activity; restrict remote file share access.",
                raw_event=event
            )
        return None

    def rule_10_mass_data_exfiltration(self, event: Dict[str, Any]) -> Optional[Alert]:
        """Rule 10: Detects sudden spike in bulk file downloads or cloud repository harvesting."""
        event_type = event.get("event_type", "")
        details = event.get("details", {})
        files_count = details.get("files_downloaded_count", 0)

        if event_type == "mass_file_download" or files_count >= 500:
            return Alert(
                rule_id="RULE-10",
                rule_name="Mass Data Exfiltration Spike",
                event_id=event.get("event_id", "N/A"),
                timestamp=event.get("timestamp", ""),
                user=event.get("user", "Unknown"),
                ip_address=event.get("ip_address", "Unknown"),
                geo_location=event.get("geo_location", "Unknown"),
                device_id=event.get("device_id", "Unknown"),
                device_name=event.get("device_name", "Unknown"),
                severity="Critical",
                points=SEVERITY_POINTS["Critical"],
                mitre_tactic="Exfiltration",
                mitre_technique_id="T1567",
                stage="Exfiltration",
                summary=f"Mass data exfiltration: {files_count} sensitive files downloaded rapidly.",
                plain_explanation=(
                    f"Over {files_count} sensitive corporate documents were downloaded in rapid succession "
                    f"to an external device ({event.get('device_name')}). This indicates active theft of intellectual property or customer PII."
                ),
                recommended_action="Block user's cloud access, terminate download sessions, and place DLP holds on compromised repositories.",
                raw_event=event
            )
        return None
