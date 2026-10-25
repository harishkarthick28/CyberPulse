"""
CyberPulse - Correlation & Dynamic Scoring Engine
Correlates disparate alerts into unified multi-stage incident clusters,
calculates dynamic 0-100 severity scores, and computes early-warning lead times.
"""

from typing import List, Dict, Any, Optional
from datetime import datetime
from collections import defaultdict
from rules.detector import Alert, SEVERITY_POINTS

def parse_iso(ts_str: str) -> Optional[datetime]:
    """Helper to parse ISO timestamp strings."""
    if not ts_str:
        return None
    try:
        clean_ts = ts_str.replace("Z", "+00:00")
        return datetime.fromisoformat(clean_ts)
    except Exception:
        return None


class IncidentCluster:
    """Represents a unified security incident constructed from correlated alerts."""

    def __init__(self, incident_id: str, primary_user: str):
        self.incident_id = incident_id
        self.primary_user = primary_user
        self.alerts: List[Alert] = []
        self.correlated_ips: set[str] = set()
        self.correlated_devices: set[str] = set()
        self.correlated_users: set[str] = {primary_user}
        self.status: str = "Active Investigation"

    def add_alert(self, alert: Alert):
        self.alerts.append(alert)
        if alert.ip_address and alert.ip_address != "Unknown":
            self.correlated_ips.add(alert.ip_address)
        if alert.device_id and alert.device_id != "Unknown":
            self.correlated_devices.add(alert.device_id)
        if alert.user and alert.user != "Unknown":
            self.correlated_users.add(alert.user)

    @property
    def stages(self) -> List[str]:
        """Returns ordered unique attack stages observed in this incident."""
        seen = []
        for a in self.alerts:
            if a.stage not in seen:
                seen.append(a.stage)
        return seen

    @property
    def score(self) -> int:
        """
        Calculates dynamic severity score (0-100).
        Formula:
          Base Severity = Highest single alert severity points (Low: 5, Medium: 15, High: 25, Critical: 40)
          Stage Multiplier = +10 points for each additional distinct attack stage.
          Alert Density Bonus = +3 points for each additional alert beyond the first.
          Capped at 100.
        """
        if not self.alerts:
            return 0

        # Maximum individual alert base score
        max_base = max(a.points for a in self.alerts)

        # Distinct attack stages
        distinct_stages_count = len(self.stages)
        extra_stages = max(0, distinct_stages_count - 1)
        stage_bonus = extra_stages * 10

        # Additional alert volume weight
        extra_alerts = max(0, len(self.alerts) - 1)
        volume_bonus = extra_alerts * 3

        total = max_base + stage_bonus + volume_bonus
        return min(100, total)

    @property
    def severity_band(self) -> str:
        """
        Returns color-coded threshold band:
          - Green (0-39): Low/Normal
          - Yellow (40-74): Suspicious / Elevated
          - Red (75-100): Critical Breach / Emergency
        """
        s = self.score
        if s >= 75:
            return "Red"
        elif s >= 40:
            return "Yellow"
        return "Green"

    @property
    def severity_label(self) -> str:
        band = self.severity_band
        if band == "Red":
            return "CRITICAL INTRUSION"
        elif band == "Yellow":
            return "ELEVATED SUSPICION"
        return "NORMAL / LOW"

    @property
    def start_time(self) -> str:
        return self.alerts[0].timestamp if self.alerts else ""

    @property
    def latest_time(self) -> str:
        return self.alerts[-1].timestamp if self.alerts else ""

    @property
    def lead_time_display(self) -> str:
        """
        Computes lead time from first early alert to the highest severity impact event.
        Returns a friendly string like '3 hours 15 minutes'.
        """
        if len(self.alerts) < 2:
            return "N/A (Initial stage)"

        t0 = parse_iso(self.alerts[0].timestamp)
        t_last = parse_iso(self.alerts[-1].timestamp)

        if not t0 or not t_last or t_last <= t0:
            return "Real-time"

        diff = t_last - t0
        hours = diff.seconds // 3600
        minutes = (diff.seconds % 3600) // 60
        if hours > 0:
            return f"{hours} hr {minutes} min early warning"
        return f"{minutes} min early warning"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "primary_user": self.primary_user,
            "status": self.status,
            "score": self.score,
            "severity_band": self.severity_band,
            "severity_label": self.severity_label,
            "lead_time": self.lead_time_display,
            "stages": self.stages,
            "correlated_users": list(self.correlated_users),
            "correlated_ips": list(self.correlated_ips),
            "correlated_devices": list(self.correlated_devices),
            "alert_count": len(self.alerts),
            "alerts": [a.to_dict() for a in self.alerts]
        }


class CorrelationEngine:
    """
    Correlates individual alerts across User, IP, Device, and Time Window parameters.
    """

    def __init__(self, time_window_minutes: int = 360):
        self.time_window_minutes = time_window_minutes

    def correlate(self, alerts: List[Alert]) -> List[IncidentCluster]:
        """
        Groups alerts into incident clusters by matching parameters:
        user identity, originating IP, or target device.
        """
        if not alerts:
            return []

        clusters: List[IncidentCluster] = []

        for alert in alerts:
            matched_cluster: Optional[IncidentCluster] = None

            # Look for an existing cluster with overlapping entity anchors
            for cluster in clusters:
                user_match = alert.user != "Unknown" and alert.user in cluster.correlated_users
                ip_match = alert.ip_address != "Unknown" and alert.ip_address in cluster.correlated_ips
                device_match = alert.device_id != "Unknown" and alert.device_id in cluster.correlated_devices

                if user_match or ip_match or device_match:
                    matched_cluster = cluster
                    break

            if matched_cluster:
                matched_cluster.add_alert(alert)
            else:
                inc_id = f"INC-2026-{len(clusters) + 1:03d}"
                new_cluster = IncidentCluster(incident_id=inc_id, primary_user=alert.user)
                new_cluster.add_alert(alert)
                clusters.append(new_cluster)

        # Sort alerts in each cluster chronologically
        for cluster in clusters:
            cluster.alerts.sort(key=lambda a: a.timestamp)

        # Sort clusters by highest score descending
        clusters.sort(key=lambda c: c.score, reverse=True)
        return clusters
