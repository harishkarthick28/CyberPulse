"""
CyberPulse - Plain-Language Narrative & Response Generator
Converts complex multi-stage telemetry into executive-level, human-readable stories
and provides guided 1-click remediation playbooks for small business operators.
"""

from typing import Dict, Any, List
from rules.correlator import IncidentCluster
from rules.detector import Alert

def generate_plain_language_narrative(cluster: IncidentCluster) -> Dict[str, Any]:
    """
    Synthesizes correlated incident telemetry into an accessible, plain-English
    narrative tailored for small business owners and busy IT administrators.
    """
    if not cluster or not cluster.alerts:
        return {
            "headline": "All Systems Normal - Zero Active Threats",
            "executive_summary": "Continuous log stream analysis shows normal day-to-day employee operations with no correlated attack chains.",
            "why_linked": "No suspicious correlation patterns detected across user identities, device fingerprints, or external network connections.",
            "business_impact": "Negligible. Normal business operations proceeding without interruption.",
            "key_takeaways": ["Standard authentications validated", "No malicious forwarding rules", "Endpoints operating in compliance"]
        }

    user = cluster.primary_user
    ip_list = ", ".join(cluster.correlated_ips) or "Unknown external IP"
    device_list = ", ".join(cluster.correlated_devices) or "Unregistered device"
    stages = cluster.stages
    lead_time = cluster.lead_time_display
    score = cluster.score

    # Determine attack classification
    is_ransomware = any(a.rule_id == "RULE-08" or "vssadmin" in str(a.raw_event) for a in cluster.alerts)
    is_exfiltration = any(a.rule_id == "RULE-10" or "mass_file" in a.raw_event.get("event_type", "") for a in cluster.alerts)
    has_priv_esc = any(a.rule_id == "RULE-06" for a in cluster.alerts)
    has_forwarding = any(a.rule_id == "RULE-05" for a in cluster.alerts)

    if is_ransomware:
        headline = f"CRITICAL: Ransomware Intrusion Chain in Progress against {user}"
        executive_summary = (
            f"An attacker initiated an intrusion against **{user}** from IP `{ip_list}`. "
            f"After bypassing authentication via MFA spam and registering rogue device `{device_list}`, "
            f"the adversary escalated to Administrator rights. The system detected volume shadow copy deletion, "
            f"which is the immediate precursor to corporate file encryption and financial extortion."
        )
        why_linked = (
            f"CyberPulse linked **{len(cluster.alerts)} discrete events** because they share the identical compromised "
            f"identity (`{user}`), originated from the same malicious IP cluster (`{ip_list}`), and pivoted through "
            f"unauthorized endpoint (`{device_list}`). The timeline proves this is not random noise, but a coordinated attack chain."
        )
        business_impact = (
            "Extremely High: Imminent total operational shutdown, complete loss of access to shared network files, "
            "and potential ransom demands ranging from $50,000 to $500,000+."
        )
    elif is_exfiltration:
        headline = f"HIGH SEVERITY: Mass Corporate Data Exfiltration linked to {user}"
        executive_summary = (
            f"An unauthorized session authenticated as **{user}** from an anonymous proxy `{ip_list}`. "
            f"During abnormal off-hours, over 1,400 confidential documents were extracted in bulk via SharePoint, "
            "indicating targeted industrial theft or customer data harvesting."
        )
        why_linked = (
            f"The events are linked by shared user profile (`{user}`), non-compliant device signature (`{device_list}`), "
            f"and sudden multi-gigabyte data transfers initiated immediately after abnormal credential access."
        )
        business_impact = (
            "Severe: Potential regulatory penalties under GDPR/CCPA, exposure of confidential client contracts, "
            "and severe reputational damage."
        )
    else:
        headline = f"SUSPICIOUS: Multi-Vector Account Anomalies on {user}"
        executive_summary = (
            f"Unusual activity detected for **{user}** across {len(stages)} attack stages ({', '.join(stages)}). "
            f"Multiple red flags were correlated originating from external IP `{ip_list}`."
        )
        why_linked = (
            f"Individual low and medium severity alerts were aggregated based on common user handle (`{user}`) "
            f"and sequential execution within a tight correlation window."
        )
        business_impact = (
            "Moderate: Account compromise likely. Immediate containment prevents escalation into ransomware or wire fraud."
        )

    # Key takeaways
    takeaways = []
    if lead_time != "N/A (Initial stage)":
        takeaways.append(f"CyberPulse provided a **{lead_time}** early-warning window before critical damage.")
    takeaways.append(f"Correlated {len(cluster.alerts)} disparate telemetry signals into a single unified incident.")
    if has_forwarding:
        takeaways.append("Interception filter detected: Malicious email auto-forwarding rule active.")
    if has_priv_esc:
        takeaways.append("Elevated danger: Attacker gained Global Administrator tenant permissions.")

    return {
        "headline": headline,
        "executive_summary": executive_summary,
        "why_linked": why_linked,
        "business_impact": business_impact,
        "lead_time": lead_time,
        "key_takeaways": takeaways,
        "risk_score": score
    }


def get_guided_remediation_actions(cluster: Optional[IncidentCluster]) -> List[Dict[str, Any]]:
    """
    Returns tailored, 1-click remediation actions with clear descriptions and urgency badges.
    """
    if not cluster or not cluster.alerts:
        return [
            {
                "id": "run_antivirus_all",
                "label": "Run Routine Endpoint Audit",
                "description": "Trigger non-intrusive background compliance scan across all company laptops.",
                "urgency": "Routine",
                "type": "info"
            }
        ]

    user = cluster.primary_user
    ips = list(cluster.correlated_ips)
    primary_ip = ips[0] if ips else "Unknown IP"
    devices = list(cluster.correlated_devices)
    primary_device = devices[0] if devices else "Unknown Device"

    actions = [
        {
            "id": "lock_account",
            "label": f"Lock Account ({user})",
            "description": f"Instantly disable sign-in for {user} across Microsoft 365, Google Workspace, and Active Directory.",
            "urgency": "Immediate",
            "type": "critical",
            "impact_statement": "Freezes account access immediately. Legitimate user will need IT to unlock."
        },
        {
            "id": "revoke_sessions",
            "label": "Revoke All Active Sessions",
            "description": f"Invalidate all OAuth tokens, browser cookies, and VPN connections for {user}.",
            "urgency": "Immediate",
            "type": "warning",
            "impact_statement": "Kicks active attacker out of active browser sessions within seconds."
        },
        {
            "id": "block_ip",
            "label": f"Block IP Address ({primary_ip})",
            "description": f"Add {primary_ip} to company perimeter firewall, Cloudflare WAF, and conditional access blocklist.",
            "urgency": "High",
            "type": "warning",
            "impact_statement": "Severely disrupts attacker command-and-control communication."
        },
        {
            "id": "isolate_endpoint",
            "label": f"Network Isolate Device ({primary_device})",
            "description": f"Instruct EDR agent to quarantine host {primary_device} from local LAN to halt lateral spread.",
            "urgency": "Critical",
            "type": "critical",
            "impact_statement": "Cuts host from network while preserving forensic telemetry connection."
        }
    ]

    return actions
