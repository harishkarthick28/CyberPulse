"""
CyberPulse - Early-Warning Cybersecurity Dashboard for Small Businesses
Production-ready Streamlit application.
"""

import streamlit as st
import json
import os
import time
import pandas as pd
from typing import Dict, Any, List

from rules.detector import DetectionEngine, Alert
from rules.correlator import CorrelationEngine, IncidentCluster
from utils.explainer import generate_plain_language_narrative, get_guided_remediation_actions
from utils.visualizer import create_risk_gauge, create_timeline_chart, create_stage_progression_bar

# -----------------------------------------------------------------------------
# 1. Page Configuration & Custom CSS Styling
# -----------------------------------------------------------------------------
st.set_page_config(
    page_title="CyberPulse | Early-Warning SOC Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

def inject_soc_css():
    st.markdown("""
    <style>
        /* Base typography & theme */
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;700&display=swap');

        html, body, [class*="css"] {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
        }

        /* App Background styling */
        .stApp {
            background-color: #090d16;
            background-image: 
                radial-gradient(at 0% 0%, rgba(14, 165, 233, 0.08) 0px, transparent 50%),
                radial-gradient(at 100% 100%, rgba(239, 68, 68, 0.05) 0px, transparent 50%),
                radial-gradient(at 50% 50%, rgba(15, 23, 42, 0.6) 0px, transparent 100%);
            color: #f1f5f9;
        }

        /* Sidebar Styling */
        section[data-testid="stSidebar"] {
            background-color: #0b111e;
            border-right: 1px solid rgba(51, 65, 85, 0.6);
        }

        /* Metrics & Cards */
        .soc-card {
            background: rgba(15, 23, 42, 0.85);
            border: 1px solid rgba(56, 189, 248, 0.18);
            border-radius: 12px;
            padding: 18px 20px;
            margin-bottom: 16px;
            box-shadow: 0 4px 20px -2px rgba(0, 0, 0, 0.4);
            backdrop-filter: blur(10px);
            transition: all 0.2s ease-in-out;
        }

        .soc-card:hover {
            border-color: rgba(56, 189, 248, 0.35);
            box-shadow: 0 8px 30px -4px rgba(14, 165, 233, 0.15);
        }

        /* Metric Tile */
        .metric-tile {
            background: linear-gradient(145deg, rgba(15, 23, 42, 0.9), rgba(30, 41, 59, 0.7));
            border: 1px solid rgba(71, 85, 105, 0.4);
            border-radius: 10px;
            padding: 14px 16px;
            position: relative;
            overflow: hidden;
        }
        .metric-title {
            font-size: 0.78rem;
            text-transform: uppercase;
            letter-spacing: 0.06em;
            color: #94a3b8;
            font-weight: 600;
            margin-bottom: 4px;
        }
        .metric-value {
            font-size: 1.6rem;
            font-weight: 700;
            font-family: 'JetBrains Mono', monospace;
            color: #f8fafc;
        }
        .metric-sub {
            font-size: 0.75rem;
            color: #64748b;
            margin-top: 4px;
        }

        /* Pulsing Status Dot */
        .pulse-dot {
            display: inline-block;
            width: 10px;
            height: 10px;
            border-radius: 50%;
            margin-right: 8px;
            vertical-align: middle;
        }
        .pulse-red {
            background: #ef4444;
            box-shadow: 0 0 12px #ef4444;
            animation: pulse-red-anim 1.5s infinite;
        }
        .pulse-yellow {
            background: #f59e0b;
            box-shadow: 0 0 10px #f59e0b;
        }
        .pulse-green {
            background: #10b981;
            box-shadow: 0 0 10px #10b981;
            animation: pulse-green-anim 2s infinite;
        }

        @keyframes pulse-red-anim {
            0% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(239, 68, 68, 0.7); }
            70% { transform: scale(1.1); box-shadow: 0 0 0 8px rgba(239, 68, 68, 0); }
            100% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(239, 68, 68, 0); }
        }
        @keyframes pulse-green-anim {
            0% { transform: scale(0.98); box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.6); }
            70% { transform: scale(1.05); box-shadow: 0 0 0 6px rgba(16, 185, 129, 0); }
            100% { transform: scale(0.98); box-shadow: 0 0 0 0 rgba(16, 185, 129, 0); }
        }

        /* Badges */
        .badge {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 6px;
            font-size: 0.72rem;
            font-weight: 700;
            font-family: 'JetBrains Mono', monospace;
            text-transform: uppercase;
        }
        .badge-red {
            background: rgba(239, 68, 68, 0.2);
            color: #f87171;
            border: 1px solid rgba(239, 68, 68, 0.4);
        }
        .badge-yellow {
            background: rgba(245, 158, 11, 0.2);
            color: #fbbf24;
            border: 1px solid rgba(245, 158, 11, 0.4);
        }
        .badge-green {
            background: rgba(16, 185, 129, 0.2);
            color: #34d399;
            border: 1px solid rgba(16, 185, 129, 0.4);
        }
        .badge-blue {
            background: rgba(56, 189, 248, 0.2);
            color: #38bdf8;
            border: 1px solid rgba(56, 189, 248, 0.4);
        }

        /* Narrative Callout Box */
        .narrative-box {
            background: linear-gradient(135deg, rgba(15, 23, 42, 0.95), rgba(24, 34, 53, 0.95));
            border-left: 4px solid #38bdf8;
            border-radius: 8px;
            padding: 18px 22px;
            margin: 12px 0 20px 0;
            box-shadow: 0 4px 16px rgba(0,0,0,0.3);
        }
        .narrative-red {
            border-left-color: #ef4444;
            background: linear-gradient(135deg, rgba(35, 14, 20, 0.8), rgba(20, 10, 18, 0.9));
        }
        .narrative-yellow {
            border-left-color: #f59e0b;
            background: linear-gradient(135deg, rgba(35, 28, 14, 0.8), rgba(22, 18, 10, 0.9));
        }

        /* Code & Monospace Pill */
        .mono-pill {
            font-family: 'JetBrains Mono', monospace;
            background: rgba(30, 41, 59, 0.8);
            border: 1px solid #334155;
            padding: 2px 6px;
            border-radius: 4px;
            color: #e2e8f0;
            font-size: 0.82rem;
        }

        /* Timeline Event Entry */
        .timeline-event-card {
            border-left: 3px solid #38bdf8;
            background: rgba(15, 23, 42, 0.7);
            border-radius: 0 8px 8px 0;
            padding: 12px 16px;
            margin-bottom: 12px;
            border-top: 1px solid rgba(51, 65, 85, 0.4);
            border-right: 1px solid rgba(51, 65, 85, 0.4);
            border-bottom: 1px solid rgba(51, 65, 85, 0.4);
        }
        .timeline-critical { border-left-color: #ef4444; }
        .timeline-high { border-left-color: #f97316; }
        .timeline-medium { border-left-color: #f59e0b; }
        .timeline-low { border-left-color: #10b981; }

        /* Streamlit widget tweaks */
        div.stButton > button {
            border-radius: 6px;
            font-weight: 600;
            transition: all 0.2s ease;
        }
        div.stButton > button:hover {
            transform: translateY(-1px);
        }
    </style>
    """, unsafe_allow_html=True)


# -----------------------------------------------------------------------------
# 2. Session State Initialization
# -----------------------------------------------------------------------------
def load_synthetic_data() -> Dict[str, Any]:
    base_dir = os.path.dirname(os.path.abspath(__file__))
    json_path = os.path.join(base_dir, "data", "synthetic_logs.json")
    with open(json_path, "r", encoding="utf-8") as f:
        return json.load(f)

if "synthetic_db" not in st.session_state:
    st.session_state.synthetic_db = load_synthetic_data()

if "selected_scenario_key" not in st.session_state:
    st.session_state.selected_scenario_key = "ransomware_chain"

if "current_event_idx" not in st.session_state:
    st.session_state.current_event_idx = 0

if "remediation_audit_log" not in st.session_state:
    st.session_state.remediation_audit_log = []

if "is_contained" not in st.session_state:
    st.session_state.is_contained = False

inject_soc_css()

# -----------------------------------------------------------------------------
# 3. Sidebar: Scenario Controls & Simulation Playback
# -----------------------------------------------------------------------------
with st.sidebar:
    st.markdown("""
        <div style="display:flex; align-items:center; margin-bottom:12px;">
            <span style="font-size:28px; margin-right:10px;">⚡</span>
            <div>
                <h2 style="margin:0; font-size:1.4rem; font-weight:800; color:#38bdf8; letter-spacing:-0.5px;">CYBERPULSE</h2>
                <div style="font-size:0.75rem; color:#94a3b8; font-weight:500;">SMB Early-Warning SOC</div>
            </div>
        </div>
    """, unsafe_allow_html=True)

    st.markdown("---")
    st.markdown("### 🎮 Attack Simulator Controls")

    scenarios = st.session_state.synthetic_db["scenarios"]
    scenario_options = {
        "ransomware_chain": "🚨 Ransomware Multi-Stage Kill Chain",
        "data_exfiltration_chain": "📦 Data Exfiltration via SharePoint",
        "normal_day": "🛡️ Normal Business Day (Quiet Logs)"
    }

    selected_key = st.selectbox(
        "Select Attack Scenario",
        options=list(scenario_options.keys()),
        format_func=lambda k: scenario_options[k],
        index=0 if st.session_state.selected_scenario_key == "ransomware_chain" else 1
    )

    # Handle scenario switch
    if selected_key != st.session_state.selected_scenario_key:
        st.session_state.selected_scenario_key = selected_key
        st.session_state.current_event_idx = 0
        st.session_state.remediation_audit_log = []
        st.session_state.is_contained = False
        st.rerun()

    active_scenario = scenarios[st.session_state.selected_scenario_key]
    all_events = active_scenario["events"]
    total_events = len(all_events)

    # Simulation Controls
    st.markdown(f"**Scenario Progress:** Event `{st.session_state.current_event_idx}` of `{total_events}`")
    progress_val = (st.session_state.current_event_idx) / total_events if total_events > 0 else 0.0
    st.progress(progress_val)

    col_btn1, col_btn2 = st.columns(2)
    with col_btn1:
        if st.button("▶ Step Event", use_container_width=True, help="Advance 1 event (perfect for recording demo videos)"):
            if st.session_state.current_event_idx < total_events:
                st.session_state.current_event_idx += 1
                st.rerun()

    with col_btn2:
        if st.button("🚀 Fast-Forward", use_container_width=True, help="Immediately play entire scenario to end"):
            st.session_state.current_event_idx = total_events
            st.rerun()

    col_rst1, col_rst2 = st.columns(2)
    with col_rst1:
        if st.button("🔄 Reset Sim", use_container_width=True):
            st.session_state.current_event_idx = 0
            st.session_state.remediation_audit_log = []
            st.session_state.is_contained = False
            st.rerun()

    with col_rst2:
        auto_step = st.button("⚡ Full Auto", use_container_width=True)

    if auto_step:
        # Step through in animated loop
        st.session_state.current_event_idx = 0
        status_holder = st.empty()
        for i in range(1, total_events + 1):
            st.session_state.current_event_idx = i
            status_holder.info(f"Simulating Event #{i}/{total_events}...")
            time.sleep(0.4)
            st.rerun()

    st.markdown("---")
    st.markdown("### 📋 Scenario Metadata")
    st.markdown(f"""
    - **Target User:** `{active_scenario.get('target_user', 'N/A')}`
    - **Primary Host:** `{active_scenario.get('target_system', 'N/A')}`
    - **Expected Outcome:** `{active_scenario.get('expected_outcome', 'N/A')}`
    - **Lead Time Window:** `{active_scenario.get('lead_time', 'N/A')}`
    """)

    st.markdown("---")
    st.markdown("""
    <div style="font-size:0.75rem; color:#64748b; text-align:center;">
        CyberPulse v1.0.0 • Production Ready<br>
        Built for GDG Hackathon 2026
    </div>
    """, unsafe_allow_html=True)


# -----------------------------------------------------------------------------
# 4. Processing & Correlation Engine Execution
# -----------------------------------------------------------------------------
# Extract only the events revealed up to current step
revealed_events = all_events[:st.session_state.current_event_idx]

# Instantiate engines
detector = DetectionEngine()
correlator = CorrelationEngine()

# Run detection
active_alerts: List[Alert] = detector.evaluate_logs(revealed_events)

# Run correlation
clusters: List[IncidentCluster] = correlator.correlate(active_alerts)
primary_cluster: IncidentCluster | None = clusters[0] if clusters else None

# Calculate score and status
if primary_cluster:
    current_score = primary_cluster.score
    if st.session_state.is_contained:
        current_score = max(10, current_score - 50)
    band = "Green" if current_score < 40 else ("Yellow" if current_score < 75 else "Red")
    lead_time_text = primary_cluster.lead_time_display
else:
    current_score = 5 if revealed_events else 0
    band = "Green"
    lead_time_text = "N/A (All Clear)"

# -----------------------------------------------------------------------------
# 5. Header & Real-time Metrics Bar
# -----------------------------------------------------------------------------
col_head1, col_head2 = st.columns([3, 1])

with col_head1:
    st.markdown("""
        <div style="display:flex; align-items:center; gap:12px; margin-top:5px;">
            <h1 style="margin:0; font-size:2.1rem; font-weight:800; color:#f8fafc; letter-spacing:-0.5px;">
                CyberPulse Security Operations Center
            </h1>
        </div>
        <div style="font-size:0.95rem; color:#94a3b8; margin-top:2px; margin-bottom:18px;">
            Deterministic Multi-Vector Threat Correlation & Plain-Language Incident Response
        </div>
    """, unsafe_allow_html=True)

with col_head2:
    if st.session_state.is_contained:
        status_badge = '<span class="pulse-dot pulse-green"></span><span style="color:#10b981; font-weight:700;">THREAT CONTAINED</span>'
    elif band == "Red":
        status_badge = '<span class="pulse-dot pulse-red"></span><span style="color:#ef4444; font-weight:700;">CRITICAL BREACH IN PROGRESS</span>'
    elif band == "Yellow":
        status_badge = '<span class="pulse-dot pulse-yellow"></span><span style="color:#f59e0b; font-weight:700;">ELEVATED SUSPICION</span>'
    else:
        status_badge = '<span class="pulse-dot pulse-green"></span><span style="color:#10b981; font-weight:700;">PERIMETER SECURE</span>'

    st.markdown(f"""
        <div style="background:rgba(15,23,42,0.8); border:1px solid #334155; border-radius:10px; padding:12px 16px; text-align:right;">
            <div style="font-size:0.75rem; color:#94a3b8; text-transform:uppercase; letter-spacing:0.05em;">System Status</div>
            <div style="font-size:0.92rem; margin-top:4px;">{status_badge}</div>
        </div>
    """, unsafe_allow_html=True)

# 4 Key Metrics Cards
mcol1, mcol2, mcol3, mcol4 = st.columns(4)

with mcol1:
    score_color = "#ef4444" if band == "Red" else ("#f59e0b" if band == "Yellow" else "#10b981")
    st.markdown(f"""
        <div class="metric-tile" style="border-left: 4px solid {score_color};">
            <div class="metric-title">Threat Severity Level</div>
            <div class="metric-value" style="color:{score_color};">{current_score}<span style="font-size:1.1rem; color:#94a3b8;">/100</span></div>
            <div class="metric-sub">Classification: <b style="color:{score_color};">{band.upper()}</b></div>
        </div>
    """, unsafe_allow_html=True)

with mcol2:
    inc_count = len(clusters)
    st.markdown(f"""
        <div class="metric-tile" style="border-left: 4px solid #38bdf8;">
            <div class="metric-title">Active Correlated Incidents</div>
            <div class="metric-value" style="color:#38bdf8;">{inc_count}</div>
            <div class="metric-sub">Triggered Alerts: <b>{len(active_alerts)}</b></div>
        </div>
    """, unsafe_allow_html=True)

with mcol3:
    lead_badge_color = "#10b981" if band == "Red" or "hr" in lead_time_text else "#94a3b8"
    st.markdown(f"""
        <div class="metric-tile" style="border-left: 4px solid #a855f7;">
            <div class="metric-title">Early Warning Lead Time</div>
            <div class="metric-value" style="font-size:1.25rem; line-height:2.1rem; color:{lead_badge_color};">
                {lead_time_text}
            </div>
            <div class="metric-sub">Prior to critical damage/encryption</div>
        </div>
    """, unsafe_allow_html=True)

with mcol4:
    raw_count = len(revealed_events)
    st.markdown(f"""
        <div class="metric-tile" style="border-left: 4px solid #10b981;">
            <div class="metric-title">Telemetry Ingestion Rate</div>
            <div class="metric-value" style="color:#10b981;">{raw_count} <span style="font-size:0.9rem; color:#94a3b8;">logs</span></div>
            <div class="metric-sub">Engine: <b>10 Rules Deterministic</b></div>
        </div>
    """, unsafe_allow_html=True)

st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)


# -----------------------------------------------------------------------------
# 6. Upper Visual Grid: Gauge & Kill Chain Progression
# -----------------------------------------------------------------------------
viz_col1, viz_col2 = st.columns([1, 2])

with viz_col1:
    st.markdown("""
        <div class="soc-card">
            <div style="font-size:0.95rem; font-weight:700; color:#e2e8f0; margin-bottom:6px;">
                🎯 Threat Severity Index
            </div>
    """, unsafe_allow_html=True)
    gauge_fig = create_risk_gauge(current_score)
    st.plotly_chart(gauge_fig, use_container_width=True, config={'displayModeBar': False})
    st.markdown("</div>", unsafe_allow_html=True)

with viz_col2:
    st.markdown("""
        <div class="soc-card">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
                <div style="font-size:0.95rem; font-weight:700; color:#e2e8f0;">
                    📈 Multi-Stage Attack Timeline Progression
                </div>
                <div style="font-size:0.75rem; color:#94a3b8;">Real-time Event Stream Correlation</div>
            </div>
    """, unsafe_allow_html=True)
    timeline_fig = create_timeline_chart(active_alerts)
    st.plotly_chart(timeline_fig, use_container_width=True, config={'displayModeBar': False})
    st.markdown("</div>", unsafe_allow_html=True)


# -----------------------------------------------------------------------------
# 7. Plain-Language Explainer Box (Crucial for SMB Business Owners)
# -----------------------------------------------------------------------------
st.markdown("### 💬 Plain-Language Incident Narrative")

narrative = generate_plain_language_narrative(primary_cluster)
narrative_class = "narrative-red" if band == "Red" else ("narrative-yellow" if band == "Yellow" else "narrative-box")

takeaways_html = "".join([f"<li style='margin-bottom:4px; font-size:0.88rem; color:#cbd5e1;'>{t}</li>" for t in narrative["key_takeaways"]])

st.markdown(f"""
<div class="narrative-box {narrative_class}">
    <div style="display:flex; align-items:center; gap:8px; margin-bottom:8px;">
        <span style="font-size:1.2rem;">🔍</span>
        <h3 style="margin:0; font-size:1.15rem; font-weight:700; color:#f8fafc;">
            {narrative['headline']}
        </h3>
    </div>
    <p style="font-size:0.94rem; line-height:1.55; color:#e2e8f0; margin-bottom:12px;">
        {narrative['executive_summary']}
    </p>
    <div style="background:rgba(0,0,0,0.25); border-radius:6px; padding:10px 14px; margin-bottom:12px; border:1px solid rgba(255,255,255,0.06);">
        <b style="font-size:0.84rem; color:#38bdf8; text-transform:uppercase; letter-spacing:0.04em;">Why CyberPulse Linked These Events:</b>
        <p style="font-size:0.88rem; color:#cbd5e1; margin:4px 0 0 0; line-height:1.45;">
            {narrative['why_linked']}
        </p>
    </div>
    <div style="display:grid; grid-template-columns: 1fr 1fr; gap:16px;">
        <div>
            <b style="font-size:0.82rem; color:#f87171; text-transform:uppercase;">Estimated Business Impact:</b>
            <p style="font-size:0.86rem; color:#cbd5e1; margin:2px 0 0 0;">
                {narrative['business_impact']}
            </p>
        </div>
        <div>
            <b style="font-size:0.82rem; color:#34d399; text-transform:uppercase;">Key Security Observations:</b>
            <ul style="margin:2px 0 0 16px; padding:0;">
                {takeaways_html}
            </ul>
        </div>
    </div>
</div>
""", unsafe_allow_html=True)


# -----------------------------------------------------------------------------
# 8. Guided Response Panel & Real-time Live Event Feed
# -----------------------------------------------------------------------------
lower_col1, lower_col2 = st.columns([1, 1])

# --- Guided Response Panel ---
with lower_col1:
    st.markdown("""
        <div class="soc-card">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
                <div style="font-size:1.05rem; font-weight:700; color:#f8fafc;">
                    ⚡ 1-Click Guided Incident Response
                </div>
                <span class="badge badge-blue">SOAR Automated Playbook</span>
            </div>
            <p style="font-size:0.84rem; color:#94a3b8; margin-top:-6px; margin-bottom:16px;">
                Execute immediate containment actions across your identity provider, cloud tenant, and endpoint fleet with single-click verification.
            </p>
    """, unsafe_allow_html=True)

    remediation_actions = get_guided_remediation_actions(primary_cluster)

    for action in remediation_actions:
        col_act_info, col_act_btn = st.columns([3, 1])
        with col_act_info:
            urgency_badge = "badge-red" if action.get("urgency") == "Immediate" or action.get("urgency") == "Critical" else "badge-yellow"
            st.markdown(f"""
                <div style="margin-bottom:8px;">
                    <span class="badge {urgency_badge}">{action.get('urgency', 'Normal')}</span>
                    <b style="font-size:0.92rem; color:#f1f5f9; margin-left:6px;">{action['label']}</b>
                    <div style="font-size:0.80rem; color:#94a3b8; margin-top:2px;">{action['description']}</div>
                    <div style="font-size:0.75rem; color:#38bdf8; font-style:italic;">{action.get('impact_statement', '')}</div>
                </div>
            """, unsafe_allow_html=True)
        with col_act_btn:
            btn_key = f"act_{action['id']}_{st.session_state.current_event_idx}"
            if st.button("Execute", key=btn_key, use_container_width=True):
                st.session_state.is_contained = True
                audit_entry = {
                    "timestamp": time.strftime("%H:%M:%S UTC"),
                    "action": action["label"],
                    "actor": "Admin / Analyst (You)",
                    "result": "SUCCESS - Dispatched API containment"
                }
                st.session_state.remediation_audit_log.insert(0, audit_entry)
                st.toast(f"✅ Executed: {action['label']}", icon="🛡️")
                st.rerun()

        st.markdown("<hr style='border-color:rgba(51,65,85,0.4); margin:8px 0 12px 0;'>", unsafe_allow_html=True)

    # Remediation Audit Log
    if st.session_state.remediation_audit_log:
        st.markdown("<b style='font-size:0.84rem; color:#38bdf8;'>Recent Containment Actions Log:</b>", unsafe_allow_html=True)
        for log in st.session_state.remediation_audit_log[:3]:
            st.markdown(f"""
                <div style="font-size:0.78rem; font-family:'JetBrains Mono', monospace; background:rgba(0,0,0,0.3); padding:4px 8px; border-radius:4px; margin-top:4px;">
                    <span style="color:#10b981;">[{log['timestamp']}]</span> <span style="color:#f8fafc;">{log['action']}</span>: <span style="color:#94a3b8;">{log['result']}</span>
                </div>
            """, unsafe_allow_html=True)

    st.markdown("</div>", unsafe_allow_html=True)


# --- Live Correlated Event Feed ---
with lower_col2:
    st.markdown("""
        <div class="soc-card">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
                <div style="font-size:1.05rem; font-weight:700; color:#f8fafc;">
                    📜 Live Correlated Event Feed
                </div>
                <div style="font-size:0.78rem; color:#94a3b8;">Showing Ingested Signals</div>
            </div>
    """, unsafe_allow_html=True)

    if not revealed_events:
        st.info("Simulation paused at Step 0. Advance via sidebar controls to ingest events.")
    else:
        # Display events from most recent to oldest
        for i, event in enumerate(reversed(revealed_events)):
            step_num = len(revealed_events) - i
            # Check if this event triggered an alert
            matching_alert = next((a for a in active_alerts if a.event_id == event.get("event_id")), None)

            if matching_alert:
                sev = matching_alert.severity
                border_class = f"timeline-{sev.lower()}"
                badge_class = f"badge-{sev.lower()}"
                alert_tag = f"<span class='badge {badge_class}'>{sev.upper()} - {matching_alert.rule_name}</span>"
            else:
                border_class = "timeline-low"
                alert_tag = "<span class='badge badge-green'>INFORMATIONAL / ROUTINE</span>"

            ts_formatted = event.get("timestamp", "").replace("T", " ").replace("Z", " UTC")

            st.markdown(f"""
                <div class="timeline-event-card {border_class}">
                    <div style="display:flex; justify-content:space-between; align-items:center;">
                        <span style="font-size:0.8rem; font-family:'JetBrains Mono', monospace; color:#38bdf8;">
                            EVENT #{step_num} • {event.get('event_id')}
                        </span>
                        <span style="font-size:0.75rem; color:#94a3b8;">{ts_formatted}</span>
                    </div>
                    <div style="margin:6px 0;">{alert_tag}</div>
                    <div style="font-size:0.86rem; color:#e2e8f0; font-weight:500;">
                        {event.get('raw_message', 'No message description available.')}
                    </div>
                    <div style="margin-top:6px; font-size:0.76rem; color:#94a3b8; display:flex; gap:10px; flex-wrap:wrap;">
                        <span>👤 <span class="mono-pill">{event.get('user', 'N/A')}</span></span>
                        <span>🌐 <span class="mono-pill">{event.get('ip_address', 'N/A')}</span></span>
                        <span>💻 <span class="mono-pill">{event.get('device_name', event.get('device_id', 'N/A'))}</span></span>
                    </div>
                </div>
            """, unsafe_allow_html=True)

    st.markdown("</div>", unsafe_allow_html=True)


# -----------------------------------------------------------------------------
# 9. MITRE ATT&CK Matrix & Raw Telemetry Inspector (Hackathon Judge Section)
# -----------------------------------------------------------------------------
st.markdown("<div style='height: 8px;'></div>", unsafe_allow_html=True)

with st.expander("🔬 Technical Deep Dive & MITRE ATT&CK Matrix Mapping (For Judges & Security Architects)", expanded=False):
    col_mitre, col_raw = st.columns([1, 1])

    with col_mitre:
        st.markdown("#### MITRE ATT&CK Stage Activation")
        st.plotly_chart(create_stage_progression_bar(primary_cluster), use_container_width=True, config={'displayModeBar': False})
        st.markdown("""
        **Detection Engine Specs:**
        - **Rule 01:** Password Spray / Credential Burst (`T1110.003`)
        - **Rule 02:** Impossible Travel Anomaly (`T1078.004`)
        - **Rule 03:** Rogue Device Enrollment (`T1204`)
        - **Rule 04:** MFA Push Fatigue Bombing (`T1621`)
        - **Rule 05:** Mailbox Siphoning / Hidden Forwarding (`T1114.003`)
        - **Rule 06:** Unauthorized Admin Privilege Escalation (`T1098`)
        - **Rule 07:** Obfuscated Base64 PowerShell (`T1059.001`)
        - **Rule 08:** Volume Shadow Copy Deletion (`T1490`)
        - **Rule 09:** Anomalous Off-Hours Bulk Collection (`T1530`)
        - **Rule 10:** Mass Cloud Data Exfiltration Spike (`T1567`)
        """)

    with col_raw:
        st.markdown("#### Correlated JSON Cluster Telemetry")
        if primary_cluster:
            st.json(primary_cluster.to_dict())
        else:
            st.json({"status": "healthy", "active_clusters": 0, "logs_inspected": len(revealed_events)})
