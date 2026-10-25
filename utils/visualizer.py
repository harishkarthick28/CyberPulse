"""
CyberPulse - Interactive Plotly Visualizations
Provides dark-mode SOC-styled visual widgets:
- Gauge Risk Score Meter (0-100)
- Attack Progression Timeline Chart
- Attack Stage Matrix / Breakdown
"""

import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
from typing import List, Dict, Any, Optional
from rules.correlator import IncidentCluster
from rules.detector import Alert

SOC_DARK_BG = "#0f172a"
SOC_CARD_BG = "#1e293b"
SOC_TEXT_COLOR = "#f8fafc"
COLOR_GREEN = "#10b981"
COLOR_YELLOW = "#f59e0b"
COLOR_RED = "#ef4444"


def create_risk_gauge(score: int, title: str = "THREAT SEVERITY SCORE") -> go.Figure:
    """Creates a high-visibility gauge meter (0-100) with color zones."""
    if score >= 75:
        bar_color = COLOR_RED
        status_text = "CRITICAL BREACH"
    elif score >= 40:
        bar_color = COLOR_YELLOW
        status_text = "ELEVATED SUSPICION"
    else:
        bar_color = COLOR_GREEN
        status_text = "LOW / NORMAL"

    fig = go.Figure(go.Indicator(
        mode="gauge+number+delta",
        value=score,
        domain={'x': [0, 1], 'y': [0, 1]},
        title={'text': f"<b>{title}</b><br><span style='font-size:14px;color:{bar_color}'>{status_text}</span>",
               'font': {'color': SOC_TEXT_COLOR, 'size': 18, 'family': 'Inter, sans-serif'}},
        number={'suffix': "/100", 'font': {'size': 44, 'color': bar_color, 'family': 'Courier New, monospace'}},
        gauge={
            'axis': {'range': [0, 100], 'tickwidth': 1, 'tickcolor': "#475569", 'tickfont': {'color': "#94a3b8"}},
            'bar': {'color': bar_color, 'thickness': 0.3},
            'bgcolor': "#1e293b",
            'borderwidth': 1,
            'bordercolor': "#334155",
            'steps': [
                {'range': [0, 40], 'color': "rgba(16, 185, 129, 0.15)"},
                {'range': [40, 75], 'color': "rgba(245, 158, 11, 0.15)"},
                {'range': [75, 100], 'color': "rgba(239, 68, 68, 0.25)"}
            ],
            'threshold': {
                'line': {'color': "#ffffff", 'width': 3},
                'thickness': 0.8,
                'value': score
            }
        }
    ))

    fig.update_layout(
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        height=260,
        margin=dict(l=30, r=30, t=50, b=10),
        font={'color': SOC_TEXT_COLOR}
    )
    return fig


def create_timeline_chart(alerts: List[Alert]) -> go.Figure:
    """Generates an interactive chronological event timeline scatter/line chart."""
    if not alerts:
        # Return empty state chart
        fig = go.Figure()
        fig.add_annotation(
            text="No attack events recorded in the current timeline.",
            xref="paper", yref="paper",
            x=0.5, y=0.5, showarrow=False,
            font=dict(size=14, color="#94a3b8")
        )
        fig.update_layout(
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            height=260,
            xaxis=dict(visible=False),
            yaxis=dict(visible=False)
        )
        return fig

    # Map alerts to dataframe
    records = []
    color_map = {
        "Critical": COLOR_RED,
        "High": "#f97316",
        "Medium": COLOR_YELLOW,
        "Low": COLOR_GREEN
    }

    for idx, a in enumerate(alerts):
        records.append({
            "Step": f"#{idx+1}",
            "Timestamp": a.timestamp.replace("T", " ").replace("Z", ""),
            "Rule": a.rule_name,
            "Stage": a.stage,
            "Severity": a.severity,
            "Points": a.points,
            "Color": color_map.get(a.severity, COLOR_GREEN),
            "Summary": a.summary,
            "User": a.user,
            "IP": a.ip_address
        })

    df = pd.DataFrame(records)

    fig = go.Figure()

    # Base connecting path
    fig.add_trace(go.Scatter(
        x=df["Timestamp"],
        y=df["Points"],
        mode="lines",
        line=dict(color="#38bdf8", width=2, dash="dot"),
        hoverinfo="skip",
        showlegend=False
    ))

    # Event markers with colors
    for sev in ["Critical", "High", "Medium", "Low"]:
        sub = df[df["Severity"] == sev]
        if not sub.empty:
            fig.add_trace(go.Scatter(
                x=sub["Timestamp"],
                y=sub["Points"],
                mode="markers+text",
                name=f"{sev} Severity",
                marker=dict(
                    size=16,
                    color=color_map[sev],
                    line=dict(width=2, color="#ffffff")
                ),
                text=sub["Step"],
                textposition="top center",
                textfont=dict(color="#ffffff", size=11, family="Inter, sans-serif"),
                customdata=sub[["Rule", "Stage", "User", "IP", "Summary"]],
                hovertemplate=(
                    "<b>%{customdata[0]}</b><br>" +
                    "Stage: %{customdata[1]}<br>" +
                    "User: %{customdata[2]}<br>" +
                    "IP: %{customdata[3]}<br>" +
                    "Details: %{customdata[4]}<extra></extra>"
                )
            ))

    fig.update_layout(
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(15, 23, 42, 0.75)',
        font=dict(color=SOC_TEXT_COLOR, family="Inter, sans-serif"),
        height=300,
        margin=dict(l=20, r=20, t=30, b=20),
        xaxis=dict(
            title=dict(text="Incident Timeline (UTC)", font=dict(color="#94a3b8")),
            showgrid=True,
            gridcolor="#1e293b",
            color="#94a3b8"
        ),
        yaxis=dict(
            title=dict(text="Severity Weight", font=dict(color="#94a3b8")),
            range=[0, 48],
            showgrid=True,
            gridcolor="#1e293b",
            color="#94a3b8"
        ),
        legend=dict(
            orientation="h",
            yanchor="bottom",
            y=1.02,
            xanchor="right",
            x=1,
            font=dict(size=11, color="#cbd5e1")
        )
    )
    return fig


def create_stage_progression_bar(cluster: Optional[IncidentCluster]) -> go.Figure:
    """Displays the attack chain progression across MITRE ATT&CK stages."""
    standard_stages = [
        "Initial Access",
        "Credential Access",
        "Persistence",
        "Privilege Escalation",
        "Execution",
        "Collection",
        "Impact / Ransomware",
        "Exfiltration"
    ]

    active_stages = set(cluster.stages) if cluster else set()

    stage_status = []
    colors = []
    values = []

    for stg in standard_stages:
        is_active = stg in active_stages or any(stg.lower() in s.lower() for s in active_stages)
        stage_status.append(stg)
        if is_active:
            values.append(1)
            colors.append(COLOR_RED if "Impact" in stg or "Exfiltration" in stg else "#f59e0b")
        else:
            values.append(0.2)
            colors.append("#334155")

    fig = go.Figure(go.Bar(
        x=stage_status,
        y=values,
        marker=dict(color=colors, line=dict(color="#475569", width=1)),
        hoverinfo="x+y",
        hovertemplate="<b>%{x}</b><br>State: Active Breach Vector<extra></extra>"
    ))

    fig.update_layout(
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font=dict(color=SOC_TEXT_COLOR, size=11),
        height=180,
        margin=dict(l=10, r=10, t=15, b=25),
        xaxis=dict(tickangle=-15, color="#94a3b8"),
        yaxis=dict(visible=False, range=[0, 1.2]),
        showlegend=False
    )
    return fig
