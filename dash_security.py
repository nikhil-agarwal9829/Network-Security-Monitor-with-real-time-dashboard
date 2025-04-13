import dash
from dash import dcc, html, dash_table
from dash.dependencies import Input, Output, State
import plotly.graph_objs as go
import pyshark
import asyncio
import time
import json
import pandas as pd
from collections import deque
import plotly.express as px

# Initialize Dash app
app = dash.Dash(__name__)

# Global variables for packet analysis
packet_history = deque(maxlen=100)
suspicious_packets = deque(maxlen=50)
security_status = {
    "total_packets": 0,
    "suspicious_count": 0,
    "last_check": time.time(),
    "system_status": "Secure"
}

def analyze_packet_security(packet):
    """Analyze a packet for potential security issues"""
    threats = []
    
    try:
        # Check for common security issues
        if hasattr(packet, 'tcp'):
            # Check for common malicious ports
            suspicious_ports = [22, 23, 3389, 445, 135, 137, 138, 139]  # SSH, Telnet, RDP, SMB ports
            if int(packet.tcp.dstport) in suspicious_ports:
                threats.append(f"Suspicious port access: {packet.tcp.dstport}")
            
            # Check for potential port scanning
            if packet.tcp.flags == "0x0002":  # SYN flag
                threats.append("Possible port scanning detected")

        # Check for large packets that might indicate data exfiltration
        if hasattr(packet, 'length') and int(packet.length) > 1500:
            threats.append("Large packet size detected")

        # Check for suspicious protocols
        if hasattr(packet, 'highest_layer'):
            suspicious_protocols = ['TELNET', 'FTP']
            if packet.highest_layer in suspicious_protocols:
                threats.append(f"Insecure protocol: {packet.highest_layer}")

    except Exception as e:
        threats.append(f"Error analyzing packet: {str(e)}")

    return threats

# Layout
app.layout = html.Div([
    html.H1("Network Security Dashboard", style={"textAlign": "center"}),
    
    # Security Status Card
    html.Div([
        html.Div([
            html.H3("System Security Status", style={"color": "#fff"}),
            html.Div(id="security-status", style={"fontSize": "24px", "fontWeight": "bold"}),
            html.Div(id="last-check", style={"fontSize": "14px"}),
        ], style={
            "backgroundColor": "#2c3e50",
            "padding": "20px",
            "borderRadius": "10px",
            "color": "#fff",
            "textAlign": "center"
        }),
    ], style={"margin": "20px 0"}),

    # Threat Detection Panel
    html.Div([
        html.Div([
            html.H3("Live Threat Detection", style={"color": "#e74c3c"}),
            dash_table.DataTable(
                id="threat-table",
                columns=[
                    {"name": "Time", "id": "time"},
                    {"name": "Source", "id": "source"},
                    {"name": "Destination", "id": "destination"},
                    {"name": "Threat Type", "id": "threat"},
                    {"name": "Risk Level", "id": "risk"}
                ],
                style_table={"overflowX": "auto"},
                style_data_conditional=[
                    {
                        'if': {'column_id': 'risk', 'filter_query': '{risk} contains "High"'},
                        'backgroundColor': '#ffebee',
                        'color': '#c62828'
                    },
                    {
                        'if': {'column_id': 'risk', 'filter_query': '{risk} contains "Medium"'},
                        'backgroundColor': '#fff3e0',
                        'color': '#ef6c00'
                    }
                ],
                page_size=5
            ),
        ], style={"padding": "20px", "border": "1px solid #e74c3c", "borderRadius": "10px"}),
    ]),

    # Statistics Cards
    html.Div([
        html.Div([
            html.Div([
                html.H4("Total Packets"),
                html.P(id="total-packets", style={"fontSize": "24px", "fontWeight": "bold"}),
            ], style={"flex": "1", "textAlign": "center", "padding": "20px", "backgroundColor": "#3498db", "color": "#fff", "borderRadius": "10px", "margin": "10px"}),
            html.Div([
                html.H4("Suspicious Packets"),
                html.P(id="suspicious-packets", style={"fontSize": "24px", "fontWeight": "bold"}),
            ], style={"flex": "1", "textAlign": "center", "padding": "20px", "backgroundColor": "#e74c3c", "color": "#fff", "borderRadius": "10px", "margin": "10px"}),
            html.Div([
                html.H4("Security Score"),
                html.P(id="security-score", style={"fontSize": "24px", "fontWeight": "bold"}),
            ], style={"flex": "1", "textAlign": "center", "padding": "20px", "backgroundColor": "#2ecc71", "color": "#fff", "borderRadius": "10px", "margin": "10px"}),
        ], style={"display": "flex", "justifyContent": "space-between", "margin": "20px 0"}),
    ]),

    # Graphs
    html.Div([
        html.Div([
            html.H3("Threat Distribution"),
            dcc.Graph(id="threat-distribution"),
        ], style={"flex": "1", "padding": "20px", "border": "1px solid #ddd", "borderRadius": "10px", "margin": "10px"}),
        
        html.Div([
            html.H3("Network Activity Timeline"),
            dcc.Graph(id="activity-timeline"),
        ], style={"flex": "1", "padding": "20px", "border": "1px solid #ddd", "borderRadius": "10px", "margin": "10px"}),
    ], style={"display": "flex", "justifyContent": "space-between"}),

    # Update interval
    dcc.Interval(
        id='interval-component',
        interval=1000,  # in milliseconds
        n_intervals=0
    )
])

@app.callback(
    [Output("security-status", "children"),
     Output("security-status", "style"),
     Output("last-check", "children"),
     Output("total-packets", "children"),
     Output("suspicious-packets", "children"),
     Output("security-score", "children"),
     Output("threat-table", "data"),
     Output("threat-distribution", "figure"),
     Output("activity-timeline", "figure")],
    Input('interval-component', 'n_intervals')
)
def update_security_dashboard(n):
    try:
        # Read the latest data from security_data.json
        with open('security_data.json', 'r') as f:
            data = json.load(f)
            
        total_packets = data.get('total_packets', 0)
        suspicious_count = data.get('suspicious_count', 0)
        recent_threats = data.get('recent_threats', [])
        packet_history = data.get('packet_history', [])
        
        # Calculate security score (0-100)
        if total_packets > 0:
            security_score = 100 - (suspicious_count / total_packets * 100) if total_packets > 0 else 100
        else:
            security_score = 100

        # Determine system status and color
        if security_score >= 90:
            status_style = {"color": "#2ecc71"}  # Green
            status_text = "System Secure"
        elif security_score >= 70:
            status_style = {"color": "#f1c40f"}  # Yellow
            status_text = "System Warning"
        else:
            status_style = {"color": "#e74c3c"}  # Red
            status_text = "System Alert"

        # Generate threat table data
        threat_data = [
            {
                "time": threat["timestamp"],
                "source": "System",
                "destination": "System",
                "threat": threat["description"],
                "risk": "High" if "suspicious" in threat["description"].lower() else "Medium"
            }
            for threat in recent_threats
        ]

        # Create threat distribution figure
        threat_types = pd.DataFrame(threat_data).get("threat", pd.Series()).value_counts()
        threat_fig = go.Figure(data=[
            go.Pie(
                labels=threat_types.index,
                values=threat_types.values,
                hole=0.3,
                marker=dict(colors=px.colors.qualitative.Set3)
            )
        ])
        threat_fig.update_layout(title="Threat Type Distribution")

        # Create activity timeline
        timeline_data = pd.DataFrame(packet_history)
        if not timeline_data.empty and len(timeline_data) > 0:
            timeline_data['timestamp'] = pd.to_datetime(timeline_data['timestamp'])
            packet_counts = timeline_data.groupby('timestamp').size().reset_index(name='packet_count')
            
            activity_fig = go.Figure()
            activity_fig.add_trace(go.Scatter(
                x=packet_counts['timestamp'],
                y=packet_counts['packet_count'],
                mode='lines+markers',
                name='Network Activity'
            ))
            activity_fig.update_layout(
                title="Network Activity Over Time",
                xaxis_title="Time",
                yaxis_title="Packet Count"
            )
        else:
            activity_fig = go.Figure()

        return (
            status_text,
            status_style,
            f"Last checked: {time.strftime('%H:%M:%S')}",
            str(total_packets),
            str(suspicious_count),
            f"{security_score:.1f}%",
            threat_data,
            threat_fig,
            activity_fig
        )
    except Exception as e:
        print(f"Error updating dashboard: {str(e)}")
        # Return empty/default values in case of error
        return (
            "System Status Unknown",
            {"color": "#95a5a6"},
            f"Last checked: {time.strftime('%H:%M:%S')}",
            "0",
            "0",
            "100.0%",
            [],
            go.Figure(),
            go.Figure()
        )

# Run app
if __name__ == "__main__":
    app.run_server(debug=True, port=8052) 