import dash
from dash import dcc, html, dash_table
from dash.dependencies import Input, Output, State
import plotly.graph_objs as go
import pyshark
import threading
import asyncio
import pandas as pd
from collections import deque
import time

# Initialize Dash app
app = dash.Dash(__name__)

# Global variables
packets_data = []
packet_count = {"incoming": 0, "outgoing": 0}
time_series = deque(maxlen=20)
protocol_counts = {}
packet_sizes = []
packet_no = 0
start_time = time.time()

# Live packet capture function
def capture_live_packets():
    global packet_no
    asyncio.set_event_loop(asyncio.new_event_loop())  # Fix async issue
    capture = pyshark.LiveCapture(interface="Wi-Fi")

    for packet in capture.sniff_continuously():
        try:
            src = packet.ip.src
            dst = packet.ip.dst
            protocol = packet.highest_layer
            length = int(packet.length)
            timestamp = time.time() - start_time
            
            packet_no += 1
            packets_data.append({
                "Packet No.": packet_no,
                "Timestamp": timestamp,
                "Source IP": src,
                "Destination IP": dst,
                "Protocol": protocol,
                "Length": length
            })
            
            if "192.168" in src:  
                packet_count["outgoing"] += 1
            else:
                packet_count["incoming"] += 1
            
            time_series.append((timestamp, length))  # Store length instead of count for throughput
            
            protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1
            packet_sizes.append(length)
        except:
            continue

# Start live packet capture in a separate thread
threading.Thread(target=capture_live_packets, daemon=True).start()

# Layout
app.layout = html.Div([
    html.H1("TCP/IP Packet Analyzer", style={"textAlign": "center"}),

    html.Div([
        html.H3("Live Packet Table"),
        dash_table.DataTable(
            id="packet-table",
            columns=[
                {"name": "Packet No.", "id": "Packet No."},
                {"name": "Timestamp", "id": "Timestamp"},
                {"name": "Source IP", "id": "Source IP"},
                {"name": "Destination IP", "id": "Destination IP"},
                {"name": "Protocol", "id": "Protocol"},
                {"name": "Length", "id": "Length"}
            ],
            style_table={"overflowX": "auto"},
            page_size=10
        ),
    ], style={"padding": "10px", "border": "1px solid black"}),

    html.Div([
        html.H3("Live Packet Counts"),
        html.Div(id="packet-count-display", style={"fontSize": "20px", "textAlign": "center"}),
    ], style={"padding": "10px", "border": "1px solid black"}),

    html.Div([
        html.H3("Real-Time Network Throughput"),
        dcc.Graph(id="network-speed-graph"),
        dcc.Interval(id="interval-component", interval=1000, n_intervals=0)
    ], style={"padding": "10px", "border": "1px solid black"}),

    html.Div([
        html.H3("Live Packet Trend"),
        dcc.Graph(id="live-line-graph"),
    ], style={"padding": "10px", "border": "1px solid black"}),

    html.Div([
        html.H3("Protocol Distribution"),
        dcc.Graph(id="protocol-pie-chart"),
    ], style={"padding": "10px", "border": "1px solid black"}),

    html.Div([
        html.H3("Packet Size Distribution"),
        dcc.Graph(id="packet-size-histogram"),
    ], style={"padding": "10px", "border": "1px solid black"})
])

# Callback to update everything
@app.callback(
    [
        Output("packet-table", "data"),
        Output("network-speed-graph", "figure"),
        Output("live-line-graph", "figure"),
        Output("protocol-pie-chart", "figure"),
        Output("packet-size-histogram", "figure"),
        Output("packet-count-display", "children")
    ],
    [Input("interval-component", "n_intervals")],
    [State("packet-table", "data")]
)
def update_dashboard(n, table_data):
    if not packets_data:
        return [], go.Figure(), go.Figure(), go.Figure(), go.Figure(), "Incoming: 0 | Outgoing: 0"

    df = pd.DataFrame(packets_data[-10:])
    
    # Real-Time Network Throughput Graph (kbps/mbps calculation)
    throughput_fig = go.Figure()
    timestamps, sizes = zip(*time_series) if time_series else ([], [])
    speeds_kbps = [(size * 8) / 1024 for size in sizes]  # Convert bytes to kbps
    throughput_fig.add_trace(go.Scatter(x=timestamps, y=speeds_kbps, mode="lines", name="Throughput (kbps)"))
    throughput_fig.update_layout(title="Real-Time Network Throughput", xaxis_title="Time (s)", yaxis_title="Throughput (kbps)", yaxis=dict(range=[0, max(speeds_kbps) if speeds_kbps else 1]))
    
    # Live Packet Trend (Line Graph)
    line_fig = go.Figure()
    if time_series:
        line_fig.add_trace(go.Scatter(x=timestamps, y=[sum(sizes[:i+1]) for i in range(len(sizes))], mode="lines+markers"))
    line_fig.update_layout(title="Live Packet Trend", xaxis_title="Time (s)", yaxis_title="Total Packets")

    # Protocol Distribution Pie Chart
    protocol_fig = go.Figure()
    if protocol_counts:
        protocol_fig.add_trace(go.Pie(labels=list(protocol_counts.keys()), values=list(protocol_counts.values()), hole=0.3))
    protocol_fig.update_layout(title="Protocol Distribution")

    # Packet Size Histogram
    packet_size_fig = go.Figure()
    if packet_sizes:
        packet_size_fig.add_trace(go.Histogram(x=packet_sizes, nbinsx=20))
    packet_size_fig.update_layout(title="Packet Size Distribution", xaxis_title="Size (bytes)", yaxis_title="Count")
    
    packet_count_text = f"Incoming: {packet_count['incoming']} | Outgoing: {packet_count['outgoing']}"
    
    return df.to_dict("records"), throughput_fig, line_fig, protocol_fig, packet_size_fig, packet_count_text

# Run app
if __name__ == "__main__":
    app.run_server(debug=True)
