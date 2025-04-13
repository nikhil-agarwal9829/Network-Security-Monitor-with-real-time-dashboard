import dash
from dash import dcc, html, dash_table
from dash.dependencies import Input, Output, State
import plotly.graph_objs as go
import pyshark
import asyncio
import base64
import pandas as pd
import os

# Initialize Dash app
app = dash.Dash(__name__)

# Layout
app.layout = html.Div([
    html.H1("TCP/IP Packet Analyzer (PCAP Mode)", style={"textAlign": "center"}),

    html.Div([
        dcc.Upload(
            id="upload-pcap",
            children=html.Div([
                'Drag and Drop or ',
                html.Button('Select a PCAP File', style={
                    'color': 'white',
                    'backgroundColor': '#007bff',
                    'border': 'none',
                    'padding': '10px 20px',
                    'borderRadius': '5px',
                    'cursor': 'pointer'
                })
            ]),
            style={
                'width': '100%',
                'height': '60px',
                'lineHeight': '60px',
                'borderWidth': '1px',
                'borderStyle': 'dashed',
                'borderRadius': '5px',
                'textAlign': 'center',
                'margin': '10px 0px'
            },
            multiple=False
        ),
        html.Div(id='upload-status', style={'margin': '10px 0px', 'color': '#666'})
    ]),

    html.Div([
        html.H3("Packet Table"),
        dash_table.DataTable(
            id="packet-table",
            columns=[
                {"name": "Packet No.", "id": "Packet No."},
                {"name": "Timestamp", "id": "Timestamp"},
                {"name": "Source", "id": "Source"},
                {"name": "Destination", "id": "Destination"},
                {"name": "Protocol", "id": "Protocol"},
                {"name": "Length", "id": "Length"},
                {"name": "Info", "id": "Info"}
            ],
            style_table={"overflowX": "auto"},
            page_size=10,
            style_data={
                'whiteSpace': 'normal',
                'height': 'auto',
            }
        ),
    ], style={"padding": "20px", "border": "1px solid #ddd", "borderRadius": "5px", "margin": "10px 0"}),

    html.Div([
        html.H3("Packet Statistics"),
        html.Div([
            html.Div([
                html.H4("Total Packets:", style={"color": "#007bff"}),
                html.P(id="total-count", style={"fontSize": "24px", "fontWeight": "bold"}),
            ], style={"flex": "1"}),
            html.Div([
                html.H4("Protocols Found:", style={"color": "#28a745"}),
                html.P(id="protocol-count", style={"fontSize": "24px", "fontWeight": "bold"}),
            ], style={"flex": "1"}),
        ], style={"display": "flex", "justifyContent": "space-around"}),
    ], style={"padding": "20px", "border": "1px solid #ddd", "borderRadius": "5px", "margin": "10px 0"}),

    html.Div([
        html.H3("Packet Size Distribution"),
        dcc.Graph(id="packet-size-graph"),
    ], style={"padding": "20px", "border": "1px solid #ddd", "borderRadius": "5px", "margin": "10px 0"}),

    html.Div([
        html.H3("Protocol Breakdown"),
        dcc.Graph(id="protocol-graph"),
    ], style={"padding": "20px", "border": "1px solid #ddd", "borderRadius": "5px", "margin": "10px 0"})
])

@app.callback(
    [Output("packet-table", "data"),
     Output("total-count", "children"),
     Output("protocol-count", "children"),
     Output("packet-size-graph", "figure"),
     Output("protocol-graph", "figure"),
     Output("upload-status", "children"),
     Output("upload-status", "style")],
    Input("upload-pcap", "contents"),
    State("upload-pcap", "filename"),
    prevent_initial_call=True
)
def parse_pcap(contents, filename):
    if contents is None:
        return [], "0", "0", go.Figure(), go.Figure(), "", {'color': '#666'}

    try:
        content_type, content_string = contents.split(",")
        decoded = base64.b64decode(content_string)
        temp_filename = "temp.pcap"
        
        with open(temp_filename, "wb") as f:
            f.write(decoded)

        # Ensure an event loop exists for pyshark
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

        capture = pyshark.FileCapture(temp_filename)
        packets = []
        packet_sizes = []
        protocol_counts = {}

        for i, packet in enumerate(capture):
            try:
                # Handle different packet types
                if hasattr(packet, 'ip'):
                    src = packet.ip.src
                    dst = packet.ip.dst
                else:
                    src = packet.highest_layer
                    dst = packet.highest_layer

                protocol = packet.highest_layer
                length = int(packet.length)
                timestamp = packet.sniff_time.strftime("%H:%M:%S")
                
                # Get additional info
                info = ""
                if hasattr(packet, 'tcp'):
                    info = f"TCP {src}:{packet.tcp.srcport} > {dst}:{packet.tcp.dstport}"
                elif hasattr(packet, 'udp'):
                    info = f"UDP {src}:{packet.udp.srcport} > {dst}:{packet.udp.dstport}"
                else:
                    info = protocol

                packets.append({
                    "Packet No.": i + 1,
                    "Timestamp": timestamp,
                    "Source": src,
                    "Destination": dst,
                    "Protocol": protocol,
                    "Length": length,
                    "Info": info
                })

                packet_sizes.append(length)
                protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1
            except Exception as e:
                continue

        capture.close()

        # Clean up temp file
        try:
            os.remove(temp_filename)
        except:
            pass

        if not packets:
            return [], "0", "0", go.Figure(), go.Figure(), "No valid packets found in the file", {'color': 'red'}

        # Packet Size Distribution
        packet_size_fig = go.Figure()
        packet_size_fig.add_trace(go.Histogram(
            x=packet_sizes, 
            nbinsx=20,
            marker_color="#007bff",
            name="Packet Sizes"
        ))
        packet_size_fig.update_layout(
            title="Packet Size Distribution",
            xaxis_title="Size (bytes)",
            yaxis_title="Count",
            template="plotly_white"
        )

        # Protocol Breakdown
        protocol_fig = go.Figure()
        protocol_fig.add_trace(go.Pie(
            labels=list(protocol_counts.keys()),
            values=list(protocol_counts.values()),
            hole=0.3,
            marker=dict(colors=['#007bff', '#28a745', '#dc3545', '#ffc107', '#17a2b8'])
        ))
        protocol_fig.update_layout(
            title="Protocol Breakdown",
            template="plotly_white"
        )

        return (
            packets,
            str(len(packets)),
            str(len(protocol_counts)),
            packet_size_fig,
            protocol_fig,
            f"Successfully analyzed {len(packets)} packets from {filename}",
            {'color': '#28a745'}
        )

    except Exception as e:
        return [], "0", "0", go.Figure(), go.Figure(), f"Error processing file: {str(e)}", {'color': 'red'}

# Run app
if __name__ == "__main__":
    app.run_server(debug=True, port=8051)
