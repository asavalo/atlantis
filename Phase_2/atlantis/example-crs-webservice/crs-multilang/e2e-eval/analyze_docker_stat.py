import json

import pandas as pd
import plotly.graph_objs as go
from plotly.offline import plot

# Load the docker_stats JSON file
with open(
    "/home/dongkwan/eval_output/2025-06-15-r3-missing-cps/docker_stats.json", "r"
) as f:
    # with open("/home/dongkwan/eval_output/2025-06-14-r3-all-2/docker_stats.json", "r") as f:
    data = json.load(f)


# Normalize units
def parse_size(size_str):
    if size_str.endswith("GiB"):
        return float(size_str[:-3]) * 1024
    elif size_str.endswith("MiB"):
        return float(size_str[:-3])
    elif size_str.endswith("kB"):
        return float(size_str[:-2]) / 1024
    elif size_str.endswith("MB"):
        return float(size_str[:-2])
    elif size_str.endswith("GB"):
        return float(size_str[:-2]) * 1024
    elif size_str.endswith("B"):
        return float(size_str[:-1]) / (1024 * 1024)
    return 0.0


def extract_value(field):
    return float(field.strip("%"))


# Convert JSON data to DataFrame
records = []
for entry in data:
    mem_used, _ = entry["MemUsage"].split(" / ")
    net_rx, net_tx = entry["NetIO"].split(" / ")
    block_rx, block_tx = entry["BlockIO"].split(" / ")

    if any([x in entry["Name"] for x in ["lsp", "joern", "redis"]]):
        continue

    records.append(
        {
            "timestamp": pd.to_datetime(entry["timestamp"]),
            "container": entry["Name"],
            "cpu": extract_value(entry["CPUPerc"]),
            "mem": parse_size(mem_used),
            "net_rx": parse_size(net_rx),
            "net_tx": parse_size(net_tx),
            "block_rx": parse_size(block_rx),
            "block_tx": parse_size(block_tx),
        }
    )

df = pd.DataFrame(records)

# Group by container
fig = go.Figure()

for container in df["container"].unique():
    c_df = df[df["container"] == container]
    fig.add_trace(
        go.Scatter(
            x=c_df["timestamp"],
            y=c_df["cpu"],
            mode="lines+markers",
            name=f"{container} - CPU %",
            yaxis="y1",
        )
    )

    fig.add_trace(
        go.Scatter(
            x=c_df["timestamp"],
            y=c_df["mem"],
            mode="lines+markers",
            name=f"{container} - Mem MiB",
            yaxis="y2",
        )
    )

# Layout with two y-axes
fig.update_layout(
    title="Docker Stats Over Time",
    xaxis=dict(title="Time"),
    yaxis=dict(title="CPU (%)", side="left"),
    yaxis2=dict(title="Memory (MiB)", overlaying="y", side="right"),
    legend=dict(orientation="h"),
    hovermode="x unified",
    height=600,
)

# Save as HTML
plot(fig, filename="docker_stats_plot.html", auto_open=False)
print("Graph saved as docker_stats_plot.html")
