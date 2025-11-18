import argparse
import json
import re
from pathlib import Path

import pandas as pd
import plotly.express as px
import plotly.io as pio  # Add this import


def load_partial_json(filepath):
    with open(filepath, "r") as f:
        content = f.read()
        # Remove trailing commas
        content = re.sub(r",\s*$", "", content.strip())
        # Forcefully close the structure if needed
        content += "]}]}}"
        if '"hosts": [' in content:
            content = '{"sysstat": {"hosts": [' + content.split('"hosts": [', 1)[1]
        return json.loads(content)


def extract_cpu_records_from_file(file_path):
    try:
        data = load_partial_json(file_path)
        stats = data["sysstat"]["hosts"][0]["statistics"]
    except Exception as e:
        print(f"❌ Skipping {file_path.name}: {e}")
        return []

    records = []
    for entry in stats:
        timestamp = entry["timestamp"]
        for cpu_data in entry["cpu-load"]:
            record = cpu_data.copy()
            record["timestamp"] = timestamp
            record["source_file"] = file_path.name
            records.append(record)
    return records


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Recursively parse mpstat-style JSON files and generate combined CPU usage"
            " plot."
        )
    )
    parser.add_argument(
        "input_dir", help="Directory to recursively search for JSON files"
    )
    args = parser.parse_args()

    all_html_parts = []
    input_path = Path(args.input_dir)

    for json_file in input_path.rglob("*.json"):
        print(f"🔍 Parsing {json_file}")
        records = extract_cpu_records_from_file(json_file)
        if not records:
            continue

        df = pd.DataFrame(records)
        df["timestamp"] = pd.to_datetime(df["timestamp"], format="%I:%M:%S %p")
        df["cpu"] = df["cpu"].astype(int)
        df["usr"] = pd.to_numeric(df["usr"], errors="coerce")
        df["sys"] = pd.to_numeric(df["sys"], errors="coerce")
        df["total_usage"] = df["usr"] + df["sys"]

        df_filtered = df  # or apply a filter like df[df['total_usage'] < 50]

        if df_filtered.empty:
            print(f"⚠️ No valid CPU records found in {json_file.name}")
            continue

        melted = df_filtered.melt(
            id_vars=["timestamp", "cpu"],
            value_vars=["total_usage"],
            var_name="metric",
            value_name="value",
        )

        fig = px.line(
            melted,
            x="timestamp",
            y="value",
            color="cpu",
            line_dash="metric",
            title=f"CPU Usage for {json_file}",
            labels={"value": "Usage (%)", "timestamp": "Time"},
        )
        fig.update_layout(height=400, legend_title="CPU / Metric")

        # Append this figure’s HTML to the full output
        html_fragment = pio.to_html(fig, full_html=False, include_plotlyjs="cdn")
        all_html_parts.append(html_fragment)

    if not all_html_parts:
        print("⚠️ No valid plots generated.")
        return

    # Combine and write the final HTML
    full_html = f"""
    <html>
    <head>
        <title>Combined CPU Usage Report</title>
        <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
    </head>
    <body>
        {"<hr>".join(all_html_parts)}
    </body>
    </html>
    """

    with open("combined_cpu_usage_report.html", "w") as f:
        f.write(full_html)

    print("✅ Saved combined plot: combined_cpu_usage_report.html")


if __name__ == "__main__":
    main()
