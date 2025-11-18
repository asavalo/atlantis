from datetime import datetime
import json
import sys
import argparse
from dataclasses import dataclass
import base64
import hashlib

import requests
import matplotlib.pyplot as plt
from hexdump import hexdump

JAEGER_API = "http://localhost:16686/api"

SERVICE = "crs-userspace"
LIMIT = 1500  # number of recent traces to pull
LOOKBACK = "2d"

@dataclass
class LogMessage:
    timestamp: datetime
    message: str

def get_traces(tags=None):
    params = {"service": SERVICE, "limit": LIMIT, "lookback": LOOKBACK}

    if tags:
        params["tags"] = tags
    res = requests.get(f"{JAEGER_API}/traces", params=params)
    res.raise_for_status()
    return [trace["traceID"] for trace in res.json().get("data", [])]

def get_trace(trace_id):
    res = requests.get(f"{JAEGER_API}/traces/{trace_id}")
    res.raise_for_status()
    return res.json().get("data", [])[0]

def __iterate_logs(trace_data, mutable_context, body_closure):
    for span in trace_data.get("spans", []):
        if span.get("operationName") != "crs-userspace":
            continue

        for log in span.get("logs", []):
            fields = {f["key"]: f["value"] for f in log.get("fields", [])}
            body_closure(mutable_context, span, log, fields)

def extract_log_fuzzer_events(trace_data):
    events = []
    def closure(events, span, log, fields):
        timestamp = log["timestamp"]
        events.append(LogMessage(
            timestamp = datetime.fromtimestamp(timestamp / 1_000_000),
            message = fields["message"]
        ))
    __iterate_logs(trace_data, events, closure)
    return events

def extract_log_fuzzer_events_filter(trace_data, log_field, func_name):
    events = []
    context = (events, log_field, func_name)
    def closure(tup, span, log, fields):
        events, log_field, func_name = tup
        if fields.get(log_field) != func_name:
            return
        timestamp = log["timestamp"]
        events.append(LogMessage(
            timestamp = datetime.fromtimestamp(timestamp / 1_000_000),
            message = fields["message"]
        ))
    __iterate_logs(trace_data, context, closure)
    return events

def extract_functions(trace_data):
    funcs = set()
    def closure(funcs, span, log, fields):
        funcs.add(fields.get("funcName"))

    __iterate_logs(trace_data, funcs, closure)
    return funcs

def extract_logs_action(action: str) -> list[LogMessage]:
    trace_ids = get_traces(f'{{"crs.action.name":"{action}"}}')
    events = []
    for tid in reversed(trace_ids):
        trace = get_trace(tid)
        events.extend(extract_log_fuzzer_events(trace))
    return events

def extract_logs_action_function(action: str, function: str) -> list[LogMessage]:
    trace_ids = get_traces(f'{{"crs.action.name":"{action}"}}')
    events = []
    for tid in reversed(trace_ids):
        trace = get_trace(tid)
        events.extend(extract_log_fuzzer_events_filter(trace, "funcName", function))
    return events

def extract_logs_action_filename(action: str, filename: str) -> list[LogMessage]:
    trace_ids = get_traces(f'{{"crs.action.name":"{action}"}}')
    events = []
    for tid in reversed(trace_ids):
        trace = get_trace(tid)
        events.extend(extract_log_fuzzer_events_filter(trace, "filename", filename))
    return events

def get_fuzzer_logs(desired_harness: str):
    events = extract_logs_action_function("fuzzer_manager", "__log_fuzzer")
    coverages = []
    execs = []
    for ev in events:
        pairs = ev.message.split()
        coverage = None
        exec_ = None
        for pair in pairs:
            k, v = pair.split('=')
            # print(k, v, ev.timestamp)
            if k == "harness" and v != desired_harness:
                break
            elif k == "coverage":
                coverage = (ev.timestamp, float(v))
            elif k == "exec_sec":
                exec_ = (ev.timestamp, float(v))
        if coverage:
            coverages.append(coverage)
        if exec_:
            execs.append(exec_)
    return (coverages, execs)

def get_crash_logs():
    records = []
    events = extract_logs_action_function("crash_collector", "collect_crashes")
    for ev in events:
        if "->New Crash<-" in ev.message:
            records.append(ev)
    return records

def plot_coverage_and_exec_sec(harness: str):
    """
    This function extracts log events from fuzzer_manager (using "log_fuzzer")
    and parses out the coverage and exec_sec values from each message.
    It then plots two graphs with time (as the x-axis) against coverage and exec_sec.
    """
    coverage_data, exec_sec_data = get_fuzzer_logs(harness)
    # Sort the data by time to ensure proper plotting
    coverage_data.sort(key=lambda x: x[0])
    exec_sec_data.sort(key=lambda x: x[0])
    
    # --- Plot Coverage Over Time ---
    if coverage_data:
        fig, ax = plt.subplots()
        times_cov = [t for t, _ in coverage_data]
        cov_values = [v for _, v in coverage_data]
        ax.plot(times_cov, cov_values, marker='o')
        ax.set_xlabel('Time')
        ax.set_ylabel('Coverage')
        ax.set_title('Coverage Over Time')
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.savefig("coverage_over_time.png")
    else:
        print("No coverage data available to plot.")

    # --- Plot Execution Seconds Over Time ---
    if exec_sec_data:
        fig, ax = plt.subplots()
        times_exec = [t for t, _ in exec_sec_data]
        exec_values = [v for _, v in exec_sec_data]
        ax.plot(times_exec, exec_values, marker='o')
        ax.set_xlabel('Time')
        ax.set_ylabel('Exec Sec')
        ax.set_title('Execution/Second Over Time')
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.savefig("exec_sec_over_time.png")
    else:
        print("No exec_sec data available to plot.")

def plot_bug_find_timeline():
    """
    This function determines the start time (from the first "__init__" event in fuzzer_manager logs)
    and then finds the first bug (a log containing "->New Crash<-" in crash_collector's collect_crashes function).
    It plots a simple timeline that shows these two events and the duration between them.
    """
    # --- Get the start time from fuzzer_manager __init__ events ---
    init_events = extract_logs_action_function("fuzzer_manager", "run")
    if not init_events:
        print("No run events found to determine start time.")
        return
    start_time = min(ev.timestamp for ev in init_events)
    
    # --- Get the first crash event (bug) from crash_collector logs ---
    crash_events = extract_logs_action_function("crash_collector", "collect_crashes")
    # Filter events that indicate a new crash
    new_crash_events = [ev for ev in crash_events if "->New Crash<-" in ev.message]
    if not new_crash_events:
        print("No new crash events found.")
        return


    # Map each event to seconds since start
    times = [(ev.timestamp - start_time).total_seconds() for ev in new_crash_events]
    messages = [ev.message for ev in new_crash_events]

    # Optionally deduplicate messages to reduce clutter
    unique_msgs = sorted(set(messages))
    msg_to_y = {msg: i for i, msg in enumerate(unique_msgs)}

    y_positions = [msg_to_y[msg] for msg in messages]

    # Plot
    fig, ax = plt.subplots(figsize=(10, 6))
    ax.scatter(times, y_positions, marker='x', color='red')
    ax.set_xlabel("Seconds Since Start")
    ax.set_ylabel("Crash Signature")
    ax.set_title("Bug Discovery Timeline (New Crashes)")
    ax.set_yticks(range(len(unique_msgs)))
    ax.set_yticklabels(unique_msgs, fontsize=8)
    plt.grid(True, axis='x', linestyle='--', alpha=0.5)
    plt.tight_layout()
    plt.savefig("bug_timeline.png")
    print("Saved bug timeline to bug_timeline.png")

def main():
    parser = argparse.ArgumentParser(description='Fuzzer metrics analysis tool')
    subparsers = parser.add_subparsers(dest='mode', help='Operation mode', required=True)

    # Dump mode
    dump_parser = subparsers.add_parser('dump_function', help='Dump logs for a specific action and function')
    dump_parser.add_argument('action', help='Action name to filter logs')
    dump_parser.add_argument('function', help='Function name to filter logs')

    dump_parser = subparsers.add_parser('dump_filename', help='Dump logs for a specific action and filename')
    dump_parser.add_argument('action', help='Action name to filter logs')
    dump_parser.add_argument('filename', help='Filename to filter logs')

    # Dump mode for fuzzing
    dump_parser = subparsers.add_parser('dump_fuzzing', help='Dump coverage and execution speed logs for a specific harness')
    dump_parser.add_argument('harness', help='Fuzzing harness')
    dump_parser.add_argument('type', choices=['coverage', 'execution'], help='Choose between execution speed or coverage logs')


    # Plot mode
    plot_parser = subparsers.add_parser('plot', help='Generate plots')
    plot_parser.add_argument('harness', help='Fuzzing harness')
    plot_parser.add_argument('--type', choices=['coverage', 'all'], default='all',
                           help='Type of plot to generate, other modes yet to be added (default: all)')

    # List crashes mode
    subparsers.add_parser('crashes', help='List all crashes')

    args = parser.parse_args()

    if args.mode == 'dump_function':
        events = extract_logs_action_function(args.action, args.function)
        for ev in events:
            print(f"{ev.timestamp} {ev.message}")
    
    if args.mode == 'dump_filename':
        events = extract_logs_action_filename(args.action, args.filename)
        for ev in events:
            print(f"{ev.timestamp} {ev.message}")
    
    if args.mode == 'dump_fuzzing':
        (coverages, execs) = get_fuzzer_logs(args.harness)
        pairing = []
        if args.type == "coverage":
            pairing = coverages
        elif args.type == "execution":
            pairing = execs
        for (timestamp, value) in pairing:
            print(f"{timestamp} {value}")

    elif args.mode == 'plot':
        if args.type in ['coverage', 'all']:
            plot_coverage_and_exec_sec(args.harness)
    
    elif args.mode == 'crashes':
        seed_suggestion_logs = extract_logs_action_function("ensembler", "process_seed_suggestion")
        directory_watch_logs = extract_logs_action_function("ensembler", "directory_watch_callback")
        all_logs = seed_suggestion_logs + directory_watch_logs
        seed_suggestion_map = {}
        for ev in all_logs:
            seed_object = json.loads(ev.message)
            # checksum of data
            for data in seed_object["data"]:
                seed_suggestion_map[data] = (ev.timestamp, seed_object["harness_id"], seed_object["origin"])

        crash_event_logs = extract_logs_action_function("ensembler", "send_to_submission_worker")
        crash_prefix = "submission:"
        crash_events = [ev.message.split(crash_prefix)[1] for ev in crash_event_logs if ev.message.startswith(crash_prefix)]
        for crash_event in crash_events:
            crash_object = json.loads(crash_event)
            seed_encoded = crash_object["data"]
            seed_data = base64.b64decode(seed_encoded)
            checksum = hashlib.md5(seed_data).hexdigest()
            seed_suggestion = seed_suggestion_map.get(checksum)
            if seed_suggestion:
                print(f"timestamp    {seed_suggestion[0].strftime('%Y-%m-%d %H:%M:%S')}")
                print(f"harness      {seed_suggestion[1]}")
                print(f"origin       {seed_suggestion[2]}")
                print(f"sanitizer    {crash_object['sanitizer_output']}")
                print(hexdump(seed_data, result="return"))
                print()
            else:
                print(f"No seed suggestion found for {crash_event}")

if __name__ == "__main__":
    main()
