# OpenTelemetry based evaluation

For local testing, we use Jaeger as our OpenTelemetry collector.
By querying the collector, we can retrieve our CRS logs in a more powerful manner.

Subdirectories
- `scripts` contains log querying scripts
- `jaeger` contains configuration files necessary for the Jaeger container
- `figures` figures collected from some runs

# Usage

By default, `docker-run.py` in development profile will store all OTEL logs
which can be later accessed by invoking `docker-run.py` with
`--profile postmortem` environment.
This then spawns a local instance of Jaeger UI on port 16686 that you can access
in the browser.

There is also `--profile evaluation` which enables the UI while the CRS is live.
Use at your own caution (alongside the postmortem profile) since this exposes
16686 on your host machine - use a firewall and/or don't keep this running long term.

In the web UI (or through the endpoint, reference `scripts/fuzzer_metrics.py`),
you can filter the spans by "crs.action.name".
For example, "crs.action.name=crash_collector" will fiter to only crash
collector logs.

You can also fiter the logs by the name of the function of which the log was
emitted in.
See `scripts/fuzzer_metrics.py:extract_logs_action_function`.

## fuzzer_metrics.py

```
usage: fuzzer_metrics.py [-h] {dump,plot,crashes} ...

Fuzzer metrics analysis tool

positional arguments:
  {dump,plot,crashes}  Operation mode
    dump               Dump logs for a specific action and function
    plot               Generate plots
    crashes            List all crashes

options:
  -h, --help           show this help message and exit
```

For the crashes, the script will also cross reference to find the origin of the seed.
Crash collector means it was from a fuzzer,
seed collector means it was from the shared directory (e.g. CRS-multilang),
and libdeepgen followed by the script UID is from a seed generator.

The dump command is an easy way to filter logs by its action and function name.
For example, `dump fuzzer_manager __log_fuzzer`.

```
usage: fuzzer_metrics.py dump [-h] action function

positional arguments:
  action      Action name to filter logs
  function    Function name to filter logs

options:
  -h, --help  show this help message and exit
```

# Cleanup

Logs will persist across CRS runs in a Docker volume.
To clear logs from previous runs, use
```
python3 docker-run.py clean <PROJECT>
```
which will invoke `docker volume rm atlantis-afc_esdata`.
