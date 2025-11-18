from loguru import logger
import os


def setup_logger():
    path = "/crs-logs/crs.log"
    for handler in logger._core.handlers.values():
        if path in str(handler):
            return
    os.makedirs(os.path.dirname(path), exist_ok=True)
    logger.remove()
    logger.add(
        path,
        rotation="10 MB",
        format="{time:HH:mm:ss} | {level} | {message}",
        enqueue=True,
    )
    logger.add(
        sink=lambda msg: print(msg, end="", flush=True),
        format="{time:HH:mm:ss} | {level} | {message}",
        colorize=True,
    )


TEMPLATE = """
filebeat.inputs:
  - type: log
    enabled: true
    paths:
      - /crs-logs/crs.log

output.file:
  path: {log_dir}
  filename: {log_name}
  codec.format:
    string: '%{{[message]}}'
"""


def setup_filebeat():
    if os.getenv("TEST_ROUND") != "True":
        return
    log_dir = f"/tarball-fs/raw_logs/"
    task_id = os.getenv("TASK_ID")
    if task_id:
        log_dir = f"{log_dir}/{task_id}"
    os.makedirs(log_dir, exist_ok=True)
    log_name = os.getenv("CRS_SERVICE_NAME") + ".log"
    conf_path = "/etc/filebeat/filebeat.yml"
    with open(conf_path, "w") as f:
        f.write(TEMPLATE.format(log_dir=log_dir, log_name=log_name))
    os.system(f"nohup filebeat -e -c {conf_path} > /dev/null 2>&1 &")
