from libatlantis.constants import KAFKA_SERVER_ADDR as _KAFKA_SERVER_ADDR


GROUP_ID = "telemetry_logger"

# 2025-03-26: Not sure why kafka-python is claiming two of these keys
# are invalid now
CONSUMER_ARGS = {
    "bootstrap_servers": _KAFKA_SERVER_ADDR,
    "group_id": GROUP_ID,
    # "group_instance_id": GROUP_ID,
    # "leave_group_on_close": False,
    "enable_auto_commit": True,
    "auto_commit_interval_ms": 100,
}
