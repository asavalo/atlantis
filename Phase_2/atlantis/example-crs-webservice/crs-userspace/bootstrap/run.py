import os
import subprocess
from pathlib import Path
from textwrap import indent
import uuid
import traceback
import logging
import time
import shutil

from confluent_kafka.admin import AdminClient, NewTopic
from libatlantis.constants import (
    KAFKA_SERVER_ADDR,
    CP_CONFIG_TOPIC,
    HELLO_TOPIC,
    FILE_OPS_TOPIC,
    FILE_OPS_RESPONSE_TOPIC,
    ALL_TOPICS,
    IN_K8S,
    LARGE_DATA_DIR,
    ARTIFACTS_DIR,
    CRS_SCRATCH_DIR,
    NODE_NUM,
)
from libatlantis.protobuf import CPConfig, FileWrite, FileOps, FileOpsResponse, Message, Hello, protobuf_repr
from libmsa.kafka.producer import Producer
from libmsa.kafka.consumer import Consumer

from libatlantis.service_utils import configure_logger, service_callback
from libCRS.otel import install_otel_logger
from libmsa.runner import Runner, execute_consumers
from libmsa.thread.pool import QueuePolicy

# rip nice modularization
import config
from context import BootstrapContext

logger = logging.getLogger(__name__)

def create_topics() -> None:
    client = AdminClient({'bootstrap.servers': KAFKA_SERVER_ADDR})

    topics = [NewTopic(name) for name in ALL_TOPICS]
    futures = client.create_topics(topics)

    # ensure topic creation
    for topic, future in futures.items():
        try:
            future.result(timeout=10)
            logger.info(f'[Bootstrap] Created topic: {topic}')
        except Exception as e:
            logger.info(f'[Bootstrap] Failed to create {topic}')
    #client.create_topics([NewTopic(name) for name in ALL_TOPICS])


def create_cp_config() -> CPConfig:
    oss_fuzz_path = os.environ.get('CRS_OSS_FUZZ_PATH')
    crs_target_name = os.environ.get('CRS_TARGET_NAME')
    crs_target_src_path = os.environ.get('CRS_TARGET_SRC_PATH')
    task_id = os.environ.get('TASK_ID', str(uuid.uuid4()))
    deadline = int(os.environ.get('TASK_DEADLINE', time.time() + 3600 * 24 * 2))

    if not oss_fuzz_path:
        logger.info('[Bootstrap] CRS_OSS_FUZZ_PATH environment variable not found.'
            ' Please set it to the path of the oss-fuzz repository or extracted task oss-fuzz tarfile (e.g., "/oss_fuzz").')
        exit(-1)
    if not crs_target_name:
        logger.info('[Bootstrap] CRS_TARGET_NAME environment variable not found.'
            ' Please set it to the name of the CP (e.g., "aixcc/cpp/example-libpng").')
        exit(-1)
    if not crs_target_src_path:
        logger.info('[Bootstrap] CRS_TARGET_SRC_PATH environment variable not found.'
            ' Please set it to the path of the cloned CP repository or extracted task CP tarfile (e.g., "/src").')
        exit(-1)

    oss_fuzz_path = Path(oss_fuzz_path)
    crs_target_src_path = Path(crs_target_src_path)
    mode = get_mode(oss_fuzz_path, crs_target_name)

    if not oss_fuzz_path.is_dir():
        logger.info(f'[Bootstrap] CRS_OSS_FUZZ_PATH path "{oss_fuzz_path}" does not exist.')
        exit(-1)
    if not crs_target_src_path.is_dir():
        logger.info(f'[Bootstrap] CRS_TARGET_SRC_PATH path "{crs_target_src_path}" does not exist.')
        exit(-1)

    return CPConfig(
        oss_fuzz_path = str(oss_fuzz_path.resolve()),
        cp_name = crs_target_name,
        cp_src_path = str(crs_target_src_path.resolve()),
        mode = mode,
        task_id = task_id,
        deadline = deadline,
    )

def get_mode(oss_fuzz_path: Path, target_name: str) -> str:
    if IN_K8S:
        tar_dir = os.environ.get('CRS_TAR_DIR')
        focus = os.environ.get('CRS_FOCUS')
        if not tar_dir:
            logger.info('[Bootstrap] CRS_TAR_DIR environment variable not found.')
        tar_dir = Path(tar_dir)
        diff_tar = tar_dir / 'diff.tar.gz'
        return "delta" if diff_tar.exists() else "full"

    dot_aixcc_ref_diff = oss_fuzz_path / "projects" / target_name / ".aixcc/ref.diff"
    if not dot_aixcc_ref_diff.exists():
        return "full"
    return "delta"

def setup_data_volumes() -> None:
    logger.info('[Bootstrap] Copying artifacts...')
    rsync(Path('/data/artifacts'), ARTIFACTS_DIR)

    if IN_K8S:
        untar_tarballs()


def run(cmd, cwd=None):
    cmd = list(map(str, cmd))
    cwd = os.getcwd() if cwd is None else cwd
    logger.info(f'[Bootstrap] {" ".join(cmd)}')
    return subprocess.run(cmd, check=False, capture_output=True, cwd=str(cwd))


def untar(tar: Path, dst: Path):
    if not dst.exists():
        os.makedirs(dst, exist_ok=True)
    run(["tar", "--use-compress-program=pigz", "-xf", tar, "-C", dst])


def rsync(src: Path, dst: Path):
    if src.is_dir():
        src = f"{src}/."
    run(["rsync", "-a", src, dst])

def patch(cwd: Path, diff: Path):
    run(["git", "apply", "--reject", diff], cwd=cwd)
    run(["rm", "-rf", ".git"], cwd=cwd)

def untar_tarballs() -> None:
    tar_dir = os.environ.get('CRS_TAR_DIR')
    focus = os.environ.get('CRS_FOCUS')
    if not tar_dir:
        logger.info('[Bootstrap] CRS_TAR_DIR environment variable not found.')
        exit(-1)
    tar_dir = Path(tar_dir)
    oss_fuzz_tar = tar_dir / 'oss-fuzz.tar.gz'
    oss_fuzz_untar = Path('/oss_fuzz_untar')
    oss_fuzz_path = Path(os.environ.get('CRS_OSS_FUZZ_PATH'))
    crs_target_repo_tar = tar_dir / 'repo.tar.gz'
    crs_target_repo_untar = Path('/target_untar')
    crs_target_src_path = Path(os.environ.get('CRS_TARGET_SRC_PATH'))
    crs_target_name = os.environ.get('CRS_TARGET_NAME')
    crs_target_src_path_prepatch = CRS_SCRATCH_DIR / 'prepatch'

    logger.info('[Bootstrap] Untaring oss-fuzz...')
    untar(oss_fuzz_tar, oss_fuzz_untar)
    rsync(list(oss_fuzz_untar.iterdir())[0], oss_fuzz_path)
    dot_aixcc_dir = oss_fuzz_path / 'projects' / crs_target_name / '.aixcc'
    if dot_aixcc_dir.exists():
        print('[Bootstrap] Remove .aixcc directory that exists in the benchmarks...')
        shutil.rmtree(dot_aixcc_dir)
    print('[Bootstrap] Always make .aixcc directory...')
    os.makedirs(dot_aixcc_dir) # exist_ok=True shouldn't be needed

    logger.info('[Bootstrap] Untaring target repo...')
    untar(crs_target_repo_tar, crs_target_repo_untar)

    logger.info('[Bootstrap] Copying target src...')
    rsync(list(crs_target_repo_untar.iterdir())[0], crs_target_src_path)

    diff_tar = tar_dir / 'diff.tar.gz'
    if diff_tar.exists():
        logger.info('[Bootstrap] Copying target src again for prepatch...')
        rsync(list(crs_target_repo_untar.iterdir())[0], crs_target_src_path_prepatch)
        logger.info('[Bootstrap] Untaring diff...')
        diff_untar = Path('/diff_untar')
        untar(diff_tar, diff_untar)
        rsync(diff_untar / 'diff/ref.diff', oss_fuzz_path / 'projects' / crs_target_name / '.aixcc/ref.diff')
        logger.info('[Bootstrap] Applying diff...')
        patch(crs_target_src_path, diff_untar / 'diff/ref.diff')
        shutil.rmtree(diff_untar)

    shutil.rmtree(oss_fuzz_untar)
    shutil.rmtree(crs_target_repo_untar)

def main_2() -> None:
    setup_data_volumes()

    hello_producer = Producer(KAFKA_SERVER_ADDR, HELLO_TOPIC)
    node_idx = int(os.environ.get("NODE_IDX", "0"))
    hello_message = Hello(node_idx=node_idx)
    hello_producer.send_message(hello_message)

    group_id = f"bootstrap_{node_idx}"
    hello_consumer = Consumer(KAFKA_SERVER_ADDR, HELLO_TOPIC, group_id, Hello)
    received_messages = set()
    start = time.time()
    now = time.time()
    hello_timeout = 600
    if IN_K8S:
        node_num = NODE_NUM
    else:
        node_num = 1
    logger.info("Now trying to sync with other bootstrap nodes...")
    while len(received_messages) < node_num and now - start < hello_timeout:
        recv_option = hello_consumer.recv_message()
        if recv_option is None:
            time.sleep(2)
        else:
            received_messages.add(recv_option.node_idx)
    if len(received_messages) == node_num:
        logger.info(f"Looks like we received all bootstrap nodes messages {received_messages}")
    else:
        logger.info(f"Bootstrap hello??? {received_messages}")

    hello_consumer.close()

    NODE_IDX = int(os.environ.get("NODE_IDX", 0))
    if NODE_IDX == 0:
        logger.info('[Bootstrap] Creating Kafka topics...')
        create_topics()

        logger.info('[Bootstrap] Detecting CP configuration...')
        cp_config = create_cp_config()
        logger.info(indent(protobuf_repr(cp_config), '[Bootstrap] '))

        logger.info('[Bootstrap] Broadcasting CP configuration...')
        producer = Producer(KAFKA_SERVER_ADDR, CP_CONFIG_TOPIC)
        producer.send_message(cp_config)

    logger.info('[Bootstrap] Completed.')


@service_callback(logger, FileOps, "bootstrap")
def process_file_writes(
    input_message: FileOps, thread_id: int, context: BootstrapContext
) -> list[Message]: 
    # flush logs
    for handler in logging.getLogger().handlers:
        handler.flush()

    node_idx = int(os.environ.get("NODE_IDX", "0"))
    response = FileOpsResponse(
        writes = input_message.writes,
        extractions = input_message.extractions,
        node_idx = node_idx,
    )

    try: # always return response, this is what triggers some more logic like deepgen!
        context.process_file_writes(input_message)
    except:
        pass

    # flush logs again
    for handler in logging.getLogger().handlers:
        handler.flush()
    return [response]


def msa():
    logger.info("MSA Start!")
    context = BootstrapContext()

    # enforce that bootstrap is the only service that can write to shared dirs
    file_contexts = [context] * config.NUM_FILE_WRITE_THREADS
    file_runner = Runner(
        FILE_OPS_TOPIC,
        FileOps,
        config.GROUP_ID,
        FILE_OPS_RESPONSE_TOPIC,
        config.NUM_FILE_WRITE_THREADS,
        QueuePolicy.ROUND_ROBIN,
        process_file_writes,
        file_contexts,
    )

    consumers = [
        file_runner.execute_thread_pool(),
    ]
    execute_consumers(consumers)


def main() -> int:
    logger.info('[Bootstrap] Start!')
    configure_logger("bootstrap")
    install_otel_logger(action_name="bootstrap", action_category="building")
    try:
        main_2()
        msa()
        return 0
    except Exception:
        logger.info('[Bootstrap] Fatal error:')
        logger.info(indent(traceback.format_exc(), '[Bootstrap] '))
        return 2


if __name__ == "__main__":
    exit(main())
