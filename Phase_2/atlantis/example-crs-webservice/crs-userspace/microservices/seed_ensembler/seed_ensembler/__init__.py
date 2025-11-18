import argparse
import logging
import os
from pathlib import Path
import subprocess
import time

try:
    from libatlantis.service_utils import configure_logger
except ImportError:
    def configure_logger(*args, **kwargs):
        logger.warning('libatlantis not available, skipping configure_logger()')

try:
    from libCRS.otel import install_otel_logger
except ImportError:
    def install_otel_logger(*args, **kwargs):
        logger.warning('libCRS.otel not available, skipping install_otel_logger()')

from libensembler import Configuration, run_with_debug, run_with_kafka


RUNNER_IMAGE = 'ghcr.io/aixcc-finals/base-runner:v1.3.0'


logger = logging.getLogger(__name__)


def run(argv: list[str] | None = None) -> None:
    logging.basicConfig(level=logging.INFO)

    parser = argparse.ArgumentParser(
        description='Application that listens for new seeds from various sources, '
            'and picks appropriate place(s) to send them to.',
    )
    parser.add_argument('--interface-mode', choices=('debug', 'kafka',), required=True,
        help='interface to use ("kafka" for CRS-Userspace)')
    parser.add_argument('--execution-mode', choices=('docker', 'chroot'), required=True,
        help='how to run libfuzzer: in Docker containers, or with chroot')
    parser.add_argument('--seeds-input-dir', type=Path, required=True,
        help='directory that libDeepGen will write its generated seeds into')
    parser.add_argument('--feedback-output-dir', type=Path, required=True,
        help='directory that libDeepGen will look for feedback jsons in')
    parser.add_argument('--temp-dir', type=Path, required=True,
        help='directory to use for temporary files (ideally in ramfs/tmpfs)')
    parser.add_argument('--worker-pool-size', type=int, metavar='N', required=True,
        help='number of worker processes managing libfuzzer instances')
    parser.add_argument('--duplicate-seeds-cache-size', type=int, metavar='N',
        help='number of recently seen seeds that the ensembler will remember,'
            ' to quickly filter out duplicates (unlimited if not specified)')
    parser.add_argument('--kafka-group-id', metavar='ID',
        help='manually set the group ID used to listen on Kafka topics'
        ' (default: "ensembler_{NODE_IDX}",'
        ' using the NODE_IDX environment variable, which defaults to "0")')

    parser.add_argument('--no-inotify', action='store_true',
        help="don't rely on inotify filesystem events to watch"
            ' directories for updates, and use a basic polling method instead')
    parser.add_argument('--verbose', action='store_true',
        help='enable verbose output mode')

    args = parser.parse_args(argv)

    configure_logger('ensembler')
    install_otel_logger(action_name='ensembler', action_category='scoring_submission')

    # for libCRS
    os.environ.update({
        'START_TIME': str(int(time.time())),
        'SANITIZER': os.environ.get('SANITIZER', 'address'),
    })

    logger.info('Start!')

    config = Configuration(
        args.seeds_input_dir,
        args.feedback_output_dir,
        args.temp_dir,
        args.worker_pool_size,
        args.duplicate_seeds_cache_size,
        not args.no_inotify,
        RUNNER_IMAGE if args.execution_mode == 'docker' else None,
        args.kafka_group_id,
        args.verbose,
    )

    # Spurious network failures here are very very bad, so...
    NUM_RETRIES = 10
    for i in range(NUM_RETRIES):
        try:
            subprocess.run(['docker', 'pull', RUNNER_IMAGE], check=True)
            break
        except subprocess.CalledProcessError:
            if i == NUM_RETRIES - 1:
                raise

    if args.interface_mode == 'debug':
        run_with_debug(config)
    elif args.interface_mode == 'kafka':
        run_with_kafka(config)
    else:
        # some other interface for crs-java
        raise NotImplementedError


main = run


if __name__ == '__main__':
    main()
