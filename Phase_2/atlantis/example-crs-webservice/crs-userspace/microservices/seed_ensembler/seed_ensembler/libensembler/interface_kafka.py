import importlib.util
from typing import NoReturn

from .models import Configuration

__all__ = ['run_with_kafka']

have_libatlantis = importlib.util.find_spec('libatlantis')
have_libmsa = importlib.util.find_spec('libmsa')

if have_libatlantis and have_libmsa:
    # Real implementation
    from .interface_kafka_inner import run_with_kafka
else:
    # Dummy implementation, just shows an error message
    def run_with_kafka(config: Configuration) -> NoReturn:
        if not have_libmsa and not have_libatlantis:
            missing = 'libMSA and libatlantis'
        elif not have_libmsa:
            missing = 'libMSA'
        else:
            missing = 'libatlantis'
        raise RuntimeError(f'{missing} not available, so Kafka ensembler interface not available')
