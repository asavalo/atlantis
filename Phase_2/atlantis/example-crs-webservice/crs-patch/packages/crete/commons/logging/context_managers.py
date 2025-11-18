import time
from contextlib import contextmanager

from crete.commons.logging.contexts import LoggingContext


@contextmanager
def logging_performance(context: LoggingContext, header: str):
    context["logger"].info(
        f"[logging_performance]({context['logging_prefix']} {header}) Started..."
    )

    start = time.perf_counter()
    try:
        exception = False
        yield
    except:
        exception = True
        raise
    finally:
        end = time.perf_counter()

        context["logger"].info(
            f"[logging_performance]({context['logging_prefix']} {header}) Took {end - start:.2f} seconds; exception={exception}"
        )
