import functools
import logging
import warnings


def consume_exc(default=None):
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                print(f"[W] {func.__name__}: {str(e)}")
                return default

        return wrapper

    return decorator


def consume_exc_method(default=None, log=True):
    def decorator(method):
        @functools.wraps(method)
        def wrapper(self, *args, **kwargs):
            try:
                return method(self, *args, **kwargs)
            except Exception as e:
                if log is True:
                    print(f"[W] {method.__name__}: {str(e)}")
                return default

        return wrapper

    return decorator


def synchronized(lock_name):
    def decorator(method):
        @functools.wraps(method)
        def wrapper(self, *args, **kwargs) -> any:
            lock = getattr(self, lock_name)
            with lock:
                return method(self, *args, **kwargs)

        return wrapper

    return decorator


def deprecated(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        warnings.warn(
            f"{func.__name__} is deprecated and will be removed in a future version.",
            DeprecationWarning,
            stacklevel=2,
        )
        return func(*args, **kwargs)

    return wrapper


def step(logger_name, msg):
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            logger = logging.getLogger(logger_name)
            logger.info(msg)
            result = func(*args, **kwargs)
            logger.info(f"{msg} [DONE]")
            return result

        return wrapper

    return decorator
