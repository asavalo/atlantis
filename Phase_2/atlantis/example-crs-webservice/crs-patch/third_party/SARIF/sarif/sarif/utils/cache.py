import hashlib
import json
from functools import wraps
from pathlib import Path
from typing import Callable

import joblib
from loguru import logger


def clear_method_cache(obj: object, func: Callable):
    cache_attr = f"_cached_{func.__name__}"
    logger.debug(f"Attempting to clear cache for {cache_attr}")
    if hasattr(obj, cache_attr):
        # TODO: this is not working as expected. The function needs to be executed once for cache_attr to be created in the object
        logger.debug(f"Clearing cache for {func.__name__}")
        cached_func = getattr(obj, cache_attr)
        cached_func.clear()


def cache_function(mem: joblib.Memory):
    def decorator(func):
        return mem.cache(func)

    return decorator


def cache_method_with_attrs(
    mem: joblib.Memory,
    attr_names: list[str] = [],
):
    def decorator(func):
        cache_attr = f"_cached_{func.__name__}"

        @wraps(func)
        def wrapper(self, *args, **kwargs):
            extra_attrs = tuple(getattr(self, name) for name in attr_names)
            extra = (func.__name__,) + extra_attrs

            def wrapped_func(*args, **kwargs):
                return func(self, *args, **kwargs)

            def func_with_extra(*args, **kwargs):
                # TODO: should be fixed. don't use extra as tuple, but as custom class
                if args and isinstance(args[-1], tuple) and len(args[-1]) == len(extra):
                    return wrapped_func(*args[:-1], **kwargs)
                return wrapped_func(*args, **kwargs)

            if not hasattr(self, cache_attr):
                cached = mem.cache(func_with_extra)
                setattr(self, cache_attr, cached)

            cached_func = getattr(self, cache_attr)

            return cached_func(*args, extra, **kwargs)

        return wrapper

    return decorator


class HybridCache:
    def __init__(self, cache_dir=".cache/reachability", json_on: bool = True):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        self.joblib_dir = self.cache_dir / "joblib"
        self.joblib_dir.mkdir(exist_ok=True)
        self.memory = joblib.Memory(location=str(self.joblib_dir), verbose=0)

        self.json_on = json_on
        if self.json_on:
            self.json_dir = self.cache_dir / "json"
            self.json_dir.mkdir(exist_ok=True)

    def method_cache(self, func: Callable) -> Callable:
        @wraps(func)
        def wrapper(obj, *args, **kwargs):
            obj_state = {
                key: value
                for key, value in obj.__dict__.items()
                if not key.startswith("_")
            }

            obj_key = json.dumps(obj_state, sort_keys=True)

            def wrapped_func(*inner_args, **inner_kwargs):
                return func(obj, *inner_args, **inner_kwargs)

            wrapped_func.__name__ = (
                f"{obj.__class__.__name__}_{func.__name__}_{hash(obj_key)}"
            )
            cached_wrapped = self.memory.cache(wrapped_func)

            result = cached_wrapped(*args, **kwargs)

            if self.json_on:
                key_data = f"{func.__name__}:{obj_key}:{str(args)}:{str(sorted(kwargs.items()))}"
                key = hashlib.md5(key_data.encode()).hexdigest()

                func_dir = self.json_dir / str(func.__name__)
                func_dir.mkdir(exist_ok=True)
                json_file = func_dir / f"{key}.json"

                if not json_file.exists():
                    with open(json_file, "w") as f:
                        json.dump(result, f, indent=2)

            return result

        return wrapper

    def cache(self, func: Callable) -> Callable:
        cached_func = self.memory.cache(func)

        @wraps(func)
        def wrapper(*args, **kwargs):
            result = cached_func(*args, **kwargs)

            if self.json_on:
                key_data = f"{func.__name__}:{str(args)}:{str(sorted(kwargs.items()))}"
                key = hashlib.md5(key_data.encode()).hexdigest()

                func_dir = self.json_dir / str(func.__name__)
                func_dir.mkdir(exist_ok=True)
                json_file = func_dir / f"{key}.json"

                if not json_file.exists():
                    with open(json_file, "w") as f:
                        json.dump(result, f, indent=2)

            return result

        return wrapper
