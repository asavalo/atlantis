import json
import os
import time
from functools import wraps
from typing import Type

from loguru import logger
from pydantic import BaseModel

from sarif.context import SarifCodeContextManager


def log_node(graph_name: str, enabled: bool = True):
    def decorator(func):
        if not enabled:
            return func

        def wrapper(state: BaseModel):
            logger.debug(f"Running {graph_name} graph node: {func.__name__}")
            return func(state)

        return wrapper

    return decorator


def read_node_cache(
    graph_name: str,
    cache_model: Type[BaseModel],
    mock: bool = False,
    enabled: bool = False,
):
    # Simple langgraph node cache
    def decorator(func):
        if not enabled:
            return func

        def wrapper(state: BaseModel):
            cache_name = f"{graph_name}_output.json"
            if os.path.exists(
                os.path.join(SarifCodeContextManager().out_dir, cache_name)
            ):
                logger.debug(f"{cache_name} exists. Loading saved state.")

                if mock:
                    return {"last_node": "cached"}

                with open(
                    os.path.join(SarifCodeContextManager().out_dir, cache_name),
                    "r",
                ) as f:
                    new_state_dict = json.load(f)

                    new_state = cache_model(**new_state_dict)

                    return new_state

            return func(state)

        return wrapper

    return decorator


def write_node_cache(
    graph_name: str, cache_model: Type[BaseModel], enabled: bool = False
):
    # Simple langgraph node cache
    def decorator(func):
        if not enabled:
            return func

        def wrapper(state: BaseModel):
            new_state: BaseModel = func(state)

            cache_state = cache_model(**new_state.model_dump())
            cache_name = f"{graph_name}_output.json"

            with open(
                os.path.join(SarifCodeContextManager().out_dir, cache_name), "w"
            ) as f:
                json.dump(cache_state.model_dump(), f)

            logger.debug(f"Saved state to {cache_name}")

            return new_state

        return wrapper

    return decorator


def measure_time(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        start = time.perf_counter()
        result = func(*args, **kwargs)
        end = time.perf_counter()
        logger.info(f"{func.__name__} took {end - start:.4f} seconds")
        return result

    return wrapper
