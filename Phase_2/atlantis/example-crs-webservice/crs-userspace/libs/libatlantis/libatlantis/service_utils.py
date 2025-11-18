from functools import wraps
import logging
from textwrap import indent
import traceback
from typing import Any, Callable, TypeAlias

from google.protobuf.message import Message

from .protobuf import protobuf_repr


# type _SERVICE_CALLBACK_TYPE = Callable[[Message, int, Any], list[Message]]

_SERVICE_CALLBACK_TYPE: TypeAlias = Callable[[Message, int, Any], list[Message]]

def configure_logger(app_name: str):
    FORMAT = f'[%(asctime)s][{app_name}][%(levelname)s] %(message)s'
    logging.basicConfig(format=FORMAT, force=True)  # todo: why is force=True needed?


def service_callback(
    logger: logging.Logger, input_message_class: type, input_message_name: str, *, log: bool = True
) -> Callable[[_SERVICE_CALLBACK_TYPE], _SERVICE_CALLBACK_TYPE]:
    """
    Decorator function that wraps a libMSA callback function and adds
    some runtime type-checking and (optionally) logging
    """
    def inner(wrapped_func: _SERVICE_CALLBACK_TYPE) -> _SERVICE_CALLBACK_TYPE:
        @wraps(wrapped_func)
        def wrapper(input_message: Message, thread_id: int, context: Any) -> list[Message]:
            extra = {"thread_id": thread_id}

            if log:
                text = "\n".join([
                    "-" * 32,
                    f"{input_message_name} message received: {protobuf_repr(input_message)}",
                ])
                logger.info(text, extra=extra)

            if not isinstance(input_message, input_message_class):
                raise TypeError(f"Expected input_message to be of type {input_message_class.__name__}")

            try:
                messages = wrapped_func(input_message, thread_id, context)
                if messages is None:
                    raise ValueError(f"{input_message_name} handler returned None instead of a list of messages")
            except Exception:
                text = "\n".join([
                    f"Exception while processing {input_message_name} message:",
                    indent(traceback.format_exc(), f"[thread {thread_id}] "),
                ])
                logger.error(text, extra=extra)
                return []

            if log:
                if not messages:
                    last_word = "messages"
                elif len(messages) == 1:
                    last_word = "message:"
                else:
                    last_word = "messages:"

                text = "\n".join([
                    f"Sending {len(messages)} response {last_word}",
                    *(protobuf_repr(m) for m in messages),
                ])
                logger.info(text, extra=extra)

            return messages

        return wrapper

    return inner
