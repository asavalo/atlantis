from pathlib import Path

import pytest
from crete.atoms.path import PACKAGES_DIRECTORY
from python_llm.api.actors import LlmApiManager

from tests.common.utils import make_portable, revert_portable


def test_make_portable():
    # Test address replacement
    for input_text, expected in [
        ("Error at 0x0123456789abcdef", "Error at 0x0000000000000000"),
        (b"Error at 0x0123456789abcdef", b"Error at 0x0000000000000000"),
    ]:
        assert expected == make_portable(input_text)

    # Test directory replacements
    for input_text, expected in [
        # CURDIR replacement
        (str(Path.cwd()) + "/test.txt", "$CURDIR/test.txt"),
        (str(Path.cwd()).encode() + b"/test.txt", b"$CURDIR/test.txt"),
        # HOME replacement
        (str(Path.home()) + "/test.txt", "$HOME/test.txt"),
        (str(Path.home()).encode() + b"/test.txt", b"$HOME/test.txt"),
        # PACKAGE_DIR replacement
        (str(PACKAGES_DIRECTORY) + "/test.txt", "$PACKAGE_DIR/test.txt"),
        (str(PACKAGES_DIRECTORY).encode() + b"/test.txt", b"$PACKAGE_DIR/test.txt"),
        # TMPFILE replacement
        ("/tmp/tmp123abc/file.txt", "$TMPFILE/file.txt"),
        (b"/tmp/tmp123abc/file.txt", b"$TMPFILE/file.txt"),
        # TMPFILE replacement
        ("/tmp/tmp123abc Hello World", "$TMPFILE Hello World"),
        (b"/tmp/tmp123abc Hello World", b"$TMPFILE Hello World"),
    ]:
        assert expected == make_portable(input_text)


@pytest.mark.vcr()
def test_portable_recording():
    def llm_echo(msg: str) -> str:
        llm_api_manager = LlmApiManager.from_environment(
            model="gpt-4o", custom_llm_provider="openai"
        )

        chat_model = llm_api_manager.langchain_litellm()
        response = chat_model.invoke(
            f"Just echo back the following message without any modification. Don't add any other text, but just the message: {msg}",
            max_tokens=100,
        )

        return response.content  # type: ignore

    assert llm_echo("Hello World") == "Hello World"

    for input_text, strict in [
        (str(Path.cwd()) + "/test.txt", True),
        (str(Path.home()) + "/test.txt", True),
        ("/tmp/tmp123abc/file.txt", False),
        ("Error at 0xabcd1234", False),
    ]:
        if strict:
            assert input_text == llm_echo(input_text)


def test_revert_portable():
    for input_text in [
        str(Path.cwd()) + "/test.txt",
        str(Path.cwd()).encode() + b"/test.txt",
        str(Path.home()) + "/test.txt",
        str(Path.home()).encode() + b"/test.txt",
        str(PACKAGES_DIRECTORY) + "/test.txt",
        str(PACKAGES_DIRECTORY).encode() + b"/test.txt",
    ]:
        assert input_text == revert_portable(make_portable(input_text))
