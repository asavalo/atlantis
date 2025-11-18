from typing import override


class ProcessError(Exception):
    __match_args__ = ("stdout", "stderr", "return_code")

    @override
    def __init__(self, stdout: bytes, stderr: bytes, return_code: int) -> None:
        super().__init__(f"Process failed with return code {return_code}")
        self.stdout = stdout
        self.stderr = stderr
        self.return_code = return_code


class TimeoutExpired(Exception):
    __match_args__ = ("stdout", "stderr")

    def __init__(self, stdout: bytes, stderr: bytes) -> None:
        super().__init__("Timeout expired")
        self.stdout = stdout
        self.stderr = stderr
