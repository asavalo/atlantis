class CommandInteractionError(Exception):
    __match_args__ = ("stdout", "stderr", "return_code")

    def __init__(self, stdout: bytes, stderr: bytes, return_code: int) -> None:
        super().__init__(
            f"Command failed with return code {return_code}\n\nstdout: {stdout}\n\nstderr: {stderr}"
        )
        self.stdout = stdout
        self.stderr = stderr
        self.return_code = return_code


class TimeoutExpired(Exception):
    __match_args__ = ("stdout", "stderr")

    def __init__(self, stdout: bytes, stderr: bytes) -> None:
        super().__init__("Command timed out")
        self.stdout = stdout
        self.stderr = stderr
