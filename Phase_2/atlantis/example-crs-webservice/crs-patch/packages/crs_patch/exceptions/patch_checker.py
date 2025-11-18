class PatchCheckerError(Exception):
    """Base exception for patch checker errors"""

    pass


class SourceDirectoryInitError(PatchCheckerError):
    """Raised when source directory initialization fails"""

    pass


class GitApplyError(PatchCheckerError):
    """Raised when git apply fails"""

    pass


class BuildError(PatchCheckerError):
    """Raised when build fails"""

    pass


class VulnerableError(PatchCheckerError):
    """Raised when patch introduces new vulnerabilities"""

    pass


class FunctionalTestError(PatchCheckerError):
    """Raised when functional tests fail after applying patch"""

    pass


class InvalidFileModificationError(PatchCheckerError):
    """Raised when patch modifies files that should not be modified"""

    pass


class PoVError(PatchCheckerError):
    """Raised when PoV fails"""

    pass
