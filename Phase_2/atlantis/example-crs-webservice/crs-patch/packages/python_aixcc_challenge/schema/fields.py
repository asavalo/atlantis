import re
from pathlib import Path
from typing import Annotated

from pydantic import AfterValidator, BeforeValidator

PathString = Annotated[Path, AfterValidator(lambda v: Path(v))]
CommitHexString = Annotated[
    str, BeforeValidator(lambda x: x if re.match(r"^[a-f0-9]{40}$", x) else None)
]
