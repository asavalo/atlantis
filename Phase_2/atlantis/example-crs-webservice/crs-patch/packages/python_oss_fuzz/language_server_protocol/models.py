from pathlib import Path

from typing import Optional
from pydantic import BaseModel
from pylspclient.lsp_pydantic_strcuts import Range


class Location(BaseModel):
    file: Path
    range: Range


class SymbolInformation(BaseModel):
    name: str

    # NOTE: The `kind` and `deprecated` fields are included together in the response to the LSP documentSymbol request.
    # They are left as comments because they can be used later.

    # kind: SymbolKind
    # deprecated: Optional[bool] = None
    location: Location
    # NOTE: The containerName field returns the expression of the entire symbol, not the symbol name.
    # e.g: public method_name(arg1, arg2)
    # Therefore, when using the field later, you need to process it so that only the symbol name can be written.
    containerName: Optional[str] = None
