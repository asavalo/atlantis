from pydantic import BaseModel
from pathlib import Path
from enum import Enum

"""C
   14 !_TAG_KIND_DESCRIPTION!C    d,macro /macro definitions/
   15 !_TAG_KIND_DESCRIPTION!C    e,enumerator    /enumerators (values inside an enumeration)/
   16 !_TAG_KIND_DESCRIPTION!C    f,function  /function definitions/
   17 !_TAG_KIND_DESCRIPTION!C    g,enum  /enumeration names/
   18 !_TAG_KIND_DESCRIPTION!C    h,header    /included header files/
   19 !_TAG_KIND_DESCRIPTION!C    m,member    /struct, and union members/
   20 !_TAG_KIND_DESCRIPTION!C    s,struct    /structure names/
   21 !_TAG_KIND_DESCRIPTION!C    t,typedef   /typedefs/
   22 !_TAG_KIND_DESCRIPTION!C    u,union /union names/
   23 !_TAG_KIND_DESCRIPTION!C    v,variable  /variable definitions/
"""

"""JAVA
    14 !_TAG_KIND_DESCRIPTION!Java a,annotation    /annotation declarations/
    15 !_TAG_KIND_DESCRIPTION!Java c,class /classes/
    16 !_TAG_KIND_DESCRIPTION!Java e,enumConstant  /enum constants/
    17 !_TAG_KIND_DESCRIPTION!Java f,field /fields/
    18 !_TAG_KIND_DESCRIPTION!Java g,enum  /enum types/
    19 !_TAG_KIND_DESCRIPTION!Java i,interface /interfaces/
    20 !_TAG_KIND_DESCRIPTION!Java m,method    /methods/
    21 !_TAG_KIND_DESCRIPTION!Java p,package   /packages/
"""


class TagKind(Enum):
    MACRO = "macro"
    ENUMERATOR = "enumerator"
    FUNCTION = "function"
    ENUM = "enum"
    HEADER = "header"
    MEMBER = "member"
    STRUCT = "struct"
    TYPEDEF = "typedef"
    UNION = "union"
    VARIABLE = "variable"
    ANNOTATION = "annotation"
    CLASS = "class"
    FIELD = "field"
    ENUMCONSTANT = "enumConstant"
    INTERFACE = "interface"
    METHOD = "method"
    PACKAGE = "package"


class CtagEntry(BaseModel):
    abs_src_path: Path
    rel_src_path: Path
    line: int
    name: str
    kind: TagKind
    pattern: str
    scope: str | None
