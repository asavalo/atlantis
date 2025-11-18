from typing import List

from pydantic import BaseModel, Field

from sarif.llm.prompt.base import BasePrompt


class VulnRootCauseModel(BaseModel):
    vuln_root_cause: str = Field(
        description="The root cause of the vulnerability in CWE format. (CWE ID and Name)"
    )
    rationale: str = Field(
        description="Rationale why you think this is the root cause."
    )


# Vuln Info
class VulnTypeModel(BaseModel):
    vuln_type: str = Field(
        description="Type of vulnerability in CWE format (CWE ID and Name)."
    )
    rationale: str = Field(
        description="Rationale why you think this is the type of vulnerability."
    )


class VulnDescModel(BaseModel):
    vuln_description: str = Field(description="Description of the vulnerability.")
    vuln_short_description: str = Field(
        description="Short description of the vulnerability."
    )
    rationale: str = Field(description="Rationale that supports the description.")


# Stack trace
class LocationModel(BaseModel):
    file_name: str = Field(description="File name.")
    line_number: int = Field(description="Line number.")
    function_name: str = Field(description="Function name.")


class LocationWithColumnModel(LocationModel):
    column_number: int = Field(description="Column number. If unknown, -1.")


class ParsedStackTraceModel(BaseModel):
    stack_trace: List[LocationWithColumnModel] = Field(
        description="The stack trace of the crash that only relates to the project code."
    )

class StackTraceModel(BaseModel):
    crash_stack_trace: List[LocationModel] = Field(
        description="The stack trace of the execution that directly caused the crash."
    )
    memory_free_stack_trace: List[LocationModel] = Field(
        description="Memory free stack trace of the vulnerability in Sanitizer output. If unknown, leave blank."
    )
    memory_allocate_stack_trace: List[LocationModel] = Field(
        description="Memory allocate stack trace of the vulnerability in Sanitizer output. If unknown, leave blank."
    )


#####################################################
###################### PROMPTS ######################
#####################################################


class VulnRootCausePrompt(BasePrompt[VulnRootCauseModel]):
    def __init__(self, **kwargs):
        super().__init__(
            VulnRootCauseModel, "vuln_info/vuln_root_cause.jinja2", **kwargs
        )


class VulnTypePrompt(BasePrompt[VulnTypeModel]):
    def __init__(self, **kwargs):
        super().__init__(VulnTypeModel, "vuln_info/vuln_type.jinja2", **kwargs)


class VulnDescPrompt(BasePrompt[VulnDescModel]):
    def __init__(self, **kwargs):
        super().__init__(VulnDescModel, "vuln_info/vuln_description.jinja2", **kwargs)


class ParseStackTracePrompt(BasePrompt[ParsedStackTraceModel]):
    def __init__(self, **kwargs):
        super().__init__(
            ParsedStackTraceModel, "vuln_info/parse_stack_trace.jinja2", **kwargs
        )


class GetStackTracePrompt(BasePrompt[StackTraceModel]):
    def __init__(self, **kwargs):
        super().__init__(StackTraceModel, "vuln_info/get_stack_trace.jinja2", **kwargs)


class FilterStackTracePrompt(BasePrompt[StackTraceModel]):
    def __init__(self, **kwargs):
        super().__init__(
            StackTraceModel, "vuln_info/filter_stack_trace.jinja2", **kwargs
        )


class WrongStackTracePrompt(BasePrompt[StackTraceModel]):
    def __init__(self, **kwargs):
        super().__init__(
            StackTraceModel, "vuln_info/wrong_stack_trace.jinja2", **kwargs
        )
