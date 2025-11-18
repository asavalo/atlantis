from pydantic import Field

from sarif.llm.prompt.base import BasePrompt
from sarif.llm.prompt.vuln_info import LocationModel


# Predicate
class RelatedLocationModel(LocationModel):
    message: str = Field(
        ...,
        description="Short message of why this location is related to the crash location.",
    )


# class RelatedLocationModel(SARIFLocationModel): ...


#####################################################
###################### PROMPTS ######################
#####################################################


class RelatedLocationPrompt(BasePrompt[RelatedLocationModel]):
    def __init__(self, **kwargs):
        super().__init__(
            RelatedLocationModel, "sarif/related_location.jinja2", **kwargs
        )
