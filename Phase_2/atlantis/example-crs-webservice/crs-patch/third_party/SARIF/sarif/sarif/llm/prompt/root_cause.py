from pydantic import BaseModel, Field

from sarif.llm.prompt.base import BaseBranchPrompt, BasePrompt
from sarif.llm.prompt.vuln_info import LocationModel


# Predicate
class PredicateModel(BaseModel):
    location: LocationModel = Field(description="Location of the predicate.")
    rank: int = Field(description="Ranking of the predicate.")
    score: float = Field(description="Ranking score of the predicate.")
    # reasons: List[str] = Field(description="Reasons why the predicate is selected by root cause analysis tool.")


# Root cause
class SelectRootCauseModel(BaseModel):
    root_cause_id: int = Field(description="ID of the root cause candidate.")
    select_rationale: str = Field(
        description="Rationale why the location is selected as the root cause."
    )


class EvalRootCauseModel(BaseModel):
    score: float = Field(
        description="rovide a numeric evaluation of the LLM's answer. Select a number between 1 (worst) and 10 (best)."
    )
    confidence: float = Field(
        description="Indicate your confidence in the given numeric score. Provide a number between 1 (no confidence) and 10 (absolute confidence)."
    )
    eval_rationale: str = Field(
        description="Explain the reasoning behind the numeric score you provided."
    )


#####################################################
###################### PROMPTS ######################
#####################################################


class SelectRootCausePrompt(BasePrompt[SelectRootCauseModel]):
    def __init__(self, **kwargs):
        super().__init__(SelectRootCauseModel, "root_cause/select.jinja2", **kwargs)


class SelectRootCauseBranchPrompt(BaseBranchPrompt[SelectRootCauseModel]):
    def __init__(self, branch_num: int = 3, **kwargs):
        super().__init__(
            SelectRootCauseModel,
            "root_cause/select.jinja2",
            branch_num=branch_num,
            **kwargs
        )


class EvalRootCausePrompt(BasePrompt[EvalRootCauseModel]):
    def __init__(self, **kwargs):
        super().__init__(EvalRootCauseModel, "root_cause/eval.jinja2", **kwargs)
