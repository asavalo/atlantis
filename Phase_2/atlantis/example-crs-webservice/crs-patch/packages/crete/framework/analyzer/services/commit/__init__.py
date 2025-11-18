from crete.atoms.detection import Detection
from crete.framework.agent.contexts import AgentContext
from crete.framework.analyzer.services.commit.functions import (
    get_call_stack_array,
    get_function_patches,
    get_prompts_from_pov_results,
    llm_commit_analyze,
    get_all_diff,
    convert_all_diff_to_patches,
)
from crete.framework.analyzer.services.commit.models import LLMCommitAnalysis
from python_llm.api.actors import LlmApiManager
from typing import List


class CommitAnalyzer:
    def __init__(self, llm_api_manager: LlmApiManager) -> None:
        self.llm_api_manager = llm_api_manager

    def analyze(
        self, context: AgentContext, detection: Detection
    ) -> List[LLMCommitAnalysis] | None:
        call_stack_array = get_call_stack_array(context, detection)

        assert call_stack_array is not None, "call_stack_array should not be None"

        function_patches = get_function_patches(context, detection, call_stack_array)

        if function_patches is None:
            all_diff = get_all_diff(context, detection)
            if all_diff is None:
                return None

            function_patches = convert_all_diff_to_patches(all_diff)

        function_analyze_result = llm_commit_analyze(
            llm_api_manager=self.llm_api_manager,
            context=context,
            detection=detection,
            patches=function_patches,
            sanitizer_prompt=get_prompts_from_pov_results(context, detection),
        )

        return function_analyze_result
