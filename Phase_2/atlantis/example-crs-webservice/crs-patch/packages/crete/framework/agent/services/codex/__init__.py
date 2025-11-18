import inspect
from typing import Iterator

from python_llm.api.actors import LlmApiManager

from crete.atoms.action import Action, NoPatchAction
from crete.atoms.detection import Detection
from crete.commons.crash_analysis.functions import get_bug_class
from crete.framework.agent.contexts import AgentContext
from crete.framework.agent.protocols import AgentProtocol
from crete.framework.coder.services.codex import CodexCoder
from crete.framework.insighter.protocols import InsighterProtocol
from crete.framework.insighter.services.crash_log import CrashLogInsighter

USER_PROMPT_TEMPLATE = inspect.cleandoc(
    """
    Create a patch to fix a {bug_class} bug given below and apply it to the code.
    NEVER fix files outside the source directory.
    NEVER do any git operations in or outside the source directory.

    {insights}
    """
).lstrip()

DEFAULT_INSIGHTS_TEMPLATE = inspect.cleandoc(
    """
    Below is the crash log:

    <crash_log>
    {crash_log}
    </crash_log>
    """
).lstrip()


class CodexAgent(AgentProtocol):
    def __init__(
        self,
        llm_api_manager: LlmApiManager,
        insighters: list[InsighterProtocol] = [],
    ) -> None:
        self._insighters = insighters
        self._llm_api_manager = llm_api_manager

    def act(self, context: AgentContext, detection: Detection) -> Iterator[Action]:
        coder = CodexCoder(context, detection, self._llm_api_manager)
        prompt = make_prompt(context, detection)
        diff = coder.run(context, prompt)

        action: Action
        if diff is None or len(diff.strip()) == 0:
            action = NoPatchAction()
        else:
            action = context["evaluator"].evaluate(context, diff, detection)

        yield action


def make_prompt(context: AgentContext, detection: Detection) -> str:
    bug_class = get_bug_class(context, detection) or ""
    crash_log = CrashLogInsighter().create(context, detection)
    insights = DEFAULT_INSIGHTS_TEMPLATE.format(crash_log=crash_log)
    return USER_PROMPT_TEMPLATE.format(bug_class=bug_class, insights=insights)
