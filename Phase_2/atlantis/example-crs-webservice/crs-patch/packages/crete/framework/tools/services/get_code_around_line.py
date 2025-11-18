from pathlib import Path

from langchain_core.tools import BaseTool

from crete.framework.environment.functions import resolve_project_path
from crete.framework.insighter.contexts import InsighterContext
from crete.utils.tools.callbacks import LoggingCallbackHandler


class GetCodeAroundLineTool(BaseTool):
    name: str = "get_code_around_line"
    description: str = "Get the code around a given line number in a file. window_size is the number of lines before and after the line number."

    def __init__(self, context: InsighterContext):
        super().__init__(
            callbacks=[LoggingCallbackHandler(context)],
        )
        self._context = context

    def _run(self, file: str, line_number: int, window_size: int) -> str:
        """
        Get the code around a given line number in a file. window_size is the number of lines before and after the line number.
        """
        return self._get_code_around_line_impl(
            self._context, file, line_number, window_size
        )

    def _get_code_around_line_impl(
        self,
        context: InsighterContext,
        file: str,
        line_number: int,
        window_size: int,
    ) -> str:
        """
        Example:

            10:     do{
            11:         printf("input item:");
            12:         buff = &items[i][0];
            13:         i++;
            14:         fgets(buff, 40, stdin);
            15:         buff[strcspn(buff, "\n")] = 0;
            16:     }while(strlen(buff)!=0);
            17:     i--;
            18: }
            19:
            20: void func_b(){

        """
        file_path = resolve_project_path(Path(file), context["pool"].source_directory)
        if not file_path:
            raise FileNotFoundError(f"File does not exist: {file_path}")

        file_content = file_path.read_text(errors="replace")
        lines = file_content.splitlines()
        start_line = max(0, line_number - window_size)
        end_line = min(len(lines), line_number + window_size)

        code_around_line = ""
        for i, line in enumerate(lines):
            if i >= start_line and i <= end_line:
                code_around_line += f"{i + 1}: {line}\n"
        return code_around_line
