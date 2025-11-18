import importlib.resources as pkg_resources
from typing import Generic, TypeVar

from langchain.prompts import ChatPromptTemplate, HumanMessagePromptTemplate
from langchain_core.messages import BaseMessage, SystemMessage
from langchain_core.output_parsers import PydanticOutputParser
from loguru import logger
from pydantic import BaseModel, Field

from sarif.types import PromptOutputT
from sarif.utils.jinja import jinja_env


def load_template_file(file_name: str) -> str:
    sub_dir = None
    if "/" in file_name:
        sub_dir, file_name = file_name.split("/")

    if sub_dir is not None:
        return pkg_resources.read_text(
            f"sarif.llm.prompt.templates.{sub_dir}", file_name
        )
    else:
        return pkg_resources.read_text("sarif.llm.prompt.templates", file_name)


default_input_variables = [
    "package_name",
    "package_language",
    "vuln_id",
    "sanitizer_output",
]


class BasePrompt(Generic[PromptOutputT]):
    def __init__(
        self,
        output_pydantic: PromptOutputT,
        human_template_file: str,
        input_variables: list = default_input_variables,
        messages: list[BaseMessage] | None = None,
        logprob_keys: list[str] | None = None,
        additional_prompt: str = "\n",
    ):
        self.output_pyantic = output_pydantic
        # self.parser = JsonOutputParser(pydantic_object=output_pydantic)
        self.parser = PydanticOutputParser(pydantic_object=output_pydantic)

        self.human_template_file = human_template_file
        self.template_message = load_template_file(self.human_template_file)
        self.human_message = load_template_file(self.human_template_file)
        self.system_message = load_template_file("basic_system.jinja2")

        self.input_variables = input_variables
        if human_template_file.endswith(".jinja2"):
            self.is_jinja = True
        else:
            self.is_jinja = False

        self.logprob_keys = logprob_keys
        self.additional_prompt = additional_prompt

        if messages == None or len(messages) == 0:
            messages = [
                SystemMessage(content=self.system_message),
            ]

        messages.append(
            HumanMessagePromptTemplate.from_template(
                self.human_message
                + "\n"
                + self.additional_prompt
                + "\n\n{format_instructions}",
                # self.human_message + self.additional_prompt + "\n\n{format_instructions}", template_format="jinja2"
            )
        )

        self.cur_msg_idx = len(messages) - 1

        self.template = ChatPromptTemplate(
            messages=messages,
            input_variables=self.input_variables,
            output_parser=self.parser,
            partial_variables={
                "format_instructions": self.parser.get_format_instructions(),
            },
            template_format="jinja2",
        )

    def update_template_with_input(self, input: dict | BaseModel):
        if isinstance(input, BaseModel):
            input = input.__dict__

        if not self.is_jinja:
            logger.warning(
                "This prompt is not jinja template. Skipping update_template_with_input"
            )
            return

        template = jinja_env.from_string(self.template_message)
        self.human_message = template.render(**input)
        # escape double curly braces
        self.human_message = self.human_message.replace("{", "{{").replace("}", "}}")

        # messages = self.template.messages
        # messages[1] = HumanMessagePromptTemplate.from_template(self.human_message + "\n\n{format_instructions}")

        self.template.messages[self.cur_msg_idx] = (
            HumanMessagePromptTemplate.from_template(
                self.human_message
                + "\n"
                + self.additional_prompt
                + "\n\n{format_instructions}",
                # self.human_message + "\n\n{format_instructions}", template_format="jinja2"
            )
        )

        self.template = ChatPromptTemplate(
            messages=self.template.messages,
            # input_variables=self.input_variables,
            output_parser=self.parser,
            partial_variables={
                "format_instructions": self.parser.get_format_instructions()
            },
            template_format="jinja2",
        )


def create_dynamic_model(base_model: BaseModel, branch_num: int):
    attributes = {}
    annotations = {}

    for name, field in base_model.model_fields.items():
        for i in range(1, branch_num + 1):
            new_name = f"{name}_{i}"

            field_type = field.annotation
            annotations[new_name] = field_type

            attributes[new_name] = Field(
                description=field.description,
                default=field.default if field.default is not None else ...,
                **field.json_schema_extra or {},
            )

    return type(
        f"Dynamic{base_model.__name__}",
        (BaseModel,),
        {
            **attributes,
            "__annotations__": annotations,
        },
    )


class BaseBranchPrompt(BasePrompt[PromptOutputT]):
    def __init__(
        self,
        output_pydantic: BaseModel,
        human_template_file: str,
        branch_num: int = 3,
        input_variables: list = default_input_variables,
        messages: list[BaseMessage] = None,
        logprob_keys: list[str] | None = None,
    ):
        new_output_pydantic = create_dynamic_model(output_pydantic, branch_num)

        super().__init__(
            output_pydantic=new_output_pydantic,
            human_template_file=human_template_file,
            input_variables=input_variables,
            messages=messages,
            logprob_keys=logprob_keys,
            additional_prompt=f"Provide as many diverse responses as possible. Regardless of your confidence, consider various possibilities.",
        )
