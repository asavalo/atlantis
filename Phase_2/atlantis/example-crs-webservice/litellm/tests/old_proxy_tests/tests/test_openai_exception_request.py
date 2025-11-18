import openai
import httpx
import os
from dotenv import load_dotenv
from atlantis.llm_compat import a_chat_completions_create, chat_completions_create

load_dotenv()
client = openai.OpenAI(
    api_key="anything",
    base_url="http://0.0.0.0:8000",
    http_client=httpx.Client(verify=False),
)

try:
    # request sent to model set on litellm proxy, `litellm --model`
    response = chat_completions_create(
        model="azure-gpt-3.5",
        messages=[
            {
                "role": "user",
                "content": "this is a test request, write a short poem" * 2000,
            }
        ],
    )

    print(response)
except Exception as e:
    print(e)
    variables_proxy_exception = vars(e)
    print("proxy exception variables", variables_proxy_exception.keys())
    print(variables_proxy_exception["body"])


api_key = os.getenv("AZURE_API_KEY")
azure_endpoint = os.getenv("AZURE_API_BASE")
print(api_key, azure_endpoint)
client = openai.AzureOpenAI(
    api_key=os.getenv("AZURE_API_KEY"),
    azure_endpoint=os.getenv("AZURE_API_BASE", "default"),
)
try:
    response = chat_completions_create(
        model="chatgpt-v-3",
        messages=[
            {
                "role": "user",
                "content": "this is a test request, write a short poem" * 2000,
            }
        ],
    )
except Exception as e:
    print(e)
    variables_exception = vars(e)
    print("openai client exception variables", variables_exception.keys())
