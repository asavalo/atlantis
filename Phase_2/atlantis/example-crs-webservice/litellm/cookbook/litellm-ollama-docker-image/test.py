import openai
from atlantis.llm_compat import a_chat_completions_create, chat_completions_create

api_base = "http://0.0.0.0:8000"

openai.api_base = api_base
openai.api_key = "temp-key"
print(openai.api_base)


print("LiteLLM: response from proxy with streaming")
response = chat_completions_create(
    model="ollama/llama2",
    messages=[
        {
            "role": "user",
            "content": "this is a test request, acknowledge that you got it",
        }
    ],
    stream=True,
)

for chunk in response:
    print(f"LiteLLM: streaming response from proxy {chunk}")

response = chat_completions_create(
    model="ollama/llama2",
    messages=[
        {
            "role": "user",
            "content": "this is a test request, acknowledge that you got it",
        }
    ],
)

print(f"LiteLLM: response from proxy {response}")
