import os
import openai
from atlantis.llm_compat import a_chat_completions_create, chat_completions_create

KEY = os.getenv("LITELLM_MASTER_KEY")
URL = os.getenv("LITELLM_URL")

TESTING_MODELS = [
    "claude-3-5-sonnet-20241022",
    "claude-3-7-sonnet-20250219",
    "claude-opus-4-20250514",
    "claude-sonnet-4-20250514",
    "gemini-2.5-flash",
    "gemini-2.5-pro",
    "gpt-4.1",
    "gpt-4.1-mini",
    "gpt-4o",
    "gpt-4o-mini",
    "grok-3",
    "grok-3-beta",
    "grok-3-mini",
    "grok-3-mini-beta",
    "o3",
    "o3-mini",
    "o4-mini",
    # "text-embedding-3-large",
    # "text-embedding-3-small",
]


def llm_model_test(model: str):
    print("Testing model: ", model)
    try:
        client = openai.OpenAI(api_key=KEY, base_url=URL)
        response = chat_completions_create(
            model=model,
            messages=[
                {
                    "role": "user",
                    "content": "this is a test request, write a short poem",
                }
            ],
        )
        if len(response.choices) == 0:
            print("Fail to get response of ", model)
            exit(-1)
        print(response)
    except Exception as e:
        print(e)


def test_tailscale():
    ret = os.system(
        "curl -u $COMPETITION_API_KEY_ID:$COMPETITION_API_KEY_TOKEN https://api.tail7e9b4c.ts.net/v1/ping -v"
    )
    assert ret == 0


for model in TESTING_MODELS:
    llm_model_test(model)

test_tailscale()
