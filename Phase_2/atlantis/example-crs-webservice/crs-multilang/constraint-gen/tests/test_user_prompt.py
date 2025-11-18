from os import wait
from pathlib import Path

from resolve.prompting import construct_user_prompt
from resolve.inconsistency import parse_inconsistency

def test_user_prompt():
    src = Path(__file__).parent / "samples/nginx/src"
    inconsistency = Path(__file__).parent / "samples/nginx/inconsistency.json"

    parsed_inconsistency = parse_inconsistency(inconsistency)
    user_prompt = construct_user_prompt(parsed_inconsistency, src, "def previous_code():\n\tpass")
    print(user_prompt)
