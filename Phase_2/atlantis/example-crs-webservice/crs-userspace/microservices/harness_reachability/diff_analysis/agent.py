from openai import OpenAI
import os

BASE_URL = os.environ.get("AIXCC_LITELLM_HOSTNAME")
LITELLM_KEY = os.environ.get("LITELLM_KEY")

client = OpenAI(
    api_key=LITELLM_KEY,
    base_url=BASE_URL,
)

def choose_location_in_hunk(hunk: str):
    line_count = hunk.count('\n') + 1 if hunk else 0
    if line_count < 100:
        nlocations = 1
    elif line_count < 200:
        nlocations = 2
    else:
        nlocations = 3
    response = client.completions.create(
        model="o3",
        prompt=f"You are an source code target location picker for directed fuzzing. Given a hunk from a diff, choose a line number from an *addition* (i.e. +) that is a good location to directed fuzz. You may choose up to {nlocations} locations. Return only the line number, separated by newlines if multiple.\n{hunk}"
    )
    return response.choices[0].text

def choose_prioritized_locations(all_hunks: str):
    prompt = """You are a source code target location picker for directed fuzzing. Given one or more hunks from a diff, choose locations from additions (i.e. +) that would be the best locations to target with directed fuzzing. 

The diff likely represents the introduction of new features or functionality. Focus on identifying:
1. New feature entry points and their core implementation
2. Conditions or at least something inside the function body
3. Meaningful function location that is not shallow
4. No duplicate/redundant locations. The directed fuzzer location is lenient, so two locations in the same function whose BB distance is close are not needed.

For each location, return the filename and line number in the format 'filename:linenum', one per line, in order of priority (most important first)."""
    
    response = client.completions.create(
        model="o3",
        prompt=f"{prompt}\n\n{all_hunks}"
    )
    return response.choices[0].text
