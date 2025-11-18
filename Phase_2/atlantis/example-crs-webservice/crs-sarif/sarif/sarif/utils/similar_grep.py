import glob
import os
import re

from rapidfuzz import fuzz


def compile_source_snippet(search_filename: str, start: int, end: int):
    if not os.path.exists(search_filename):
        raise ValueError("Source file location is invalid")

    with open(search_filename, "r") as f:
        file_lines = f.readlines()
        search_snippet = "".join(file_lines[start - 1 : end])
        search_snippet = re.sub(r"\s+", "", search_snippet)

    if not search_snippet:
        raise ValueError("Target location is invalid")

    return search_snippet


def find_similar_snippet(
    target_filename: str, search_snippet: str, start: int, end: int
):

    search_snippet_linecnt = end - start + 1

    if not search_snippet:
        raise ValueError("Target location is invalid")

    if not os.path.exists(target_filename):
        raise ValueError("Target filename is invalid")

    with open(target_filename, "r") as f:
        content_lines = f.readlines()

    if len(content_lines) < end:
        raise ValueError("Target has too small lines")

    # needle_len = len(search_snippet)
    best_matches = list()

    for i in range(len(content_lines) - search_snippet_linecnt):
        window = "".join(content_lines[i : i + search_snippet_linecnt])
        window = re.sub(r"\s+", "", window)
        similarity = fuzz.ratio(search_snippet, window)

        if similarity > 90:
            line_num = i + 1
            best_matches.append(
                (
                    target_filename,
                    line_num,
                    line_num + search_snippet_linecnt - 1,
                    similarity,
                )
            )

    return sorted(best_matches, key=lambda x: x[3], reverse=True)[0]


def is_valid_source_file(filename: str) -> bool:
    if "." not in filename:
        return False

    file_ext = filename.split(".")[-1]
    if file_ext in ["c", "cpp", "in", "h", "hpp", "cc"]:
        return True
    return False


def _grep_for_light_snippet(
    src_dir: str, target_dir: str, search_filename: str, start: int, end: int
):
    full_search_filepath = os.path.join(src_dir, search_filename)
    try:
        search_snippet = compile_source_snippet(full_search_filepath, start, end)
    except Exception:
        return list()

    files = glob.glob(f"{target_dir}/**", recursive=True)
    detecteds = list()
    for file in files:
        if os.path.isfile(file) and is_valid_source_file(os.path.basename(file)):
            try:
                # Outputs: [filepath, line_start, line_end, similarity]
                detecteds.append(find_similar_snippet(file, search_snippet, start, end))
            except Exception:
                pass

    detecteds = sorted(detecteds, key=lambda x: x[3], reverse=True)
    result = list()
    for detected in detecteds:
        if detected[0] == full_search_filepath:
            continue
        result.append(
            {
                "filepath": os.path.relpath(detected[0], target_dir),
                "start": detected[1],
                "end": detected[2],
                "similarity": detected[3],
            }
        )

    return result


def _race_candidates(
    src_dir: str,
    target_dir: str,
    search_filename: str,
    start: int,
    end: int,
    candidates: list,
):
    full_search_filepath = os.path.join(src_dir, search_filename)
    try:
        search_snippet = compile_source_snippet(full_search_filepath, start, end)
    except Exception:
        return list()

    result = list()
    for candidate in candidates:
        try:
            full_candidate_file_path = os.path.join(target_dir, candidate["filepath"])
            candidate_snippet = compile_source_snippet(
                full_candidate_file_path, candidate["start"], candidate["end"]
            )
            similarity = fuzz.ratio(search_snippet, candidate_snippet)
            if similarity > 90:
                candidate["similarity"] = similarity
                result.append(candidate)

        except Exception:
            continue

    return result


def similar_grep(
    src_dir: str, target_dir: str, search_filename: str, start: int, end: int
):
    if end - start < 20:
        return _grep_for_light_snippet(src_dir, target_dir, search_filename, start, end)

    snippet_components = list()
    snippet_components_cnt = min((end - start) // 20, 3)
    total_lines = end - start + 1

    for i in range(snippet_components_cnt):
        center = start + (total_lines * (i + 1)) // (snippet_components_cnt + 1)
        component_start = max(start, center - 10)
        component_end = min(end, component_start + 20 - 1)
        snippet_components.append((component_start, component_end))

    candidates = list()
    for snippet_component in snippet_components:
        distance_for_start = snippet_component[0] - start
        distance_for_end = end - snippet_component[1]

        candidate_components = _grep_for_light_snippet(
            src_dir,
            target_dir,
            search_filename,
            snippet_component[0],
            snippet_component[1],
        )

        for candidate_component in candidate_components:
            candidate_component["start"] = (
                candidate_component["start"] - distance_for_start
            )
            candidate_component["end"] = candidate_component["end"] + distance_for_end
            candidate_component.pop("similarity")
            candidates.append(candidate_component)

    candidates = list({tuple(d.items()): d for d in candidates}.values())
    return _race_candidates(
        src_dir, target_dir, search_filename, start, end, candidates
    )


if __name__ == "__main__":
    import json

    # SRC_ROOT: vanila source code directory
    # TARGET_ROOT: CodeQL's unzipped src directory
    SRC_ROOT = "/home/azurefox/Desktop/sqlite3-src"
    TARGET_ROOT = "/home/azurefox/Downloads/src"
    result = similar_grep(
        SRC_ROOT,
        TARGET_ROOT,
        "src/callback.c",  # sarif's uri
        120,
        127,
    )
    print(json.dumps(result, indent=2))
