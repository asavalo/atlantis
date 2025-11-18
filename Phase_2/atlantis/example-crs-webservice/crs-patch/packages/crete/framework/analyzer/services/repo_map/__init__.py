import math
from collections import Counter, defaultdict
from pathlib import Path
from typing import Callable, Iterator, NamedTuple, cast

import litellm
import networkx as nx
from grep_ast import TreeContext
from pygments.lexers import guess_lexer_for_filename
from pygments.token import Token
from python_aixcc_challenge.language.types import Language
from python_llm.api.actors import LlmApiManager
from tree_sitter_language_pack import get_language, get_parser

from crete.atoms.detection import Detection
from crete.commons.utils import not_none
from crete.framework.analyzer.services.repo_map.functions import filter_important_files
from crete.framework.analyzer.services.repo_map.queries import (
    c_tags_scm,
    cpp_tags_scm,
    java_tags_scm,
)
from crete.framework.evaluator.contexts import EvaluatingContext
from crete.framework.fault_localizer.functions import get_git_tracked_files

Tag = NamedTuple(
    "Tag",
    [
        ("relative_filename", Path),
        ("filename", Path),
        ("line", int),
        ("name", str),
        ("kind", str),
    ],
)


class RepoMapAnalyzer:
    def __init__(self, llm_api_manager: LlmApiManager):
        self._llm_api_manager = llm_api_manager

    def analyze(
        self,
        context: EvaluatingContext,
        detection: Detection,
        target_files: list[Path],
    ) -> str | None:
        caching_function = cast(  # pyright: ignore[reportUnknownVariableType]
            Callable[..., str | None],
            context["memory"].cache(  # pyright: ignore[reportUnknownMemberType]
                self._analyze_no_cache, ignore=["context"]
            ),
        )
        return caching_function(context, detection, target_files)

    def _analyze_no_cache(
        self,
        context: EvaluatingContext,
        detection: Detection,
        target_files: list[Path],
    ) -> str | None:
        all_absolute_files = set(
            _all_files_in_absolute_path(context["pool"].source_directory)
        )
        other_files = list(all_absolute_files - set(target_files))
        all_absolute_files = list(all_absolute_files)

        try:
            return _get_repo_map(
                context=context,
                detection=detection,
                chat_filenames=target_files,
                other_filenames=other_files,
                llm_api_manager=self._llm_api_manager,
            )

        except RecursionError:
            # Repo is too large
            pass
        except Exception:
            pass

        # Fallback to global repo map.
        try:
            return _get_repo_map(
                context=context,
                detection=detection,
                chat_filenames=[],
                other_filenames=all_absolute_files,
                llm_api_manager=self._llm_api_manager,
            )
        except RecursionError:
            # Repo is too large
            pass
        except Exception:
            pass

        context["logger"].warning("Failed to generate repo map.")
        return None


def _all_files_in_absolute_path(source_dir: Path) -> list[Path]:
    files = _get_all_relative_files(source_dir)
    return [source_dir.resolve() / path for path in files]


def _get_all_relative_files(source_dir: Path) -> list[Path]:
    return sorted(set(get_git_tracked_files(source_dir)))


def _get_repo_map(
    context: EvaluatingContext,
    detection: Detection,
    chat_filenames: list[Path],
    other_filenames: list[Path],
    llm_api_manager: LlmApiManager,
) -> str:
    # Support caching?

    ranked_tags = _get_ranked_tags(
        context=context,
        detection=detection,
        chat_filenames=chat_filenames,
        other_filenames=other_filenames,
    )

    other_relative_filenames = sorted(
        set(
            _get_relative_filename(f, context["pool"].source_directory)
            for f in other_filenames
        )
    )
    special_filenames = filter_important_files(other_relative_filenames)
    ranked_tags_filenames = set(tag.relative_filename for tag in ranked_tags)
    special_filenames = [
        fn for fn in special_filenames if fn not in ranked_tags_filenames
    ]
    special_filenames = [
        Tag(
            relative_filename=fn,
            filename=Path(""),
            line=0,
            name="",
            kind="",
        )
        for fn in special_filenames
    ]

    ranked_tags = special_filenames + ranked_tags

    num_tags = len(ranked_tags)
    lower_bound = 0
    upper_bound = num_tags
    best_tree = ""
    best_tree_tokens = 0

    chat_relative_filenames = set(
        _get_relative_filename(f, context["pool"].source_directory)
        for f in chat_filenames
    )

    max_map_tokens = llm_api_manager.max_tokens
    middle = min(max_map_tokens // 25, num_tags)
    while lower_bound <= upper_bound:
        tree = _tags_to_tree(ranked_tags[:middle], chat_relative_filenames)
        num_tokens = _token_count(llm_api_manager.model, tree)

        error_percentage = abs(num_tokens - max_map_tokens) / max_map_tokens
        ok_error = 0.15
        if (
            num_tokens <= max_map_tokens and num_tokens > best_tree_tokens
        ) or error_percentage < ok_error:
            best_tree = tree
            best_tree_tokens = num_tokens

            if error_percentage < ok_error:
                break

        if num_tokens < max_map_tokens:
            lower_bound = middle + 1
        else:
            upper_bound = middle - 1

        middle = (lower_bound + upper_bound) // 2

    return best_tree


def _get_ranked_tags(
    context: EvaluatingContext,
    detection: Detection,
    chat_filenames: list[Path],
    other_filenames: list[Path],
) -> list[Tag]:
    definition_files_by_tag_name: defaultdict[str, set[Path]] = defaultdict(set)
    reference_files_by_tag_name: defaultdict[str, list[Path]] = defaultdict(list)
    definition_tags_by_path_and_tag_name: defaultdict[tuple[Path, str], set[Tag]] = (
        defaultdict(set)
    )

    personalization: dict[Path, float] = dict()

    filenames = set(chat_filenames).union(set(other_filenames))
    chat_relative_filenames: set[Path] = set()

    try:
        personalize = 100 / len(filenames)
    except ZeroDivisionError:
        personalize = 1

    for filename in filenames:
        if not (Path(filename).exists() and Path(filename).is_file()):
            continue

        relative_filename = _get_relative_filename(
            filename, context["pool"].source_directory
        )

        if relative_filename in chat_filenames:
            personalization[relative_filename] = personalize
            chat_relative_filenames.add(relative_filename)

        tags = list(_get_tags(detection, filename, relative_filename))
        if not any(tags):
            continue

        for tag in tags:
            if tag.kind == "def":
                definition_files_by_tag_name[tag.name].add(relative_filename)
                key = (relative_filename, tag.name)
                definition_tags_by_path_and_tag_name[key].add(tag)

            elif tag.kind == "ref":
                reference_files_by_tag_name[tag.name].append(relative_filename)

    if not reference_files_by_tag_name:
        for k, v in definition_files_by_tag_name.items():
            reference_files_by_tag_name[k] = list(v)

    idents = set(definition_files_by_tag_name.keys()).intersection(
        set(reference_files_by_tag_name.keys())
    )

    G = nx.MultiDiGraph()  # type: ignore

    for ident in idents:
        definers = definition_files_by_tag_name[ident]
        if ident.startswith("_"):
            mul = 0.1
        else:
            mul = 1

        for referencer, num_refs in Counter(reference_files_by_tag_name[ident]).items():
            for definer in definers:
                num_refs = math.sqrt(num_refs)

                G.add_edge(referencer, definer, weight=num_refs * mul, ident=ident)  # type: ignore

    pers_args: dict[str, dict[Path, float]]
    if personalization:
        pers_args = dict(
            personalization=personalization,
            dangling=personalization,
        )
    else:
        pers_args = dict()

    try:
        ranked = nx.pagerank(G, weight="weight", **pers_args)  # type: ignore
    except ZeroDivisionError:
        return []

    definitions_with_rank_info: dict[tuple[Path, str], float] = defaultdict(float)
    for src in G.nodes:  # type: ignore
        src_rank = ranked[src]  # type: ignore
        total_weight = sum(
            data["weight"]
            for _, _, data in G.out_edges(src, data=True)  # type: ignore
        )
        for _, dst, data in G.out_edges(src, data=True):  # type: ignore
            data["rank"] = src_rank * data["weight"] / total_weight
            ident = data["ident"]  # type: ignore
            definitions_with_rank_info[(dst, ident)] += data["rank"]

    ranked_tags: list[Tag] = []
    ranked_definitions = sorted(
        definitions_with_rank_info.items(), key=lambda x: x[1], reverse=True
    )

    for (filename, ident), _ in ranked_definitions:
        if filename in chat_relative_filenames:
            continue
        ranked_tags += list(
            definition_tags_by_path_and_tag_name.get((filename, ident), set())
        )

    rel_other_filenames_without_tags = set(
        _get_relative_filename(filename, context["pool"].source_directory)
        for filename in other_filenames
    )

    filenames_already_included = set(rt[0] for rt in ranked_tags)

    top_rank: list[tuple[float, Path]] = sorted(
        [(rank, node) for (node, rank) in ranked.items()],  # type: ignore
        reverse=True,
    )

    for _, filename in top_rank:  # type: ignore
        if filename in rel_other_filenames_without_tags:
            rel_other_filenames_without_tags.remove(filename)
        if filename not in filenames_already_included:
            ranked_tags.append(
                Tag(
                    relative_filename=filename,
                    filename=Path(""),
                    line=0,
                    name="",
                    kind="",
                )
            )

    for filename in rel_other_filenames_without_tags:
        ranked_tags.append(
            Tag(
                relative_filename=filename,
                filename=Path(""),
                line=0,
                name="",
                kind="",
            )
        )

    return ranked_tags


def _get_tags(
    detection: Detection, filename: Path, relative_filename: Path
) -> Iterator[Tag]:
    try:
        language = _get_language(detection.language)
        parser = _get_parser(detection.language)
    except Exception:
        return None

    try:
        query_scm = _get_query_scm(detection.language)
    except NotImplementedError:
        return None

    try:
        code = Path(filename).read_text(errors="replace")
    except FileNotFoundError:
        return None

    if not code:
        return None

    tree = parser.parse(code.encode("utf-8"))

    query = language.query(query_scm)
    captures = list(query.captures(tree.root_node).items())

    saw: set[str] = set()
    for tag, nodes in captures:
        if tag.startswith("name.definition"):
            kind = "def"
        elif tag.startswith("name.reference"):
            kind = "ref"
        else:
            continue

        saw.add(kind)

        for node in nodes:
            yield Tag(
                relative_filename=relative_filename,
                filename=filename,
                name=not_none(node.text).decode("utf-8"),
                kind=kind,
                line=node.start_point[0],
            )

    if "ref" in saw:
        return None
    if "def" not in saw:
        return None

    # # We saw defs, without any refs
    # # Some tags files only provide defs (cpp, for example)
    # # Use pygments to backfill refs

    try:
        lexer = guess_lexer_for_filename(filename, code)
    except Exception:  # On Windows, bad ref to time.clock which is deprecated?
        # self.io.tool_error(f"Error lexing {fname}")
        return

    tokens = list(lexer.get_tokens(code))  # type: ignore
    tokens = [token[1] for token in tokens if token[0] in Token.Name]  # type: ignore

    for token in tokens:  # type: ignore
        yield Tag(
            relative_filename=relative_filename,
            filename=filename,
            name=token,
            kind="ref",
            line=-1,
        )


def _get_query_scm(lang: Language) -> str:
    match lang:
        case "c":
            return c_tags_scm
        case "cpp" | "c++":
            return cpp_tags_scm
        case "jvm":
            return java_tags_scm


def _tags_to_tree(tags: list[Tag], chat_relative_filenames: set[Path]) -> str:
    if not tags:
        return ""

    cur_filename = Path("")
    cur_abs_filename = Path("")
    ready_to_add: bool = False
    lines_of_interest: list[int] = []
    output = ""

    dummy_tag = Tag(Path(""), Path(""), 0, "", "")
    for tag in sorted(tags) + [dummy_tag]:
        this_relative_filename = tag.relative_filename
        if this_relative_filename in chat_relative_filenames:
            continue

        if this_relative_filename != cur_filename:
            if ready_to_add:
                output += "\n"
                output += f"{cur_filename}:\n"
                try:
                    output += _render_tree(
                        cur_abs_filename, cur_filename, lines_of_interest
                    )
                except Exception:
                    pass
                ready_to_add = False
                lines_of_interest = []
            elif cur_filename != Path(""):
                output += f"\n{cur_filename}\n"
            if tag.filename != Path(""):
                ready_to_add = True
                cur_abs_filename = tag.filename
            cur_filename = this_relative_filename

        if ready_to_add:
            lines_of_interest.append(tag.line)

    return "\n".join([line[:100] for line in output.splitlines()]) + "\n"


def _render_tree(
    filename: Path, relative_filename: Path, lines_of_interest: list[int]
) -> str:
    try:
        code = filename.read_text(errors="replace")
    except Exception:
        code = ""
    if not code.endswith("\n"):
        code += "\n"

    context = TreeContext(
        relative_filename,
        code,
    )
    context.add_lines_of_interest(lines_of_interest)  # type: ignore
    context.add_context()
    return context.format()


def _token_count(model: str, text: str) -> int:
    len_text = len(text)
    if len_text < 200:
        return _get_estimate_token_count(model, text)

    lines = text.splitlines(keepends=True)
    num_lines = len(lines)
    step = num_lines // 100 or 1
    lines = lines[::step]
    sample_text = "".join(lines)
    sample_tokens = _get_estimate_token_count(model, sample_text)
    est_tokens = int(sample_tokens / len(sample_text) * len_text)
    return est_tokens


def _get_estimate_token_count(model: str, text: str) -> int:
    try:
        return len(litellm.encode(model=model, text=text))  # type: ignore
    except Exception:
        return 0


def _get_relative_filename(filename: Path, source_directory: Path) -> Path:
    try:
        return filename.relative_to(source_directory.resolve())
    except ValueError:
        return filename


def _get_language(language: Language):
    match language:
        case "c":
            return get_language("c")
        case "cpp" | "c++":
            return get_language("cpp")
        case "jvm":
            return get_language("java")


def _get_parser(language: Language):
    match language:
        case "c":
            return get_parser("c")
        case "cpp" | "c++":
            return get_parser("cpp")
        case "jvm":
            return get_parser("java")
