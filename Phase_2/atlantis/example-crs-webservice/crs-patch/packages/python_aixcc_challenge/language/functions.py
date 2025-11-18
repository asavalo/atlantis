from python_aixcc_challenge.language.types import Language


def get_language_file_extensions(language: Language) -> list[str]:
    match language:
        case "c":
            return [".c", ".h"]
        case "cpp" | "c++":
            return [".c", ".h", ".cpp", ".hpp", ".cc", ".hh", ".C", ".cxx", ".hxx"]
        case "jvm":
            return [".java"]
