import argparse
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Generator

from sarif.models import FunctionCoverage, FuzzerCoverage


def _xml_to_dict(xml_path: Path, must_list: list[str] = []) -> dict:
    tree = ET.parse(xml_path.as_posix())
    root = tree.getroot()

    def _element_to_dict(element):
        result = {}

        for key, value in element.attrib.items():
            result[key] = value

        children_by_tag = {}
        for child in element:
            child_dict = _element_to_dict(child)
            tag = child.tag
            if tag in children_by_tag:
                if not isinstance(children_by_tag[tag], list):
                    children_by_tag[tag] = [children_by_tag[tag]]
                children_by_tag[tag].append(child_dict)
            else:
                if tag in must_list:
                    children_by_tag[tag] = [child_dict]
                else:
                    children_by_tag[tag] = child_dict

        if element.text and element.text.strip():
            result["_text"] = element.text.strip()

        result.update(children_by_tag)

        return result

    return {root.tag: _element_to_dict(root)}


def _exclude_attr(d: dict | object, exclude_tags: list[str]) -> dict:
    if not isinstance(d, dict):
        return d

    result = {}
    for k, v in d.items():
        if k in exclude_tags:
            continue

        if isinstance(v, list):
            result[k] = [_exclude_attr(item, exclude_tags) for item in v]
        elif isinstance(v, dict):
            result[k] = _exclude_attr(v, exclude_tags)
        else:
            result[k] = v

    return result


def _filter_jacoco_dict(raw_dict: dict) -> dict:
    exclude_tags: list[str] = ["line", "sessioninfo"]

    return _exclude_attr(raw_dict, exclude_tags)


def _extract_info(jacoco_dict: dict) -> Generator[FunctionCoverage, None, None]:
    # report -> package -> class -> method
    report = jacoco_dict["report"]
    for package in report["package"]:
        for class_ in package["class"]:
            class_name = class_["name"]
            file_name = class_["sourcefilename"]

            if "method" in class_:
                for method in class_["method"]:
                    func_name = method["name"]
                    desc = method["desc"]

                    yield FunctionCoverage(
                        class_name=class_name,
                        file_name=file_name,
                        func_name=func_name,
                        desc=desc,
                    )


def get_coverage_info_from_jacoco(jacoco_path: Path) -> FuzzerCoverage:
    raw_dict = _xml_to_dict(jacoco_path, must_list=["method", "class", "package"])
    jacoco_dict = _filter_jacoco_dict(raw_dict)

    return FuzzerCoverage(func_coverages=list(_extract_info(jacoco_dict)))


def merge_coverage_info(
    coverage_infos: list[FuzzerCoverage],
) -> FuzzerCoverage:
    merged_coverage_infos: list[FunctionCoverage] = []

    for coverage_info in coverage_infos:
        merged_coverage_infos.extend(coverage_info.func_coverages)

    unique_functions = {}

    for coverage in merged_coverage_infos:
        key = (coverage.class_name, coverage.func_name)
        unique_functions[key] = coverage

    return FuzzerCoverage(func_coverages=list(unique_functions.values()))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument("--jacoco", type=Path, required=True)
    args = parser.parse_args()

    info = get_coverage_info_from_jacoco(Path(args.jacoco))
