import argparse
import json
from pathlib import Path
from typing import List, Dict, Set, Any
from pydantic import BaseModel, RootModel
import subprocess
import tempfile
import hashlib
from base64 import b64encode

class FunctionCoverage(BaseModel):
    src: str
    lines: List[int]


class UniaflCov(RootModel):
    root: Dict[str, FunctionCoverage]


class SrcLocation(BaseModel):
    src_path: str
    line: int
    col: int

    def __hash__(self):
        return hash((self.src_path, self.line, self.col))


class SymccMap(BaseModel):
    inner: Dict[int, SrcLocation]


class UnsolvedPathConstraint(BaseModel):
    related_identifiers: List[str]
    src_location: SrcLocation


class SymCCAux(BaseModel):
    covered_lines: Dict[str, Set[int]]
    unidentified_sites: List[int]


class SymStateProcessResult(BaseModel):
    unsolved_path_constraints: List[UnsolvedPathConstraint]
    aux: SymCCAux


def read_path_constraint_sites(trace_file: Path) -> Set[int]:
    with trace_file.open() as f:
        trace = json.load(f)
    path_constraint_sites = set()
    for _sym_expr_ref, sym_expr in trace:
        if "PathConstraint" in sym_expr:
            path_constraint_sites.add(sym_expr["PathConstraint"]["location"])
    return path_constraint_sites


def get_missing_locations(
    target: str,
    harness_name: str,
    out_dir: Path,
    work_dir: Path,
    symcc_map: Dict[int, SrcLocation],
    obs_symcc_map: Dict[int, SrcLocation],
) -> List[SrcLocation]:
    trace_file = work_dir / "trace-obsessive.json"
    partial_trace_file = work_dir / "trace.json"
    if not partial_trace_file.exists():
        raise FileNotFoundError(partial_trace_file)
    out_dir = out_dir.resolve()
    work_dir = work_dir.resolve()
    docker_image_name = f"aixcc-afc/{target}"
    docker_run_cmd = "docker run --rm "
    docker_run_cmd += f"-v {out_dir}:/out "
    docker_run_cmd += f"-v {work_dir}:/work "
    docker_run_cmd += f"-w /out "
    docker_run_cmd += (
        f"-e SYMCC_OBSESSIVE=1 -e SYMCC_TRACE_FILE=/work/{trace_file.name} "
    )
    docker_run_cmd += (
        f"{docker_image_name} /out/{harness_name}-symcc-obsessive /work/input.txt"
    )
    subprocess.run(
        docker_run_cmd,
        shell=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=True,
    )
    if not trace_file.exists():
        raise FileNotFoundError(trace_file)
    all_sites = read_path_constraint_sites(trace_file)
    partial_sites = read_path_constraint_sites(partial_trace_file)
    all_locations = set()
    partial_locations = set()
    for s in all_sites:
        if not s in obs_symcc_map:
            continue
        all_locations.add(obs_symcc_map[s])
    for s in partial_sites:
        if not s in symcc_map:
            continue
        partial_locations.add(symcc_map[s])
    return list(all_locations - partial_locations)


def try_rebase_path(src: str, rebase_dir: Path) -> Path:
    top_level = Path(src).resolve().relative_to("/src").parts[0]
    other_parts = Path(src).resolve().relative_to(f"/src/{top_level}")
    src_path = rebase_dir / "repo" / other_parts
    if not src_path.exists():
        raise FileNotFoundError(src_path)
    return src_path

def sha256sum(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def create_source_report(code_contents: List[str], line: int) -> str:
    report = ""
    for i, code_line in enumerate(code_contents, start=1):
        if i < line - 10 or i > line + 10:
            continue
        if i == line:
            report += f"-> {i}| {code_line}\n"
        else:
            report += f"   {i}| {code_line}\n"
    return report

def create_input_report(input_bytes: bytes) -> str:
    report = ""
    b64_input = b64encode(input_bytes).decode()
    report += f"Base64 encoded input: {b64_input}\n" 
    return report

def convert_srcloc_list_to_map(
    srcloc_list: List[Any]
) -> Dict[str, List[int]]:
    res = dict()
    for srcloc in srcloc_list:
        if isinstance(srcloc, UnsolvedPathConstraint):
            srcloc = srcloc.src_location
        if not srcloc.src_path in res:
            res[srcloc.src_path] = set()
        res[srcloc.src_path].add(srcloc.line)
    return res

def handle_result(
    result: SymStateProcessResult,
    input_bytes: bytes,
    target: str,
    harness_name: str,
    out_dir: Path,
    work_dir: Path,
    output_dir: Path,
    rebase_dir: Path | None,
    symcc_map: Dict[int, SrcLocation],
    obs_symcc_map: Dict[int, SrcLocation],
):
    unsolvable_locations_list = result.unsolved_path_constraints
    src_files = set()
    
    missing_locations = dict() 
    unsovlable_locations = convert_srcloc_list_to_map(unsolvable_locations_list) 

    src_files.update(result.aux.covered_lines.keys())
    for src in src_files:
        src_path = Path(src).resolve()
        relative_path = src_path.relative_to("/src")
        if rebase_dir:
            src_path = rebase_dir / relative_path
            if not src_path.exists():
                src_path = try_rebase_path(src, rebase_dir)
        code_contents = src_path.read_text().splitlines()
        unsolvable_lines = unsovlable_locations.get(src, set())
        for unsolvable_line in unsolvable_lines:
            unsolvable_id = sha256sum(f"{src}:{unsolvable_line}".encode())
            report_path = output_dir / f"unsolvable/{unsolvable_id}.txt"
            report = ""
            report += f"Unsolvable path constraint at {src}\n"
            report += create_input_report(input_bytes)
            report += create_source_report(code_contents, unsolvable_line)
            if not report_path.parent.exists():
                report_path.parent.mkdir(parents=True)
            with open(report_path, "w") as f:
                f.write(report)
        for missing_src, missing_lines in missing_locations.items():
            if missing_src != src:
                continue
            for missing_line in missing_lines:
                missing_id = sha256sum(f"{src}:{missing_line}".encode())
                report_path = output_dir / f"missing/{missing_id}.txt"
                report = ""
                report += f"Missing path constraint at {src}\n"
                report += create_input_report(input_bytes)
                report += create_source_report(code_contents, missing_line)
                if not report_path.parent.exists():
                    report_path.parent.mkdir(parents=True)
                with open(report_path, "w") as f:
                    f.write(report)


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "eval_out_dir",
        type=str,
    )
    parser.add_argument("-t", "--target", type=str, required=True)
    parser.add_argument("-H", "--harness", type=str, required=True)
    parser.add_argument("-m", "--multilang-root", type=str, required=True)
    parser.add_argument("-o", "--output", type=str, required=True)
    return parser.parse_args()


def parse_symcc_map(
    multilang_root: Path, target: str, harness: str, obsessive=False
) -> Dict[int, SrcLocation]:
    symcc_map_parser = multilang_root / "target/debug/symcc_map_parser"
    suffix = "symcc-obsessive" if obsessive else "symcc"
    target_binary_path = (
        multilang_root / f"libs/oss-fuzz/build/out/{target}/{harness}-{suffix}"
    )
    if not symcc_map_parser.exists():
        raise FileNotFoundError(symcc_map_parser)
    with tempfile.NamedTemporaryFile() as f:
        subprocess.run(
            [symcc_map_parser, "--harness", target_binary_path, "--output", f.name],
            stderr=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            check=True,
        )
        f.seek(0)
        symcc_map = SymccMap.model_validate(json.load(f))
    return symcc_map.inner


def main():
    args = parse_args()
    eval_out_dir = Path(args.eval_out_dir).resolve()
    if not eval_out_dir.exists() or not eval_out_dir.is_dir():
        raise FileNotFoundError(eval_out_dir)
    uniafl_cov = (
        Path(args.eval_out_dir) / f"{args.target}/eval_result/uniafl_cov/{args.harness}"
    )
    if not uniafl_cov.exists() or not uniafl_cov.is_dir():
        raise FileNotFoundError(uniafl_cov)
    concolic = (
        Path(args.eval_out_dir) / f"{args.target}/eval_result/concolic/{args.harness}"
    )
    if not concolic.exists() or not concolic.is_dir():
        raise FileNotFoundError(concolic)
    output_dir = Path(args.output).resolve()
    multilang_root = Path(args.multilang_root).resolve()
    out_dir = multilang_root / f"libs/oss-fuzz/build/out/{args.target}"
    rebase_dir = multilang_root / f"benchmarks/projects/{args.target}"

    symcc_map = parse_symcc_map(multilang_root, args.target, args.harness)
    obs_symcc_map = parse_symcc_map(
        multilang_root, args.target, args.harness, obsessive=True
    )

    for worker_dir in concolic.glob("worker-*"):
        if worker_dir.is_dir():
            for input_dir in worker_dir.iterdir():
                input_dir = input_dir.resolve()
                if input_dir.is_dir():
                    result_json = input_dir / "result.json"
                    input_bytes = open(input_dir / "input.txt", "rb").read()
                    if result_json.exists():
                        data = json.loads(result_json.read_text())
                        result_obj = SymStateProcessResult.model_validate(data)
                        handle_result(
                            result_obj,
                            input_bytes,
                            args.target,
                            args.harness,
                            out_dir,
                            input_dir,
                            output_dir,
                            rebase_dir,
                            symcc_map,
                            obs_symcc_map,
                        )


if __name__ == "__main__":
    main()
