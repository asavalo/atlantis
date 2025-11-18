import glob
import json
import logging
import os
import subprocess
import tempfile
import threading
from pathlib import Path
from typing import Optional, Tuple

from vuli.common.decorators import consume_exc_method
from vuli.common.setting import Setting
from vuli.common.singleton import Singleton
from vuli.struct import Sanitizer


class CP(metaclass=Singleton):
    def __init__(self):
        self.harnesses: dict = {}
        self.sanitizers: list[Sanitizer] = []
        self.source_dir: Optional[Path] = None
        self.cp_name = None
        self._diff_path: Optional[Path] = None
        self._semaphore = threading.Semaphore(1)
        self._logger = logging.getLogger("CP")

    def _load_cp_meta(self, meta_file: Path):
        if not meta_file.exists():
            raise RuntimeError(f"CP metadata file not found: {meta_file}")
        with meta_file.open("r") as f:
            self.meta = json.load(f)

    def load(self, meta_file: Path, harnesses: list[str]):
        self._load_cp_meta(meta_file)
        self.cp_name = self.meta.get("cp_name", "")

        try:
            self._set_diff_path(Path(self.meta["ref_diff_path"]))
        except Exception:
            self._logger.info("No Delta Mode")

        self.source_dir = Path(self.meta.get("cp_full_src", ""))
        if not self.source_dir.exists():
            raise RuntimeError(f"CP source directory not found: {self.source_dir}")

        harness_meta: dict = self.meta.get("harnesses", {})
        self.harnesses: dict = harness_meta
        if len(harnesses) > 0:
            self.harnesses: dict = {
                key: value for key, value in self.harnesses.items() if key in harnesses
            }
        if len(self.harnesses) == 0:
            self._logger.warning("No Target Harness Found")
        else:
            self._logger.info(
                f"Target Harnesses: {", ".join(harness for harness in self.harnesses)}"
            )

        # truncate harness['src_path'] inside for correct Joern query results

        self.built_path = Path(Setting().cp_root) / self.meta.get("built_path", "")
        if not self.built_path.exists():
            raise RuntimeError(f"CP built directory not found: {self.built_path}")

        self.sanitizers = [
            Sanitizer("OS Command Injection", ["jazze"]),
            Sanitizer("Server Side Request Forgery", ["jazzer.example.com"]),
            Sanitizer("Deserialization", ["jaz.Zer"]),
            Sanitizer("SQL Injection", ["'"]),
            Sanitizer(
                "Remote JNDI Lookup", ["${jndi:ldap://g.co/}", "${ldap://g.co/}"]
            ),
            Sanitizer("LDAP Injection", ["("]),
            Sanitizer("XPath Injection", ["document(2)"]),
            Sanitizer("Load Arbitrary Library", ["jazzer_honeypot"]),
            Sanitizer("Regular Expression Injection", ["*"]),
            Sanitizer("Script Engine Injection", ['"jaz"+"zer"']),
            Sanitizer("File Path Traversal", ["../jazzer-traversal"]),
            Sanitizer(
                "Express Language Injection",
                [['Byte.class.forName("jaz.Zer").getMethod("el").invoke(null)']],
            ),
        ]

    def get_dependent_jars(self):
        """Jars of all harnesses under one CP."""
        cp_built_path = self.built_path
        if cp_built_path is None or not os.path.exists(cp_built_path):
            raise RuntimeError(
                f"Invalid CP_BUILT_PATH {cp_built_path}: not set or not exists"
            )

        jars = {}
        for jar in glob.glob(
            os.path.join(cp_built_path, "**", "*.jar"), recursive=True
        ):
            name = os.path.basename(jar)
            if name in jars or name == "jazzer_agent_deploy.jar":
                continue
            jars[name] = os.path.abspath(jar)
        return list(jars.values())

    @consume_exc_method("")
    def get_harness_path(self, id: str) -> Path:
        return Path(self.harnesses[id]["src_path"])

    @consume_exc_method("")
    def get_harness_bin_path(self, id: str) -> Path:
        return Path(self.harnesses[id]["bin_path"])

    @consume_exc_method("")
    def get_harness_path_by_name(self, harness_name: str) -> Path:
        harness = self.harnesses.get(harness_name)
        if harness:
            return Path(harness.get("src_path", ""))
        return Path("")

    def get_harness_name(self, harness_file_path: Path) -> str:
        for name, harness in self.harnesses.items():
            if harness.get("src_path", "") == str(harness_file_path):
                return name
        return ""

    def get_harness_names(self) -> list[str]:
        return list(self.harnesses.keys())

    def get_jars(self, harness_path: Path):
        for harness in self.harnesses.values():
            if harness["src_path"] == str(harness_path):
                jars: list[str] = harness["classpath"]
                return jars
        return []

    def get_sanitizer(self, name: str) -> Optional[Sanitizer]:
        return {sanitizer.name: sanitizer for sanitizer in self.sanitizers}.get(
            name, None
        )

    def get_fuzzer_exception_log(self, log: str):
        result = ""
        libfuzzer_log = [
            "INFO: seed corpus",
            "#2\tINITED",
            "#2\tDONE",
            "Done",
            "INFO: Instrumented",
        ]
        for idx, line in enumerate(log):
            if (
                not line.startswith("INFO: Instrumented")
                and "exception" in line.lower()
            ):
                result = log[idx:]
                break
        filtered_log = [
            line
            for line in result
            if not any(line.startswith(exclude) for exclude in libfuzzer_log)
        ]

        return "\n".join(filtered_log)

    def run_pov(
        self,
        blob: bytes,
        enable_integer_overflow: bool,
        harness_path: Path,
        output: Path = None,
    ) -> Tuple[bool, str]:
        with self._semaphore:
            harness = None
            for h in self.harnesses.values():
                if h["src_path"] == str(harness_path):
                    harness = h
                    break
            if harness is None:
                raise RuntimeError(f"Invalid harness_path: {harness_path}")

            if True:
                env = os.environ.copy()
                env["ASAN_OPTIONS"] = "detect_leaks=0"
                env["LSAN_OPTIONS"] = "detect_leaks=0"
                cmd: list[str] = [
                    harness["bin_path"],
                    f"-runs=1",
                    f"-timeout=10"
                ]
            else:
                jazzer_dir = Setting().jazzer_path.parent
                agent_path = jazzer_dir / "jazzer_standalone_deploy.jar"

                jars = [str(jazzer_dir.resolve())]
                jars.extend(harness["classpath"])
                classpath: str = ":".join(jars)
                classname: str = harness["target_class"]
                cmd: list[str] = [
                    str(Setting().jazzer_path),
                    f"--agent_path={str(agent_path)}",
                    "-runs=1",
                    f"--cp={classpath}",
                    f"--target_class={classname}",
                    "--instrumentation_excludes=org.apache.logging.**:com.fasterxml.**:org.apache.commons.**",
                    "--jvm_args=-Djdk.attach.allowAttachSelf=true:-XX:+StartAttachListener",
                ]
                if output is not None:
                    cmd += ["--coverage_dump=coverage.exec", f"--coverage_report={output}"]
                if not enable_integer_overflow:
                    cmd.append(
                        "--disabled_hooks=com.code_intelligence.jazzer.sanitizers.IntegerOverflow"
                    )
                env = None

        if True:
            parent_dir = Setting().tmp_dir
        else:
            parent_dir = "/"
        with tempfile.TemporaryDirectory(prefix="llmpocgen-", dir=parent_dir) as tmp_dir:
            queue_dir = Path(tmp_dir, "queue")
            queue_dir.mkdir()

            blob_file = queue_dir / "blob"
            with blob_file.open("wb") as f:
                f.write(blob)
            cmd.append(str(queue_dir))
            self._logger.debug(f"Run Pov: {" ".join(cmd)}")
            try:
                p = subprocess.run(
                    cmd,
                    cwd=tmp_dir,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    timeout=10,
                    env=env
                )
                if True:
                    if p.returncode == 1:
                        return True, ""
                else:            
                    if p.returncode == 77:
                        return True, ""
                fuzzer_log = p.stdout.decode(
                    "utf-8", errors="ignore"
                ).split("\n")
                return False, self.get_fuzzer_exception_log(fuzzer_log)
            except subprocess.TimeoutExpired:
                return False, ""

    def _set_diff_path(self, diff_path: Path) -> None:
        if diff_path.exists() and diff_path.is_file():
            self._diff_path = diff_path
        else:
            self._diff_path = None
