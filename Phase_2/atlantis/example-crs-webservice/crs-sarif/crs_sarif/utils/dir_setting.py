import logging
import shutil
import tarfile
import zipfile
from pathlib import Path

from crs_sarif.utils.cmd import copytree
from crs_sarif.utils.context import CRSEnv

logger = logging.getLogger(__name__)


class CRSDirSetting:
    @staticmethod
    def _extract_tarballs(tarball_path: Path, output_dir: Path, clean=False):
        if clean:
            if output_dir.exists():
                shutil.rmtree(output_dir)

        if not output_dir.exists():
            output_dir.mkdir(parents=True, exist_ok=True)

        with tarfile.open(tarball_path, "r:gz") as tar:
            tar.extractall(path=output_dir)

    @staticmethod
    async def _download_codeql_build_shared_dir():
        # clean build dir
        if CRSEnv().build_dir.exists():
            for file in CRSEnv().build_dir.iterdir():
                if file.is_file():
                    file.unlink()
                elif file.is_dir():
                    shutil.rmtree(file)

        # codeql
        copytree(
            CRSEnv().build_shared_dir / "codeql.tar.gz",
            CRSEnv().build_dir / "codeql.tar.gz",
        )
        CRSDirSetting._extract_tarballs(
            CRSEnv().build_dir / "codeql.tar.gz",
            CRSEnv().build_dir,
        )

        # unzip codeql src.zip
        codeql_src_zip = CRSEnv().build_dir / "codeql" / "src.zip"
        if codeql_src_zip.exists():
            with zipfile.ZipFile(codeql_src_zip, "r") as zip_ref:
                zip_ref.extractall(CRSEnv().compiled_src_dir)

    @staticmethod
    async def _download_joern_build_shared_dir():
        # joern
        copytree(
            CRSEnv().build_shared_dir / "joern.tar.gz",
            CRSEnv().build_dir / "joern.tar.gz",
        )
        CRSDirSetting._extract_tarballs(
            CRSEnv().build_dir / "joern.tar.gz",
            CRSEnv().build_dir,
        )

    @staticmethod
    async def _download_poc_gen_build_shared_dir():
        # gdb out
        copytree(
            CRSEnv().build_shared_dir / "debug.tar.gz",
            CRSEnv().build_dir / "debug.tar.gz",
        )
        CRSDirSetting._extract_tarballs(
            CRSEnv().build_dir / "debug.tar.gz",
            CRSEnv().build_dir,
        )

        # cpg src
        copytree(
            CRSEnv().build_shared_dir / "cpg_src.tar.gz",
            CRSEnv().build_dir / "cpg_src.tar.gz",
        )
        CRSDirSetting._extract_tarballs(
            CRSEnv().build_dir / "cpg_src.tar.gz",
            CRSEnv().build_dir,
        )

    @staticmethod
    async def _download_aux_build_shared_dir():
        # SVF
        copytree(
            CRSEnv().build_shared_dir / "SVF.tar.gz",
            CRSEnv().build_dir / "SVF.tar.gz",
        )
        CRSDirSetting._extract_tarballs(
            CRSEnv().build_dir / "SVF.tar.gz", CRSEnv().build_dir
        )

        # Sootup
        if CRSEnv().project_language == "jvm":
            (CRSEnv().build_dir / "sootup").mkdir(parents=True, exist_ok=True)

            copytree(
                CRSEnv().build_shared_dir / "out.tar.gz",
                CRSEnv().build_dir / "out.tar.gz",
            )

            CRSDirSetting._extract_tarballs(
                CRSEnv().build_dir / "out.tar.gz",
                CRSEnv().out_dir,
            )
