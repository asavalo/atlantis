import logging
import shutil
import tarfile
import time
from pathlib import Path

from crs_sarif.utils.cmd import copytree, rsync
from crs_sarif.utils.context import CRSEnv

logger = logging.getLogger(__name__)


class CRSDirSetting:
    # def __init__(self):
    #     CRSDirSetting._extract_repo_tarballs()
    #     CRSDirSetting._download_essential_build_shared_dir()
    #     if CRSEnv().project_language in ["c", "cpp", "c++"]:
    #         CRSDirSetting._download_poc_gen_build_shared_dir()

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
    def _extract_repo_tarballs():
        # Repo tarballs
        repo_tarballs = CRSEnv().tarball_dir / "repo.tar.gz"
        CRSDirSetting._extract_tarballs(repo_tarballs, CRSEnv().src_dir)

    @staticmethod
    async def _download_essential_build_shared_dir():
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
