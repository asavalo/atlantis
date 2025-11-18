import subprocess
from pathlib import Path

from python_oss_fuzz.path.globals import OSS_FUZZ_BASE_IMAGE_TAG

crete_root = Path(__file__).parent.parent.parent.parent


def build_docker_image(
    image_name: str,
    dockerfile: Path,
    cwd: Path,
    extra_args: str = "",
):
    subprocess.check_call(
        f"docker build . -t {image_name} -f {dockerfile} {extra_args}",
        cwd=cwd,
        shell=True,
    )


def main():
    build_docker_image(
        "crs-patch-main",
        Path("packages/crs_patch/docker/Dockerfile.main"),
        crete_root,
    )
    build_docker_image(
        "crs-patch-sub",
        Path("packages/crs_patch/docker/Dockerfile.sub"),
        crete_root,
    )
    build_docker_image(
        "crete-lsp",
        Path("./Dockerfile"),
        crete_root / "packages" / "python_lsp",
        extra_args=f"--build-arg IMG_TAG={OSS_FUZZ_BASE_IMAGE_TAG}",
    )


if __name__ == "__main__":
    main()
