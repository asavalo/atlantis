FROM nvidia/cuda:12.1.1-devel-ubuntu22.04
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/
ARG HF_TOKEN
ARG MODEL_VERSION
ENV HF_TOKEN=${HF_TOKEN}
ENV MODEL=betarixm/eraser
ENV UV_LINK_MODE=copy
WORKDIR /app
ADD .python-version /app/.python-version
RUN uv python install
RUN uv venv
RUN uv pip install transformers==4.52.3 torch==2.6.0
RUN uv run python -c "from huggingface_hub import snapshot_download; snapshot_download(repo_id='betarixm/eraser', local_dir='models/betarixm/eraser', revision='${MODEL_VERSION}')"
ADD pyproject.toml uv.lock README.md /app/
RUN --mount=type=cache,target=/root/.cache/uv uv sync
ADD . /app
ENTRYPOINT ["uv", "run", "supervisord"]
