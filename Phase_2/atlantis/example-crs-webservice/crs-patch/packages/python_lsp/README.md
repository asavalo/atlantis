This directory contains the prebuilt LSP Docker image. (We build this before the competition)

The Docker image includes the following components:

- APT packages in `.deb` format: `socat`, `clangd-18`, and `bear`
- `eclipse-jdt-ls` for Java language support
- Utility scripts for running the LSP within the CP Docker environment: `prepare.sh` and `run.sh`

The lsp-version project Docker image is built on top of the original project Docker image using a multi-stage build:

```dockerfile
COPY --from=TEAM_ATLANTA_DOCKER_REGISTRY/crete-lsp:TEAM_ATLANTA_IMAGE_VERSION ...
```