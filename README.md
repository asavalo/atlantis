# Atlantis (AIxCC – LLM-Assisted Vulnerability Discovery)

This repo is a fork of the Team Atlanta AIxCC submission plus additional glue and testing to make it easier to:

- Run the Atlantis CRS (Competition Runtime System) + LLM to find vulnerabilities in source code.
- Drive scans via shell scripts against single files or entire repos.
- Stand up a Phase 2 CAPI + Web UI stack for the AIxCC competition portal style workflow.

Atlantis trades extra setup complexity (Docker, LLM hosting, container stack) for richer findings and better control over how code is chunked, sent to the model, and aggregated.

> For a deeper component-level view, see [`ARCHITECTURE.md`](ARCHITECTURE.md).

---

## Repository Layout

```text
atlantis/
├── Phase_2/
│   ├── stack/          # Docker Compose stack (Atlantis + CAPI + LLM gateway + Ollama)
│   ├── capi/           # Competition API backend (FastAPI)
│   ├── webui/          # Optional competition portal (React/Vite via Nginx)
│   └── ...             # Env/config and helper scripts
├── example-crs-webservice/
│   └── crs_webserver/  # Original Team Atlanta CRS webservice
├── python/             # Python helpers, testing, and analysis utilities
├── scripts/            # Extra helper scripts / tooling
├── docker-compose.yml  # Simple local stack: atlantis-webservice + ollama
├── UserImpersonation.java
├── VulnerableApp.java  # Example vulnerable Java files
└── *.sh, *.txt         # Scan helper scripts & corpus lists


