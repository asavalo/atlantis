# Crete

## Usage

### Installation

```bash
$ uv sync
$ uv run scripts/setup.py
```

### LLM Tracing with Phoenix

The [arize-phoenix](https://github.com/Arize-ai/phoenix) package provides LLM application runtime tracing using OpenTelemetry-based instrumentation. Enable this by following the steps below.

1. If locally self-hosting Phoenix server, launch a instance by:

    ```bash
    phoenix serve
    ```

2. Set `PHOENIX_COLLECTOR_ENDPOINT` environment variable to the serving endpoint(local or remote) in `.env`.

3. Set instrumentation environment variable to `true` in `.env` to enable tracing. Example:

    ```bash
    PHOENIX_INSTRUMENT_LANGCHAIN=true
    PHOENIX_INSTRUMENT_LITELLM=true
    ```

Now LLM traces can be seen in the hosted Phoenix server. For more details and advanced usages, refer to the [Phoenix documentation](https://docs.arize.com/phoenix).

## Patch Agents

- [Martian agent](./docs/martian.md) (`apps.custom.martian_FL_o4_mini_CG_claude_4`)
- [ClaudeLike agent](./docs/claude_like.md) (`apps.claude_like.claude_like`)
- [Vincent agent](./docs/vincent.md) (`apps.vincent.vincent_gemini_2_5_pro`)

## Development Guidelines

### Directory Structure

```plaintext
[package]/
├─ [notion: singular]/
│  ├─ [plural].py
│  ├─ functions.py
│  ├─ models.py
```

#### Example

```plaintext
framework/
├─ round/
│  ├─ functions.py
│  ├─ models.py
│  ├─ [plural].py
├─ team/
│  ├─ functions.py
│  ├─ models.py
│  ├─ [plural].py
├─ manager/
│  ├─ functions.py
│  ├─ models.py
│  ├─ [plural].py
```

### Git Collaboration

#### Commit Messages

- Conventional Commit: <https://www.conventionalcommits.org/en/v1.0.0/>

#### Branch Guideline

- Semi-linear history: <https://baekjungho.github.io/wiki/git/git-merge-semi-linear-history/>
- Do not push directly to the `main` branch.
  - Reviewer: @betarixm, ...

### Static Analysis

**It is highly recommended to use `pyright` instead of `mypy`.** Refer to the [official comparison document](https://github.com/microsoft/pyright/blob/main/docs/mypy-comparison.md) for more details. If you are using Visual Studio Code with the Python extension, simply enable `Type Checking: strict` option, which utilizes pyright.

### Immutable by Default

Strive for immutability everywhere, except for intentional and carefully considered cases of mutability.

### Linting

Use `ruff` for formatting.

### Unit Test

```bash
uv run pytest
```

### Clean Code

Follow: <https://bxta.kr/clean-code.pdf>

### License

This project is primarily licensed under the MIT License. However, it includes modified code from other projects:

- **SWE** (Modified): Originally MIT Licensed. The modifications continue to carry the MIT License.
- **Aider** (Modified): Originally licensed under Apache License 2.0. The aider components remain under Apache License 2.0.
- **Agentless** (Partial): Portions of the code are derived from the Agentless project, which is licensed under the MIT License.

Please refer to the [LICENSE](./LICENSE) and [NOTICE](./NOTICE) files for full details.