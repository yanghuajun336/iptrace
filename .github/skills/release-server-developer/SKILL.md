---
name: release-server-developer
description: Development, testing, and management toolkit for the Release Server component (in `release-server/` directory). Use this skill when need to (1) Understand, research, or explore the Release Server architecture and implementation, (2) Develop, modify, or debug server code (routes, auth, config), (3) Build, run, or release the Release Server Docker image using provided scripts, (4) Perform operational tasks like uploading, listing, or deleting packages, or Run tests and verification pipelines for the Release Server.
---

# Release Server Developer

This skill provides a comprehensive toolkit for developing, testing, and managing the Release Server.
See **[Technical Architecture & Structure](reference/technical-context.md)** for detailed stack and directory info.

## Scenarios & Workflows

Choose the workflow that matches your current task.

### 1. Feature Development

**Scenario**: Adding APIs, modifying storage, fixing bugs, or updating configuration.

1.  **Environment Setup**:
    *   **Goal**: Ensure dependencies are installed.
    *   **Tool**: [release-server-setup](#setup-development-environment) (`release-server-setup.py`)
    *   **Manual**: `cd release-server && uv sync --all-extras`
2.  **Impact Analysis**:
    *   **API Changes**: Check `openapi.yaml` and client scripts.
    *   **Storage Changes**: Verify persistence compatibility.
3.  **Development & Test**:
    *   Modify code in `src/`.
    *   Write tests in `tests/`.
    *   **Run Tests**: `cd release-server && uv run pytest`
4.  **Verification**:
    *   **Pipeline Check**: [release-server-test](#local-workflow-test) (`release-server-test.py`) (Simulate CI - MANDATORY for core changes)
        *   *Troubleshooting*: If pytest fails with compilation errors or segfaults, clear act cache:
            1.  Check: `docker volume ls | grep act-toolcache`
            2.  Remove: `docker volume rm act-toolcache`
    *   **Packaging Check**: [release-server-build](#build-docker-image) (`release-server-build.py`) to ensure Docker build succeeds.
5.  **Documentation**:
    *   Update `release-server/README.md` (Features/Config).
    *   Update `release-server/openapi.yaml` (API Contract).
    *   Update `release-server/chart/README.md` (Deployment params).
    *   Update `reference/technical-context.md` (Tech Stack/Structure).

### 2. Packaging & Release

**Scenario**: Creating Docker images and Helm charts for release.

1.  **Build Docker Image**:
    *   **Tool**: [release-server-build](#build-docker-image)
    *   **Manual**: `scripts/build.sh`
2.  **Verify Chart**:
    *   **Action**: Test Helm chart packaging.
    *   **Script**: `.github/workflows/scripts/publish-release-server-chart-ghcr.sh <version>` (Dry run or use test version)
3.  **Create Release**:
    *   **Tool**: [release-server-release](#create-release)

### 3. Server Operations

**Scenario**: Managing a running server (local or remote) and its content.

1.  **Run Locally**:
    *   **Tool**: [release-server-run](#run-server-locally)
    *   **Manual**: `uv run uvicorn release_server.main:app --reload`
2.  **Manage Packages**:
    *   **List**: [release-server-list](#list-packages)
    *   **Upload**: [release-server-upload](#upload-package)
    *   **Delete**: [release-server-delete](#delete-package)

## Development Guidelines

### Code Contribution Locations

*   **Routes**: `src/release_server/router.py`
*   **Auth**: `src/release_server/auth.py`
*   **Config**: `src/release_server/config.py`
*   **Storage**: `src/release_server/storage.py`
*   **Prompts**: `src/release_server/prompts/`

### Testing Standards

*   **Unit Tests**: Must cover new logic. Use `client` fixture.
*   **Integration**: Verify `gh act` passes before PR.

## Tools Reference

Wrapper scripts are available in `.github/skills/release-server-developer/scripts/` to perform common operations.

### Setup Development Environment
<!-- tool: release-server-setup start -->

```text
usage: release-server-setup.py [-h]

Initialize the Release Server Development Environment.

options:
  -h, --help  show this help message and exit
```

<!-- tool: release-server-setup end -->

### Build Docker Image
<!-- tool: release-server-build start -->

```text
usage: release-server-build.py [-h] [--registry REGISTRY] [--author AUTHOR]
                               [--image-name IMAGE_NAME] [--tag TAG]

Build the Release Server Docker image.

options:
  -h, --help            show this help message and exit
  --registry REGISTRY   Container registry (default: ghcr.io)
  --author AUTHOR       Image author/namespace (default: zlink-cloudtech)
  --image-name IMAGE_NAME
                        Image name (default: speckit-rs)
  --tag TAG             Image tag (default: latest)
```

<!-- tool: release-server-build end -->

### Local Workflow Test
<!-- tool: release-server-test start -->

```text
usage: release-server-test.py [-h] [--event {push,pull_request}] [version]

Run the release-server-publish workflow locally using 'gh act' via the wrapper script.

positional arguments:
  version               Optional version string to test (e.g., 0.0.90-localtest)

options:
  -h, --help            show this help message and exit
  --event {push,pull_request}, -e {push,pull_request}
                        The event to trigger (default: push)
```

<!-- tool: release-server-test end -->

### Run Server Locally
<!-- tool: release-server-run start -->

```text
usage: release-server-run.py [-h] [--port PORT] [--host HOST] [--reload]

Run the Release Server locally.

options:
  -h, --help   show this help message and exit
  --port PORT  Port to run on (default: 8000)
  --host HOST  Host to bind to (default: 127.0.0.1)
  --reload     Enable auto-reload (default: True)
```

<!-- tool: release-server-run end -->

### List Packages
<!-- tool: release-server-list start -->

```text
usage: release-server-list.py [-h] [--url URL] [--token TOKEN] [--json]

List packages on the Release Server

options:
  -h, --help     show this help message and exit
  --url URL      Release Server URL
  --token TOKEN  Auth token (if required)
  --json         Output raw JSON
```

<!-- tool: release-server-list end -->

### Upload Package
<!-- tool: release-server-upload start -->

```text
usage: release-server-upload.py [-h] [--url URL] [--token TOKEN] [--force]
                                file_path

Upload a package to the Release Server.

positional arguments:
  file_path             Path to the file to upload

options:
  -h, --help            show this help message and exit
  --url URL, -u URL     Server URL
  --token TOKEN, -t TOKEN
                        Auth Token
  --force, -f           Overwrite existing file
```

<!-- tool: release-server-upload end -->

### Delete Package
<!-- tool: release-server-delete start -->

```text
usage: release-server-delete.py [-h] [--url URL] [--token TOKEN] filename

Delete a package from the Release Server.

positional arguments:
  filename              Name of the file/package to delete

options:
  -h, --help            show this help message and exit
  --url URL, -u URL     Server URL
  --token TOKEN, -t TOKEN
                        Auth Token
```

<!-- tool: release-server-delete end -->

### Create Release
<!-- tool: release-server-release start -->

```text
usage: release-server-release.py [-h] [version]

Package and release the Release Server application.

positional arguments:
  version     Version to release (optional, defaults to pyproject.toml
              version)

options:
  -h, --help  show this help message and exit
```

<!-- tool: release-server-release end -->

## References

- **Documentation**: See [release-server/README.md](/root/workspaces/zlink-cloudtech/spec-kit/release-server/README.md) for Quickstart, Features, Configuration, and API Endpoints.
