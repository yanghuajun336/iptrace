# Release Server Technical Context

## Tech Stack

- **Language**: Python 3.12+ (managed via `uv`)
- **Web Framework**: FastAPI
- **Server**: Uvicorn (ASGI)
- **Templating**: Jinja2 (Serverside rendering)
- **File Handling**: python-multipart (Uploads), aiofiles (Async I/O)
- **Settings**: pydantic-settings (Dotenv support)
- **Testing**: pytest, httpx (Integrations)

## Project Structure

```text
release-server/
├── chart/               # Helm chart for Kubernetes deployment
│   ├── templates/       # K8s manifests (Deployment, Service, PVC)
│   ├── Chart.yaml       # Chart metadata
│   └── values.yaml      # Default configuration
├── scripts/             # Shell scripts for build/release workflows
│   ├── build.sh         # Docker build wrapper
│   ├── release.sh       # Release packaging
│   └── upload.sh        # Upload utility wrapper
├── src/
│   └── release_server/  # Main Application Package
│       ├── __init__.py
│       ├── main.py      # Entrypoint & App Factory
│       ├── config.py    # Configuration & Validation (Pydantic)
│       ├── router.py    # API Route Definitions
│       ├── auth.py      # Authentication Middleware & Logic
│       ├── storage.py   # File System & Metadata Logic
│       ├── services/    # Business Logic Domains
│       │   └── package_service.py # Package Management Logic
│       └── templates/   # HTML Templates (Jinja2)
├── tests/               # Test Suite
│   ├── conftest.py      # Fixtures (Client, Settings)
│   ├── test_api.py      # End-to-End API Tests
│   └── ...
├── Dockerfile           # Optimized Multi-stage Build
├── pyproject.toml       # Dependencies & Build Config
└── uv.lock              # Lockfile
```

## Critical Interactions

- **Storage**: The server relies on a mounted volume (Production) or local directory (Dev). It uses "Sidecar Files" strategy for metadata (e.g., `<file>.sha256` sits next to `<file>`).
- **Auth**: Bearer token authentication. Tokens are static or environment-variable based.
- **Contract**: Conforms to the GitHub Release API format for compatibility with `specify` CLI.
