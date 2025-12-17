# VLLM Proxy

A proxy for vLLM.

## Requirements

- Python 3.12+


## Run for development

```bash
# Run with Uvicorn
PYTHONPATH=src uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload

# Or run via the local runner (uses the project logging config)
PYTHONPATH=src python src/run.py

# FastAPI dev server (optional)
PYTHONPATH=src fastapi dev src/app/main.py --host 0.0.0.0 --port 8000
```


## Production 

### Build for production

```bash
# Minimal image (recommended)
bash docker/build.sh vllm-proxy:latest runtime

# Includes nv-ppcie-verifier in an isolated venv for GPU evidence collection
bash docker/build.sh vllm-proxy:gpu runtime-gpu
```

### Run for production

```bash
cd docker
docker compose up -d
```

### GPU evidence collection

The minimal image does not include `nv-ppcie-verifier` (it conflicts with the main app dependencies). Use the `runtime-gpu` image, or provide a separate Python environment and set `GPU_EVIDENCE_PYTHON` to its interpreter:

```bash
UV_NO_MANAGED_PYTHON=1 UV_PYTHON_DOWNLOADS=never uv venv .venv-ppcie -p python3
uv pip install --python .venv-ppcie/bin/python -r requirements-gpu.txt
export GPU_EVIDENCE_PYTHON="$PWD/.venv-ppcie/bin/python"
```

## Tests

### Quick Start

```bash
# Preferred: uv
UV_NO_MANAGED_PYTHON=1 UV_PYTHON_DOWNLOADS=never uv venv -p python3
uv pip install --python .venv/bin/python -r requirements.txt -r test-requirements.txt
./run_tests.sh
```

For detailed testing documentation, see [TESTING.md](./docs/TESTING.md).
